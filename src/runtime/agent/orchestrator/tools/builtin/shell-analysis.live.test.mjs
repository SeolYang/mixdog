import '../../../../../../scripts/test-data-dir.mjs';
import assert from 'node:assert/strict';
import { after, test as nodeTest } from 'node:test';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { shutdownNativeSpawnServer } from '../lib/native-spawn-client.mjs';
import { preflightPowerShellHygiene } from './shell-analysis.mjs';

const PS = { shellType: 'powershell', shellName: 'powershell.exe' };
const test = (name, fn) => nodeTest(name, {
  skip: process.platform !== 'win32' && 'requires Windows PowerShell 5.1',
}, fn);
after(() => shutdownNativeSpawnServer());

test('PowerShell comments are preserved and excluded from syntax checks and path rewrites', async () => {
  for (const command of [
    '# &&',
    'Write-Output OK # && $PID=1 /c/comment',
    '# " && $PID=1 /c/comment\nWrite-Output OK',
    "# ' && $PID=1 /c/comment\r\nWrite-Output OK",
    '# &&\rWrite-Output OK',
    '<# && $PID=1 /c/comment " \'\n#> Write-Output OK',
    'Write-Output OK;# &&',
    '(Write-Output OK)# &&',
    'Write-Output "OK"# &&',
    "Write-Output '#' # &&",
    '<# first #><# && #> Write-Output OK',
    "Write-Output @'\n' # && $PID=1 /c/literal\n'@",
    'Write-Output @"\n" # && $PID=1 /c/literal\n"@',
  ]) {
    assert.deepEqual(
      await preflightPowerShellHygiene(command, PS),
      { command, block: null, note: null },
      JSON.stringify(command)
    );
  }
});

test('live connectors and assignments after comments remain blocked', async () => {
  for (const newline of ['\n', '\r\n', '\r']) {
    assert.match(
      (await preflightPowerShellHygiene(`# "\`${newline}Write-Output one && Write-Output two`, PS)).block,
      /`&&`/
    );
    assert.match((await preflightPowerShellHygiene(`# '${newline}$PID=1`, PS)).block, /`\$PID`/);
  }
  for (const command of [
    '<# && #> Write-Output one && Write-Output two',
    '<# outer <# inner #> Write-Output one && Write-Output two',
    "Write-Output @'\n' # literal\n'@; Write-Output one && Write-Output two",
    'Write-Output foo#bar && Write-Output two',
    'Write-Output foo<# && #>',
    'Write-Output `# && Write-Output two',
    'Write-Output foo` #bar && Write-Output two',
  ]) {
    assert.match((await preflightPowerShellHygiene(command, PS)).block, /`&&`/, command);
  }
  assert.match((await preflightPowerShellHygiene('<# $PID=2 #> $PID=1', PS)).block, /`\$PID`/);
});

test('a live MSYS path is rewritten without changing neighboring comments', async () => {
  const result = await preflightPowerShellHygiene('# /d/comment "\ncd /c/Project # /e/comment', PS);
  assert.equal(result.command, '# /d/comment "\ncd C:\\Project # /e/comment');
  assert.equal(result.block, null);
  assert.match(result.note, /MSYS/);
});

test('expression operators introduce comments without changing argument tokens', async () => {
  for (const operator of ['=', '+=', '+', '-', '*', '/', '%', '-eq']) {
    const expression = ['=', '+='].includes(operator) ? `$x${operator}` : `$x=1${operator}`;
    const command = `${expression}<# && $PID=1 #>2`;
    assert.deepEqual(await preflightPowerShellHygiene(command, PS), { command, block: null, note: null });
    assert.match((await preflightPowerShellHygiene(`${command}; Write-Output A && Write-Output B`, PS)).block, /`&&`/);
    assert.match((await preflightPowerShellHygiene(`${command}; $PID=1`, PS)).block, /`\$PID`/);
    assert.match((await preflightPowerShellHygiene(`Write-Output foo${operator}<# && #>`, PS)).block, /`&&`/);
  }
  for (const command of [
    '$x=# &&\n1',
    'Write-Output (1+<# && #>2)',
    '$x=Write-Output (1+<# && #>2)',
    'Write-Output ([int]1+<# && #>2)',
  ]) {
    assert.deepEqual(await preflightPowerShellHygiene(command, PS), { command, block: null, note: null });
  }
  for (const command of [
    'Write-Output (1+2) foo+<# && #>',
    '$x=Write-Output foo=<# && #>',
    'Write-Output $x+<# && #>',
  ]) {
    assert.match((await preflightPowerShellHygiene(command, PS)).block, /`&&`/);
  }
});

test('line continuations preserve comment and argument boundaries', async () => {
  for (const newline of ['\n', '\r\n', '\r']) {
    for (const command of [
      `Write-Output \`${newline}# &&${newline}Write-Output OK`,
      `Write-Output \`${newline}<# && #> OK`,
    ]) {
      assert.deepEqual(await preflightPowerShellHygiene(command, PS), { command, block: null, note: null });
    }
    // ParseInput treats CRLF after a backtick inside a bareword differently
    // from LF or CR: the LF ends that token and the following # is a comment.
    const continuedArgument = await preflightPowerShellHygiene(`Write-Output foo\`${newline}# &&`, PS);
    if (newline === '\r\n') assert.equal(continuedArgument.block, null);
    else assert.match(continuedArgument.block, /`&&`/);
    assert.match((await preflightPowerShellHygiene(`Write-Output \`${newline}# &&${newline}$PID=1`, PS)).block, /`\$PID`/);
  }
});

test('MSYS rewrites preserve escapes instead of inserting masked characters', async () => {
  for (const shell of [PS, { shellType: 'powershell', shellName: 'pwsh.exe' }]) {
    for (const suffix of ['My` Documents', 'My`#Documents', 'My`;Documents', 'My`&Documents']) {
      const result = await preflightPowerShellHygiene(`Write-Output /c/${suffix}`, shell);
      assert.equal(result.command, `Write-Output C:\\${suffix}`);
      assert.equal(result.block, null);
      assert.match(result.note, /MSYS/);
      assert.ok(!result.command.includes('\0'));
    }
  }
  const command = 'Write-Output /c/My` Documents';
  assert.deepEqual(
    await preflightPowerShellHygiene(command, { shellType: 'posix', shellName: 'bash' }),
    { command, block: null, note: null }
  );
  assert.equal((await preflightPowerShellHygiene('Write-Output A && Write-Output B', {
    shellType: 'powershell', shellName: 'pwsh.exe',
  })).block, null);
});

test('native syntax boundaries cover hashtables, parameters, keywords and invocation operators', async () => {
  for (const command of [
    '$h=@{a=<# && #>1}; Write-Output $h.a',
    '$h=@{a=<# /c/comment #>1}; Write-Output $h.a',
    'Write-Output -InputObject:<# && #>1',
    '1<# && #>+2',
    '$x=1; $x<# && #>+2',
    'return 1+<# && #>2',
    'Write-Output "/c/literal"',
    "Write-Output foo='/c/literal'",
  ]) {
    assert.deepEqual(await preflightPowerShellHygiene(command, PS), { command, block: null, note: null }, command);
  }
  for (const command of [
    '& $cmd +<# && #>',
    '& "Write-Output" +<# && #>',
    '. $cmd +<# && #>',
    '`e`cho +<# && #>',
    'Write-Output "$(Write-Output A && Write-Output B)"',
    'Write-Output --% && /c/literal',
  ]) {
    assert.match((await preflightPowerShellHygiene(command, PS)).block, /`&&`/, command);
  }
  for (const command of ['$PID <# note #>=1', '[int]$PID=1', '${PID}=1']) {
    assert.match((await preflightPowerShellHygiene(command, PS)).block, /`\$PID`/, command);
  }
});

test('only bareword drive roots change and all other source bytes survive', async () => {
  const source = '# 😀 /d/comment\nWrite-Output /c/한글` Documents/sub /e/Other "문자열 /f/literal"';
  const expected = '# 😀 /d/comment\nWrite-Output C:\\한글` Documents/sub E:\\Other "문자열 /f/literal"';
  const result = await preflightPowerShellHygiene(source, PS);
  assert.equal(result.block, null);
  assert.equal(result.command, expected);
  assert.ok(!result.command.includes('\0'));
  for (const [command, rewritten] of [
    ['Write-Output /c/$name', 'Write-Output C:\\$name'],
    ['Write-Output /c/${name}', 'Write-Output C:\\${name}'],
    ["Write-Output /c/'My Folder'", "Write-Output C:\\'My Folder'"],
    ['Write-Output "$(Write-Output /c/Live)"', 'Write-Output "$(Write-Output C:\\Live)"'],
  ]) {
    const checked = await preflightPowerShellHygiene(command, PS);
    assert.equal(checked.command, rewritten);
    assert.equal(checked.block, null);
  }
});

test('analysis never executes source, accepts long input and reports bounded latency', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'mixdog-parse-no-execution-'));
  try {
    const marker = join(directory, 'must-not-exist.txt').replaceAll("'", "''");
    const source = `Set-Content -LiteralPath '${marker}' -Value EXECUTED\n# &&\n${'# filler\n'.repeat(5000)}`;
    const started = performance.now();
    const result = await preflightPowerShellHygiene(source, PS);
    assert.deepEqual(result, { command: source, block: null, note: null });
    assert.deepEqual(await readdir(directory), []);
    t.diagnostic(`parse-only ${(performance.now() - started).toFixed(1)}ms; ${source.length} UTF-16 code units`);
    const fastStarted = performance.now();
    assert.equal((await preflightPowerShellHygiene('Write-Output OK', PS)).block, null);
    t.diagnostic(`non-candidate ${(performance.now() - fastStarted).toFixed(1)}ms`);
    const cancelled = await preflightPowerShellHygiene('# &&', { ...PS, abortSignal: AbortSignal.abort(new Error('cancelled')) });
    assert.match(cancelled.block, /cancelled/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
