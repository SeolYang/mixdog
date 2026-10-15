import assert from 'node:assert/strict';
import test from 'node:test';
import { preflightPowerShellHygiene } from './shell-analysis.mjs';

const PS = { shellType: 'powershell', shellName: 'powershell.exe' };

test('PowerShell comments are preserved and excluded from syntax checks and path rewrites', () => {
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
      preflightPowerShellHygiene(command, PS),
      { command, block: null, note: null },
      JSON.stringify(command)
    );
  }
});

test('live connectors and assignments after comments remain blocked', () => {
  for (const newline of ['\n', '\r\n', '\r']) {
    assert.match(
      preflightPowerShellHygiene(`# "\`${newline}Write-Output one && Write-Output two`, PS).block,
      /`&&`/
    );
    assert.match(preflightPowerShellHygiene(`# '${newline}$PID=1`, PS).block, /`\$PID`/);
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
    assert.match(preflightPowerShellHygiene(command, PS).block, /`&&`/, command);
  }
  assert.match(preflightPowerShellHygiene('<# $PID=2 #> $PID=1', PS).block, /`\$PID`/);
});

test('a live MSYS path is rewritten without changing neighboring comments', () => {
  const result = preflightPowerShellHygiene('# /d/comment "\ncd /c/Project # /e/comment', PS);
  assert.equal(result.command, '# /d/comment "\ncd C:\\Project # /e/comment');
  assert.equal(result.block, null);
  assert.match(result.note, /MSYS/);
});

test('expression operators introduce comments without changing argument tokens', () => {
  for (const operator of ['=', '+=', '+', '-', '*', '/', '%', '-eq']) {
    const expression = ['=', '+='].includes(operator) ? `$x${operator}` : `$x=1${operator}`;
    const command = `${expression}<# && $PID=1 #>2`;
    assert.deepEqual(preflightPowerShellHygiene(command, PS), { command, block: null, note: null });
    assert.match(preflightPowerShellHygiene(`${command}; Write-Output A && Write-Output B`, PS).block, /`&&`/);
    assert.match(preflightPowerShellHygiene(`${command}; $PID=1`, PS).block, /`\$PID`/);
    assert.match(preflightPowerShellHygiene(`Write-Output foo${operator}<# && #>`, PS).block, /`&&`/);
  }
  for (const command of [
    '$x=# &&\n1',
    'Write-Output (1+<# && #>2)',
    '$x=Write-Output (1+<# && #>2)',
    'Write-Output ([int]1+<# && #>2)',
  ]) {
    assert.deepEqual(preflightPowerShellHygiene(command, PS), { command, block: null, note: null });
  }
  for (const command of [
    'Write-Output (1+2) foo+<# && #>',
    '$x=Write-Output foo=<# && #>',
    'Write-Output $x+<# && #>',
  ]) {
    assert.match(preflightPowerShellHygiene(command, PS).block, /`&&`/);
  }
});

test('line continuations preserve comment and argument boundaries', () => {
  for (const newline of ['\n', '\r\n', '\r']) {
    for (const command of [
      `Write-Output \`${newline}# &&${newline}Write-Output OK`,
      `Write-Output \`${newline}<# && #> OK`,
    ]) {
      assert.deepEqual(preflightPowerShellHygiene(command, PS), { command, block: null, note: null });
    }
    assert.match(preflightPowerShellHygiene(`Write-Output foo\`${newline}# &&`, PS).block, /`&&`/);
    assert.match(preflightPowerShellHygiene(`Write-Output \`${newline}# &&${newline}$PID=1`, PS).block, /`\$PID`/);
  }
});

test('MSYS rewrites preserve escapes instead of inserting masked characters', () => {
  for (const shell of [PS, { shellType: 'powershell', shellName: 'pwsh.exe' }]) {
    for (const suffix of ['My` Documents', 'My`#Documents', 'My`;Documents', 'My`&Documents']) {
      const result = preflightPowerShellHygiene(`Write-Output /c/${suffix}`, shell);
      assert.equal(result.command, `Write-Output C:\\${suffix}`);
      assert.equal(result.block, null);
      assert.match(result.note, /MSYS/);
      assert.ok(!result.command.includes('\0'));
    }
  }
  const command = 'Write-Output /c/My` Documents';
  assert.deepEqual(
    preflightPowerShellHygiene(command, { shellType: 'posix', shellName: 'bash' }),
    { command, block: null, note: null }
  );
  assert.equal(preflightPowerShellHygiene('Write-Output A && Write-Output B', {
    shellType: 'powershell', shellName: 'pwsh.exe',
  }).block, null);
});
