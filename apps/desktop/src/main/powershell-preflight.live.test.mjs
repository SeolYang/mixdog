import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { copyRuntimePackagePayload } from '../../scripts/runtime-package-payload.mjs';

const desktopDir = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const repositoryRoot = resolve(desktopDir, '../..');

test('packaged PowerShell preflight accepts comments and runs them in Windows PowerShell 5.1', {
  skip: process.platform !== 'win32' && 'requires Windows PowerShell 5.1',
}, async () => {
  const directory = mkdtempSync(join(desktopDir, 'out', 'mixdog-powershell-preflight-'));
  try {
    assert.ok(process.env.npm_execpath, 'run through npm run test:live -- powershell-preflight');
    const [manifest] = JSON.parse(execFileSync(process.execPath, [
      process.env.npm_execpath, 'pack', '--dry-run', '--json', '--ignore-scripts',
    ], { cwd: repositoryRoot, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, windowsHide: true }));
    const packageRoot = join(directory, 'node_modules', 'mixdog');
    await copyRuntimePackagePayload({
      rootDir: repositoryRoot,
      manifest,
      destination: packageRoot,
    });
    const { preflightPowerShellHygiene } = await import(pathToFileURL(join(
      packageRoot, 'src/runtime/agent/orchestrator/tools/builtin/shell-analysis.mjs'
    )).href);
    const shellName = join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe');
    const shell = { shellType: 'powershell', shellName };
    const run = (command) => spawnSync(shellName, [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
      Buffer.from(command, 'utf16le').toString('base64'),
    ], { encoding: 'utf8', timeout: 15_000, windowsHide: true });
    const command = [
      "$ErrorActionPreference = 'Stop'",
      '$PSVersionTable.PSVersion.ToString()',
      '# &&',
      "Write-Output 'COMMENT_ONLY_OK'",
      "Write-Output 'INLINE_COMMENT_OK' # &&",
      '<# && $PID=1 /c/comment "',
      '#> Write-Output BLOCK_COMMENT_OK',
    ].join('\r\n');
    const prepared = await preflightPowerShellHygiene(command, shell);
    assert.deepEqual(prepared, { command, block: null, note: null });
    const result = run(prepared.command);
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    const [version, ...lines] = result.stdout.trim().split(/\r?\n/);
    assert.match(version, /^5\.1\./);
    assert.deepEqual(lines, ['COMMENT_ONLY_OK', 'INLINE_COMMENT_OK', 'BLOCK_COMMENT_OK']);

    const invalid = '# "\r\nWrite-Output one && Write-Output two';
    assert.match((await preflightPowerShellHygiene(invalid, shell)).block, /`&&`/);
    const rejected = run(invalid);
    assert.equal(rejected.error, undefined);
    assert.equal(rejected.status, 1);
    assert.match(rejected.stderr, /InvalidEndOfLine/);

    const regressions = [
      ['$x=<# && #>1; Write-Output $x', '1'],
      ['$x=1+<# && #>2; Write-Output $x', '3'],
      ['Write-Output (1+<# && #>2)', '3'],
      ['Write-Output ([int]1+<# && #>2)', '3'],
      ['Write-Output CONTINUATION_OK `\n# &&', 'CONTINUATION_OK'],
      ['Write-Output /c/My` Documents', 'C:\\My Documents'],
      ['$h=@{a=<# && #>1}; Write-Output $h.a', '1'],
      ['Write-Output -InputObject:<# && #>1', '1'],
      ['1<# && #>+2', '3'],
      ['$x=1; $x<# && #>+2', '3'],
      ['return 1+<# && #>2', '3'],
    ];
    for (const [source, expected] of regressions) {
      const prepared = await preflightPowerShellHygiene(source, shell);
      assert.equal(prepared.block, null, source);
      assert.ok(!prepared.command.includes('\0'), source);
      const executed = run(`$ErrorActionPreference = 'Stop'\n${prepared.command}`);
      assert.equal(executed.error, undefined, source);
      assert.equal(executed.status, 0, executed.stderr);
      assert.equal(executed.stdout.trim(), expected, source);
    }

    // The actual 5.1 parser, not the masking implementation, is the oracle
    // for whether operator-adjacent text is a comment or an argument.
    const parserCases = [
      ...regressions.map(([source]) => [source, true]),
      ...['=', '+=', '+', '-', '*', '/', '%', '-eq'].flatMap((operator) => {
        const expression = ['=', '+='].includes(operator) ? `$x${operator}` : `$x=1${operator}`;
        return [
          [`${expression}<# && #>2`, true],
          [`Write-Output foo${operator}<# && #>`, false],
        ];
      }),
      ['Write-Output (1+2) foo+<# && #>', false],
      ['$x=Write-Output foo=<# && #>', false],
      ['Write-Output foo`\n# &&', false],
      ['$x=# &&\n1', true],
      ['& $cmd +<# && #>', false],
      ['& "Write-Output" +<# && #>', false],
      ['`e`cho +<# && #>', false],
      ['$h=@{a=<# /c/comment #>1}', true],
    ];
    const encodedCases = Buffer.from(JSON.stringify(parserCases.map(([source]) => source)), 'utf8').toString('base64');
    const parsed = run([
      `$cases = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encodedCases}')) | ConvertFrom-Json`,
      'foreach ($source in $cases) {',
      '$tokens = $null; $parseErrors = $null',
      '$null = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)',
      'Write-Output ($parseErrors.Count -eq 0)',
      '}',
    ].join('\n'));
    assert.equal(parsed.error, undefined);
    assert.equal(parsed.status, 0, parsed.stderr);
    assert.deepEqual(
      parsed.stdout.trim().split(/\r?\n/),
      parserCases.map(([, valid]) => valid ? 'True' : 'False')
    );
    for (const [source, valid] of parserCases) {
      const checked = await preflightPowerShellHygiene(source, shell);
      assert.equal(checked.block === null, valid, source);
      if (source.includes('/c/comment')) assert.equal(checked.command, source);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
