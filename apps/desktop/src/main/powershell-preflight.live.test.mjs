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
    const prepared = preflightPowerShellHygiene(command, shell);
    assert.deepEqual(prepared, { command, block: null, note: null });
    const result = run(prepared.command);
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    const [version, ...lines] = result.stdout.trim().split(/\r?\n/);
    assert.match(version, /^5\.1\./);
    assert.deepEqual(lines, ['COMMENT_ONLY_OK', 'INLINE_COMMENT_OK', 'BLOCK_COMMENT_OK']);

    const invalid = '# "\r\nWrite-Output one && Write-Output two';
    assert.match(preflightPowerShellHygiene(invalid, shell).block, /`&&`/);
    const rejected = run(invalid);
    assert.equal(rejected.error, undefined);
    assert.equal(rejected.status, 1);
    assert.match(rejected.stderr, /InvalidEndOfLine/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
