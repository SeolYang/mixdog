import '../../../../../../scripts/test-data-dir.mjs';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import test from 'node:test';
import { normalizeToolEnvelope } from '../../session/tool-envelope.mjs';
import { shutdownNativeSpawnServer } from '../lib/native-spawn-client.mjs';
import { executeBashTool } from './bash-tool.mjs';
import { setConfiguredShell } from './shell-runtime.mjs';

test('the shell tool executes comment-bearing commands through Windows PowerShell 5.1', {
  skip: process.platform !== 'win32' && 'requires Windows PowerShell 5.1',
}, async (t) => {
  setConfiguredShell(join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe'));
  t.after(async () => {
    setConfiguredShell('');
    await shutdownNativeSpawnServer();
  });
  const run = async (command) => normalizeToolEnvelope(await executeBashTool(
    { command, timeout_ms: 10_000 },
    process.cwd()
  )).result;

  await t.test('comments reach the real shell and return exact output', async () => {
    const output = await run([
      '$PSVersionTable.PSVersion.ToString()',
      '# &&',
      'Write-Output COMMENT_ONLY_OK',
      'Write-Output INLINE_COMMENT_OK # &&',
      '<# && $PID=1 /c/comment "',
      '#> Write-Output BLOCK_COMMENT_OK',
    ].join('\r\n'));
    const [status, separator, version, ...lines] = output.trim().split(/\r?\n/);
    assert.equal(status, '[exit code: 0]');
    assert.equal(separator, '');
    assert.match(version, /^5\.1\./);
    assert.deepEqual(lines, ['COMMENT_ONLY_OK', 'INLINE_COMMENT_OK', 'BLOCK_COMMENT_OK']);
  });

  await t.test('comments do not break pipelines or quoted arguments', async () => {
    assert.equal(
      (await run('# &&\nWrite-Output A | ForEach-Object { $_.ToLowerInvariant() } # &&')).trim(),
      '[exit code: 0]\n\na'
    );
    assert.equal(
      (await run('Write-Output "a && b" # &&')).trim(),
      '[exit code: 0]\n\na && b'
    );
  });

  await t.test('expression comments, continuations and escaped paths survive dispatch', async () => {
    for (const [command, expected] of [
      ['$x=<# && #>1; Write-Output $x', '1'],
      ['$x=1+<# && #>2; Write-Output $x', '3'],
      ['Write-Output ([int]1+<# && #>2)', '3'],
      ['Write-Output CONTINUATION_OK `\n# &&', 'CONTINUATION_OK'],
      ['Write-Output /c/My` Documents', 'C:\\My Documents'],
    ]) {
      assert.equal((await run(command)).trim(), `[exit code: 0]\n\n${expected}`, command);
    }
  });

  await t.test('live invalid syntax after a comment remains blocked before dispatch', async () => {
    const connector = await run('# "\nWrite-Output SHOULD_NOT_RUN && Write-Output NEVER');
    assert.match(connector, /PowerShell preflight blocked/);
    assert.match(connector, /`&&` is not supported/);
    assert.doesNotMatch(connector, /SHOULD_NOT_RUN|NEVER|\[exit code: 0\]/);
    const assignment = await run("# '\n$PID=1");
    assert.match(assignment, /PowerShell preflight blocked/);
    assert.match(assignment, /`\$PID` is a reserved/);
  });
});
