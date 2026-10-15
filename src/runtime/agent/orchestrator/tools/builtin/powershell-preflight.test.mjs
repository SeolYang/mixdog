import '../../../../../../scripts/test-data-dir.mjs';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { mock, test } from 'node:test';

let reply;
let calls;
let abortDuringParse;
mock.module('../shell-command.mjs', {
  namedExports: {
    execShellCommand: async (options) => {
      const path = options.env.MIXDOG_POWERSHELL_PARSE_SOURCE;
      calls.push({ source: await readFile(path, 'utf8'), path });
      abortDuringParse?.abort(new Error('cancelled during analysis'));
      if (reply instanceof Error) throw reply;
      return reply;
    },
  },
});
const { preflightPowerShellHygiene } = await import('./powershell-preflight.mjs');
const PS = { shellType: 'powershell', shellName: 'powershell.exe' };
const result = (data) => ({ exitCode: 0, stdout: JSON.stringify(data), stderr: '' });

test('ordinary commands and POSIX commands do not launch the parser', async () => {
  calls = [];
  for (const [command, shell] of [
    ['node --version', PS],
    ['Write-Output OK', PS],
    ['echo x && echo y /c/Docs $PID=1', { shellType: 'posix', shellName: 'bash' }],
  ]) {
    assert.deepEqual(await preflightPowerShellHygiene(command, shell), { command, block: null, note: null });
  }
  assert.deepEqual(calls, []);
});

test('the actual parser version determines connector support and source files are removed', async () => {
  calls = [];
  const command = 'Write-Output A && Write-Output B';
  reply = result({ major: 7, andAnd: true, pidAssignment: false, paths: [] });
  assert.equal((await preflightPowerShellHygiene(command, PS)).block, null);
  reply = result({ major: 5, andAnd: true, pidAssignment: false, paths: [] });
  assert.match((await preflightPowerShellHygiene(command, { ...PS, shellName: 'pwsh.exe' })).block, /`&&`/);
  for (const call of calls) {
    assert.equal(call.source, command);
    await assert.rejects(readFile(call.path), { code: 'ENOENT' });
  }
});

test('parser-confirmed drive roots are replaced without rebuilding any suffix', async () => {
  calls = [];
  const command = '# 😀 /d/comment\nWrite-Output /c/My` Documents/sub /e/Other';
  reply = result({
    major: 5, andAnd: false, pidAssignment: false,
    paths: [command.indexOf('/c/'), command.indexOf('/e/')],
  });
  const checked = await preflightPowerShellHygiene(command, PS);
  assert.equal(checked.command, '# 😀 /d/comment\nWrite-Output C:\\My` Documents/sub E:\\Other');
  assert.equal(checked.block, null);
  assert.match(checked.note, /MSYS/);
});

test('analysis failures and cancellation never pass the command through as safe', async () => {
  calls = [];
  const command = '# &&';
  for (const failure of [
    new Error('parser unavailable'),
    { exitCode: 1, stdout: '', stderr: 'parser failed' },
    { exitCode: null, stdout: '', stderr: '', timedOut: true },
    { exitCode: 0, stdout: 'not JSON', stderr: '' },
    result({ major: 5, andAnd: false, pidAssignment: false, paths: [999] }),
  ]) {
    reply = failure;
    const checked = await preflightPowerShellHygiene(command, PS);
    assert.match(checked.block, /could not analyze/);
    assert.equal(checked.command, command);
    assert.equal(checked.note, null);
  }
  const count = calls.length;
  assert.match((await preflightPowerShellHygiene(command, {
    ...PS, abortSignal: AbortSignal.abort(new Error('cancelled before analysis')),
  })).block, /cancelled before analysis/);
  assert.equal(calls.length, count);
  reply = result({ major: 5, andAnd: false, pidAssignment: false, paths: [] });
  abortDuringParse = new AbortController();
  try {
    assert.match((await preflightPowerShellHygiene(command, {
      ...PS, abortSignal: abortDuringParse.signal,
    })).block, /cancelled during analysis/);
  } finally {
    abortDuringParse = null;
  }
  for (const call of calls) await assert.rejects(readFile(call.path), { code: 'ENOENT' });
});
