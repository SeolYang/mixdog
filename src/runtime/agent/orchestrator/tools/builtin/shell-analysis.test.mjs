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
