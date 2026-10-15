import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Parse data, never invoke it. The source is read as UTF-8 from a private
// temporary file, not interpolated into PowerShell code or an argv payload.
const PARSER_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$source = [IO.File]::ReadAllText($env:MIXDOG_POWERSHELL_PARSE_SOURCE, [Text.Encoding]::UTF8)
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
function Has-AndAnd($items) {
  foreach ($item in $items) {
    if ($item.Kind -eq [System.Management.Automation.Language.TokenKind]::AndAnd) { return $true }
    if ($item -is [System.Management.Automation.Language.StringExpandableToken]) {
      if (Has-AndAnd $item.NestedTokens) { return $true }
    }
  }
  return $false
}
$assignments = @($ast.FindAll({
  param($node)
  if ($node -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { return $false }
  $left = $node.Left
  while ($left -is [System.Management.Automation.Language.AttributedExpressionAst]) { $left = $left.Child }
  return ($left -is [System.Management.Automation.Language.VariableExpressionAst] -and $left.VariablePath.UserPath -ieq 'PID')
}, $true))
$paths = @($ast.FindAll({
  param($node)
  return (($node -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
    $node -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) -and
    $node.StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::BareWord -and
    $node.Extent.Text -match '^/[a-zA-Z]/')
}, $true) | ForEach-Object { $_.Extent.StartOffset })
[pscustomobject]@{
  major = $PSVersionTable.PSVersion.Major
  andAnd = [bool](Has-AndAnd $tokens)
  pidAssignment = ($assignments.Count -gt 0)
  paths = $paths
} | ConvertTo-Json -Compress
`;

async function parsePowerShellSource(source, { shellName, cwd, abortSignal, timeoutMs, ownerSessionId, clientHostPid }) {
  const directory = await mkdtemp(join(tmpdir(), 'mixdog-powershell-parse-'));
  try {
    const sourcePath = join(directory, 'source.txt');
    await writeFile(sourcePath, source, 'utf8');
    const [{ execShellCommand }, { buildShellSpawnEnv }] = await Promise.all([
      import('../shell-command.mjs'),
      import('./bash-tool/spawn-env.mjs'),
    ]);
    const result = await execShellCommand({
      shell: shellName,
      command: 'PowerShell syntax analysis (ParseInput only)',
      directArgv: [
        '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
        Buffer.from(PARSER_SCRIPT, 'utf16le').toString('base64'),
      ],
      env: { ...buildShellSpawnEnv(cwd), MIXDOG_POWERSHELL_PARSE_SOURCE: sourcePath },
      cwd,
      abortSignal,
      timeoutMs,
      admissionWaitMs: timeoutMs,
      backgroundOnTimeout: false,
      ownerSessionId,
      clientHostPid,
    });
    if (result.exitCode !== 0 || result.killed || result.timedOut || result.outputCaptureError) {
      throw new Error(result.stderr || result.failureReason || result.killCause || 'PowerShell parser did not complete');
    }
    const parsed = JSON.parse(result.stdout);
    if (!Number.isInteger(parsed.major) || typeof parsed.andAnd !== 'boolean' ||
        typeof parsed.pidAssignment !== 'boolean' || !Array.isArray(parsed.paths) ||
        parsed.paths.some((offset) => !Number.isInteger(offset) || offset < 0 ||
          !/^\/[a-zA-Z]\//.test(source.slice(offset, offset + 3)))) {
      throw new Error('PowerShell parser returned an invalid analysis');
    }
    return parsed;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

export async function preflightPowerShellHygiene(command, {
  shellType, shellName, cwd = process.cwd(), abortSignal = null,
  timeoutMs = 10_000, ownerSessionId = null, clientHostPid = null,
} = {}) {
  const original = String(command || '');
  const unchanged = { command: original, block: null, note: null };
  if (shellType !== 'powershell' || !original.trim()) return unchanged;
  // Only a candidate detector: all syntax decisions belong to ParseInput.
  // Ordinary commands keep the direct-exe path without a second process.
  if (!/&&|\$\{?PID\b|\/[a-zA-Z]\//i.test(original)) return unchanged;
  try {
    abortSignal?.throwIfAborted();
    const analysis = await parsePowerShellSource(original, {
      shellName, cwd, abortSignal, timeoutMs, ownerSessionId, clientHostPid,
    });
    abortSignal?.throwIfAborted();
    const violations = [];
    if (analysis.pidAssignment) {
      violations.push('`$PID` is a reserved PowerShell automatic variable — do not reassign it (use a different name).');
    }
    if (analysis.major < 7 && analysis.andAnd) {
      violations.push('`&&` is not supported in Windows PowerShell 5.1 — use separate calls or explicit success checks for dependent commands.');
    }
    if (violations.length) {
      return { ...unchanged, block: `PowerShell preflight blocked this command (invalid PowerShell syntax). Fix and retry:\n- ${violations.join('\n- ')}` };
    }
    let rewritten = original;
    // Only native-parser-confirmed bareword drive roots are replaced. Windows
    // accepts forward slashes in the suffix; retaining it preserves quotes,
    // escapes and interpolation instead of rebuilding text from a mask.
    for (const offset of [...new Set(analysis.paths)].sort((a, b) => b - a)) {
      rewritten = `${rewritten.slice(0, offset)}${original[offset + 1].toUpperCase()}:\\${rewritten.slice(offset + 3)}`;
    }
    return {
      command: rewritten,
      block: null,
      note: rewritten === original ? null : 'note: rewrote MSYS-style `/x/…` absolute path(s) to Windows `X:\\…`.',
    };
  } catch (error) {
    return { ...unchanged, block: `PowerShell preflight could not analyze this command: ${error.message || String(error)}` };
  }
}
