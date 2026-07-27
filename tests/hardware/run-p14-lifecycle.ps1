param(
  [Parameter(Mandatory = $true)][string]$RouterHost,
  [Parameter(Mandatory = $true)][string]$IdentityFile,
  [Parameter(Mandatory = $true)][string]$KnownHostsFile,
  [Parameter(Mandatory = $true)][string]$OutputRoot,
  [string]$RunId = ""
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ssh = Join-Path $env:WINDIR "System32\OpenSSH\ssh.exe"
$scp = Join-Path $env:WINDIR "System32\OpenSSH\scp.exe"
if (!$RunId) { $RunId = "p14-lifecycle-$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))" }
if ($RunId -notmatch '^p14-lifecycle-[a-z0-9._-]{1,80}$') { throw "Unsafe P14 lifecycle run ID" }
if ($RouterHost -notmatch '^[A-Za-z0-9.:-]+$') { throw "Unsafe router host" }
$runner = Join-Path $PSScriptRoot "p14-lifecycle-runner.sh"
$launcher = Join-Path $PSScriptRoot "p14-launcher.sh"
foreach ($required in @($ssh, $scp, $IdentityFile, $KnownHostsFile, $runner, $launcher)) {
  if (!(Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing required file: $required" }
}

$go = $env:GO_BINARY
if (!$go) {
  $goCommand = Get-Command go -ErrorAction SilentlyContinue
  if ($goCommand) { $go = $goCommand.Source }
}
if (!$go) {
  $fallback = Join-Path $repo ".tools\go1.26.5\go\bin\go.exe"
  if (Test-Path -LiteralPath $fallback) { $go = $fallback }
}
if (!$go) { throw "Go toolchain is unavailable" }

$localRun = Join-Path $OutputRoot $RunId
$temp = Join-Path ([System.IO.Path]::GetTempPath()) "flintroute-$RunId"
New-Item -ItemType Directory -Force -Path $localRun, $temp | Out-Null
$candidate = Join-Path $temp "router-policy"
$oldOS, $oldArch, $oldCGO = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED
try {
  $env:GOOS = "linux"; $env:GOARCH = "arm64"; $env:CGO_ENABLED = "0"
  & $go build -trimpath -ldflags "-s -w" -o $candidate ./cmd/router-policy
  if ($LASTEXITCODE -ne 0) { throw "P14 ARM64 candidate build failed" }
} finally {
  $env:GOOS, $env:GOARCH, $env:CGO_ENABLED = $oldOS, $oldArch, $oldCGO
}

$sshArgs = @("-i", $IdentityFile, "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=$KnownHostsFile", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", "root@$RouterHost")
$scpArgs = @("-O", "-i", $IdentityFile, "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=$KnownHostsFile", "-o", "StrictHostKeyChecking=yes")
$remoteRoot = "/tmp/router-policy/p14-hardware"
$remoteRun = "$remoteRoot/$RunId"
$completed = $false
try {
  & $ssh @sshArgs "umask 077; mkdir -p '$remoteRun'; chmod 700 '$remoteRun'"
  if ($LASTEXITCODE -ne 0) { throw "Cannot create remote P14 run directory" }
  & $scp @scpArgs $candidate $runner $launcher "root@${RouterHost}:$remoteRun/"
  if ($LASTEXITCODE -ne 0) { throw "P14 candidate upload failed" }
  & $ssh @sshArgs "sh '$remoteRun/p14-launcher.sh' '$remoteRun'"
  if ($LASTEXITCODE -ne 0) { throw "Cannot launch disconnected P14 lifecycle run" }

  $deadline = (Get-Date).AddMinutes(12)
  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    & $ssh @sshArgs "test -f '$remoteRun/done'"
    if ($LASTEXITCODE -eq 0) { $completed = $true; break }
    $runnerPid = (& $ssh @sshArgs "cat '$remoteRun/runner.pid' 2>/dev/null").Trim()
    if ($runnerPid -notmatch '^[1-9][0-9]*$') { break }
    & $ssh @sshArgs "kill -0 '$runnerPid' 2>/dev/null"
    if ($LASTEXITCODE -ne 0) { break }
  }
  if (!$completed) {
    & $scp @scpArgs "root@${RouterHost}:$remoteRun/runner.log" "$localRun\" 2>$null
    foreach ($pattern in @("*.json", "*.txt")) {
      & $scp @scpArgs "root@${RouterHost}:$remoteRun/$pattern" "$localRun\" 2>$null
    }
    $log = Join-Path $localRun "runner.log"
    if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log | Select-Object -Last 80 }
    throw "P14 lifecycle run did not complete"
  }
  foreach ($pattern in @("*.json", "*.txt", "runner.log")) {
    & $scp @scpArgs "root@${RouterHost}:$remoteRun/$pattern" "$localRun\"
    if ($LASTEXITCODE -ne 0) { throw "Cannot download P14 lifecycle evidence: $pattern" }
  }
  $summary = Get-Content -LiteralPath (Join-Path $localRun "summary.txt")
  if ($summary -notcontains "result=PASS") { throw "P14 lifecycle summary is not PASS" }
  Write-Host "p14_lifecycle_run=$RunId"
  Write-Host "p14_lifecycle_evidence=$localRun"
  Write-Host "p14_lifecycle_result=PASS"
} finally {
  try { & $ssh @sshArgs "case '$remoteRun' in /tmp/router-policy/p14-hardware/p14-lifecycle-*) rm -rf '$remoteRun' ;; *) exit 64 ;; esac" | Out-Null } catch { }
  if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
