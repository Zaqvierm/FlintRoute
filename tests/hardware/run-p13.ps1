param(
  [Parameter(Mandatory = $true)][string]$RouterHost,
  [Parameter(Mandatory = $true)][string]$IdentityFile,
  [Parameter(Mandatory = $true)][string]$KnownHostsFile,
  [Parameter(Mandatory = $true)][string]$RecoveryBundle,
  [Parameter(Mandatory = $true)][string]$OutputRoot,
  [string]$CasesPath = "",
  [string]$RunId = "",
  [switch]$KeepRemote
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ssh = Join-Path $env:WINDIR "System32\OpenSSH\ssh.exe"
$scp = Join-Path $env:WINDIR "System32\OpenSSH\scp.exe"

if (!$CasesPath) { $CasesPath = Join-Path $PSScriptRoot "p13-cases.example.json" }
if (!$RunId) { $RunId = "p13-$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))" }
if ($RunId -notmatch '^[a-z0-9][a-z0-9._-]{0,95}$') { throw "Unsafe run ID" }
if ($RouterHost -notmatch '^[A-Za-z0-9.:-]+$') { throw "Unsafe router host" }
foreach ($required in @($ssh, $scp, $IdentityFile, $KnownHostsFile, $RecoveryBundle, $CasesPath)) {
  if (!(Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing required file: $required" }
}

$commit = (& git -C $repo rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw "Cannot resolve source commit" }
$recoverySHA = (Get-FileHash -Algorithm SHA256 -LiteralPath $RecoveryBundle).Hash.ToLowerInvariant()
$go = $env:GO_BINARY
if (!$go) {
  $candidate = Join-Path $repo ".tools\go1.26.5\go\bin\go.exe"
  if (Test-Path -LiteralPath $candidate) { $go = $candidate } else { $go = (Get-Command go -ErrorAction Stop).Source }
}

$temp = Join-Path ([System.IO.Path]::GetTempPath()) "flintroute-$RunId"
$localRun = Join-Path $OutputRoot $RunId
if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
New-Item -ItemType Directory -Path $temp, $localRun -Force | Out-Null
$hardwareBinary = Join-Path $temp "flintroute-hardware"
$oldGOOS, $oldGOARCH, $oldCGO = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED
try {
  $env:GOOS = "linux"; $env:GOARCH = "arm64"; $env:CGO_ENABLED = "0"
  & $go build -trimpath -ldflags "-s -w" -o $hardwareBinary ./cmd/flintroute-hardware
  if ($LASTEXITCODE -ne 0) { throw "Hardware harness build failed" }
} finally {
  $env:GOOS, $env:GOARCH, $env:CGO_ENABLED = $oldGOOS, $oldGOARCH, $oldCGO
}

$sshArgs = @("-i", $IdentityFile, "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=$KnownHostsFile", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", "root@$RouterHost")
$scpArgs = @("-O", "-i", $IdentityFile, "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=$KnownHostsFile", "-o", "StrictHostKeyChecking=yes")
$remoteBase = "/tmp/flintroute-p13"
$remoteRun = "$remoteBase/$RunId"

& $ssh @sshArgs "umask 077; mkdir -p '$remoteRun'; chmod 700 '$remoteRun'"
if ($LASTEXITCODE -ne 0) { throw "Remote evidence directory creation failed" }
& $scp @scpArgs $hardwareBinary $CasesPath "root@${RouterHost}:$remoteRun/"
if ($LASTEXITCODE -ne 0) { throw "Harness upload failed" }

$remoteBinarySHA = (& $ssh @sshArgs "sha256sum /usr/bin/router-policy | awk '{print `$1}'").Trim()
if ($LASTEXITCODE -ne 0 -or $remoteBinarySHA -notmatch '^[0-9a-f]{64}$') { throw "Cannot bind the installed router-policy digest" }
$remoteHarness = "$remoteRun/flintroute-hardware"
$remoteCases = "$remoteRun/$([System.IO.Path]::GetFileName($CasesPath))"
& $ssh @sshArgs "chmod 700 '$remoteHarness' && '$remoteHarness' baseline --run-dir '$remoteRun' --commit '$commit' --build-sha256 '$remoteBinarySHA' --recovery-sha256 '$recoverySHA'"
if ($LASTEXITCODE -ne 0) { throw "P13 baseline gate failed" }
& $ssh @sshArgs "'$remoteHarness' matrix --run-dir '$remoteRun' --cases '$remoteCases'"
if ($LASTEXITCODE -ne 0) { throw "P13 route matrix failed" }
& $ssh @sshArgs "'$remoteHarness' finalize --run-dir '$remoteRun'"
if ($LASTEXITCODE -ne 0) { throw "P13 evidence finalization failed" }

& $scp @scpArgs "root@${RouterHost}:$remoteRun/*" "$localRun\"
if ($LASTEXITCODE -ne 0) { throw "Evidence download failed" }

$manifest = Join-Path $localRun "SHA256SUMS.txt"
foreach ($line in Get-Content -LiteralPath $manifest -Encoding UTF8) {
  if (!$line) { continue }
  if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$') { throw "Invalid evidence manifest line" }
  $expected, $relative = $Matches[1], $Matches[2]
  $path = Join-Path $localRun ($relative -replace '/', '\')
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
  if ($actual -ne $expected) { throw "Evidence digest mismatch: $relative" }
}

if (!$KeepRemote) {
  & $ssh @sshArgs "case '$remoteRun' in /tmp/flintroute-p13/p13-*) rm -rf '$remoteRun' ;; *) exit 64 ;; esac"
  if ($LASTEXITCODE -ne 0) { throw "Verified remote evidence cleanup failed" }
}

Remove-Item -LiteralPath $temp -Recurse -Force
Write-Host "p13_run=$RunId"
Write-Host "p13_commit=$commit"
Write-Host "p13_evidence=$localRun"
Write-Host "p13_baseline_matrix=PASS"
