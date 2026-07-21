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
if (!$RunId) { $RunId = "p13-state-$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))" }
if ($RunId -notmatch '^p13-state-[a-z0-9._-]{1,80}$') { throw "Unsafe state-corruption run ID" }
if ($RouterHost -notmatch '^[A-Za-z0-9.:-]+$') { throw "Unsafe router host" }
foreach ($required in @($ssh, $scp, $IdentityFile, $KnownHostsFile)) {
  if (!(Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing required file: $required" }
}

$runner = Join-Path $PSScriptRoot "p13-state-corruption-runner.sh"
$localRun = Join-Path $OutputRoot $RunId
$remoteRun = "/tmp/flintroute-p13/$RunId"
$remoteRecovery = "/etc/router-policy/state/recovery-tests/$RunId"
$sshArgs = @("-i", $IdentityFile, "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=$KnownHostsFile", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", "root@$RouterHost")
$scpArgs = @("-O", "-i", $IdentityFile, "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=$KnownHostsFile", "-o", "StrictHostKeyChecking=yes")
$completed = $false

function Invoke-SSH([string]$Command) {
  $output = & $ssh @sshArgs $Command
  if ($LASTEXITCODE -ne 0) { throw "Remote command failed" }
  return ($output -join "`n")
}

function Assert-RouteProbe([string]$Route, [string]$ExpectedType, [string]$Domain, [string]$Service) {
  $raw = Invoke-SSH "ROUTER_POLICY_CONFIG=/etc/router-policy/config/default.json /usr/bin/router-policy probe-route --no-persist --route '$Route' '$Domain' '$Service'"
  $probe = $raw | ConvertFrom-Json
  if ($probe.status -ne "OK" -or !$probe.path_verified -or $probe.simulation -or $probe.route_type -ne $ExpectedType) {
    throw "Route proof failed for $Route"
  }
  return [ordered]@{ route = $Route; route_type = $probe.route_type; path_verified = [bool]$probe.path_verified; simulation = [bool]$probe.simulation }
}

try {
  New-Item -ItemType Directory -Path $localRun -Force | Out-Null
  Invoke-SSH "umask 077; mkdir -p '$remoteRun'; chmod 700 '$remoteRun'" | Out-Null
  & $scp @scpArgs $runner "root@${RouterHost}:$remoteRun/state-corruption-runner.sh"
  if ($LASTEXITCODE -ne 0) { throw "State-corruption runner upload failed" }
  Invoke-SSH "chmod 700 '$remoteRun/state-corruption-runner.sh'; '$remoteRun/state-corruption-runner.sh' run '$RunId'" | Out-Null

  $proofs = @(
    (Assert-RouteProbe "direct" "direct" "github.com" "github"),
    (Assert-RouteProbe "zapret" "zapret" "discord.com" "discord_acceptance"),
    (Assert-RouteProbe "proxy-4" "vless" "chatgpt.com" "chatgpt"),
    (Assert-RouteProbe "smart-dns-primary" "smart_dns" "chatgpt.com" "chatgpt")
  )
  & $scp @scpArgs "root@${RouterHost}:$remoteRun/state-corruption.env" $localRun
  if ($LASTEXITCODE -ne 0) { throw "State-corruption evidence copy failed" }
  [ordered]@{
    run_id = $RunId
    checked_at = (Get-Date).ToUniversalTime().ToString("o")
    routes = $proofs
    passed = $true
  } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $localRun "post-recovery-probes.json") -Encoding UTF8
  Get-ChildItem -LiteralPath $localRun -File | Sort-Object Name | ForEach-Object {
    "$((Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant())  $($_.Name)"
  } | Set-Content -LiteralPath (Join-Path $localRun "SHA256SUMS.txt") -Encoding ASCII
  Write-Host "p13_state_run=$RunId"
  Write-Host "p13_state_evidence=$localRun"
  Write-Host "p13_state_corruption=PASS"
  $completed = $true
} finally {
  try {
    Invoke-SSH "if test -s '$remoteRecovery/router-policy.bbolt.verified' && ! curl -fsS http://127.0.0.1:8787/api/v1/health >/dev/null 2>&1; then /etc/init.d/router-policy-watchdog stop >/dev/null 2>&1 || true; /etc/init.d/router-policy stop >/dev/null 2>&1 || true; cp '$remoteRecovery/router-policy.bbolt.verified' /etc/router-policy/state/router-policy.bbolt.emergency; chmod 600 /etc/router-policy/state/router-policy.bbolt.emergency; /usr/bin/router-policy internal-verify-state-backup --path /etc/router-policy/state/router-policy.bbolt.emergency >/dev/null; mv /etc/router-policy/state/router-policy.bbolt.emergency /etc/router-policy/state/router-policy.bbolt; /etc/init.d/router-policy start; /etc/init.d/router-policy-watchdog start; fi" | Out-Null
  } catch { }
  if ($completed) {
    try { Invoke-SSH "case '$remoteRun' in /tmp/flintroute-p13/p13-state-*) rm -rf '$remoteRun' ;; *) exit 64 ;; esac; case '$remoteRecovery' in /etc/router-policy/state/recovery-tests/p13-state-*) rm -rf '$remoteRecovery' ;; *) exit 64 ;; esac" | Out-Null } catch { }
  }
}
