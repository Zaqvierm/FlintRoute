param(
  [Parameter(Mandatory = $true)][string]$RouterHost,
  [Parameter(Mandatory = $true)][string]$IdentityFile,
  [Parameter(Mandatory = $true)][string]$KnownHostsFile,
  [Parameter(Mandatory = $true)][string]$RecoveryBundle,
  [Parameter(Mandatory = $true)][string]$OutputRoot,
  [string]$RunId = "",
  [switch]$SkipControlledReboot
)

$ErrorActionPreference = "Stop"
$ssh = Join-Path $env:WINDIR "System32\OpenSSH\ssh.exe"
$scp = Join-Path $env:WINDIR "System32\OpenSSH\scp.exe"
if (!$RunId) { $RunId = "p13-fault-$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))" }
if ($RunId -notmatch '^p13-fault-[a-z0-9._-]{1,80}$') { throw "Unsafe fault run ID" }
if ($RouterHost -notmatch '^[A-Za-z0-9.:-]+$') { throw "Unsafe router host" }
$runner = Join-Path $PSScriptRoot "p13-fault-runner.sh"
foreach ($required in @($ssh, $scp, $IdentityFile, $KnownHostsFile, $RecoveryBundle, $runner)) {
  if (!(Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing required file: $required" }
}

$recoverySHA = (Get-FileHash -Algorithm SHA256 -LiteralPath $RecoveryBundle).Hash.ToLowerInvariant()
if ($recoverySHA -notmatch '^[0-9a-f]{64}$') { throw "Recovery bundle digest is invalid" }
$localRun = Join-Path $OutputRoot $RunId
New-Item -ItemType Directory -Path $localRun -Force | Out-Null
$sshArgs = @("-i", $IdentityFile, "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=$KnownHostsFile", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", "root@$RouterHost")
$scpArgs = @("-O", "-i", $IdentityFile, "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=$KnownHostsFile", "-o", "StrictHostKeyChecking=yes")
$remoteRun = "/tmp/flintroute-p13/$RunId"

function Complete-FaultRun([string]$RebootStatus) {
  @("recovery_sha256=$recoverySHA", "controlled_reboot=$RebootStatus", "process_restart_matrix=PASS") | Set-Content -LiteralPath (Join-Path $localRun "summary.txt") -Encoding ASCII
  $manifest = Get-ChildItem -LiteralPath $localRun -File | Sort-Object Name | ForEach-Object {
    "{0}  {1}" -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant(), $_.Name
  }
  $manifest | Set-Content -LiteralPath (Join-Path $localRun "SHA256SUMS.txt") -Encoding ASCII
  & $ssh @sshArgs "case '$remoteRun' in /tmp/flintroute-p13/p13-fault-*) rm -rf '$remoteRun' ;; *) exit 64 ;; esac"
  if ($LASTEXITCODE -ne 0) { throw "Verified remote fault cleanup failed" }
  Write-Host "p13_fault_run=$RunId"
  Write-Host "p13_fault_evidence=$localRun"
  Write-Host "p13_fault_process_matrix=PASS"
  Write-Host "p13_fault_controlled_reboot=$RebootStatus"
}

& $ssh @sshArgs "umask 077; mkdir -p '$remoteRun'; chmod 700 '$remoteRun'"
if ($LASTEXITCODE -ne 0) { throw "Cannot create remote fault directory" }
& $scp @scpArgs $runner "root@${RouterHost}:$remoteRun/p13-fault-runner.sh"
if ($LASTEXITCODE -ne 0) { throw "Fault runner upload failed" }
& $ssh @sshArgs "chmod 700 '$remoteRun/p13-fault-runner.sh' && '$remoteRun/p13-fault-runner.sh' '$remoteRun'"
if ($LASTEXITCODE -ne 0) { throw "Process fault matrix failed" }
& $scp @scpArgs "root@${RouterHost}:$remoteRun/*" "$localRun\"
if ($LASTEXITCODE -ne 0) { throw "Fault evidence download failed" }
if ($SkipControlledReboot) {
  Complete-FaultRun "NOT_RUN"
  exit 0
}

$preReboot = & $ssh @sshArgs "sha256sum /etc/router-policy/config/default.json /etc/router-policy/zapret/nfqws.conf; cat /tmp/router-policy/active-transaction.env"
if ($LASTEXITCODE -ne 0) { throw "Cannot capture pre-reboot state" }
$preReboot | Set-Content -LiteralPath (Join-Path $localRun "pre-reboot-sha256.txt") -Encoding ASCII

& $ssh @sshArgs "sync; reboot" 2>$null
$deadline = (Get-Date).AddMinutes(6)
$reconnected = $false
Start-Sleep -Seconds 10
while ((Get-Date) -lt $deadline) {
  $attemptExit = 1
  try {
    & $ssh @sshArgs "true" 2>$null
    $attemptExit = $LASTEXITCODE
  } catch {
    $attemptExit = 1
  }
  if ($attemptExit -eq 0) { $reconnected = $true; break }
  Start-Sleep -Seconds 5
}
if (!$reconnected) { throw "Router did not reconnect after controlled reboot" }

$servicesReady = $false
$serviceDeadline = (Get-Date).AddMinutes(2)
while ((Get-Date) -lt $serviceDeadline) {
  $serviceExit = 1
  try {
    & $ssh @sshArgs "/etc/init.d/router-policy running && /etc/init.d/router-policy-watchdog running && /etc/init.d/router-policy-zapret running && /etc/init.d/router-policy-xray running && ROUTER_POLICY_CONFIG=/etc/router-policy/config/default.json /usr/bin/router-policy status >/dev/null" 2>$null
    $serviceExit = $LASTEXITCODE
  } catch {
    $serviceExit = 1
  }
  if ($serviceExit -eq 0) { $servicesReady = $true; break }
  Start-Sleep -Seconds 3
}
if (!$servicesReady) { throw "Services did not become ready after controlled reboot" }
$postStatus = & $ssh @sshArgs "ROUTER_POLICY_CONFIG=/etc/router-policy/config/default.json /usr/bin/router-policy status"
if ($LASTEXITCODE -ne 0) { throw "Services did not recover after controlled reboot" }
$postStatus | Set-Content -LiteralPath (Join-Path $localRun "post-reboot-status.json") -Encoding UTF8
$postReboot = & $ssh @sshArgs "sha256sum /etc/router-policy/config/default.json /etc/router-policy/zapret/nfqws.conf; cat /tmp/router-policy/active-transaction.env"
if ($LASTEXITCODE -ne 0) { throw "Cannot capture post-reboot state" }
$postReboot | Set-Content -LiteralPath (Join-Path $localRun "post-reboot-sha256.txt") -Encoding ASCII
if (($preReboot -join "`n") -ne ($postReboot -join "`n")) { throw "Committed artifact binding changed across controlled reboot" }

$probes = @(
  @{ Name = "direct-after-reboot.json"; Command = "ROUTER_POLICY_CONFIG=/etc/router-policy/config/default.json /usr/bin/router-policy probe-route --no-persist --route direct github.com github" },
  @{ Name = "zapret-after-reboot.json"; Command = "ROUTER_POLICY_CONFIG=/etc/router-policy/config/default.json /usr/bin/router-policy probe-route --no-persist --route zapret discord.com discord_acceptance" },
  @{ Name = "vless-after-reboot.json"; Command = "ROUTER_POLICY_CONFIG=/etc/router-policy/config/default.json /usr/bin/router-policy probe-route --no-persist --route proxy-4 chatgpt.com chatgpt" },
  @{ Name = "drop-after-reboot.json"; Command = "ROUTER_POLICY_CONFIG=/etc/router-policy/config/default.json /usr/bin/router-policy probe-route --no-persist --route drop example.invalid github" }
)
foreach ($probe in $probes) {
  $proofOK = $false
  $jsonText = ""
  for ($attempt = 1; $attempt -le 3; $attempt++) {
    $result = & $ssh @sshArgs $probe.Command
    if ($LASTEXITCODE -eq 0) {
      $jsonText = $result -join "`n"
      $decoded = $jsonText | ConvertFrom-Json
      if ($decoded.status -eq "OK" -and $decoded.path_verified -and !$decoded.simulation) {
        $proofOK = $true
        break
      }
    }
    Start-Sleep -Seconds 5
  }
  if (!$proofOK) { throw "Post-reboot proof is invalid: $($probe.Name)" }
  $jsonText | Set-Content -LiteralPath (Join-Path $localRun $probe.Name) -Encoding UTF8
}

Complete-FaultRun "PASS"
