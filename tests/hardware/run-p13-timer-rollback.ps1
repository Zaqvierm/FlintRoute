param(
  [Parameter(Mandatory = $true)][string]$RouterHost,
  [Parameter(Mandatory = $true)][string]$IdentityFile,
  [Parameter(Mandatory = $true)][string]$KnownHostsFile,
  [Parameter(Mandatory = $true)][string]$CredentialFile,
  [Parameter(Mandatory = $true)][string]$SmartDNSPrimary,
  [Parameter(Mandatory = $true)][string]$SmartDNSSecondary,
  [Parameter(Mandatory = $true)][string]$OutputRoot,
  [string]$RunId = "",
  [int]$MaximumRollbackTimeoutSeconds = 300,
  [switch]$CommitProduction
)

$ErrorActionPreference = "Stop"
$ssh = Join-Path $env:WINDIR "System32\OpenSSH\ssh.exe"
if (!$RunId) {
  $prefix = if ($CommitProduction) { "p13-smartdns" } else { "p13-timer" }
  $RunId = "$prefix-$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))"
}
if ($RunId -notmatch '^p13-(?:timer|smartdns)-[a-z0-9._-]{1,80}$') { throw "Unsafe Smart DNS run ID" }
if ($RouterHost -notmatch '^[A-Za-z0-9.:-]+$') { throw "Unsafe router host" }
if ($MaximumRollbackTimeoutSeconds -lt 60 -or $MaximumRollbackTimeoutSeconds -gt 600) { throw "Maximum rollback timeout must be 60..600 seconds" }
foreach ($resolver in @($SmartDNSPrimary, $SmartDNSSecondary)) {
  if ($resolver -notmatch '^\[?[0-9A-Fa-f:.]+\]?(?::53)?$') { throw "Smart DNS resolver must be an IP endpoint" }
}
foreach ($required in @($ssh, $IdentityFile, $KnownHostsFile, $CredentialFile)) {
  if (!(Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing required file: $required" }
}

$localRun = Join-Path $OutputRoot $RunId
New-Item -ItemType Directory -Path $localRun -Force | Out-Null
$sshArgs = @("-i", $IdentityFile, "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=$KnownHostsFile", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", "root@$RouterHost")
$cookie = "/tmp/flintroute-p13/$RunId.cookie"
$csrf = ""
$password = $null
$changeID = ""
$completed = $false
$pollFailures = 0

function Invoke-SSH([string]$Command, [string]$InputText = "") {
  if ($InputText) {
    $output = $InputText | & $ssh @sshArgs $Command
  } else {
    $output = & $ssh @sshArgs $Command
  }
  if ($LASTEXITCODE -ne 0) { throw "Remote command failed" }
  return ($output -join "`n")
}

function Invoke-API([string]$Method, [string]$Path, [string]$Body = "", [switch]$NoCSRF) {
  if ($Path -notmatch '^/[A-Za-z0-9/_-]+$') { throw "Unsafe API path" }
  $csrfPart = ""
  if (!$NoCSRF -and $Method -ne "GET") {
    if ($csrf -notmatch '^[A-Za-z0-9_-]{20,200}$') { throw "CSRF token is unavailable" }
    $csrfPart = "-H 'X-CSRF-Token: $csrf'"
  }
  $bodyPart = if ($Body) { "--data-binary @-" } else { "" }
  $command = "curl -sS -b '$cookie' -c '$cookie' -H 'Content-Type: application/json' $csrfPart -X '$Method' $bodyPart -w '\n%{http_code}' 'http://127.0.0.1:8787/api/v1$Path'"
  $raw = Invoke-SSH $command $Body
  $lines = $raw -split "`n"
  if ($lines.Count -lt 2 -or $lines[-1] -notmatch '^\d{3}$') { throw "API response is malformed" }
  $status = [int]$lines[-1]
  $payload = ($lines[0..($lines.Count - 2)] -join "`n")
  if ($status -lt 200 -or $status -ge 300) {
    $code = "unknown"
    try { $code = [string](($payload | ConvertFrom-Json).error.code) } catch { }
    throw "API $Method $Path failed with HTTP $status code=$code"
  }
  return ($payload | ConvertFrom-Json)
}

function Get-Change([string]$ID) {
  $env = Invoke-API "GET" "/changes"
  $change = @($env.data) | Where-Object id -eq $ID | Select-Object -First 1
  if (!$change) { throw "ChangeSet disappeared" }
  return $change
}

function Format-DNSRouteEndpoint([string]$Resolver) {
  if ($Resolver -match '^\d{1,3}(?:\.\d{1,3}){3}:53$' -or $Resolver -match '^\[[0-9A-Fa-f:]+\]:53$') { return $Resolver }
  $parsed = $null
  if (![System.Net.IPAddress]::TryParse($Resolver, [ref]$parsed)) { throw "Smart DNS resolver is not an IP address" }
  if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return "[$Resolver]:53" }
  return "${Resolver}:53"
}

function Assert-RouteProbe([string]$Route, [string]$ExpectedType, [string]$Domain, [string]$Service) {
  foreach ($value in @($Route, $ExpectedType, $Domain, $Service)) {
    if ($value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { throw "Unsafe route probe value" }
  }
  $raw = Invoke-SSH "ROUTER_POLICY_CONFIG=/etc/router-policy/config/default.json /usr/bin/router-policy probe-route --no-persist --route '$Route' '$Domain' '$Service'"
  $probe = $raw | ConvertFrom-Json
  if ($probe.status -ne "OK" -or !$probe.path_verified -or $probe.simulation -or $probe.route_type -ne $ExpectedType) {
    throw "Route proof failed for $Route"
  }
  return [ordered]@{
    route = $Route
    route_type = $probe.route_type
    path_verified = [bool]$probe.path_verified
    service_ok = [bool]$probe.service_ok
    simulation = [bool]$probe.simulation
    host_preserved = [bool]$probe.path_evidence.host_preserved
    sni_preserved = [bool]$probe.path_evidence.sni_preserved
    dns_response_safe = [bool]$probe.path_evidence.dns_response_safe
  }
}

try {
  Invoke-SSH "umask 077; mkdir -p /tmp/flintroute-p13; command -v curl >/dev/null; rm -f '$cookie'" | Out-Null
  $secure = Import-Clixml -LiteralPath $CredentialFile
  if ($secure -isnot [System.Security.SecureString]) { throw "Credential file must contain a DPAPI SecureString" }
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  try { $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

  $loginBody = @{ username = "admin"; password = $password } | ConvertTo-Json -Compress
  $login = Invoke-API "POST" "/auth/login" $loginBody -NoCSRF
  $csrf = [string]$login.data.csrf_token
  if ($login.data.role -ne "administrator" -or !$csrf) { throw "Administrator login failed" }

  $configRaw = Invoke-SSH "cat /etc/router-policy/config/default.json"
  $config = $configRaw | ConvertFrom-Json
  $effectiveRollbackTimeout = [int]$config.openwrt.rollback_timeout_seconds
  if ($effectiveRollbackTimeout -lt 60 -or $effectiveRollbackTimeout -gt $MaximumRollbackTimeoutSeconds) { throw "Active rollback timeout is outside the approved hardware-test window" }
  $revisionState = Invoke-API "GET" "/revisions"
  $baseVersion = [int64]$revisionState.data.config_version
  if ($baseVersion -lt 1) { throw "Active control-plane config version is invalid" }
  $preConfigSHA = (Invoke-SSH "sha256sum /etc/router-policy/config/default.json | awk '{print `$1}'").Trim()
  $preBindingSHA = (Invoke-SSH "sha256sum /tmp/router-policy/active-transaction.env | awk '{print `$1}'").Trim()
  if ($preConfigSHA -notmatch '^[0-9a-f]{64}$' -or $preBindingSHA -notmatch '^[0-9a-f]{64}$') { throw "Pre-test binding digest is invalid" }
  if (!$config.services.chatgpt) { throw "Required chatgpt service is missing" }

  $routes = @($config.routes | Where-Object type -ne "smart_dns")
  $routes += [pscustomobject]@{ type = "smart_dns"; tag = "smart-dns-primary"; priority = 30; dns_server = (Format-DNSRouteEndpoint $SmartDNSPrimary); connect_to_resolved_ip = $true }
  $routes += [pscustomobject]@{ type = "smart_dns"; tag = "smart-dns-secondary"; priority = 31; dns_server = (Format-DNSRouteEndpoint $SmartDNSSecondary); connect_to_resolved_ip = $true }
  $allowedPaths = @("smart_dns") + @($config.services.chatgpt.allowed_paths | Where-Object { $_ -ne "smart_dns" })
  $forbiddenPaths = @($config.services.chatgpt.forbidden_paths | Where-Object { $_ -ne "smart_dns" })
  $operations = @(
    @{ type = "set"; path = "/routes"; value = $routes },
    @{ type = "set"; path = "/services/chatgpt/allowed_paths"; value = $allowedPaths },
    @{ type = "set"; path = "/services/chatgpt/forbidden_paths"; value = $forbiddenPaths }
  )
  $title = if ($CommitProduction) { "Activate production Smart DNS" } else { "Validate Smart DNS rollback timer" }
  $createBody = @{ title = $title; base_version = $baseVersion; operations = $operations } | ConvertTo-Json -Compress -Depth 100
  $created = Invoke-API "POST" "/changes" $createBody
  $changeID = [string]$created.data.id
  if ($changeID -notmatch '^chg_[0-9a-f]{16}$') { throw "ChangeSet ID is invalid" }

  try {
    $validated = Invoke-API "POST" "/changes/$changeID/validate" "{}"
  } catch {
    $invalid = Get-Change $changeID
    $codes = @($invalid.validation | ForEach-Object code | Where-Object { $_ }) -join ","
    throw "$($_.Exception.Message) validation_codes=$codes"
  }
  if ($validated.data.state -ne "validated") { throw "Smart DNS candidate validation failed" }
  $applied = Invoke-API "POST" "/changes/$changeID/apply" "{}"
  if ($applied.data.state -ne "awaiting_confirmation" -or !$applied.data.data_plane_verified) {
    $lastStep = @($applied.data.steps) | Select-Object -Last 1
    throw "Smart DNS candidate stopped at state=$($applied.data.state) adapter=$($applied.data.adapter_status) last_step=$($lastStep.step) last_status=$($lastStep.status) last_reason=$($lastStep.reason)"
  }

  $proof = Assert-RouteProbe "smart-dns-primary" "smart_dns" "chatgpt.com" "chatgpt"
  if ($CommitProduction) {
    $secondaryProof = Assert-RouteProbe "smart-dns-secondary" "smart_dns" "chatgpt.com" "chatgpt"
    $confirmed = Invoke-API "POST" "/changes/$changeID/confirm" "{}"
    if ($confirmed.data.state -ne "committed" -or !$confirmed.data.management_verified -or !$confirmed.data.data_plane_verified) {
      throw "Smart DNS confirmation did not commit a verified ChangeSet"
    }
    $postConfigSHA = (Invoke-SSH "sha256sum /etc/router-policy/config/default.json | awk '{print `$1}'").Trim()
    $postBindingSHA = (Invoke-SSH "sha256sum /tmp/router-policy/active-transaction.env | awk '{print `$1}'").Trim()
    if ($postConfigSHA -eq $preConfigSHA -or $postBindingSHA -eq $preBindingSHA) { throw "Committed Smart DNS config or binding did not advance" }
    $activeSmartDNS = [int](Invoke-SSH "jsonfilter -i /etc/router-policy/config/default.json -e '@.routes[*].type' | grep -c '^smart_dns`$'").Trim()
    if ($activeSmartDNS -ne 2) { throw "Committed config does not contain two Smart DNS routes" }
    $direct = Assert-RouteProbe "direct" "direct" "github.com" "github"
    $zapret = Assert-RouteProbe "zapret" "zapret" "discord.com" "discord_acceptance"
    $vless = Assert-RouteProbe "proxy-4" "vless" "chatgpt.com" "chatgpt"
    [ordered]@{
      run_id = $RunId
      checked_at = (Get-Date).ToUniversalTime().ToString("o")
      change_id = $changeID
      final_state = [string]$confirmed.data.state
      active_smart_dns_routes = $activeSmartDNS
      smart_dns_bound_paths = @($proof, $secondaryProof)
      committed_config_advanced = $true
      committed_binding_advanced = $true
      post_commit_routes = @($direct, $zapret, $vless)
      passed = $true
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $localRun "smartdns-activation.json") -Encoding UTF8
    $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $localRun "smartdns-activation.json")).Hash.ToLowerInvariant()
    "$digest  smartdns-activation.json" | Set-Content -LiteralPath (Join-Path $localRun "SHA256SUMS.txt") -Encoding ASCII
    Write-Host "p13_smartdns_run=$RunId"
    Write-Host "p13_smartdns_evidence=$localRun"
    Write-Host "p13_smartdns_activation=PASS"
    $completed = $true
    return
  }
  $deadline = (Get-Date).AddSeconds($effectiveRollbackTimeout + 90)
  $finalState = ""
  $consecutivePollFailures = 0
  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    try {
      $change = Get-Change $changeID
      $consecutivePollFailures = 0
    } catch {
      $pollFailures++
      $consecutivePollFailures++
      if ($consecutivePollFailures -ge 5) {
        throw "Control-plane polling failed five times in a row: $($_.Exception.Message)"
      }
      continue
    }
    $finalState = [string]$change.state
    if ($finalState -in @("expired", "rolled_back", "rollback_failed", "failed")) { break }
  }
  if ($finalState -notin @("expired", "rolled_back")) { throw "Rollback timer did not complete safely" }

  $postConfigSHA = (Invoke-SSH "sha256sum /etc/router-policy/config/default.json | awk '{print `$1}'").Trim()
  $postBindingSHA = (Invoke-SSH "sha256sum /tmp/router-policy/active-transaction.env | awk '{print `$1}'").Trim()
  if ($postConfigSHA -ne $preConfigSHA -or $postBindingSHA -ne $preBindingSHA) { throw "Rollback timer did not restore the committed config and binding" }
  $direct = Assert-RouteProbe "direct" "direct" "github.com" "github"
  $zapret = Assert-RouteProbe "zapret" "zapret" "discord.com" "discord_acceptance"
  $vless = Assert-RouteProbe "proxy-4" "vless" "chatgpt.com" "chatgpt"

  [ordered]@{
    run_id = $RunId
    checked_at = (Get-Date).ToUniversalTime().ToString("o")
    change_id = $changeID
    rollback_timeout_seconds = $effectiveRollbackTimeout
    final_state = $finalState
    smart_dns_bound_path = $proof
    restored_config_digest = $true
    restored_binding_digest = $true
    transient_poll_failures = $pollFailures
    post_rollback_routes = @($direct, $zapret, $vless)
    passed = $true
  } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $localRun "timer-rollback.json") -Encoding UTF8
  $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $localRun "timer-rollback.json")).Hash.ToLowerInvariant()
  "$digest  timer-rollback.json" | Set-Content -LiteralPath (Join-Path $localRun "SHA256SUMS.txt") -Encoding ASCII
  Write-Host "p13_timer_run=$RunId"
  Write-Host "p13_timer_evidence=$localRun"
  Write-Host "p13_timer_rollback=PASS"
  $completed = $true
} finally {
  if (!$completed -and $changeID -match '^chg_[0-9a-f]{16}$' -and $csrf) {
    try {
      $unfinished = Get-Change $changeID
      if ($unfinished.state -in @("prepared", "applying", "verifying", "awaiting_confirmation", "committing", "rolling_back")) {
        Invoke-API "POST" "/changes/$changeID/rollback" "{}" | Out-Null
      } elseif ($unfinished.state -in @("draft", "validated")) {
        Invoke-API "POST" "/changes/$changeID/delete" "{}" | Out-Null
      }
    } catch { }
  }
  if ($csrf) {
    try { Invoke-API "POST" "/auth/logout" "{}" | Out-Null } catch { }
  }
  try { Invoke-SSH "case '$cookie' in /tmp/flintroute-p13/p13-timer-*.cookie|/tmp/flintroute-p13/p13-smartdns-*.cookie) rm -f '$cookie' ;; *) exit 64 ;; esac" | Out-Null } catch { }
  $password = $null
}
