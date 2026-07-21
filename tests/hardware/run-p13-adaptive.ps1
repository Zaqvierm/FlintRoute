param(
  [Parameter(Mandatory = $true)][string]$RouterHost,
  [Parameter(Mandatory = $true)][string]$IdentityFile,
  [Parameter(Mandatory = $true)][string]$KnownHostsFile,
  [Parameter(Mandatory = $true)][string]$CredentialFile,
  [Parameter(Mandatory = $true)][string]$OutputRoot,
  [string]$RunId = ""
)

$ErrorActionPreference = "Stop"
$ssh = Join-Path $env:WINDIR "System32\OpenSSH\ssh.exe"
$scp = Join-Path $env:WINDIR "System32\OpenSSH\scp.exe"
if (!$RunId) { $RunId = "p13-adaptive-$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))" }
if ($RunId -notmatch '^p13-adaptive-[a-z0-9._-]{1,80}$') { throw "Unsafe adaptive run ID" }
if ($RouterHost -notmatch '^[A-Za-z0-9.:-]+$') { throw "Unsafe router host" }
foreach ($required in @($ssh, $scp, $IdentityFile, $KnownHostsFile, $CredentialFile)) {
  if (!(Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing required file: $required" }
}

$localRun = Join-Path $OutputRoot $RunId
$temp = Join-Path ([System.IO.Path]::GetTempPath()) "flintroute-$RunId"
New-Item -ItemType Directory -Force -Path $localRun, $temp | Out-Null
$sshArgs = @("-i", $IdentityFile, "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=$KnownHostsFile", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", "root@$RouterHost")
$scpArgs = @("-O", "-i", $IdentityFile, "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=$KnownHostsFile", "-o", "StrictHostKeyChecking=yes")
$remoteBase = "/tmp/flintroute-p13/$RunId"
$cookie = "$remoteBase/session.cookie"
$catalogPath = "/etc/router-policy/zapret/catalog.json"
$remoteCatalog = "$remoteBase/catalog.json"
$remoteCatalogBad = "$remoteBase/catalog-bad.json"
$csrf = ""
$password = $null
$adaptiveEnabled = $false
$catalogInstalled = $false
$completed = $false

function Set-Phase([string]$Name) {
  Write-Host "p13_adaptive_phase=$Name"
}

function Invoke-SSH([string]$Command, [string]$InputText = "") {
  if ($InputText) { $output = $InputText | & $ssh @sshArgs $Command } else { $output = & $ssh @sshArgs $Command }
  if ($LASTEXITCODE -ne 0) { throw "Remote command failed" }
  return ($output -join "`n")
}

function Invoke-API-Raw([string]$Method, [string]$Path, [string]$Body = "", [switch]$NoCSRF) {
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
  $payload = ($lines[0..($lines.Count - 2)] -join "`n")
  $data = $null
  if ($payload) { $data = $payload | ConvertFrom-Json }
  return [pscustomobject]@{ Status = [int]$lines[-1]; Payload = $data; Raw = $payload }
}

function Invoke-API([string]$Method, [string]$Path, [string]$Body = "", [switch]$NoCSRF) {
  $response = Invoke-API-Raw $Method $Path $Body -NoCSRF:$NoCSRF
  if ($response.Status -lt 200 -or $response.Status -ge 300) {
    $code = if ($response.Payload.error.code) { [string]$response.Payload.error.code } else { "unknown" }
    $message = if ($response.Payload.error.message) { [string]$response.Payload.error.message } else { "no message" }
    throw "API $Method $Path failed with HTTP $($response.Status) code=$code message=$message"
  }
  return $response.Payload
}

function Invoke-Change([array]$Operations, [string]$Title) {
  $revision = Invoke-API "GET" "/revisions"
  $body = @{ title = $Title; base_version = [int64]$revision.data.config_version; operations = $Operations } | ConvertTo-Json -Compress -Depth 100
  $created = Invoke-API "POST" "/changes" $body
  $id = [string]$created.data.id
  if ($id -notmatch '^chg_[0-9a-f]{16}$') { throw "ChangeSet ID is invalid" }
  try {
    $validated = Invoke-API "POST" "/changes/$id/validate" "{}"
    if ($validated.data.state -ne "validated") { throw "ChangeSet validation did not complete" }
    $applied = Invoke-API "POST" "/changes/$id/apply" "{}"
    if ($applied.data.state -ne "awaiting_confirmation" -or !$applied.data.data_plane_verified) { throw "ChangeSet apply was not verified" }
    $confirmed = Invoke-API "POST" "/changes/$id/confirm" "{}"
    if ($confirmed.data.state -ne "committed" -or !$confirmed.data.management_verified -or !$confirmed.data.data_plane_verified) { throw "ChangeSet confirmation failed" }
    return $confirmed.data
  } catch {
    $originalError = $_.Exception.Message
    $validationCodes = ""
    try {
      $changes = Invoke-API "GET" "/changes"
      $current = @($changes.data) | Where-Object id -eq $id | Select-Object -First 1
      $validationCodes = @($current.validation | ForEach-Object code | Where-Object { $_ }) -join ","
      if ($current.state -in @("draft", "validated")) {
        Invoke-API "POST" "/changes/$id/delete" "{}" | Out-Null
      } elseif ($current.state -in @("prepared", "applying", "verifying", "awaiting_confirmation", "committing", "rolling_back")) {
        Invoke-API "POST" "/changes/$id/rollback" "{}" | Out-Null
      }
    } catch { }
    throw "$originalError validation_codes=$validationCodes"
  }
}

function Get-Digest([string]$Text) {
  $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
  $algorithm = [Security.Cryptography.SHA256]::Create()
  try { $hash = $algorithm.ComputeHash($bytes) } finally { $algorithm.Dispose() }
  return "sha256:" + ([BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
}

function New-Score([hashtable]$Key, [string]$Profile, [bool]$Healthy, [double]$LatencyMS) {
  if ($Healthy) {
    return @{ key = $Key; profile_id = $Profile; attempts = 20; successes = 20; safety_gate = $true; required_checks_passed = $true; wilson_lower_bound = 0.82; wilson_upper_bound = 1.0; success_ratio = 1.0; stable_windows = 4; median_latency_ms = $LatencyMS; p95_latency_ms = $LatencyMS + 20; eligible = $true; production_ready = $true }
  }
  return @{ key = $Key; profile_id = $Profile; attempts = 20; successes = 2; safety_gate = $false; required_checks_passed = $false; recent_hard_failure = $true; wilson_lower_bound = 0.01; wilson_upper_bound = 0.2; success_ratio = 0.1; failed_windows = 2; failure_streak = 3; median_latency_ms = $LatencyMS; p95_latency_ms = $LatencyMS; eligible = $false; production_ready = $false }
}

function Invoke-Evaluate([hashtable]$Key, [array]$Ranking, [switch]$ExpectFailure) {
  $body = @{ key = $Key; ranking = $Ranking } | ConvertTo-Json -Compress -Depth 20
  $response = Invoke-API-Raw "POST" "/zapret/adaptive/evaluate" $body
  if ($ExpectFailure) {
    if ($response.Status -ge 200 -and $response.Status -lt 300) { throw "Adaptive evaluation unexpectedly succeeded" }
    return $response
  }
  if ($response.Status -lt 200 -or $response.Status -ge 300) { throw "Adaptive evaluation failed with HTTP $($response.Status)" }
  return $response.Payload.data
}

function Get-AdaptiveState([hashtable]$Key) {
  $body = @{ key = $Key } | ConvertTo-Json -Compress -Depth 10
  return (Invoke-API "POST" "/zapret/adaptive/state" $body).data
}

function Assert-Route([string]$Route, [string]$Domain, [string]$Service, [string]$Type) {
  foreach ($value in @($Route, $Domain, $Service, $Type)) {
    if ($value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { throw "Unsafe route proof value" }
  }
  $probe = (Invoke-SSH "ROUTER_POLICY_CONFIG=/etc/router-policy/config/default.json /usr/bin/router-policy probe-route --no-persist --route '$Route' '$Domain' '$Service'") | ConvertFrom-Json
  if ($probe.status -ne "OK" -or !$probe.path_verified -or $probe.simulation -or $probe.route_type -ne $Type) { throw "Bound route proof failed for $Route" }
  return [ordered]@{ route = $Route; route_type = $Type; path_verified = $true; service_ok = [bool]$probe.service_ok; simulation = $false }
}

function Disable-Adaptive {
  $ops = @(
    @{ type = "set"; path = "/zapret/adaptive_enabled"; value = $false },
    @{ type = "set"; path = "/zapret/adaptive_catalog_file"; value = "" },
    @{ type = "set"; path = "/zapret/adaptive_assignments"; value = @() }
  )
  Invoke-Change $ops "Restore static Zapret profile" | Out-Null
  $script:adaptiveEnabled = $false
}

try {
  Set-Phase "prepare"
  Invoke-SSH "umask 077; mkdir -p '$remoteBase'; chmod 700 '$remoteBase'; rm -f '$cookie'" | Out-Null
  $secure = Import-Clixml -LiteralPath $CredentialFile
  if ($secure -isnot [Security.SecureString]) { throw "Credential file must contain a DPAPI SecureString" }
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  try { $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
  Set-Phase "login"
  $login = Invoke-API "POST" "/auth/login" (@{ username = "admin"; password = $password } | ConvertTo-Json -Compress) -NoCSRF
  $csrf = [string]$login.data.csrf_token
  if ($login.data.role -ne "administrator" -or !$csrf) { throw "Administrator login failed" }

  Set-Phase "inspect-baseline"
  $configRaw = Invoke-SSH "cat /etc/router-policy/config/default.json"
  $config = $configRaw | ConvertFrom-Json
  if ($config.zapret.adaptive_enabled) { throw "Adaptive Zapret is already enabled; bounded test requires the static baseline" }
  $service = $config.services.discord_acceptance
  if (!$service -or @($service.domains).Count -eq 0) { throw "Discord acceptance service is unavailable" }
  $binaryDigest = (Invoke-SSH "sha256sum /usr/bin/nfqws | awk '{print `$1}'").Trim()
  if ($binaryDigest -notmatch '^[0-9a-f]{64}$') { throw "nfqws digest is invalid" }
  $versionLine = Invoke-SSH "/usr/bin/nfqws --version 2>&1 | head -1"
  if ($versionLine -notmatch 'v([0-9]+\.[0-9]+)') { throw "nfqws version is unavailable" }
  $providerVersion = $Matches[1]
  $stableStrategy = "--qnum=200`n--filter-tcp=80`n--dpi-desync=fake,fakedsplit`n--dpi-desync-split-pos=method+2`n--dpi-desync-fooling=md5sig`n--new`n--filter-tcp=443`n--dpi-desync=fake`n--dpi-desync-ttl=3`n--orig-ttl=1`n--orig-mod-start=s1`n--orig-mod-cutoff=d1`n"
  $challengerStrategy = "--qnum=200`n--filter-tcp=80`n--dpi-desync=fake,fakedsplit`n--dpi-desync-split-pos=method+2`n--new`n--filter-tcp=443`n--dpi-desync=fake`n--dpi-desync-ttl=4`n--orig-ttl=1`n--orig-mod-start=s1`n--orig-mod-cutoff=d1`n"
  $stable = "stable-v72"
  $challenger = "ttl3-v72"
  $bundle = "discord_acceptance"
  $catalog = [ordered]@{
    version = 1
    profiles = @(
      [ordered]@{ id = $stable; provider = "nfqws-v1"; provider_version = $providerVersion; binary_digest = "sha256:$binaryDigest"; route_type = "zapret"; ip_families = @("ipv4"); transports = @("tcp"); ports = @(80,443); queue = 200; safety = "reviewed"; strategy_digest = (Get-Digest $stableStrategy); strategy = $stableStrategy },
      [ordered]@{ id = $challenger; provider = "nfqws-v1"; provider_version = $providerVersion; binary_digest = "sha256:$binaryDigest"; route_type = "zapret"; ip_families = @("ipv4"); transports = @("tcp"); ports = @(80,443); queue = 200; safety = "reviewed"; strategy_digest = (Get-Digest $challengerStrategy); strategy = $challengerStrategy }
    )
    bundles = @([ordered]@{ id = $bundle; category = "TSPU_RESTRICTED"; required_domains = @($service.domains); protocols = @([ordered]@{transport="tcp";port=80},[ordered]@{transport="tcp";port=443}); ip_families = @("ipv4"); allowed_profiles = @($stable,$challenger); failure_route = "drop" })
  }
  Set-Phase "install-catalog"
  $catalogFile = Join-Path $temp "catalog.json"
  [IO.File]::WriteAllText($catalogFile, ($catalog | ConvertTo-Json -Depth 20), (New-Object Text.UTF8Encoding($false)))
  & $scp @scpArgs $catalogFile "root@${RouterHost}:$remoteCatalog"
  if ($LASTEXITCODE -ne 0) { throw "Adaptive catalog upload failed" }
  Invoke-SSH "cp '$remoteCatalog' '$catalogPath'; chmod 0600 '$catalogPath'; cp '$remoteCatalog' '$remoteCatalogBad'; chmod 0600 '$remoteCatalogBad'"
  $catalogInstalled = $true

  $enableOps = @(
    @{ type = "set"; path = "/zapret/adaptive_enabled"; value = $true },
    @{ type = "set"; path = "/zapret/adaptive_catalog_file"; value = $catalogPath },
    @{ type = "set"; path = "/zapret/adaptive_assignments"; value = @(@{ bundle_id = $bundle; profile_id = $stable }) }
  )
  Set-Phase "enable-adaptive"
  $enabled = Invoke-Change $enableOps "Enable bounded adaptive Zapret"
  $adaptiveEnabled = $true
  $fingerprint = "sha256:" + (Invoke-SSH "{ ubus call network.interface.wan status 2>/dev/null || true; ip route show table main; } | sha256sum | awk '{print `$1}'").Trim()
  if ($fingerprint -notmatch '^sha256:[0-9a-f]{64}$') { throw "Network fingerprint is invalid" }
  $key = @{ bundle_id = $bundle; transport = "tcp"; port = 443; ip_family = "ipv4"; network_fingerprint = $fingerprint }

  Set-Phase "switch-challenger"
  $switch = Invoke-Evaluate $key @((New-Score $key $challenger $true 70),(New-Score $key $stable $false 500))
  if ($switch.decision.action -ne "SWITCH" -or $switch.decision.to_profile -ne $challenger -or $switch.change.state -ne "committed") { throw "Active-profile degradation did not commit the challenger" }
  $postSwitch = Get-AdaptiveState $key
  if ($postSwitch.active_profile_id -ne $challenger -or !($postSwitch.cooldown_until)) { throw "Switch cooldown was not persisted" }
  $challengerProof = Assert-Route "zapret" "discord.com" "discord_acceptance" "zapret"

  Set-Phase "pin-fallback"
  $pinBody = @{ key = $key; pin = @{ profile_id = $challenger; mode = "safe_fallback"; allowed_fallbacks = @($stable) } } | ConvertTo-Json -Compress -Depth 20
  $pinned = (Invoke-API "POST" "/zapret/adaptive/pin" $pinBody).data
  if ($pinned.pin.mode -ne "safe_fallback") { throw "Manual pin was not persisted" }
  Set-Phase "restore-stable"
  $fallback = Invoke-Evaluate $key @((New-Score $key $stable $true 75),(New-Score $key $challenger $false 500))
  if ($fallback.decision.action -ne "SWITCH" -or $fallback.decision.to_profile -ne $stable -or $fallback.change.state -ne "committed") { throw "Pinned safe fallback did not restore the stable profile" }
  $unpinBody = @{ key = $key } | ConvertTo-Json -Compress -Depth 10
  $unpinned = (Invoke-API "POST" "/zapret/adaptive/unpin" $unpinBody).data
  if ($unpinned.pin) { throw "Manual pin was not cleared" }

  Set-Phase "verify-cooldown"
  $cooldown = Invoke-Evaluate $key @((New-Score $key $challenger $true 60),(New-Score $key $stable $true 100))
  if ($cooldown.decision.action -ne "HOLD" -or $cooldown.decision.reason -ne "cooldown_active") { throw "Cooldown did not hold a non-emergency challenger" }

  Set-Phase "reject-bad-challenger"
  $badCatalog = $catalog | ConvertTo-Json -Depth 20 | ConvertFrom-Json
  $badCatalog.profiles[1].strategy_digest = "sha256:" + ("0" * 64)
  $badFile = Join-Path $temp "catalog-bad.json"
  [IO.File]::WriteAllText($badFile, ($badCatalog | ConvertTo-Json -Depth 20), (New-Object Text.UTF8Encoding($false)))
  & $scp @scpArgs $badFile "root@${RouterHost}:$remoteCatalogBad"
  if ($LASTEXITCODE -ne 0) { throw "Bad challenger catalog upload failed" }
  Invoke-SSH "cp '$remoteCatalogBad' '$catalogPath'; chmod 0600 '$catalogPath'"
  $badResult = Invoke-Evaluate $key @((New-Score $key $challenger $true 50),(New-Score $key $stable $false 500)) -ExpectFailure
  Invoke-SSH "cp '$remoteCatalog' '$catalogPath'; chmod 0600 '$catalogPath'"
  $quarantined = Get-AdaptiveState $key
  $quarantineUntil = $quarantined.quarantined_until.$challenger
  if (!$quarantineUntil -or ([datetime]$quarantineUntil).ToUniversalTime() -le (Get-Date).ToUniversalTime()) { throw "Failed challenger was not quarantined" }
  $quarantineHold = Invoke-Evaluate $key @((New-Score $key $challenger $true 50),(New-Score $key $stable $false 500))
  if ($quarantineHold.decision.action -eq "SWITCH" -and $quarantineHold.decision.to_profile -eq $challenger) { throw "Quarantined challenger was selected again" }

  Set-Phase "restore-static-baseline"
  Disable-Adaptive
  if ((Invoke-API-Raw "POST" "/zapret/adaptive/state" $unpinBody).Status -ne 409) { throw "Adaptive runtime remained enabled after baseline restoration" }
  if ((Invoke-SSH "jsonfilter -i /etc/router-policy/config/default.json -e '@.zapret.adaptive_enabled' 2>/dev/null || true").Trim()) { throw "Static Zapret baseline was not restored" }
  $postRoutes = @(
    (Assert-Route "direct" "github.com" "github" "direct"),
    (Assert-Route "zapret" "discord.com" "discord_acceptance" "zapret"),
    (Assert-Route "proxy-4" "chatgpt.com" "chatgpt" "vless")
  )
  Set-Phase "write-evidence"
  $summary = [ordered]@{
    run_id = $RunId
    checked_at = (Get-Date).ToUniversalTime().ToString("o")
    enable_change_id = [string]$enabled.id
    active_degradation_switch = [ordered]@{ from = $stable; to = $challenger; decision = $switch.decision.reason; committed = $true; route_proof = $challengerProof }
    pin_safe_fallback = [ordered]@{ mode = "safe_fallback"; restored_profile = $stable; committed = $true }
    cooldown = [ordered]@{ action = $cooldown.decision.action; reason = $cooldown.decision.reason; passed = $true }
    bad_challenger = [ordered]@{ http_status = $badResult.Status; quarantined = $true; reselection_blocked = $true }
    static_baseline_restored = $true
    post_test_routes = $postRoutes
    passed = $true
  }
  $summaryPath = Join-Path $localRun "adaptive-faults.json"
  [IO.File]::WriteAllText($summaryPath, ($summary | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding($false)))
  $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $summaryPath).Hash.ToLowerInvariant()
  "$digest  adaptive-faults.json" | Set-Content -LiteralPath (Join-Path $localRun "SHA256SUMS.txt") -Encoding ascii
  $completed = $true
  Write-Host "p13_adaptive_run=$RunId"
  Write-Host "p13_adaptive_evidence=$localRun"
  Write-Host "p13_adaptive_faults=PASS"
} finally {
  if ($catalogInstalled) {
    try { Invoke-SSH "if test -f '$remoteCatalog'; then cp '$remoteCatalog' '$catalogPath'; chmod 0600 '$catalogPath'; fi" | Out-Null } catch { }
  }
  if (!$completed -and $adaptiveEnabled -and $csrf) {
    try { Disable-Adaptive } catch { }
  }
  if ($catalogInstalled -and !$adaptiveEnabled) {
    try { Invoke-SSH "rm -f '$catalogPath'" | Out-Null } catch { }
  }
  if ($csrf) { try { Invoke-API "POST" "/auth/logout" "{}" | Out-Null } catch { } }
  try { Invoke-SSH "case '$remoteBase' in /tmp/flintroute-p13/p13-adaptive-*) rm -rf '$remoteBase' ;; *) exit 64 ;; esac" | Out-Null } catch { }
  $password = $null
  if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
