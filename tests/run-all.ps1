$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Invoke-Npm {
  param([string[]]$NpmArgs)
  $npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
  if (!$npmCommand) {
    $npmCommand = Get-Command npm -ErrorAction SilentlyContinue
  }
  if (!$npmCommand) {
    throw "npm is missing; install Node.js/npm to test the web UI"
  }
  & $npmCommand.Source @NpmArgs
  if ($LASTEXITCODE -ne 0) {
    throw "npm $($NpmArgs -join ' ') failed with exit code $LASTEXITCODE"
  }
}

# Go: use GO_BINARY env var, then go from PATH, then local .tools fallback
$go = $env:GO_BINARY
if (!$go) {
  $goCmd = Get-Command go -ErrorAction SilentlyContinue
  if ($goCmd) { $go = $goCmd.Source }
}
if (!$go) {
  $localGo = Join-Path $root ".tools\go1.26.5\go\bin\go.exe"
  if (Test-Path $localGo) { $go = $localGo }
}
if (!$go) {
  throw "Go toolchain not found. Set GO_BINARY, add go to PATH, or install under .tools/"
}
Write-Host "Using Go: $go"

Write-Host "== go test =="
& $go test ./...
if ($LASTEXITCODE -ne 0) {
  throw "go test failed with exit code $LASTEXITCODE"
}

Write-Host "== go vet =="
& $go vet ./...
if ($LASTEXITCODE -ne 0) {
  throw "go vet failed with exit code $LASTEXITCODE"
}

Write-Host "== frontend =="
Invoke-Npm @("run", "typecheck")
Invoke-Npm @("run", "build")

Write-Host "== build =="
powershell -ExecutionPolicy Bypass -File .\scripts\build-go.ps1 | Out-Host
if ($LASTEXITCODE -ne 0) {
  throw "build script failed with exit code $LASTEXITCODE"
}

Write-Host "== shellcheck =="
$shellcheck = $env:SHELLCHECK_BINARY
if (!$shellcheck) {
  $scCmd = Get-Command shellcheck -ErrorAction SilentlyContinue
  if ($scCmd) { $shellcheck = $scCmd.Source }
}
if (!$shellcheck) {
  $localSc = Join-Path $root ".tools\shellcheck-stable\shellcheck.exe"
  if (Test-Path $localSc) { $shellcheck = $localSc }
}
if ($shellcheck -and (Test-Path -LiteralPath $shellcheck)) {
  $shellFiles = Get-ChildItem -Recurse -File -Include *.sh,router-policy,router-policy-boot-guard,router-policy-watchdog,router-policy-xray,router-policy-zapret,95-router-policy,install.sh,uninstall.sh |
    Where-Object { $_.FullName -notmatch '\\.tools\\|\\.git\\|\\.local\\|\\dist\\|\\node_modules\\' }
  & $shellcheck -x @($shellFiles.FullName)
  if ($LASTEXITCODE -ne 0) {
    throw "ShellCheck failed with exit code $LASTEXITCODE"
  }
} else {
  Write-Host "shellcheck_missing=true"
}

Write-Host "== installer backup failure =="
$gitSh = $env:GIT_BASH
if (!$gitSh) {
  $bashCmd = Get-Command bash -ErrorAction SilentlyContinue
  if ($bashCmd) { $gitSh = $bashCmd.Source }
}
if (!$gitSh) {
  $gitSh = "C:\Program Files\Git\bin\bash.exe"
}
$env:GO = ($go -replace '\\', '/')
if (Test-Path $gitSh) {
  & $gitSh tests/installer-backup.sh
  if ($LASTEXITCODE -ne 0) {
    throw "installer backup failure test failed"
  }
} else {
  throw "Git sh is required for installer backup behavior test"
}

Write-Host "== OpenWrt package =="
& $gitSh tests/package-openwrt.sh
if ($LASTEXITCODE -ne 0) {
  throw "OpenWrt package verification failed"
}

Write-Host "== installer lifecycle =="
& $gitSh tests/installer-lifecycle.sh
if ($LASTEXITCODE -ne 0) {
  throw "installer lifecycle test failed"
}

Write-Host "== adapter rollback integrity =="
& $gitSh tests/adapter-rollback.sh
if ($LASTEXITCODE -ne 0) {
  throw "adapter rollback integrity test failed"
}

Write-Host "== OpenWrt adapter transaction integration =="
& $gitSh tests/openwrt-adapter-integration.sh
if ($LASTEXITCODE -ne 0) {
  throw "OpenWrt adapter transaction integration test failed"
}

Write-Host "== cli validate =="
.\dist\router-policy.exe validate-config | ConvertFrom-Json | Out-Null

Write-Host "== cli candidates =="
$candidates = .\dist\router-policy.exe candidates chatgpt.com openai | ConvertFrom-Json
if (($candidates.candidates | Where-Object { $_.type -eq "direct" -or $_.type -eq "zapret" }).Count -ne 0) {
  throw "GEO_LOCKED candidates contain direct/zapret"
}

Write-Host "== VPN subscription fixtures =="
.\dist\router-policy.exe subscription-normalize tests\sample-subscription-array.json | ConvertFrom-Json | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "subscription-normalize fixture failed"
}
.\dist\router-policy.exe subscription-routes tests\sample-subscription-array.json | ConvertFrom-Json | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "subscription-routes fixture failed"
}
$xrayOut = Join-Path $env:TEMP "router-policy-xray-test.json"
$xraySummary = .\dist\router-policy.exe subscription-xray --out $xrayOut tests\sample-subscription-array.json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
  throw "subscription-xray fixture failed"
}
if (!$xraySummary.secrets_printed -and (Test-Path $xrayOut)) {
  Remove-Item $xrayOut -Force
} else {
  throw "subscription-xray did not create a safe summary/output"
}

Write-Host "== tspu fixture =="
$tspuCache = Join-Path $env:TEMP "router-policy-tspu-cache.json"
$cacheJson = @{
  generated_at = "2026-07-11T12:00:00Z"
  expires_at = "2999-01-01T00:00:00Z"
  sources = @(@{ name = "fixture"; url = "file://fixture"; entries = 3; accepted = $true; confidence = 0.9 })
  entries = @{
    "googlevideo.com" = @{ domain = "googlevideo.com"; source = "fixture"; confidence = 0.9; first_seen = "2026-07-11T12:00:00Z"; last_seen = "2026-07-11T12:00:00Z" }
  }
} | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($tspuCache, $cacheJson, [System.Text.UTF8Encoding]::new($false))
$tspuResult = .\dist\router-policy.exe tspu-check --cache $tspuCache rr1---sn.googlevideo.com | ConvertFrom-Json
if (!$tspuResult.matched) {
  throw "tspu-check fixture did not match"
}
Remove-Item $tspuCache -Force

Write-Host "== secret scan =="
$scanRoots = @("README.md", "SECURITY.md", "config", "docs", "scripts", "internal", "cmd", "openwrt", "tests", "ui", "package.json", "package-lock.json", "vite.config.ts", "tsconfig.json")
$scanFiles = foreach ($scanRoot in $scanRoots) {
  if (Test-Path $scanRoot -PathType Leaf) {
    Get-Item $scanRoot
  } elseif (Test-Path $scanRoot -PathType Container) {
    Get-ChildItem $scanRoot -Recurse -File
  }
}
$secretHits = $scanFiles |
  Where-Object { $_.FullName -notmatch '\\node_modules\\|\\.tools\\|\\.git\\|\\dist\\|tests\\run-all\.(ps1|sh)$' } |
  Select-String -Pattern 'vless://|TELEGRAM_BOT_TOKEN=[A-Za-z0-9]|-----BEGIN (OPENSSH |RSA |EC )?PRIVATE KEY-----|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' |
  Where-Object { $_.Line -notmatch 'UUID_PLACEHOLDER|11111111-1111-4111-8111-111111111111|22222222-2222-4222-8222-222222222222|33333333-3333-4333-8333-333333333333' }
if ($secretHits) {
  $secretHits | Format-Table -AutoSize | Out-String | Write-Host
  throw "secret-like values found"
}

Write-Host "== forbidden route-specific functions =="
$badNames = Get-ChildItem -Recurse -File scripts,internal,cmd |
  Select-String -Pattern 'check_direct|check_zapret|check_smart_dns|check_vless|check_regional_direct|check_regional_zapret'
if ($badNames) {
  $badNames | Format-Table -AutoSize | Out-String | Write-Host
  throw "forbidden duplicated route check names found"
}

Write-Host "all_tests_ok=true"
