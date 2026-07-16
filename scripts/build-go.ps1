$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
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

function Invoke-Npm {
  param([string[]]$NpmArgs)
  $npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
  if (!$npmCommand) {
    $npmCommand = Get-Command npm -ErrorAction SilentlyContinue
  }
  if (!$npmCommand) {
    throw "npm is missing; install Node.js/npm to build the embedded web UI"
  }
  & $npmCommand.Source @NpmArgs
  if ($LASTEXITCODE -ne 0) {
    throw "npm $($NpmArgs -join ' ') failed with exit code $LASTEXITCODE"
  }
}

$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null

Push-Location $root
try {
  Invoke-Npm @("run", "typecheck")
  Invoke-Npm @("run", "build")
} finally {
  Pop-Location
}

& $go test ./...

& $go build -o (Join-Path $dist "router-policy.exe") ./cmd/router-policy

$env:GOOS = "linux"
$env:GOARCH = "arm64"
$env:CGO_ENABLED = "0"
& $go build -trimpath -ldflags="-s -w" -o (Join-Path $dist "router-policy-linux-arm64") ./cmd/router-policy

$bashCommand = Get-Command bash -ErrorAction SilentlyContinue
$bashPath = if ($bashCommand) { $bashCommand.Source } else { $null }
if (!$bashPath) {
  $gitBash = "C:\Program Files\Git\bin\bash.exe"
  if (Test-Path $gitBash) { $bashPath = $gitBash }
}
if (!$bashPath) {
  throw "Git Bash is required to package the OpenWrt bundle"
}
& $bashPath scripts/package-openwrt.sh
if ($LASTEXITCODE -ne 0) {
  throw "OpenWrt package build failed with exit code $LASTEXITCODE"
}

Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue

Get-ChildItem $dist | Select-Object Name,Length
