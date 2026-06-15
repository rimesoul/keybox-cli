# keybox test script — Windows PowerShell
# Usage: powershell -File scripts/test.ps1 [-Build]

param([switch]$Build)

$ErrorActionPreference = "Stop"
$script:Errors = 0

# Config
$env:KEYBOX_CONFIG_DIR = Join-Path $env:TEMP "keybox-test-$(Get-Random)"
$env:KEYBOX_LLM_CALLING = "0"
$Bin = ".\target\debug\keybox.exe"

function cleanup { Remove-Item -Recurse -Force $env:KEYBOX_CONFIG_DIR -ErrorAction SilentlyContinue }
# No trap in PS; rely on temp dir

function Log($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok($msg)  { Write-Host "  PASS: $msg" -ForegroundColor Green }
function Err($msg, $detail) {
    Write-Host "  FAIL: $msg — $detail" -ForegroundColor Red
    $script:Errors++
}

# Build
if ($Build) {
    Log "Building..."
    cargo build
}

# ── Secret tier ──────────────────────────────────────────

Log "Secret tier — add"
& $Bin add gitea pat --non-interactive --password "test-token-123"
if ($LASTEXITCODE -eq 0) { Ok "add" } else { Err "add" "failed" }

Log "Secret tier — get"
$result = & $Bin get gitea pat 2>$null
if ($result -eq "test-token-123") { Ok "get" } else { Err "get" "expected test-token-123, got $result" }

Log "Secret tier — list"
$list = & $Bin list 2>$null
if ($list -match "gitea") { Ok "list domains" } else { Err "list domains" "gitea not found" }

Log "Secret tier — update"
& $Bin update gitea pat --non-interactive --password "new-token-456"
if ($LASTEXITCODE -eq 0) { Ok "update" } else { Err "update" "failed" }

$result = & $Bin get gitea pat 2>$null
if ($result -eq "new-token-456") { Ok "update verify" } else { Err "update verify" "expected new-token-456" }

Log "Secret tier — duplicate add"
$dup = & $Bin add gitea pat --non-interactive --password "dup" 2>&1
if ($dup -match "already exists") { Ok "duplicate add rejected" } else { Err "duplicate add" "should reject" }

Log "Secret tier — delete"
"y" | & $Bin delete gitea pat 2>$null
if ($LASTEXITCODE -eq 0) { Ok "delete" } else { Err "delete" "failed" }

$result = & $Bin get gitea pat 2>&1
if ($LASTEXITCODE -ne 0) { Ok "delete verify" } else { Err "delete verify" "should be gone" }

# ── Generate ─────────────────────────────────────────────

Log "Generate — default"
$result = & $Bin generate 2>$null
if ($result.Length -eq 16) { Ok "generate default length" } else { Err "generate default" "len=$($result.Length)" }

Log "Generate — digits only"
$result = & $Bin generate --digits --length 6 2>$null
if ($result -match '^\d{6}$') { Ok "generate digits" } else { Err "generate digits" "got $result" }

Log "Generate — passphrase"
$result = & $Bin generate --passphrase --length 4 2>$null
if (($result -split '-').Count -eq 4) { Ok "generate passphrase" } else { Err "generate passphrase" "got $result" }

Log "Generate — save"
& $Bin generate --digits --length 6 --save test pin 2>$null
if ($LASTEXITCODE -eq 0) { Ok "generate save" } else { Err "generate save" "failed" }

$result = & $Bin get test pin 2>$null
if ($result -match '^\d{6}$') { Ok "generate save verify" } else { Err "generate save verify" "got $result" }

# ── Summary ──────────────────────────────────────────────

Write-Host ""
if ($script:Errors -eq 0) {
    Write-Host "All tests passed!" -ForegroundColor Green
} else {
    Write-Host "$($script:Errors) test(s) failed" -ForegroundColor Red
    exit 1
}

cleanup
