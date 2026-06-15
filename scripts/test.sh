#!/usr/bin/env bash
# keybox test script — macOS / Linux
# Usage: bash scripts/test.sh [--build]
#   --build   Compile before testing

set -eu

RED='\033[31m'; GREEN='\033[32m'; CYAN='\033[36m'; NC='\033[0m'
PASS="${GREEN}PASS${NC}"; FAIL="${RED}FAIL${NC}"
ERRORS=0

# Config
export KEYBOX_CONFIG_DIR="$(mktemp -d)"
export KEYBOX_LLM_CALLING=0
BIN="./target/debug/keybox"

cleanup() { rm -rf "$KEYBOX_CONFIG_DIR"; }
trap cleanup EXIT

log() { echo -e "${CYAN}==>${NC} $*"; }
ok()  { echo -e "  ${PASS}: $1"; }
err() { echo -e "  ${FAIL}: $1 — $2"; ((ERRORS++)); }

# Build if requested
if [[ "${1:-}" == "--build" ]]; then
    log "Building..."
    source "$HOME/.cargo/env" 2>/dev/null || true
    cargo build
fi

# ── Secret tier ──────────────────────────────────────────

log "Secret tier — init"
$BIN get gitea nonexistent 2>/dev/null && err auto_init "should have failed" || ok "auto_init on first use"

log "Secret tier — add"
$BIN add gitea pat --non-interactive --password "test-token-123" && ok "add" || err add "failed"

log "Secret tier — get"
RESULT=$($BIN get gitea pat 2>/dev/null)
[[ "$RESULT" == "test-token-123" ]] && ok "get" || err get "expected test-token-123, got '$RESULT'"

log "Secret tier — list domains"
$BIN list | grep -q gitea && ok "list domains" || err list_domains "gitea not found"

log "Secret tier — list accounts"
$BIN list gitea | grep -q pat && ok "list accounts" || err list_accounts "pat not found"

log "Secret tier — update"
$BIN update gitea pat --non-interactive --password "new-token-456" && ok "update" || err update "failed"
RESULT=$($BIN get gitea pat 2>/dev/null)
[[ "$RESULT" == "new-token-456" ]] && ok "update verify" || err update_verify "expected new-token-456"

log "Secret tier — duplicate add"
$BIN add dup-test acct --non-interactive --password "p1" 2>/dev/null || true
OUTPUT=$($BIN add dup-test acct --non-interactive --password "p2" 2>&1) || true
[[ "$OUTPUT" =~ "already exists" ]] && ok "duplicate add rejected" || err duplicate_add "should reject"

log "Secret tier — delete"
echo "y" | $BIN delete gitea pat 2>/dev/null && ok "delete" || err delete "failed"
$BIN get gitea pat 2>/dev/null && err delete_verify "should be gone" || ok "delete verify"

# ── Generate ─────────────────────────────────────────────

log "Generate — default"
RESULT=$($BIN generate 2>/dev/null)
[[ ${#RESULT} -eq 16 ]] && ok "generate default length" || err generate_default "len=${#RESULT}"

log "Generate — digits only"
RESULT=$($BIN generate --digits --length 6 2>/dev/null)
[[ "$RESULT" =~ ^[0-9]{6}$ ]] && ok "generate digits" || err generate_digits "got '$RESULT'"

log "Generate — passphrase"
RESULT=$($BIN generate --passphrase --length 4 2>/dev/null)
[[ $(echo "$RESULT" | tr '-' '\n' | wc -l | tr -d ' ') -eq 4 ]] && ok "generate passphrase" || err generate_passphrase "got '$RESULT'"

log "Generate — save"
$BIN generate --digits --length 6 --save test pin 2>/dev/null && ok "generate save" || err generate_save "failed"
RESULT=$($BIN get test pin 2>/dev/null)
[[ "$RESULT" =~ ^[0-9]{6}$ ]] && ok "generate save verify" || err generate_save_verify "expected 6 digits, got '$RESULT'"

# ── Confidential tier (manual daemon testing) ────────────
# Daemon tests require a real TTY for password prompts.
# To test the daemon manually:
#   keybox --confidential init --non-interactive --password "master123"
#   keybox --confidential serve &
#   keybox --confidential unlock    # enter "master123"
#   keybox --confidential add ldap workuser
#   keybox --confidential get ldap workuser
#   keybox --confidential lock
#   keybox --confidential stop

# ── Non-interactive / LLM mode ───────────────────────────

log "LLM mode — blocks interactive"
KEYBOX_LLM_CALLING=1 $BIN add gitea test-llm 2>&1 | grep -qi "LLM calling mode" && ok "LLM mode detected" || err llm_mode "should block with KEYBOX_LLM_CALLING"

# ── Summary ──────────────────────────────────────────────

echo ""
if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}${ERRORS} test(s) failed${NC}"
    exit 1
fi
