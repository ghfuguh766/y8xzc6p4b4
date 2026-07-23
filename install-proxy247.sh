#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  proxy247 — One-Line Installer
#  Usage:
#    curl -fsSL https://raw.githubusercontent.com/adittaya/workflow-proxy/main/install-proxy247.sh | bash
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

REPO="adittaya/workflow-proxy"
RAW="https://raw.githubusercontent.com/$REPO/main"
BIN="/usr/local/bin/proxy247"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}${1}${NC}"; }
warn() { echo -e "  ${YELLOW}${1}${NC}"; }
fail() { echo -e "  ${RED}${1}${NC}"; }
info() { echo -e "${CYAN}${1}${NC}"; }

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         proxy247 — One-Line Installer        ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ── Check prerequisites ────────────────────────────────
MISSING=()
for cmd in python3 git; do
  command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
done
if [ ${#MISSING[@]} -gt 0 ]; then
  fail "Missing: ${MISSING[*]} — install them first"
  exit 1
fi

PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
[ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -ge 8 ] || { fail "Python 3.8+ required (found $PY_MAJOR.$PY_MINOR)"; exit 1; }
ok "Python $PY_MAJOR.$PY_MINOR"

# ── Install pynacl ─────────────────────────────────────
info "Installing pynacl (for GitHub Secrets encryption)..."
PIP_CMD=""
for c in pip3 pip; do
  command -v "$c" &>/dev/null && PIP_CMD="$c" && break
done
if [ -n "$PIP_CMD" ]; then
  PIP_EXTRA=""
  python3 -c "import sys; import site; sys.exit(0 if hasattr(site, 'ENABLE_USER_SITE') and site.ENABLE_USER_SITE else 1)" 2>/dev/null || PIP_EXTRA="--break-system-packages"
  $PIP_CMD install pynacl --quiet $PIP_EXTRA 2>/dev/null || warn "Could not install pynacl ('proxy247 deploy' will fail on secret encryption)"
  ok "pynacl installed"
else
  warn "pip not found; install pynacl manually: pip install pynacl"
fi

# ── Download proxy247 ─────────────────────────────────
info "Downloading proxy247..."
TMPFILE=$(mktemp)
FETCH_URL="https://api.github.com/repos/$REPO/contents/proxy247.py"
if ! curl -fsSL -H "Accept: application/vnd.github.v3.raw" "$FETCH_URL" -o "$TMPFILE" 2>/dev/null; then
  curl -fsSL "https://raw.githubusercontent.com/$REPO/main/proxy247.py" -o "$TMPFILE" 2>/dev/null
fi
if [ ! -s "$TMPFILE" ]; then
  rm -f "$TMPFILE"
  fail "Failed to download proxy247.py"
  exit 1
fi
if [ -w "$(dirname "$BIN")" ]; then
  mv "$TMPFILE" "$BIN"
  chmod +x "$BIN"
else
  sudo mv "$TMPFILE" "$BIN" 2>/dev/null
  sudo chmod +x "$BIN" 2>/dev/null
fi
ok "Installed: $BIN"

mkdir -p "$HOME/.proxy247"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  ✓ proxy247 installed!                                  ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  Next:                                                  ║${NC}"
echo -e "${BOLD}║    proxy247                    # interactive menu    ║${NC}"
echo -e "${BOLD}║    proxy247 setup               # interactive wizard ║${NC}"
echo -e "${BOLD}║    proxy247 account add         # add GitHub account  ║${NC}"
echo -e "${BOLD}║    proxy247 deploy new          # deploy hunter       ║${NC}"
echo -e "${BOLD}║    proxy247 test <repo>         # test your hunter    ║${NC}"
echo -e "${BOLD}║    proxy247 status              # view status         ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
