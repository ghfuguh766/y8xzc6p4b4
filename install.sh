#!/usr/bin/env bash
# VPLINK Proxy Hunter — Universal Installer
# Works on: Linux, macOS, Termux, proot-distro, WSL, Docker, CI
set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
REPO="https://github.com/adittaya/vplink-proxy-hunter.git"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     VPLINK PROXY HUNTER INSTALLER       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ─── Detect interactive / non-interactive ─────────────────────
INTERACTIVE=false
if [ -t 0 ] && [ -t 1 ]; then
    INTERACTIVE=true
fi

# ─── Detect environment ─────────────────────────────────────────
SUDO="sudo"
IS_TERMUX=false
PKG_INSTALL=""

if [ -n "${TERMUX_VERSION:-}" ] || [ "$(uname -o 2>/dev/null)" = "Android" ]; then
    IS_TERMUX=true
    SUDO=""
    PKG_INSTALL="pkg install -y"
    echo -e "  ${YELLOW}[i]${NC} Termux detected"
elif [ -f /etc/debian_version ]; then
    if [ "$(whoami)" = "root" ]; then
        SUDO=""
    fi
    PKG_INSTALL="apt install -y"
    echo -e "  ${YELLOW}[i]${NC} Debian/Ubuntu detected"
elif [ -f /etc/arch-release ]; then
    PKG_INSTALL="pacman -S --noconfirm"
    echo -e "  ${YELLOW}[i]${NC} Arch Linux detected"
elif [ -f /etc/redhat-release ]; then
    if command -v dnf &>/dev/null; then
        PKG_INSTALL="dnf install -y"
    else
        PKG_INSTALL="yum install -y"
    fi
    echo -e "  ${YELLOW}[i]${NC} RHEL/Fedora detected"
elif [ -f /etc/alpine-release ]; then
    PKG_INSTALL="apk add"
    echo -e "  ${YELLOW}[i]${NC} Alpine Linux detected"
elif [ "$(uname)" = "Darwin" ]; then
    SUDO=""
    echo -e "  ${YELLOW}[i]${NC} macOS detected"
else
    PKG_INSTALL="apt install -y"
    echo -e "  ${YELLOW}[i]${NC} Linux (apt fallback) detected"
fi

# ─── [1/6] Install system dependencies ────────────────────────
echo ""
echo -e "${BOLD}[1/6] Installing system dependencies...${NC}"

# Prevent interactive prompts in clean/bootstrap environments
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export APT_LISTCHANGES_FRONTEND=none

if [ "$IS_TERMUX" = true ]; then
    pkg update -y 2>/dev/null || true
    $SUDO $PKG_INSTALL python python-pip curl git 2>&1 | sed 's/^/  /' || {
        echo -e "  ${YELLOW}[!]${NC} Package install had issues, continuing..."
    }
elif [ -n "$PKG_INSTALL" ]; then
    if echo "$PKG_INSTALL" | grep -q "apt" && [ "$SUDO" = "sudo" ]; then
        sudo apt-get update -qq 2>/dev/null || true
    fi
    $SUDO $PKG_INSTALL python3 python3-pip python3-venv curl git 2>&1 | sed 's/^/  /' || \
    $SUDO $PKG_INSTALL python3 python3-pip curl git 2>&1 | sed 's/^/  /' || \
    echo -e "  ${YELLOW}[!]${NC} System deps install had issues, continuing..."
elif [ "$(uname)" = "Darwin" ]; then
    if ! command -v brew &>/dev/null; then
        echo -e "  ${YELLOW}[!] Installing Homebrew...${NC}"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew install python curl git 2>&1 | sed 's/^/  /'
fi

echo -e "  ${GREEN}[✓]${NC} System deps ready"

# ─── [2/6] Check Python ───────────────────────────────────────
echo ""
echo -e "${BOLD}[2/6] Checking Python...${NC}"

PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON="$cmd"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo -e "  ${RED}[!] Python not found. Install it manually.${NC}"
    exit 1
fi

$PYTHON -c "import sys; sys.exit(0) if sys.version_info >= (3,8) else sys.exit(1)" 2>/dev/null || {
    echo -e "  ${RED}[!] Python 3.8+ required, got $($PYTHON --version)${NC}"
    exit 1
}
echo -e "  ${GREEN}[✓]${NC} $($PYTHON --version)"

# ─── [3/6] Check curl ──────────────────────────────────────────
echo ""
echo -e "${BOLD}[3/6] Checking curl...${NC}"
command -v curl &>/dev/null || { echo -e "  ${RED}[!] curl not found. Install it.${NC}"; exit 1; }
echo -e "  ${GREEN}[✓]${NC} $(curl --version | head -1)"

# ─── [4/6] Get source code ─────────────────────────────────────
echo ""
echo -e "${BOLD}[4/6] Getting source code...${NC}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR=""

if [ -f "$SCRIPT_DIR/pyproject.toml" ] && [ -d "$SCRIPT_DIR/vplink_hunter" ]; then
    REPO_DIR="$SCRIPT_DIR"
    echo -e "  ${GREEN}[✓]${NC} Found local copy"
else
    if [ "$IS_TERMUX" = true ]; then
        REPO_DIR="$HOME/storage/downloads/vplink-proxy-hunter"
    else
        REPO_DIR="$HOME/vplink-proxy-hunter"
    fi

    if [ -d "$REPO_DIR" ]; then
        echo -e "  ${YELLOW}[i]${NC} Updating existing clone..."
        cd "$REPO_DIR" && git pull 2>&1 | sed 's/^/  /'
    else
        echo -e "  ${YELLOW}[i]${NC} Cloning from GitHub..."
        git clone --depth=1 "$REPO" "$REPO_DIR" 2>&1 | sed 's/^/  /'
    fi
    echo -e "  ${GREEN}[✓]${NC} Source at $REPO_DIR"
fi

# ─── [5/6] Install Python package ─────────────────────────────
echo ""
echo -e "${BOLD}[5/6] Installing Python package...${NC}"

VENV_DIR="$HOME/.local/share/vplink-hunter/venv"
BIN_DIR="$HOME/.local/bin"
mkdir -p "$VENV_DIR" "$BIN_DIR"

VENV_OK=false
if $PYTHON -m venv --help &>/dev/null; then
    rm -rf "$VENV_DIR"
    if $PYTHON -m venv "$VENV_DIR" 2>/dev/null; then
        # shellcheck disable=SC1091
        source "$VENV_DIR/bin/activate"
        pip install -q --upgrade pip 2>/dev/null || true
        VENV_OK=true
    fi
fi

if [ "$VENV_OK" = true ]; then
    pip install -q -e "$REPO_DIR" 2>&1 | sed 's/^/  /' || {
        echo -e "  ${YELLOW}[!]${NC} Editable install failed, trying regular install..."
        pip install -q "$REPO_DIR" 2>&1 | sed 's/^/  /'
    }
    ln -sf "$VENV_DIR/bin/vplink-hunter" "$BIN_DIR/vplink-hunter" 2>/dev/null || true
    echo -e "  ${GREEN}[✓]${NC} Installed in virtualenv"
else
    echo -e "  ${YELLOW}[!]${NC} venv unavailable; installing with --user"
    $PYTHON -m pip install --user --upgrade pip 2>/dev/null || true
    $PYTHON -m pip install --user -e "$REPO_DIR" 2>&1 | sed 's/^/  /' || \
    $PYTHON -m pip install --user "$REPO_DIR" 2>&1 | sed 's/^/  /'
    if command -v vplink-hunter &>/dev/null; then
        VENV_OK=true
    fi
    USER_BIN="$HOME/.local/bin"
    if [ "$IS_TERMUX" = true ]; then
        USER_BIN="$PREFIX/bin"
    fi
    if [ -f "$USER_BIN/vplink-hunter" ]; then
        VENV_OK=true
    fi
    echo -e "  ${GREEN}[✓]${NC} Installed (user)"
    BIN_DIR="$USER_BIN"
fi

# Symlink standalone tools
ln -sf "$REPO_DIR/proxy_pull.py" "$BIN_DIR/proxy-pull" 2>/dev/null || true
ln -sf "$REPO_DIR/proxy_finder.py" "$BIN_DIR/proxy-finder" 2>/dev/null || true
ln -sf "$REPO_DIR/proxy_hunter.py" "$BIN_DIR/proxy-hunter" 2>/dev/null || true
ln -sf "$REPO_DIR/proxy_api.py" "$BIN_DIR/proxy-api" 2>/dev/null || true
chmod +x "$REPO_DIR/proxy_pull.py" "$REPO_DIR/proxy_finder.py" "$REPO_DIR/proxy_hunter.py" "$REPO_DIR/proxy_api.py" 2>/dev/null || true

# ─── Add to PATH ──────────────────────────────────────────────
PATH_UPDATED=false
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    export PATH="$PATH:$BIN_DIR"
    PATH_UPDATED=true
fi

# Persist PATH in shell config
SHELL_CONFIG=""
case "${SHELL##*/}" in
    bash) SHELL_CONFIG="$HOME/.bashrc" ;;
    zsh)  SHELL_CONFIG="$HOME/.zshrc"  ;;
    fish) SHELL_CONFIG="$HOME/.config/fish/config.fish" ;;
esac

if [ -n "$SHELL_CONFIG" ]; then
    if [ ! -f "$SHELL_CONFIG" ]; then
        mkdir -p "$(dirname "$SHELL_CONFIG")"
        touch "$SHELL_CONFIG"
    fi
    if ! grep -qF "$BIN_DIR" "$SHELL_CONFIG" 2>/dev/null; then
        if [ "${SHELL##*/}" = "fish" ]; then
            echo "fish_add_path $BIN_DIR" >> "$SHELL_CONFIG"
        else
            echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$SHELL_CONFIG"
        fi
        echo -e "  ${YELLOW}[i]${NC} Added $BIN_DIR to PATH in $SHELL_CONFIG"
    fi
fi

# Verify vplink-hunter is accessible
if command -v vplink-hunter &>/dev/null; then
    echo -e "  ${GREEN}[✓]${NC} vplink-hunter command is available"
else
    # Try to find it
    if [ -x "$BIN_DIR/vplink-hunter" ]; then
        echo -e "  ${YELLOW}[i]${NC} vplink-hunter is at $BIN_DIR/vplink-hunter"
        echo -e "  ${YELLOW}[i]${NC} Run: export PATH=\"\$PATH:$BIN_DIR\""
    else
        echo -e "  ${YELLOW}[!]${NC} vplink-hunter not found in PATH"
        echo -e "  ${YELLOW}[i]${NC} Try: source ~/.bashrc && vplink-hunter --help"
    fi
fi

# ─── [6/6] Configure Supabase ─────────────────────────────────
echo ""
echo -e "${BOLD}[6/6] Supabase configuration...${NC}"

CONFIG_DIR="$HOME/.config/vplink-hunter"
CONFIG_FILE="$CONFIG_DIR/config.json"
mkdir -p "$CONFIG_DIR"

if [ -f "$CONFIG_FILE" ]; then
    echo -e "  ${GREEN}[✓]${NC} Config already exists at $CONFIG_FILE"
elif [ "$INTERACTIVE" = true ]; then
    echo ""
    echo -e "  ${YELLOW}Enter your Supabase credentials (or press Enter 3x to skip):${NC}"
    echo ""
    read -rp "  Supabase URL [https://xxxx.supabase.co]: " SB_URL
    read -rp "  Service Key [sb_secret_xxxx]: " SB_KEY
    read -rp "  Anon Key [sb_publishable_xxxx]: " SB_ANON
    echo ""

    if [ -n "$SB_URL" ] && [ -n "$SB_KEY" ]; then
        cat > "$CONFIG_FILE" <<-EOF
{
  "supabase_url": "${SB_URL}",
  "service_key": "${SB_KEY}",
  "anon_key": "${SB_ANON:-}"
}
EOF
        chmod 600 "$CONFIG_FILE"
        echo -e "  ${GREEN}[✓]${NC} Config saved to $CONFIG_FILE"
    else
        echo -e "  ${YELLOW}[i]${NC} Skipped. Run 'vplink-hunter' later to configure."
    fi
else
    # Non-interactive: create empty config placeholder
    echo -e "  ${YELLOW}[i]${NC} Non-interactive shell detected."
    echo -e "  ${YELLOW}[i]${NC} To configure Supabase, run: vplink-hunter"
    echo -e "  ${YELLOW}[i]${NC} Or create $CONFIG_FILE with your credentials."
fi

# ─── Copy .env.example if .env doesn't exist ──────────────────
if [ ! -f "$REPO_DIR/.env" ] && [ -f "$REPO_DIR/.env.example" ]; then
    cp "$REPO_DIR/.env.example" "$REPO_DIR/.env"
    echo -e "  ${YELLOW}[i]${NC} Created .env from .env.example"
fi

# ─── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     INSTALLATION COMPLETE!               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Commands:${NC}"
echo -e "    vplink-hunter --help     # Show help"
echo -e "    vplink-hunter            # Start scanner (configure Supabase first)"
echo -e "    vplink-hunter --once     # Single batch then exit"
echo -e "    vplink-hunter --list     # Query database"
echo -e "    proxy-pull --help        # Pull proxies with filters"
echo -e "    proxy-api --port 8080    # REST API server"
echo ""
echo -e "  ${YELLOW}Note:${NC} Restart your shell or run:  ${BOLD}source ~/.bashrc${NC}"
echo ""
