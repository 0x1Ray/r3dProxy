#!/usr/bin/env bash
#
# r3dProxy — install the external security tools it integrates with.
# Best-effort across apt, go, pipx/pip. Safe to re-run.
#
#   bash scripts/install_tools.sh            # everything incl. Ollama AI (apt needs sudo)
#   bash scripts/install_tools.sh --nosudo   # skip apt (go/pip/pipx + AI only)
#   bash scripts/install_tools.sh --no-ai    # skip the Ollama/Qwen AI setup
#   bash scripts/install_tools.sh --list     # just show what's installed
#
set -o pipefail

NOSUDO=0
LIST=0
NOAI=0
AI_MODEL="${R3DPROXY_AI_MODEL:-qwen2.5}"
for a in "$@"; do
  case "$a" in
    --nosudo) NOSUDO=1 ;;
    --list)   LIST=1 ;;
    --no-ai)  NOAI=1 ;;
  esac
done

green() { printf '\033[32m%s\033[0m\n' "$1"; }
red()   { printf '\033[31m%s\033[0m\n' "$1"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$1"; }

have() { command -v "$1" >/dev/null 2>&1; }

APT_TOOLS=(nmap nikto dirb wfuzz whatweb feroxbuster amass)
GO_TOOLS=(
  "ffuf:github.com/ffuf/ffuf/v2@latest"
  "gobuster:github.com/OJ/gobuster/v3@latest"
  "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "assetfinder:github.com/tomnomnom/assetfinder@latest"
)
PIPX_TOOLS=(wafw00f dirsearch sublist3r)

ALL_BINS=(ollama nmap nikto dirb wfuzz whatweb feroxbuster amass ffuf gobuster nuclei \
          subfinder httpx assetfinder wafw00f dirsearch sublist3r testssl.sh findomain wpscan)

status_report() {
  echo "== tool status =="
  for b in "${ALL_BINS[@]}"; do
    if have "$b"; then green "  [ok ] $b"; else red "  [ -- ] $b"; fi
  done
}

if [ "$LIST" = 1 ]; then status_report; exit 0; fi

# ---- AI runtime: Ollama + a local model (required for the AI assistant) ----
if [ "$NOAI" = 0 ]; then
  yellow "Setting up local AI (Ollama + $AI_MODEL)…"
  if have ollama; then
    green "  ollama already present"
  elif have curl; then
    curl -fsSL https://ollama.com/install.sh | sh && green "  installed ollama" || red "  ollama install failed — see https://ollama.com"
  else
    red "  curl not found — install Ollama manually from https://ollama.com"
  fi
  if have ollama; then
    ( ollama pull "$AI_MODEL" && green "  model $AI_MODEL ready" ) || \
      yellow "  could not pull now — later run: ollama pull $AI_MODEL (and 'ollama serve')"
  fi
else
  yellow "Skipping AI setup (--no-ai)."
fi

# ---- apt (needs sudo) ----
if [ "$NOSUDO" = 0 ] && have apt-get; then
  yellow "Installing apt packages (needs sudo)…"
  sudo apt-get update -y
  for t in "${APT_TOOLS[@]}"; do
    have "$t" && { green "  $t already present"; continue; }
    sudo apt-get install -y "$t" && green "  installed $t" || red "  apt could not install $t"
  done
elif [ "$NOSUDO" = 1 ]; then
  yellow "Skipping apt (--nosudo)."
else
  yellow "apt-get not found — skipping distro packages (install nmap/nikto/dirb/wfuzz/whatweb via your package manager)."
fi

# ---- go tools ----
if have go; then
  yellow "Installing Go tools…"
  export PATH="$PATH:$(go env GOPATH)/bin"
  for pair in "${GO_TOOLS[@]}"; do
    bin="${pair%%:*}"; pkg="${pair#*:}"
    have "$bin" && { green "  $bin already present"; continue; }
    GO111MODULE=on go install "$pkg" && green "  installed $bin" || red "  go could not install $bin"
  done
  echo "  (make sure $(go env GOPATH)/bin is on your PATH)"
else
  yellow "Go not found — skipping ffuf/gobuster/nuclei/subfinder/httpx/assetfinder."
  echo "  Install Go from https://go.dev/dl/ then re-run."
fi

# ---- pipx / pip tools ----
PIPX=""
if have pipx; then PIPX="pipx";
elif have pip3; then PIPX="pip3 install --user";
elif have pip; then PIPX="pip install --user"; fi
if [ -n "$PIPX" ]; then
  yellow "Installing Python tools via: $PIPX"
  for t in "${PIPX_TOOLS[@]}"; do
    have "$t" && { green "  $t already present"; continue; }
    if [ "$PIPX" = "pipx" ]; then pipx install "$t" && green "  installed $t" || red "  pipx could not install $t";
    else $PIPX "$t" && green "  installed $t" || red "  pip could not install $t"; fi
  done
else
  yellow "No pipx/pip — skipping wafw00f/dirsearch/sublist3r."
fi

# ---- manual-only tools ----
echo
yellow "Manual installs (optional):"
echo "  testssl.sh : git clone --depth 1 https://github.com/drwetter/testssl.sh && sudo ln -s \$PWD/testssl.sh/testssl.sh /usr/local/bin/testssl.sh"
echo "  findomain  : https://github.com/findomain/findomain/releases (download binary to /usr/local/bin)"
echo "  wpscan     : sudo gem install wpscan"
echo
status_report
green "Done. Re-open r3dProxy's Recon tab and click 'Check tools'."
