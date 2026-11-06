#!/usr/bin/env bash
# Install a desktop launcher + icon for r3dProxy so it shows in your app menu
# and can be pinned to the taskbar/dock.
set -e

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ICON_SRC="$REPO/r3dproxy/gui/assets/icon.png"

# pick a python: the repo venv if present, else python3
if [ -x "$REPO/.venv/bin/python" ]; then
  PY="$REPO/.venv/bin/python"
else
  PY="$(command -v python3 || command -v python)"
fi

APPS="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor/256x256/apps"
mkdir -p "$APPS" "$ICONS" "$HOME/.r3dproxy"
cp -f "$ICON_SRC" "$ICONS/r3dproxy.png"

cat > "$APPS/r3dProxy.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=r3dProxy
GenericName=Web Security Proxy
Comment=AI-assisted intercepting web proxy for authorized testing
Exec=bash -c 'cd "$REPO" && "$PY" run.py >> "$HOME/.r3dproxy/run.log" 2>&1'
Path=$REPO
Icon=r3dproxy
Terminal=false
Categories=Development;Security;Network;
StartupNotify=true
EOF

chmod +x "$APPS/r3dProxy.desktop" || true
update-desktop-database "$APPS" 2>/dev/null || true
gtk-update-icon-cache "$HOME/.local/share/icons/hicolor" 2>/dev/null || true

echo "Installed launcher: $APPS/r3dProxy.desktop"
echo "Icon: $ICONS/r3dproxy.png"
echo "Find 'r3dProxy' in your application menu (you may need to log out/in or"
echo "refresh the menu). Output is logged to ~/.r3dproxy/run.log."
