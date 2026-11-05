#!/usr/bin/env bash
# Publish r3dProxy to GitHub as a public repo under your account.
# Requires the GitHub CLI (gh) authenticated:  gh auth login
set -e

REPO_NAME="${1:-r3dProxy}"
DESC="AI-assisted intercepting web proxy with a GUI (Burp-like) for authorized security testing — OWASP scanner plugins, raw-socket sender, Claude analysis, OAST."

cd "$(dirname "$0")"

# git history already exists in this folder (initial commit made).
# If not, uncomment:
# git init -q && git add -A && git commit -q -m "r3dProxy v0.1"

echo "Creating public repo '$REPO_NAME' and pushing…"
gh repo create "$REPO_NAME" --public --source=. --remote=origin --push --description "$DESC"

echo
echo "Done. Repo: $(gh repo view --json url -q .url 2>/dev/null)"
