# Contributing to r3dProxy

Thanks for your interest! r3dProxy is a tool for **authorized** web security
testing. Contributions that make it a better tool for legitimate testing are
welcome; contributions aimed at attacking systems without permission are not.

## Getting set up

```bash
git clone https://github.com/0x1Ray/r3dProxy.git
cd r3dProxy
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

Python 3.10+ and PySide6 are required. On headless CI you can import-check and
run the non-GUI tests with `QT_QPA_PLATFORM=offscreen`.

## Project layout

- `r3dproxy/core/` — engine, senders, plugins, AI, OAST (no Qt except `oast.py`).
- `r3dproxy/gui/` — PySide6 tabs and widgets.
- See `README.md` for the full map.

## Ways to contribute

- **New scanner plugins.** One vulnerability class per plugin. Favor detection
  that compares against the baseline/control and avoids false positives over
  "fire on any reflection". Start from `plugin_template.py`; built-ins live in
  `r3dproxy/core/plugins/builtin.py`.
- **Payload variations.** Keep them practical and attribute non-obvious sources.
- **Wordlists.** Small, high-signal lists. Large corpora belong in the user's
  `~/.r3dproxy/wordlists/`, not the repo.
- **Bug fixes / UX.** Screenshots help for GUI changes.

## Guidelines

- Match the existing style; keep core modules Qt-free where they already are.
- No network calls at import time. Senders/AI must run off the GUI thread.
- Add a short note to the README feature list if you add a user-facing feature.
- Only submit payloads/techniques that are already public knowledge.

## Reporting bugs / ideas

Use the issue templates. For security issues in r3dProxy itself, please open a
minimal report rather than posting a working exploit against third parties.

By contributing you agree your work is licensed under the project's MIT license.
