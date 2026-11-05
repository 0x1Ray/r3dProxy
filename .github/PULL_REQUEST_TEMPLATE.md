## What this does

Short description of the change.

## Type
- [ ] Bug fix
- [ ] New scanner plugin
- [ ] New feature
- [ ] Docs / chore

## Checklist
- [ ] Runs locally (`python run.py`) without new errors
- [ ] `python -m py_compile` passes on changed files
- [ ] Core modules kept Qt-free where they already were
- [ ] No network calls at import time; network/AI work runs off the GUI thread
- [ ] README feature list updated if user-facing
- [ ] For a new plugin: detection compares against baseline/control to limit
      false positives, and payloads are public knowledge

## Notes
Anything reviewers should know (screenshots for GUI changes welcome).
