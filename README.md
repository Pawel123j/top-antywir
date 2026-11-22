# Top Antywir

> **Educational prototype only. This is not a real antivirus and cannot
> reliably detect or stop malware. Do not use it to protect a computer or
> scan files you cannot afford to lose.**

[![CI](https://github.com/Pawel123j/top-antywir/actions/workflows/ci.yml/badge.svg)](https://github.com/Pawel123j/top-antywir/actions/workflows/ci.yml)

Top Antywir is a Python file-scanning demo with a command-line interface and a
CustomTkinter desktop UI. It demonstrates local hash and pattern matching,
scan reporting, signature-pack validation, audit logging, and a recoverable
quarantine. Signatures are small and manually maintained; the project does not
provide production malware protection.

## Screenshots

Both images are from the running Linux GUI. The second scans a plain-text
fixture containing an inert pattern example; no command in that file is run.

![Top Antywir idle window](docs/screenshots/gui-idle.png)

![Top Antywir showing a pattern match](docs/screenshots/gui-detection.png)

More detail and a repeatable capture command are in
[docs/screenshots/README.md](docs/screenshots/README.md).

## Features

- Scan a file or directory, common locations, or the full filesystem.
- Stream progress and report clean, suspicious, infected, skipped, and failed
  paths. A scan with errors is marked incomplete.
- Review findings, export HTML, and move detections to local quarantine.
- Restore quarantined files to a new or original path; metadata and payloads
  are written so interrupted operations can be recovered.
- Validate JSON packs of hashes and regular expressions before installation.
- Monitor selected directories from user space and schedule scans through the
  platform scheduler.

The scanner skips symlinks and configured exclusions and reports those paths.
It does not inspect archives or execute files. Detection results only describe
the bundled or manually installed signatures that were checked.

## Install

The application supports Python 3.10+. Optional icon generation
(`scripts/make_icon.py`) and screenshot capture (`scripts/screenshot_gui.py`)
require **Python 3.11+ and Pillow 13+**. Install `.[dev]` on Python 3.11+ to use
these tools; Python 3.10 installs the test/lint tools without Pillow. Packaged icons
and the ordinary Tk interface do not require Pillow. Do not install an older,
vulnerable Pillow just to use image tooling on Python 3.10.

Builds require setuptools 84.1+ (including the PyInstaller environment); this is
declared in `pyproject.toml` and both packaging workflows.

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade "pip>=26.2"
pip install -e .
top-antywir-gui
```

### Linux (Debian / Ubuntu / Kali)

```bash
sudo apt install python3-tk          # required by the GUI
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade "pip>=26.2"
pip install -e .
top-antywir-gui
```

Register Top Antywir in the application menu (no sudo):

```bash
bash packaging/install-desktop.sh
```

### macOS

```bash
brew install python-tk@3.12          # (or whichever Python you use; Tk ships in Python.org installers)
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade "pip>=26.2"
pip install -e .
top-antywir-gui
```

## Run a safe demo

This creates an inert text file so the sample pattern can be observed. It does
not create or run a program:

```bash
cat > /tmp/top-antywir-demo.txt <<'EOF'
Static text used to demonstrate signature matching. Never execute this file.
powershell.exe -EncodedCommand NOT_EXECUTED_DEMO_VALUE
EOF

top-antywir scan /tmp/top-antywir-demo.txt --json --html /tmp/top-antywir-report.html
```

The example produces a `Suspicious-Encoded-Powershell` match. Exit codes are
`0` for clean, `1` for suspicious results or scan errors, and `2` for an
infected result.

## CLI and GUI

```text
top-antywir scan PATH [--json] [--html REPORT.html] [--quarantine]
top-antywir scan --quick
top-antywir scan --full
top-antywir monitor PATH [--once] [--quarantine]
top-antywir signatures import PACK.json
top-antywir quarantine list|restore|delete
top-antywir audit --json
```

The GUI flow is choose a file or folder, scan it, then select a result to view
details. It also has Quick and Full presets, cancellation, HTML export, a
user-space monitor toggle, and quarantine management. Full scans can take a
long time; review the selected target before starting one.

On Linux, application data follows XDG locations. On macOS it uses Application
Support and Logs; on Windows it uses LocalAppData. Signature packs, quarantine
payloads, and the audit log are kept in the application data directories.

## Recovering interrupted quarantine operations

Quarantine writes and flushes a recovery journal before transferring a file. The
transfer copies into a newly created destination, flushes it, and only then removes
the source. A full disk, denied write or interrupted transfer therefore leaves the
source in place or a discoverable quarantine entry. This also works when the source
and quarantine are on different filesystems, at the cost of temporarily needing
space for both copies. If the source changes during copying, it is not removed.

`quarantine list` and the GUI show files with missing/damaged metadata or a short,
interrupted copy as **recovery** entries. The existing files and metadata are kept;
they are never silently reset. Check the original location first: it may still hold
the complete file. Recover an orphan to a **new** explicit path with:

```bash
top-antywir quarantine restore ITEM_ID --to /path/to/new-recovered-file
```

The GUI asks for another destination when the original path is unavailable.
Restoring never overwrites an occupied path, including dangling symbolic links.
If a restore is interrupted, the complete quarantine copy remains until copying
and flushing succeeds. A failed cleanup can leave a partial destination; use a new
path for retry, and inspect the old one before deleting it yourself. If removing
the source fails after a successful copy, both complete copies remain. A `recovery`
entry is a recovery aid, not a claim that an interrupted copy is complete.

Older quarantine journals remain readable. Symbolic-link payloads are refused;
metadata cannot redirect a restore/delete operation outside the selected stored file.
These are local filesystem safeguards, not tamper protection against another
process running under the same user account or a guarantee against hardware failure.

## Development

```bash
python -m pip install -e '.[dev]'
python -m pytest
ruff check .
```

Build a wheel with `python -m pip wheel --no-deps .`. To build a local
PyInstaller executable, install the `build` extra with
`python -m pip install -e '.[build]'`, then use the platform packaging workflow.
PyInstaller builds are platform-specific.

The CI workflow tests Linux, Windows, and macOS and builds platform-specific
executables. A CI result or a local Linux run does not validate another OS.
Scheduling and long-running monitor behavior depend on each platform's
services and need separate checks.

The [Security workflow](.github/workflows/security.yml) adds dependency auditing,
CodeQL analysis and Git history secret scanning. See [security scope](SECURITY.md)
for the threat model and the limits of these checks.

## Current local validation — 2026-11-12

- 111 Python tests and 9 subtests pass on Linux with Python 3.12. The GUI
  test is skipped because this environment has no display/Xvfb. Ruff passes.
- Recovery tests cover journal/copy/flush failures, partial and orphaned
  payloads, concurrent source/destination changes, and occupied restore paths.
- The screenshots and earlier GUI/CLI smoke checks remain from the preceding
  revision. The GUI, wheel, and PyInstaller executable were not rebuilt or
  revalidated for this change. Windows/macOS still require their CI runs.

These checks exercise the demo paths. They do not measure detection quality or
provide evidence that the application can replace antivirus software.

Design and file formats: [architecture](docs/ARCHITECTURE.md),
[signature packs](docs/SIGNATURE-PACKS.md), and
[example pack](examples/example-pack.json).

MIT — see [LICENSE](LICENSE).
