# Top Antywir

> **WARNING: This is a prototype — NOT a working antivirus.**
> Top Antywir is an educational proof-of-concept. It does **not** provide real
> protection: it will not reliably detect or stop actual malware, and it must
> **not** be used as your computer's real antivirus. Treat it strictly as a
> learning project and a starting point.
>
> **UWAGA: To jest prototyp antywirusa, a nie działający antywirus.**
> Top Antywir to projekt edukacyjny / dowód koncepcji. **Nie** zapewnia realnej
> ochrony — nie wykryje ani nie zatrzyma prawdziwego złośliwego oprogramowania
> i **nie** wolno używać go jako właściwego antywirusa na komputerze. Traktuj go
> wyłącznie jako projekt do nauki i punkt wyjścia.

[![CI](https://github.com/Pawel123j/top-antywir/actions/workflows/ci.yml/badge.svg)](https://github.com/Pawel123j/top-antywir/actions/workflows/ci.yml)

A cross-platform antivirus **prototype** written in Python — runs on **Windows, Linux and macOS**, with both a CLI and a modern dark-theme desktop GUI. Intentionally simple, no paid cloud, no kernel driver, no hidden telemetry.

> Note: Real commercial antivirus products do far more (signed signature updates, real-time kernel-level monitor, tamper protection, lab certification). Top Antywir is a usable on-demand **and** real-time *prototype* scanner with quarantine, audit log, extensible signature packs and scheduled scans — good as a teaching tool and a starting point, but not a substitute for a real antivirus.

## Features

- **Three scan modes**: a specific path, common malware locations (Quick), or the entire computer (Full).
- **Real-time folder monitor**: watches chosen folders (or the Quick locations) and scans files the moment they appear or change, with optional auto-quarantine — zero dependencies, identical on every OS.
- **Extensible signature packs**: drop in JSON packs of SHA-256 hashes and regex patterns; they merge with the built-ins. Packs are *data*, never code, and are validated on import.
- **Scheduled scans** registered with the native OS scheduler — Task Scheduler on Windows, systemd user timers on Linux, launchd LaunchAgents on macOS.
- **HTML reports**: export a self-contained, styled scan report from the CLI (`--html`) or the GUI.
- **Modern GUI** built on customtkinter with live progress, stats cards, cancel-mid-scan, a real-time protection toggle, HTML export, and a quarantine manager with restore/delete.
- **Cross-platform paths**: XDG on Linux, Application Support on macOS, LocalAppData on Windows.
- **Append-only audit log** of every scan, monitor and quarantine action (JSON Lines).
- **Streaming scan engine** with cooperative cancellation, exclusion lists, and single-pass file reads.
- **Quarantine** that disarms files on add (no execute bits / hidden+system on Windows) and re-arms on restore.
- **18 built-in pattern signatures** for common shell-malware, plus SHA-256 hash matching and entropy/heuristic checks.
- **JSON output** for machine-parseable scan reports.

## Install

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
top-antywir-gui
```

### Linux (Debian / Ubuntu / Kali)

```bash
sudo apt install python3-tk          # required by the GUI
python3 -m venv .venv
source .venv/bin/activate
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
pip install -e .
top-antywir-gui
```

## CLI

| Command                                | Action                                                  |
|----------------------------------------|---------------------------------------------------------|
| `top-antywir scan PATH`                | Scan a specific file or folder                          |
| `top-antywir scan --quick`             | Scan common malware locations (Downloads, Temp, …)      |
| `top-antywir scan --full`              | Scan all fixed drives / root filesystem                 |
| `top-antywir scan --quick --list-targets` | Print which paths Quick would scan, then exit         |
| `top-antywir scan PATH --json`         | Emit a machine-parseable JSON report                    |
| `top-antywir scan PATH --quarantine`   | Move detections to quarantine                           |
| `top-antywir scan PATH --html OUT.html`| Also write a self-contained HTML report                 |
| `top-antywir monitor [PATHS…]`         | Watch folders, scan files as they appear/change         |
| `top-antywir monitor --quick --quarantine` | Watch the Quick locations and auto-quarantine       |
| `top-antywir monitor --once`           | One-shot pass over the watched paths, then exit         |
| `top-antywir signatures import PACK.json` | Validate and install a user signature pack           |
| `top-antywir signatures list`          | List built-in + installed signature packs               |
| `top-antywir signatures dir`           | Print the signatures directory                          |
| `top-antywir schedule create --mode quick --at 03:00` | Register a daily scan with the OS scheduler  |
| `top-antywir schedule list`            | List Top Antywir scheduled jobs                         |
| `top-antywir schedule remove --mode quick` | Remove a scheduled scan                             |
| `top-antywir quarantine list`          | Show quarantined items                                  |
| `top-antywir quarantine restore ID`    | Restore an item to its original path                    |
| `top-antywir quarantine delete ID`     | Permanently delete an item                              |
| `top-antywir audit --limit 20`         | Tail the audit log                                      |
| `top-antywir audit --json`             | Audit log as JSON Lines (for scripts / SIEM ingest)     |

Exit codes: `0` clean, `1` suspicious or errors, `2` infected (useful for CI gates). `monitor --once` follows the same convention.

### Signature packs

A pack is a JSON file of additional detections that merge with the built-ins (built-ins always win on conflict):

```json
{
  "name": "my-pack",
  "hashes": [
    {"name": "Evil-Dropper", "sha256": "<64 hex chars>", "severity": "high",
     "description": "Known dropper hash."}
  ],
  "patterns": [
    {"name": "Curl-Pipe-Bash", "regex": "curl\\s+\\S+\\s*\\|\\s*bash",
     "flags": ["IGNORECASE"], "severity": "medium",
     "description": "Pipe-to-shell installer."}
  ]
}
```

Install it with `top-antywir signatures import my-pack.json`. Invalid entries are skipped with a reported reason rather than aborting the import.

## GUI

Launch with `top-antywir-gui`. The window shows:

- Path input + 📄 Plik / 📁 Folder / ⚡ Skanuj buttons
- 🚀 Szybkie skanowanie / 🌐 Pełne skanowanie komputera preset buttons
- Live progress with cancel (button transforms ⚡ Skanuj → ⏹ Zatrzymaj)
- Four stat cards (Clean / Suspicious / Infected / Errors)
- Detections table with severity color-coding and 📂 Pokaż w eksploratorze action
- 💾 Raport HTML to export the last scan as a styled HTML file
- 🛡 Ochrona toggle that turns the real-time folder monitor on/off
- 🔒 Quarantine window with ↩ Restore / 🗑 Delete / ⟳ Refresh

### Keyboard shortcuts

| Shortcut         | Action                                |
|------------------|---------------------------------------|
| `Enter` / `F5`   | Start scan of the current path        |
| `Ctrl+O`         | Choose file to scan                   |
| `Ctrl+Shift+O`   | Choose folder to scan                 |
| `Ctrl+1`         | 🚀 Quick scan                         |
| `Ctrl+2`         | 🌐 Full computer scan                 |
| `Escape`         | Cancel current scan                   |
| `Ctrl+E`         | Export last scan as HTML report       |
| `Ctrl+M`         | Toggle real-time protection           |
| `Ctrl+L`         | Focus path entry                      |
| `Ctrl+K`         | Open quarantine                       |
| `Ctrl+Q`         | Quit                                  |

Inside the quarantine window: `Ctrl+R` restore · `Delete` purge · `F5` refresh · `Escape` close.

## Where Top Antywir stores data

| OS      | Quarantine                                                                  | Audit log                                                |
|---------|-----------------------------------------------------------------------------|----------------------------------------------------------|
| Windows | `%LOCALAPPDATA%\top-antywir\quarantine`                                     | `%LOCALAPPDATA%\top-antywir\logs\audit.jsonl`            |
| macOS   | `~/Library/Application Support/top-antywir/quarantine`                      | `~/Library/Logs/top-antywir/audit.jsonl`                 |
| Linux   | `$XDG_DATA_HOME/top-antywir/quarantine`<br>(`~/.local/share/top-antywir/…`) | `$XDG_STATE_HOME/top-antywir/logs/audit.jsonl`           |

User signature packs live next to the quarantine, in a `signatures/` subfolder of the data directory (run `top-antywir signatures dir` to print the exact path).

## EICAR Test

Test detection using the harmless [EICAR](https://en.wikipedia.org/wiki/EICAR_test_file) string:

```bash
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
top-antywir scan eicar.com
```

On Windows your real antivirus will probably eat the EICAR file before Top Antywir sees it — that's expected.

## Development

```bash
python -m pip install -e ".[dev]"   # albo: pip install pytest ruff
python -m pytest                    # 65 testów
ruff check .                        # linter (konfiguracja w pyproject.toml)
python -m top_antywir scan ~/Downloads
```

### CI

`.github/workflows/ci.yml` uruchamia na każdej gałęzi trzy zadania:

| Zadanie | Co robi |
|---|---|
| Testy | 65 testów na **Ubuntu, Windows i macOS**, na Pythonie 3.10 i 3.13 (6 kombinacji) |
| Ruff | Linter z wersją przypiętą w workflow |
| Binarka | PyInstaller na trzech systemach + **uruchomienie** zbudowanej binarki na pliku EICAR |

Macierz ma `fail-fast: false` celowo: w projekcie, który chwali się
wieloplatformowością, najważniejszą informacją z przebiegu jest to, czy
problem dotyczy wszystkich systemów, czy jednego. Przerwanie po pierwszym
czerwonym tę informację niszczy.

Zadanie „Binarka" nie kończy się na zbudowaniu pliku — uruchamia go
i sprawdza, że wykrywa EICAR. Build, którego nikt nie uruchomił, nie jest
dowodem na nic.

### Wydania

`.github/workflows/release.yml` buduje binarki na trzy systemy, sprawdza
każdą z nich na pliku EICAR, liczy sumy kontrolne SHA-256 i publikuje
wydanie:

```bash
git tag v0.4.0
git push origin v0.4.0
```

Sumy kontrolne są dołączane świadomie: binarka antywirusa pobrana
z internetu bez możliwości weryfikacji to dokładnie ten scenariusz, przed
którym ten program ostrzega.

### Dokumentacja

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — warstwy, decyzje projektowe
  i ich uzasadnienia, przepływ skanowania, czego testy **nie** pokrywają.
- [docs/SIGNATURE-PACKS.md](docs/SIGNATURE-PACKS.md) — pełny format pakietów
  sygnatur, zasada pierwszeństwa, pułapki przy pisaniu wzorców.
- [examples/example-pack.json](examples/example-pack.json) — gotowy do
  zaimportowania przykład.

### Zrzuty ekranu GUI

Katalog `docs/screenshots/` jest pusty i to jest świadome: zrzuty interfejsu
wymagają środowiska z tkinterem i serwerem okien, a `scripts/screenshot_gui.py`
w obecnej postaci działa wyłącznie na Windowsie (używa `ctypes.windll`
i `ImageGrab`). Wstawienie tu wizualizacji zamiast prawdziwego zrzutu byłoby
gorsze niż brak obrazka.

Żeby je zrobić, na Windowsie:

```bash
pip install -e . pillow
python scripts/screenshot_gui.py    # zapisuje do %TEMP%\top-antywir-shot.png
```

## What This Is Not Yet

Top Antywir now has extensible signature packs, a real-time folder monitor and
scheduled scans, but a production-ready antivirus would still need:

- frequent **signed, auto-updating** signature feeds (packs here are installed manually and unsigned),
- a **kernel-level** real-time monitor (the built-in one polls the filesystem from user space — robust and dependency-free, but not as instantaneous or tamper-resistant as a driver/inotify/FSEvents-based one),
- tamper protection,
- secure licensing and payment handling,
- independent malware lab testing,
- legal documents and privacy policy.
