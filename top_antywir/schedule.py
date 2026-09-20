"""Scheduled scans via the native OS scheduler.

No long-running daemon of our own: we register a job with whatever the
platform already ships —

* **Windows** — Task Scheduler (``schtasks``)
* **Linux**   — a *systemd user* timer + service unit
* **macOS**   — a ``launchd`` LaunchAgent plist

Each job runs ``python -m top_antywir.cli scan --quick`` (or ``--full``)
on a daily schedule. The command-building and unit/plist/argv generators
are pure functions so they can be unit-tested without touching the real
scheduler; the ``create`` / ``list_jobs`` / ``remove`` entry points are
the only ones that shell out.
"""
from __future__ import annotations

import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .paths import is_macos, is_windows

SUPPORTED_MODES = ("quick", "full")


@dataclass
class ScheduleResult:
    backend: str
    name: str
    detail: str


# ── Command building (pure) ───────────────────────────────────────────────────

def scan_command_argv(mode: str, quarantine: bool = True) -> list[str]:
    """argv that a scheduled job should execute."""
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"mode must be one of {SUPPORTED_MODES}, got {mode!r}")
    argv = [sys.executable, "-m", "top_antywir.cli", "scan", f"--{mode}", "--no-progress"]
    if quarantine:
        argv.append("--quarantine")
    return argv


def parse_hhmm(at: str) -> tuple[int, int]:
    """Parse ``"HH:MM"`` (24-hour) into validated (hour, minute)."""
    try:
        hh, mm = at.split(":")
        hour, minute = int(hh), int(mm)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"time must be HH:MM, got {at!r}") from exc
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(f"time out of range: {at!r}")
    return hour, minute


def job_label(mode: str) -> str:
    """Stable identifier for a job, per backend."""
    if is_windows():
        return f"TopAntywir-{mode.capitalize()}-Scan"
    if is_macos():
        return f"com.topantywir.{mode}scan"
    return f"top-antywir-{mode}-scan"  # systemd unit base name


# ── Windows: schtasks ─────────────────────────────────────────────────────────

def windows_create_argv(name: str, command: str, at: str) -> list[str]:
    hour, minute = parse_hhmm(at)
    return [
        "schtasks", "/Create", "/TN", name,
        "/TR", command, "/SC", "DAILY",
        "/ST", f"{hour:02d}:{minute:02d}", "/F",
    ]


def windows_command_string(argv: list[str]) -> str:
    """Quote argv into the single string Task Scheduler's /TR expects."""
    return subprocess.list2cmdline(argv)


# ── Linux: systemd user units ──────────────────────────────────────────────────

def systemd_dir() -> Path:
    return Path.home() / ".config" / "systemd" / "user"


def systemd_service_unit(mode: str, argv: list[str]) -> str:
    exec_start = " ".join(shlex.quote(a) for a in argv)
    return (
        "[Unit]\n"
        f"Description=Top Antywir {mode} scan\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={exec_start}\n"
    )


def systemd_timer_unit(mode: str, at: str) -> str:
    hour, minute = parse_hhmm(at)
    return (
        "[Unit]\n"
        f"Description=Top Antywir {mode} scan schedule\n\n"
        "[Timer]\n"
        f"OnCalendar=*-*-* {hour:02d}:{minute:02d}:00\n"
        "Persistent=true\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


# ── macOS: launchd ─────────────────────────────────────────────────────────────

def launchagents_dir() -> Path:
    return Path.home() / "Library" / "LaunchAgents"


def launchd_plist(label: str, argv: list[str], at: str) -> str:
    hour, minute = parse_hhmm(at)
    args_xml = "\n".join(f"    <string>{_xml_escape(a)}</string>" for a in argv)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        "<dict>\n"
        "  <key>Label</key>\n"
        f"  <string>{_xml_escape(label)}</string>\n"
        "  <key>ProgramArguments</key>\n"
        "  <array>\n"
        f"{args_xml}\n"
        "  </array>\n"
        "  <key>StartCalendarInterval</key>\n"
        "  <dict>\n"
        f"    <key>Hour</key><integer>{hour}</integer>\n"
        f"    <key>Minute</key><integer>{minute}</integer>\n"
        "  </dict>\n"
        "  <key>RunAtLoad</key>\n"
        "  <false/>\n"
        "</dict>\n"
        "</plist>\n"
    )


def _xml_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# ── High-level actions (shell out) ─────────────────────────────────────────────

def create(mode: str = "quick", at: str = "03:00", quarantine: bool = True) -> ScheduleResult:
    """Register a daily scheduled scan. Raises RuntimeError on failure."""
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"mode must be one of {SUPPORTED_MODES}")
    parse_hhmm(at)  # validate early
    argv = scan_command_argv(mode, quarantine=quarantine)
    name = job_label(mode)

    if is_windows():
        cmd = windows_command_string(argv)
        _run(windows_create_argv(name, cmd, at))
        return ScheduleResult("schtasks", name, f"daily at {at}")

    if is_macos():
        plist = launchd_plist(name, argv, at)
        path = launchagents_dir() / f"{name}.plist"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(plist, encoding="utf-8")
        # Unload first in case it already exists, then load.
        subprocess.run(["launchctl", "unload", str(path)],
                       capture_output=True, text=True, check=False)
        _run(["launchctl", "load", "-w", str(path)])
        return ScheduleResult("launchd", name, f"{path} (daily at {at})")

    # Linux / systemd
    unit_dir = systemd_dir()
    unit_dir.mkdir(parents=True, exist_ok=True)
    (unit_dir / f"{name}.service").write_text(systemd_service_unit(mode, argv), encoding="utf-8")
    (unit_dir / f"{name}.timer").write_text(systemd_timer_unit(mode, at), encoding="utf-8")
    _run(["systemctl", "--user", "daemon-reload"])
    _run(["systemctl", "--user", "enable", "--now", f"{name}.timer"])
    return ScheduleResult("systemd", name, f"{name}.timer (daily at {at})")


def list_jobs() -> list[str]:
    """Return human-readable lines describing Top Antywir scheduled jobs."""
    if is_windows():
        out = _run(
            ["schtasks", "/Query", "/FO", "CSV", "/NH"], check=False
        )
        lines = []
        for row in out.splitlines():
            if "TopAntywir" in row:
                lines.append(row.strip().strip('"').split('","')[0].strip('"'))
        return lines

    if is_macos():
        d = launchagents_dir()
        if not d.is_dir():
            return []
        return [p.stem for p in sorted(d.glob("com.topantywir.*.plist"))]

    d = systemd_dir()
    if not d.is_dir():
        return []
    return [p.name for p in sorted(d.glob("top-antywir-*.timer"))]


def remove(mode: str = "quick") -> bool:
    """Remove a scheduled scan. Returns True if something was removed."""
    name = job_label(mode)

    if is_windows():
        result = subprocess.run(
            ["schtasks", "/Delete", "/TN", name, "/F"],
            capture_output=True, text=True, check=False,
        )
        return result.returncode == 0

    if is_macos():
        path = launchagents_dir() / f"{name}.plist"
        if not path.exists():
            return False
        subprocess.run(["launchctl", "unload", "-w", str(path)],
                       capture_output=True, text=True, check=False)
        path.unlink(missing_ok=True)
        return True

    unit_dir = systemd_dir()
    timer = unit_dir / f"{name}.timer"
    service = unit_dir / f"{name}.service"
    if not timer.exists() and not service.exists():
        return False
    subprocess.run(["systemctl", "--user", "disable", "--now", f"{name}.timer"],
                   capture_output=True, text=True, check=False)
    timer.unlink(missing_ok=True)
    service.unlink(missing_ok=True)
    subprocess.run(["systemctl", "--user", "daemon-reload"],
                   capture_output=True, text=True, check=False)
    return True


def _run(argv: list[str], check: bool = True) -> str:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise RuntimeError(f"Scheduler tool not found: {argv[0]} ({exc})") from exc
    if check and result.returncode != 0:
        raise RuntimeError(
            f"{argv[0]} failed (exit {result.returncode}): "
            f"{(result.stderr or result.stdout).strip()}"
        )
    return result.stdout
