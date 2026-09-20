"""Command line interface for Top Antywir."""

from __future__ import annotations

import argparse
import contextlib
import json
import signal
import sys
import threading
import time
from pathlib import Path

from . import __version__
from .audit import AuditLog
from .quarantine import Quarantine
from .scanner import Scanner, ScanResult, Verdict
from .targets import full_scan_targets, quick_scan_targets


def _make_output_robust() -> None:
    """Stop legacy console code pages (e.g. Windows cp1250/cp1252) from
    crashing the program with UnicodeEncodeError.

    File paths and signature names can contain characters that are not
    representable in the active code page. Rather than aborting mid-report,
    fall back to a backslash escape so output is always printable. This is a
    no-op on modern UTF-8 consoles and on Python builds without
    ``reconfigure`` (it was added in 3.7, but guard anyway)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(AttributeError, ValueError, OSError):
            reconfigure(errors="backslashreplace")


def main(argv: list[str] | None = None) -> int:
    _make_output_robust()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args)
    if args.command == "quarantine":
        return run_quarantine(args)
    if args.command == "audit":
        return run_audit(args)
    if args.command == "monitor":
        return run_monitor(args)
    if args.command == "signatures":
        return run_signatures(args)
    if args.command == "schedule":
        return run_schedule(args)

    parser.print_help()
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="top-antywir",
        description="Cross-platform antivirus prototype (Windows / Linux / macOS).",
    )
    parser.add_argument(
        "--version", action="version", version=f"top-antywir {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")

    # ── scan ──────────────────────────────────────────────────────────────────
    scan = subparsers.add_parser("scan", help="Scan files, folders, or the whole computer.")
    target_group = scan.add_mutually_exclusive_group()
    target_group.add_argument(
        "target", type=Path, nargs="?",
        help="File or directory to scan.",
    )
    target_group.add_argument(
        "--quick", action="store_true",
        help="Scan common malware locations (Downloads, Temp, Startup, ...).",
    )
    target_group.add_argument(
        "--full", action="store_true",
        help="Scan the entire computer (all fixed drives / root filesystem).",
    )
    scan.add_argument("--json", action="store_true", help="Print report as JSON.")
    scan.add_argument(
        "--html", type=Path, default=None, metavar="FILE",
        help="Also write a standalone HTML report to FILE.",
    )
    scan.add_argument(
        "--quarantine", action="store_true",
        help="Move detections to quarantine.",
    )
    scan.add_argument(
        "--quarantine-root", type=Path, default=None,
        help="Custom quarantine directory.",
    )
    scan.add_argument(
        "--list-targets", action="store_true",
        help="Only print which paths --quick or --full would scan, then exit.",
    )
    scan.add_argument(
        "--no-progress", action="store_true",
        help="Suppress per-file progress output (useful when piping).",
    )

    # ── quarantine ────────────────────────────────────────────────────────────
    quarantine = subparsers.add_parser("quarantine", help="Manage quarantined files.")
    qsub = quarantine.add_subparsers(dest="quarantine_command")

    q_list = qsub.add_parser("list", help="List quarantined files.")
    q_list.add_argument("--quarantine-root", type=Path, default=None)

    q_restore = qsub.add_parser("restore", help="Restore a quarantined file.")
    q_restore.add_argument("item_id", help="Quarantine item id.")
    q_restore.add_argument("--to", type=Path, default=None, help="Restore to a custom path.")
    q_restore.add_argument("--quarantine-root", type=Path, default=None)

    q_delete = qsub.add_parser("delete", help="Permanently delete a quarantined file.")
    q_delete.add_argument("item_id", help="Quarantine item id.")
    q_delete.add_argument("--quarantine-root", type=Path, default=None)

    # ── audit ─────────────────────────────────────────────────────────────────
    audit = subparsers.add_parser("audit", help="Show the audit log.")
    audit.add_argument("--limit", type=int, default=20, help="How many entries to show.")
    audit.add_argument("--json", action="store_true", help="Output as JSON lines.")

    # ── monitor ───────────────────────────────────────────────────────────────
    monitor = subparsers.add_parser(
        "monitor",
        help="Watch folders and scan files as they appear or change.",
    )
    monitor.add_argument(
        "paths", type=Path, nargs="*",
        help="Folders to watch (default: the quick-scan locations).",
    )
    monitor.add_argument(
        "--quick", action="store_true",
        help="Watch the common malware locations instead of explicit paths.",
    )
    monitor.add_argument(
        "--interval", type=float, default=2.0,
        help="Seconds between polls (default: 2.0).",
    )
    monitor.add_argument(
        "--quarantine", action="store_true",
        help="Automatically quarantine detections as they are found.",
    )
    monitor.add_argument(
        "--quarantine-root", type=Path, default=None,
        help="Custom quarantine directory.",
    )
    monitor.add_argument(
        "--once", action="store_true",
        help="Scan everything under the watched paths once, then exit "
             "(useful for cron / Task Scheduler).",
    )

    # ── signatures ────────────────────────────────────────────────────────────
    signatures = subparsers.add_parser(
        "signatures", help="Manage user signature packs."
    )
    ssub = signatures.add_subparsers(dest="signatures_command")
    s_import = ssub.add_parser("import", help="Validate and install a signature pack.")
    s_import.add_argument("file", type=Path, help="Path to a pack JSON file.")
    ssub.add_parser("list", help="List installed signature packs and counts.")
    ssub.add_parser("dir", help="Print the signatures directory and exit.")

    # ── schedule ──────────────────────────────────────────────────────────────
    schedule = subparsers.add_parser(
        "schedule", help="Schedule recurring scans via the OS scheduler."
    )
    schsub = schedule.add_subparsers(dest="schedule_command")
    sch_create = schsub.add_parser("create", help="Create a daily scheduled scan.")
    sch_create.add_argument(
        "--mode", choices=("quick", "full"), default="quick",
        help="Which scan to schedule (default: quick).",
    )
    sch_create.add_argument(
        "--at", default="03:00", metavar="HH:MM",
        help="Daily time in 24h format (default: 03:00).",
    )
    sch_create.add_argument(
        "--no-quarantine", action="store_true",
        help="Scan and log only; do not auto-quarantine detections.",
    )
    schsub.add_parser("list", help="List Top Antywir scheduled jobs.")
    sch_remove = schsub.add_parser("remove", help="Remove a scheduled scan.")
    sch_remove.add_argument(
        "--mode", choices=("quick", "full"), default="quick",
        help="Which scheduled scan to remove (default: quick).",
    )

    return parser


# ── scan ──────────────────────────────────────────────────────────────────────

def run_scan(args: argparse.Namespace) -> int:
    scanner = Scanner()
    audit = AuditLog()
    quarantine = Quarantine(args.quarantine_root, audit=audit)

    # Resolve the list of targets based on flags.
    if args.quick:
        targets = quick_scan_targets()
        mode = "quick"
    elif args.full:
        targets = full_scan_targets()
        mode = "full"
    elif args.target is not None:
        targets = [args.target]
        mode = "custom"
    else:
        print(
            "Error: provide a path, or use --quick / --full / --list-targets.",
            file=sys.stderr,
        )
        return 1

    if args.list_targets:
        for t in targets:
            print(t)
        return 0

    if not targets:
        print("Error: no scan targets resolved.", file=sys.stderr)
        return 1

    audit.log("scan.start", mode=mode, targets=targets)
    started = time.monotonic()

    results: list[ScanResult] = []
    detections = 0
    show_progress = not args.no_progress and not args.json

    for result in scanner.iter_scan(targets):
        results.append(result)
        if result.is_detection:
            detections += 1
        if show_progress and len(results) % 50 == 0:
            sys.stderr.write(
                f"\r  scanned: {len(results):>7}  detections: {detections}"
            )
            sys.stderr.flush()

    if show_progress:
        sys.stderr.write("\r" + " " * 60 + "\r")
        sys.stderr.flush()

    quarantined: dict[str, str] = {}
    if args.quarantine:
        for result in results:
            if result.is_detection and result.path.exists():
                item = quarantine.add(result)
                quarantined[str(result.path)] = item.item_id

    duration = time.monotonic() - started
    audit.log(
        "scan.done", mode=mode,
        scanned=len(results),
        detections=detections,
        errors=sum(1 for r in results if r.verdict == Verdict.ERROR),
        quarantined=len(quarantined),
        duration_seconds=round(duration, 2),
    )

    if args.json:
        print(json.dumps(report_to_json(results, quarantined), indent=2, sort_keys=True))
    else:
        print_human_report(results, quarantined, mode=mode, duration=duration)

    if args.html is not None:
        from .report import write_html_report
        try:
            written = write_html_report(
                args.html, results, mode=mode, duration=duration, quarantined=quarantined,
            )
            print(f"HTML report written to: {written}", file=sys.stderr)
        except OSError as exc:
            print(f"Error: could not write HTML report: {exc}", file=sys.stderr)

    if any(result.verdict == Verdict.INFECTED for result in results):
        return 2
    if any(result.verdict in {Verdict.SUSPICIOUS, Verdict.ERROR} for result in results):
        return 1
    return 0


def run_quarantine(args: argparse.Namespace) -> int:
    quarantine = Quarantine(args.quarantine_root)

    if args.quarantine_command == "list":
        items = quarantine.list_items()
        if not items:
            print("Quarantine is empty.")
            return 0
        for item in items:
            print(f"{item.item_id}  {item.verdict:10}  {item.original_path}")
        return 0

    if args.quarantine_command == "restore":
        try:
            restored = quarantine.restore(args.item_id, args.to)
            print(f"Restored to: {restored}")
            return 0
        except (FileExistsError, FileNotFoundError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    if args.quarantine_command == "delete":
        try:
            quarantine.delete(args.item_id)
            print(f"Deleted: {args.item_id}")
            return 0
        except FileNotFoundError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    print("Missing quarantine command.", file=sys.stderr)
    return 1


def run_audit(args: argparse.Namespace) -> int:
    log = AuditLog()
    entries = log.read_recent(limit=args.limit)
    if not entries:
        print("Audit log is empty.")
        return 0
    if args.json:
        for entry in entries:
            print(json.dumps({
                "timestamp": entry.timestamp,
                "event": entry.event,
                "data": entry.data,
            }))
        return 0
    for entry in entries:
        ts = entry.timestamp[:19].replace("T", " ")
        summary = ""
        if entry.event.startswith("scan.") or entry.event.startswith("monitor."):
            summary = ", ".join(
                f"{k}={v}" for k, v in entry.data.items()
                if k not in {"targets", "roots", "findings"}
            )
        elif entry.event.startswith("quarantine."):
            summary = entry.data.get("original_path") or entry.data.get("item_id", "")
        print(f"{ts}  {entry.event:22}  {summary}")
    return 0


# ── monitor ─────────────────────────────────────────────────────────────────

def run_monitor(args: argparse.Namespace) -> int:
    from .monitor import FolderMonitor

    roots = [p.expanduser() for p in args.paths] if args.paths else quick_scan_targets()
    if not roots:
        print("Error: no folders to monitor (none of the defaults exist).",
              file=sys.stderr)
        return 1

    scanner = Scanner()
    audit = AuditLog()
    quarantine = Quarantine(args.quarantine_root, audit=audit) if args.quarantine else None
    monitor = FolderMonitor(
        scanner, roots,
        interval=args.interval,
        auto_quarantine=args.quarantine,
        quarantine=quarantine,
        audit=audit,
    )

    detections = 0

    def on_detection(result: ScanResult) -> None:
        nonlocal detections
        detections += 1
        names = ", ".join(f.name for f in result.findings) or "-"
        moved = "  -> quarantined" if args.quarantine else ""
        print(f"[DETECTION] {result.verdict.value.upper():9} {result.path}  ::  {names}{moved}")

    if args.once:
        # Deliberately do NOT prime(): an un-primed poll scans every file
        # under the roots once (rather than baselining them away), which is
        # exactly what a cron/Task Scheduler "scan now" invocation wants.
        for result in monitor.poll():
            on_detection(result)
        print(f"Single pass complete. Detections: {detections}", file=sys.stderr)
        return 1 if detections else 0

    print("Watching for new/changed files (Ctrl+C to stop):", file=sys.stderr)
    for r in roots:
        print(f"  - {r}", file=sys.stderr)

    stop_event = threading.Event()

    def _stop(_signum, _frame) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, _stop)
    # SIGTERM nie istnieje na każdej platformie i nie da się go ustawić
    # spoza głównego wątku — brak obsługi jest tu dopuszczalny.
    with contextlib.suppress(ValueError, AttributeError, OSError):
        signal.signal(signal.SIGTERM, _stop)

    def on_tick(total_scanned: int, _this_tick: int) -> None:
        sys.stderr.write(f"\r  watching...  scanned: {total_scanned:>7}  detections: {detections}")
        sys.stderr.flush()

    monitor.run(stop_event, on_detection=on_detection, on_tick=on_tick)
    sys.stderr.write("\r" + " " * 60 + "\r")
    print("Monitor stopped.", file=sys.stderr)
    return 0


# ── signatures ────────────────────────────────────────────────────────────────

def run_signatures(args: argparse.Namespace) -> int:
    from . import signature_store as store

    if args.signatures_command == "dir":
        print(store.signatures_dir())
        return 0

    if args.signatures_command == "import":
        try:
            result = store.import_pack(args.file)
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        print(f"Installed pack '{result.name}' -> {result.dest}")
        print(f"  hash signatures:    {result.hashes}")
        print(f"  pattern signatures: {result.patterns}")
        for err in result.errors:
            print(f"  skipped: {err}", file=sys.stderr)
        return 0

    if args.signatures_command == "list":
        directory = store.signatures_dir()
        from .signatures import HASH_SIGNATURES, PATTERN_SIGNATURES
        print(f"Built-in:  {len(HASH_SIGNATURES)} hashes, {len(PATTERN_SIGNATURES)} patterns")
        print(f"User dir:  {directory}")
        if not directory.is_dir():
            print("  (no signature packs installed)")
            return 0
        packs = sorted(directory.glob("*.json"))
        if not packs:
            print("  (no signature packs installed)")
            return 0
        for pack in packs:
            report = store.load_pack(pack)
            print(f"  {pack.name}: {len(report.hashes)} hashes, "
                  f"{len(report.patterns)} patterns"
                  + (f", {len(report.errors)} errors" if report.errors else ""))
        return 0

    print("Missing signatures command (import / list / dir).", file=sys.stderr)
    return 1


# ── schedule ────────────────────────────────────────────────────────────────

def run_schedule(args: argparse.Namespace) -> int:
    from . import schedule as scheduler

    if args.schedule_command == "create":
        try:
            result = scheduler.create(
                mode=args.mode, at=args.at, quarantine=not args.no_quarantine,
            )
        except (ValueError, RuntimeError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        print(f"Scheduled '{result.name}' via {result.backend}: {result.detail}")
        return 0

    if args.schedule_command == "list":
        jobs = scheduler.list_jobs()
        if not jobs:
            print("No Top Antywir scheduled jobs.")
            return 0
        for job in jobs:
            print(job)
        return 0

    if args.schedule_command == "remove":
        try:
            removed = scheduler.remove(mode=args.mode)
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        print(f"Removed scheduled {args.mode} scan." if removed
              else f"No scheduled {args.mode} scan to remove.")
        return 0

    print("Missing schedule command (create / list / remove).", file=sys.stderr)
    return 1


# ── reporting ─────────────────────────────────────────────────────────────────

def print_human_report(
    results: list[ScanResult],
    quarantined: dict[str, str],
    mode: str = "custom",
    duration: float = 0.0,
) -> None:
    counts = {verdict: 0 for verdict in Verdict}
    for result in results:
        counts[result.verdict] += 1

    print(f"Top Antywir {__version__} - scan report ({mode})")
    print("=" * 56)
    print(f"Scanned:    {len(results)}")
    print(f"Clean:      {counts[Verdict.CLEAN]}")
    print(f"Suspicious: {counts[Verdict.SUSPICIOUS]}")
    print(f"Infected:   {counts[Verdict.INFECTED]}")
    print(f"Errors:     {counts[Verdict.ERROR]}")
    if duration:
        print(f"Duration:   {duration:.1f}s")
    print()

    for result in results:
        if result.verdict == Verdict.CLEAN:
            continue

        print(f"{result.verdict.value.upper()}: {result.path}")
        if result.sha256:
            print(f"  sha256: {result.sha256}")
        if result.error:
            print(f"  error: {result.error}")
        for finding in result.findings:
            print(f"  - [{finding.severity}] {finding.name}: {finding.description}")
        item_id = quarantined.get(str(result.path))
        if item_id:
            print(f"  quarantined: {item_id}")
        print()


def report_to_json(
    results: list[ScanResult], quarantined: dict[str, str]
) -> list[dict[str, object]]:
    payload: list[dict[str, object]] = []
    for result in results:
        payload.append({
            "path": str(result.path),
            "verdict": result.verdict.value,
            "sha256": result.sha256,
            "error": result.error,
            "quarantine_id": quarantined.get(str(result.path)),
            "findings": [
                {
                    "name": finding.name,
                    "severity": finding.severity,
                    "description": finding.description,
                }
                for finding in result.findings
            ],
        })
    return payload


if __name__ == "__main__":
    raise SystemExit(main())
