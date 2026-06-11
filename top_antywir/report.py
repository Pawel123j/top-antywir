"""Stand-alone HTML scan reports.

Renders a self-contained, dark-themed HTML file (all CSS inlined, no
external assets) summarising a scan. Useful for archiving results,
attaching to a ticket, or emailing — anything the JSON report is too raw
for. Pure string building on top of the stdlib; safe against HTML
injection via :func:`html.escape`.
"""
from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path

from . import __version__
from .scanner import ScanResult, Verdict


_VERDICT_LABEL = {
    Verdict.CLEAN: "Clean",
    Verdict.SUSPICIOUS: "Suspicious",
    Verdict.INFECTED: "Infected",
    Verdict.ERROR: "Error",
}

_VERDICT_COLOR = {
    Verdict.CLEAN: "#3fb950",
    Verdict.SUSPICIOUS: "#d29922",
    Verdict.INFECTED: "#f85149",
    Verdict.ERROR: "#8b949e",
}

_SEVERITY_COLOR = {
    "low": "#8b949e",
    "medium": "#d29922",
    "high": "#f85149",
}


def render_html_report(
    results: list[ScanResult],
    *,
    mode: str = "custom",
    duration: float = 0.0,
    quarantined: dict[str, str] | None = None,
    generated_at: str | None = None,
    counts: dict[Verdict, int] | None = None,
    scanned: int | None = None,
) -> str:
    """Build the full HTML document as a string.

    ``counts`` / ``scanned`` let a caller that only retained the
    *detections* (e.g. the GUI, which drops clean files) still render
    accurate summary cards and a correct total. When omitted they are
    derived from ``results``.
    """
    quarantined = quarantined or {}
    generated_at = generated_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if counts is None:
        counts = {verdict: 0 for verdict in Verdict}
        for result in results:
            counts[result.verdict] += 1
    else:
        counts = {verdict: counts.get(verdict, 0) for verdict in Verdict}
    total_scanned = scanned if scanned is not None else len(results)

    cards = "".join(
        _stat_card(_VERDICT_LABEL[v], counts[v], _VERDICT_COLOR[v])
        for v in (Verdict.CLEAN, Verdict.SUSPICIOUS, Verdict.INFECTED, Verdict.ERROR)
    )

    detail_rows = "".join(
        _detail_row(r, quarantined.get(str(r.path)))
        for r in results
        if r.verdict != Verdict.CLEAN
    )
    if not detail_rows:
        detail_rows = (
            '<tr><td colspan="3" class="empty">No suspicious, infected '
            "or errored files — everything scanned came back clean.</td></tr>"
        )

    return _DOCUMENT.format(
        version=escape(__version__),
        mode=escape(mode),
        generated_at=escape(generated_at),
        scanned=total_scanned,
        duration=f"{duration:.1f}",
        cards=cards,
        detail_rows=detail_rows,
    )


def write_html_report(
    path: Path,
    results: list[ScanResult],
    *,
    mode: str = "custom",
    duration: float = 0.0,
    quarantined: dict[str, str] | None = None,
    counts: dict[Verdict, int] | None = None,
    scanned: int | None = None,
) -> Path:
    """Render and write the report to ``path``. Returns the path written."""
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    html = render_html_report(
        results, mode=mode, duration=duration, quarantined=quarantined,
        counts=counts, scanned=scanned,
    )
    path.write_text(html, encoding="utf-8")
    return path


# ── Fragments ─────────────────────────────────────────────────────────────────

def _stat_card(label: str, count: int, color: str) -> str:
    return (
        '<div class="card">'
        f'<div class="bar" style="background:{color}"></div>'
        f'<div class="num" style="color:{color}">{count}</div>'
        f'<div class="lbl">{escape(label)}</div>'
        "</div>"
    )


def _detail_row(result: ScanResult, quarantine_id: str | None) -> str:
    color = _VERDICT_COLOR[result.verdict]
    verdict = (
        f'<span class="pill" style="color:{color};border-color:{color}">'
        f"{escape(_VERDICT_LABEL[result.verdict])}</span>"
    )

    findings_parts: list[str] = []
    for f in result.findings:
        sev_color = _SEVERITY_COLOR.get(f.severity, "#8b949e")
        findings_parts.append(
            f'<div class="finding"><span class="sev" style="color:{sev_color}">'
            f"[{escape(f.severity)}]</span> <b>{escape(f.name)}</b>"
            f"<div class='desc'>{escape(f.description)}</div></div>"
        )
    if result.error:
        findings_parts.append(f'<div class="finding err">{escape(result.error)}</div>')
    if result.sha256:
        findings_parts.append(f'<div class="hash">sha256: {escape(result.sha256)}</div>')
    if quarantine_id:
        findings_parts.append(
            f'<div class="quar">→ quarantined: {escape(quarantine_id)}</div>'
        )
    findings = "".join(findings_parts) or "—"

    return (
        "<tr>"
        f"<td>{verdict}</td>"
        f'<td class="path">{escape(str(result.path))}</td>'
        f"<td>{findings}</td>"
        "</tr>"
    )


_DOCUMENT = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Top Antywir — scan report</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 0 0 48px;
    background: #0d1117; color: #e6edf3;
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }}
  header {{
    background: #161b22; border-bottom: 1px solid #30363d;
    padding: 22px 32px;
  }}
  header h1 {{ margin: 0; font-size: 22px; }}
  header h1 .shield {{ color: #58a6ff; }}
  header .ver {{ color: #8b949e; font-size: 13px; font-weight: normal; }}
  header .meta {{ color: #8b949e; font-size: 13px; margin-top: 6px; }}
  .wrap {{ max-width: 1080px; margin: 0 auto; padding: 0 32px; }}
  .cards {{ display: flex; gap: 14px; margin: 26px 0; flex-wrap: wrap; }}
  .card {{
    flex: 1 1 0; min-width: 150px; background: #161b22;
    border: 1px solid #30363d; border-radius: 10px;
    padding: 16px; text-align: center;
  }}
  .card .bar {{ height: 4px; border-radius: 3px; margin-bottom: 10px; }}
  .card .num {{ font-size: 34px; font-weight: 700; line-height: 1; }}
  .card .lbl {{ color: #8b949e; font-size: 13px; margin-top: 6px; }}
  h2 {{ font-size: 16px; color: #c9d1d9; margin: 28px 0 12px; }}
  table {{
    width: 100%; border-collapse: collapse; background: #161b22;
    border: 1px solid #30363d; border-radius: 10px; overflow: hidden;
  }}
  th, td {{
    text-align: left; padding: 12px 14px;
    border-bottom: 1px solid #21262d; vertical-align: top;
  }}
  th {{ background: #21262d; color: #8b949e; font-size: 12px;
        text-transform: uppercase; letter-spacing: .04em; }}
  tr:last-child td {{ border-bottom: none; }}
  td.path {{ font-family: Consolas, "SF Mono", Menlo, monospace;
             font-size: 13px; word-break: break-all; }}
  .pill {{ display: inline-block; padding: 2px 10px; border-radius: 999px;
           border: 1px solid; font-size: 12px; font-weight: 600; }}
  .finding {{ margin-bottom: 8px; font-size: 13px; }}
  .finding .sev {{ font-weight: 700; }}
  .finding .desc {{ color: #8b949e; font-size: 12px; }}
  .finding.err {{ color: #f85149; }}
  .hash {{ color: #6e7681; font-size: 11px;
           font-family: Consolas, monospace; word-break: break-all; }}
  .quar {{ color: #58a6ff; font-size: 12px; margin-top: 4px; }}
  td.empty {{ color: #8b949e; text-align: center; padding: 28px; }}
  footer {{ color: #6e7681; font-size: 12px; text-align: center; margin-top: 36px; }}
</style>
</head>
<body>
<header>
  <h1><span class="shield">🛡</span> Top Antywir
      <span class="ver">v{version}</span></h1>
  <div class="meta">Scan mode: <b>{mode}</b> &middot; Files scanned:
      <b>{scanned}</b> &middot; Duration: <b>{duration}s</b>
      &middot; Generated: {generated_at}</div>
</header>
<div class="wrap">
  <div class="cards">{cards}</div>
  <h2>Detections &amp; errors</h2>
  <table>
    <thead><tr><th>Status</th><th>File</th><th>Findings</th></tr></thead>
    <tbody>{detail_rows}</tbody>
  </table>
  <footer>Generated by Top Antywir v{version} — prototype on-demand scanner.</footer>
</div>
</body>
</html>
"""
