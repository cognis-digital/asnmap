"""Command-line interface for asnmap.

Subcommands:
    analyze <file>   Parse an RIR/whois export and run triage analysis.
    map <file>       Print the ASN -> CIDR ownership map only.

Global:
    --version
    --format {table,json,html}   Output format (html writes a shareable report).
    -o / --output FILE           Write output to FILE (default stdout).

Exit codes:
    0  success, no medium+ findings
    1  runtime / IO error
    2  medium-or-higher severity findings present (pipeline gate)
"""
from __future__ import annotations

import argparse
import html as _html
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import SEVERITY_ORDER, Report, analyze, parse_export

SEVERITY_COLORS = {
    "info": "#6b7280",
    "low": "#2563eb",
    "medium": "#d97706",
    "high": "#dc2626",
    "critical": "#7c1d6f",
}


def _render_table(report: Report) -> str:
    out: List[str] = []
    s = report.to_dict()["summary"]
    out.append(f"{TOOL_NAME} {TOOL_VERSION} - netblock triage")
    out.append(
        "summary: %d records | %d ASNs | %d neighbor pairs | %d findings | max=%s"
        % (s["records"], s["asns"], s["neighbor_pairs"], s["findings"], s["max_severity"])
    )
    out.append("")
    out.append("ASN OWNERSHIP MAP")
    for asn in sorted(report.asn_map):
        cidrs = report.asn_map[asn]
        out.append(f"  {asn}: {len(cidrs)} block(s)")
        for c in cidrs:
            out.append(f"      {c}")
    if report.neighbors:
        out.append("")
        out.append("ADJACENT NETBLOCKS")
        for a, b in report.neighbors:
            out.append(f"  {a}  <->  {b}")
    out.append("")
    out.append("FINDINGS")
    if not report.findings:
        out.append("  (none)")
    for f in report.findings:
        loc = f.cidr or "-"
        out.append(f"  [{f.severity.upper():8}] {f.kind:20} {loc:20} {f.message}")
    return "\n".join(out) + "\n"


def _render_map(report: Report) -> str:
    out: List[str] = []
    for asn in sorted(report.asn_map):
        for c in report.asn_map[asn]:
            out.append(f"{asn}\t{c}")
    return "\n".join(out) + "\n"


def _render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2) + "\n"


def _render_html(report: Report) -> str:
    d = report.to_dict()
    s = d["summary"]
    esc = _html.escape

    rows = []
    for f in report.findings:
        color = SEVERITY_COLORS.get(f.severity, "#6b7280")
        rows.append(
            "<tr>"
            f'<td><span class="sev" style="background:{color}">{esc(f.severity.upper())}</span></td>'
            f"<td>{esc(f.kind)}</td>"
            f"<td class=mono>{esc(f.cidr or '-')}</td>"
            f"<td class=mono>{esc(f.asn or '-')}</td>"
            f"<td>{esc(f.message)}</td>"
            "</tr>"
        )
    findings_rows = "\n".join(rows) or '<tr><td colspan=5>No findings.</td></tr>'

    asn_rows = []
    for asn in sorted(report.asn_map):
        cidrs = report.asn_map[asn]
        asn_rows.append(
            f"<tr><td class=mono>{esc(asn)}</td><td>{len(cidrs)}</td>"
            f"<td class=mono>{esc(', '.join(cidrs))}</td></tr>"
        )
    asn_table = "\n".join(asn_rows) or "<tr><td colspan=3>No ASNs.</td></tr>"

    nbr_rows = []
    for a, b in report.neighbors:
        nbr_rows.append(f"<tr><td class=mono>{esc(a)}</td><td class=mono>{esc(b)}</td></tr>")
    nbr_table = "\n".join(nbr_rows) or "<tr><td colspan=2>No adjacent blocks.</td></tr>"

    max_color = SEVERITY_COLORS.get(s["max_severity"], "#6b7280")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(TOOL_NAME)} report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background:#0f172a; color:#e2e8f0; }}
  header {{ padding: 24px 32px; background:#1e293b; border-bottom:3px solid {max_color}; }}
  h1 {{ margin:0; font-size:20px; }}
  .meta {{ color:#94a3b8; font-size:13px; margin-top:4px; }}
  main {{ padding: 24px 32px; max-width: 1100px; }}
  h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:.05em; color:#94a3b8; margin-top:32px; }}
  table {{ border-collapse: collapse; width:100%; background:#1e293b; border-radius:8px; overflow:hidden; font-size:13px; }}
  th, td {{ text-align:left; padding:8px 12px; border-bottom:1px solid #334155; vertical-align:top; }}
  th {{ background:#0f172a; color:#94a3b8; font-weight:600; }}
  tr:last-child td {{ border-bottom:none; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
  .sev {{ display:inline-block; padding:2px 8px; border-radius:4px; color:#fff; font-size:11px; font-weight:700; }}
  .cards {{ display:flex; gap:16px; flex-wrap:wrap; margin-top:16px; }}
  .card {{ background:#1e293b; padding:16px 20px; border-radius:8px; min-width:120px; }}
  .card .n {{ font-size:26px; font-weight:700; }}
  .card .l {{ color:#94a3b8; font-size:12px; text-transform:uppercase; }}
</style></head><body>
<header>
  <h1>{esc(TOOL_NAME)} <span style="color:#64748b">v{esc(TOOL_VERSION)}</span> &mdash; netblock ownership &amp; triage</h1>
  <div class="meta">ASN/CIDR map from RIR/whois export</div>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="n">{s['records']}</div><div class="l">records</div></div>
    <div class="card"><div class="n">{s['asns']}</div><div class="l">ASNs</div></div>
    <div class="card"><div class="n">{s['neighbor_pairs']}</div><div class="l">adjacencies</div></div>
    <div class="card"><div class="n">{s['findings']}</div><div class="l">findings</div></div>
    <div class="card" style="border-left:4px solid {max_color}"><div class="n" style="color:{max_color}">{esc(s['max_severity'].upper())}</div><div class="l">max severity</div></div>
  </div>

  <h2>Findings</h2>
  <table><thead><tr><th>Severity</th><th>Kind</th><th>CIDR</th><th>ASN</th><th>Detail</th></tr></thead>
  <tbody>
{findings_rows}
  </tbody></table>

  <h2>ASN Ownership Map</h2>
  <table><thead><tr><th>ASN</th><th>Blocks</th><th>CIDRs</th></tr></thead>
  <tbody>
{asn_table}
  </tbody></table>

  <h2>Adjacent Netblocks</h2>
  <table><thead><tr><th>Block A</th><th>Block B</th></tr></thead>
  <tbody>
{nbr_table}
  </tbody></table>
</main>
</body></html>
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Map ASN/CIDR ownership & neighbors from whois/RIR exports (defensive triage).",
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument(
        "--format",
        choices=["table", "json", "html"],
        default="table",
        help="output format (html writes a shareable report)",
    )
    p.add_argument("-o", "--output", help="write output to FILE instead of stdout")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="parse export and run triage analysis")
    a.add_argument("file", help="path to RIR/whois export ('-' for stdin)")

    m = sub.add_parser("map", help="print ASN -> CIDR ownership map only")
    m.add_argument("file", help="path to RIR/whois export ('-' for stdin)")

    return p


def _read_input(path: str) -> str:
    if path == "-":
        try:
            return sys.stdin.read()
        except UnicodeDecodeError as exc:
            raise OSError(f"stdin contains non-UTF-8 bytes: {exc}") from exc
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except UnicodeDecodeError as exc:
        raise OSError(f"{path!r} contains non-UTF-8 bytes: {exc}") from exc


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        text = _read_input(args.file)
    except OSError as exc:
        print(f"{TOOL_NAME}: cannot read {args.file}: {exc}", file=sys.stderr)
        return 1

    try:
        records, errors = parse_export(text)
        report = analyze(records, errors)
    except Exception as exc:  # pragma: no cover
        print(f"{TOOL_NAME}: analysis failed: {exc}", file=sys.stderr)
        return 1

    if args.command == "map" and args.format == "table":
        rendered = _render_map(report)
    elif args.format == "json":
        rendered = _render_json(report)
    elif args.format == "html":
        rendered = _render_html(report)
    else:
        rendered = _render_table(report)

    try:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(rendered)
            print(f"{TOOL_NAME}: wrote {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(rendered)
    except OSError as exc:
        print(f"{TOOL_NAME}: cannot write output: {exc}", file=sys.stderr)
        return 1

    # Pipeline gate: non-zero exit when medium-or-higher findings exist.
    if SEVERITY_ORDER.get(report.max_severity, 0) >= SEVERITY_ORDER["medium"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
