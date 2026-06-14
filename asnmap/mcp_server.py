"""ASNMAP MCP server — exposes analyze() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json
import sys

from asnmap.core import analyze, parse_export


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-asnmap[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-asnmap[mcp]'", file=sys.stderr)
        return 1
    app = FastMCP("asnmap")

    @app.tool()
    def asnmap_scan(export_text: str) -> str:
        """Map ASN/CIDR ownership & neighbors from a pipe-delimited RIR/whois export.

        Args:
            export_text: Raw pipe-delimited export text (one record per line).

        Returns:
            JSON string with records, asn_map, findings, and summary.
        """
        if not export_text or not export_text.strip():
            return json.dumps({"error": "export_text is empty", "summary": {}})
        records, errors = parse_export(export_text)
        report = analyze(records, errors)
        return json.dumps(report.to_dict())

    app.run()
    return 0
