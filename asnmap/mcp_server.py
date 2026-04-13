"""ASNMAP MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from asnmap.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-asnmap[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-asnmap[mcp]'")
        return 1
    app = FastMCP("asnmap")

    @app.tool()
    def asnmap_scan(target: str) -> str:
        """Map ASN/CIDR ownership & neighbors from whois/RIR exports. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
