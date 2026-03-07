"""DASTLITE MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from dastlite.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-dastlite[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-dastlite[mcp]'")
        return 1
    app = FastMCP("dastlite")

    @app.tool()
    def dastlite_scan(target: str) -> str:
        """A headless, config-as-code DAST runner that crawls an authenticated web/mobile-API surface and fires a curated active-scan ruleset, emitting deduplicated SARIF.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
