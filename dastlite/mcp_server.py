"""DASTLITE MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from dastlite.core import scan_targets, to_json


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
        """Scan a single URL with passive DAST checks and return JSON findings."""
        if not target or not target.strip():
            return json.dumps({"error": "target URL must not be empty"})
        result = scan_targets([target.strip()])
        return json.dumps(to_json(result))

    app.run()
    return 0
