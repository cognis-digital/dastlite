"""dastlite — part of the Cognis Neural Suite."""
try:  # re-export the tool's public API + identity from core
    from dastlite.core import *  # noqa: F401,F403
    from dastlite.core import (  # noqa: F401
        TOOL_NAME, TOOL_VERSION, Finding, Target, ScanResult,
        scan_response, scan_targets, run_passive_checks, severity_rank,
        to_sarif, to_json, fetch, scan_input, scan_input_file,
        target_from_record, PASSIVE_CHECKS,
    )
except Exception:  # pragma: no cover
    pass
try:
    from dastlite.core import TOOL_NAME, TOOL_VERSION
except Exception:  # pragma: no cover
    TOOL_NAME = "dastlite"
    TOOL_VERSION = "0.1.0"
__version__ = TOOL_VERSION
