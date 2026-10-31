from __future__ import annotations

from pathlib import Path

from engine.models import UnifiedFinding


def _resolve_file(file_path: str) -> str:
    return str(Path(file_path).resolve())


def match_findings_to_routes(
    routes: list, findings: list[UnifiedFinding]
) -> list[UnifiedFinding]:
    """Map findings only when their source line belongs to a route or its helper."""
    for finding in findings:
        if finding.source_tool != "semgrep":
            continue

        finding_file = _resolve_file(finding.file)
        in_handler = [
            route
            for route in routes
            if route.target_id == finding.target_id
            and _resolve_file(route.file) == finding_file
            and route.start_line <= finding.line <= route.end_line
        ]
        if in_handler:
            candidates = in_handler
        else:
            candidates = [
                route
                for route in routes
                if route.target_id == finding.target_id
                and any(
                    _resolve_file(scope.file) == finding_file
                    and scope.start_line <= finding.line <= scope.end_line
                    for scope in route.helper_scopes
                )
            ]

        if len(candidates) == 1:
            matched = candidates[0]
            finding.mapping_status = "mapped"
            finding.route = matched.path
            finding.method = matched.methods[0] if len(matched.methods) == 1 else None
            finding.candidate_routes = [matched.path]
        elif candidates:
            finding.mapping_status = "ambiguous"
            finding.candidate_routes = sorted({route.path for route in candidates})
        else:
            finding.mapping_status = "unmapped"
            finding.candidate_routes = []
    return findings
