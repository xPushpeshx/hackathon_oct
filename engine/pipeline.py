from __future__ import annotations

import os
from pathlib import Path

from engine.ast_express import discover_express_routes
from engine.ast_flask import discover_flask_routes
from engine.correlate import correlate_findings
from engine.gcb import score_code_context
from engine.report import build_scan_report, write_scan_report
from engine.route_matcher import match_findings_to_routes
from engine.semgrep_runner import run_semgrep
from engine.targets import ensure_target_ready, load_scan_profile, load_target_profile
from engine.zap_runner import run_zap_scan

ENGINE_ROOT = Path(__file__).resolve().parents[1]


def run_scan(
    target_name: str,
    profile_path: str | Path = "config/scan_profile.yaml",
    *,
    use_gcb: bool = True,
    mode: str = "default",
) -> dict:
    """Run the implemented target checks, the optional model stage, and the planner."""
    target = load_target_profile(target_name)
    ensure_target_ready(target)
    profile = load_scan_profile(profile_path)
    profile["mode"] = mode

    if target.app_type == "flask":
        routes = discover_flask_routes(Path(target.source_path), target.target_id)
    elif target.app_type == "express":
        routes = discover_express_routes(Path(target.source_path), target.target_id)
    else:
        raise NotImplementedError(f"Unsupported target app type: {target.app_type}")
    semgrep = run_semgrep(
        target.source_path,
        target.target_id,
        ENGINE_ROOT / "config" / "semgrep",
        semgrep_version=str(profile.get("versions", {}).get("semgrep", "")) or None,
    )
    findings = match_findings_to_routes(routes, semgrep.findings)

    graph_scores: dict[str, float] = {}
    graph_status: dict[str, str] = {}
    for finding in findings:
        if finding.mapping_status not in {"mapped", "ambiguous"}:
            continue
        route = next((item for item in routes if getattr(item, "path", None) == finding.route), None)
        snippet = ""
        if Path(finding.file).exists():
            text = Path(finding.file).read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            start = max(0, finding.line - 15)
            end = min(len(lines), finding.line + 15)
            snippet = "\n".join(lines[start:end])
        score_result = score_code_context(
            finding_id=finding.finding_id,
            route_id=getattr(route, "route_id", finding.route or "unknown"),
            code=snippet,
            route_path=finding.route,
            vulnerability_family=None,
            file_path=finding.file,
            line=finding.line,
            use_model=use_gcb,
        )
        graph_scores[finding.finding_id] = score_result.score
        graph_status[finding.finding_id] = score_result.status

    zap = run_zap_scan(
        target.target_id,
        routes,
        findings,
        profile,
        graph_scores,
        target_url=os.environ.get("ZAP_TARGET_URL", target.runtime_url),
        base_url=os.environ.get("ZAP_BASE_URL", "http://127.0.0.1:8080"),
        api_key=os.environ.get("ZAP_API_KEY"),
        mode="baseline" if mode == "baseline" else "planner",
    )
    tasks = zap["tasks"]
    correlation = correlate_findings(findings, [])
    report = build_scan_report(
        target=target.model_dump(),
        profile=profile,
        routes=[route.model_dump() for route in routes],
        semgrep={"status": semgrep.status, "error": semgrep.error},
        findings=[finding.model_dump() for finding in findings],
        tasks=tasks,
        zap=zap,
        correlation=correlation,
    )
    report["model_status"] = {
        "graphcodebert": "enabled" if use_gcb else "disabled",
        "status": "ok" if use_gcb else "skipped",
        "scores": {key: value for key, value in graph_scores.items()},
        "findings": graph_status,
    }
    write_scan_report(report, Path("reports") / target.target_id)

    return {
        "target": target.model_dump(),
        "profile": profile,
        "routes": [route.model_dump() for route in routes],
        "semgrep": {
            "status": semgrep.status,
            "error": semgrep.error,
        },
        "findings": [finding.model_dump() for finding in findings],
        "tasks": tasks,
        "zap": zap,
        "correlation": [item.model_dump() for item in correlation],
        "report": report,
        "graphcodebert": {
            "enabled": use_gcb,
            "scores": graph_scores,
            "status": graph_status,
        },
    }
