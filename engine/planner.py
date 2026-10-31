from __future__ import annotations

from copy import deepcopy

from engine.models import ScanTask, UnifiedFinding


def _severity_score(severity: str | None) -> float:
    lookup = {
        "critical": 1.0,
        "high": 0.75,
        "medium": 0.5,
        "low": 0.25,
        "info": 0.1,
        "error": 1.0,
        "warning": 0.75,
    }
    return lookup.get((severity or "").lower(), 0.25)


def _mapping_quality(status: str | None) -> float:
    if status == "mapped":
        return 1.0
    if status == "ambiguous":
        return 0.4
    return 0.0


def plan_scan_tasks(
    routes: list,
    findings: list[UnifiedFinding],
    target_id: str,
    profile: dict | None = None,
    graph_scores: dict[str, float] | None = None,
) -> list[ScanTask]:
    """Create focused and broad ZAP tasks ordered by the configured priority weights."""
    weights = (profile or {}).get("weights", {}) if isinstance(profile, dict) else {}
    weights = {
        "map": float(weights.get("map", 0.4)),
        "severity": float(weights.get("severity", 0.3)),
        "graphcodebert": float(weights.get("graphcodebert", 0.2)),
        "has_input": float(weights.get("has_input", 0.1)),
    }
    graph_scores = graph_scores or {}
    tasks: list[ScanTask] = []
    seen: set[tuple[str, str, str, str]] = set()

    for finding in findings:
        route_name = finding.route or ""
        mapped_route = next((route for route in routes if getattr(route, "path", None) == route_name), None)
        candidates = [route_name] if route_name else []
        if not mapped_route and finding.candidate_routes:
            candidates = finding.candidate_routes
        if not candidates and route_name:
            candidates = [route_name]

        method_name = finding.method or (getattr(mapped_route, "methods", ["GET"])[0] if mapped_route else "GET")
        inputs = [finding.parameter or "request"]
        if mapped_route:
            inputs = [item.name for item in getattr(mapped_route, "inputs", []) or []]
            if not inputs:
                inputs = [finding.parameter or "request"]

        mapping_q = _mapping_quality(finding.mapping_status)
        severity_score = _severity_score(finding.severity)
        graph_score = float(graph_scores.get(finding.finding_id, 0.0))
        for input_name in inputs:
            for route in candidates or [route_name]:
                task_key = (str(route), method_name, str(input_name), str(finding.tool_rule_id))
                if task_key in seen:
                    continue
                seen.add(task_key)
                priority = (
                    weights["map"] * mapping_q
                    + weights["severity"] * severity_score
                    + weights["graphcodebert"] * graph_score
                    + weights["has_input"] * (1 if input_name and input_name != "request" else 0)
                )
                reason = (
                    "mapping_quality={:.2f}; severity_score={:.2f}; graphcodebert={:.2f}; "
                    "has_input={}; weighted_priority={:.3f}"
                ).format(mapping_q, severity_score, graph_score, 1 if input_name and input_name != "request" else 0, priority)
                tasks.append(
                    ScanTask(
                        task_id=f"{target_id}:{len(tasks)}:{route}:{method_name}:{input_name}",
                        target_id=target_id,
                        route=str(route),
                        method=method_name,
                        input=str(input_name),
                        zap_rule_ids=[finding.tool_rule_id],
                        queue="focused" if route else "broad",
                        priority=priority,
                        reason=reason,
                        status="queued",
                    )
                )

    # Broad queue: every other discovered route without a focused task.
    for route in routes:
        route_path = getattr(route, "path", "")
        route_methods = getattr(route, "methods", ["GET"]) or ["GET"]
        inputs = [item.name for item in getattr(route, "inputs", []) or []]
        if not inputs:
            inputs = ["request"]
        for method_name in route_methods:
            for input_name in inputs:
                task_key = (route_path, method_name, input_name, "broad")
                if any(task.route == route_path and task.method == method_name and task.input == input_name for task in tasks):
                    continue
                tasks.append(
                    ScanTask(
                        task_id=f"{target_id}:broad:{route_path}:{method_name}:{input_name}",
                        target_id=target_id,
                        route=route_path,
                        method=method_name,
                        input=input_name,
                        zap_rule_ids=[],
                        queue="broad",
                        priority=0.0,
                        reason="broad-route-fallback: no semgrep mapping; route discovered from AST only",
                        status="queued",
                    )
                )

    return sorted(tasks, key=lambda task: (-task.priority, task.route, task.method, task.input))
