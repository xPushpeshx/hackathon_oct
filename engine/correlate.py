from __future__ import annotations

from pathlib import Path

import yaml

from engine.models import CorrelationResult, UnifiedFinding


def _load_cwe_families() -> dict[str, list[int]]:
    config_path = Path(__file__).resolve().parents[1] / "config" / "cwe_map.yaml"
    if not config_path.exists():
        return {}
    with config_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    families = raw.get("families", {})
    parsed: dict[str, list[int]] = {}
    for family, values in families.items():
        parsed[family] = [int(value) for value in values]
    return parsed


def _cwe_same_family(cwe_a: int | None, cwe_b: int | None) -> bool:
    if cwe_a is None or cwe_b is None:
        return cwe_a == cwe_b
    if cwe_a == cwe_b:
        return True
    families = _load_cwe_families()
    for family_values in families.values():
        if cwe_a in family_values and cwe_b in family_values:
            return True
    return False


def _route_matches(sast_finding: UnifiedFinding, route_path: str | None) -> bool:
    if not route_path:
        return False
    return (sast_finding.route or "") == route_path


def _parameter_matches(sast_finding: UnifiedFinding, dast_finding: UnifiedFinding) -> bool:
    if not sast_finding.parameter and not dast_finding.parameter:
        return True
    left = (sast_finding.parameter or "").strip()
    right = (dast_finding.parameter or "").strip()
    return left == right or not left or not right


def _narrow_scope_score(sast_finding: UnifiedFinding) -> tuple[int, int]:
    # Prefer the most specific mapping: exact route match > helper-scope match; fewer candidates is better.
    if getattr(sast_finding, "mapping_status", "n/a") == "mapped":
        return (1, 0)
    if getattr(sast_finding, "mapping_status", "n/a") == "ambiguous":
        return (0, len(getattr(sast_finding, "candidate_routes", []) or []))
    return (0, 999)


def correlate_findings(
    sast_findings: list[UnifiedFinding],
    dast_findings: list[UnifiedFinding],
) -> list[CorrelationResult]:
    """Correlate SAST and DAST findings using the strict rules in plan.md §7.8."""
    results: list[CorrelationResult] = []
    used_dast: set[str] = set()

    for dast in dast_findings:
        if dast.target_id is None:
            continue

    for sast in sast_findings:
        if sast.mapping_status != "mapped":
            continue

        best_match: UnifiedFinding | None = None
        best_criteria: dict | None = None
        best_score: tuple[int, int] | None = None

        for dast in dast_findings:
            if dast.target_id != sast.target_id:
                continue
            if dast.finding_id in used_dast:
                continue
            criteria = {
                "target_id": sast.target_id == dast.target_id,
                "cwe_family": _cwe_same_family(sast.cwe, dast.cwe),
                "route": _route_matches(sast, dast.route),
                "scope": True,
                "parameter": _parameter_matches(sast, dast),
                "method": True,
            }

            if sast.route and dast.route and sast.route != dast.route:
                criteria["route"] = False
            if sast.route and dast.route and sast.route == dast.route:
                criteria["scope"] = True
            if sast.method and dast.method and sast.method.lower() != dast.method.lower():
                criteria["method"] = False

            if not all(criteria.values()):
                continue

            score = _narrow_scope_score(sast)
            if best_match is None or score > best_score:
                best_match = dast
                best_criteria = criteria
                best_score = score

        if best_match is not None and best_criteria is not None:
            used_dast.add(best_match.finding_id)
            results.append(
                CorrelationResult(
                    sast_finding_id=sast.finding_id,
                    dast_finding_id=best_match.finding_id,
                    criteria=best_criteria,
                    label="Confirmed",
                    rationale="SAST and DAST findings match on target, CWE family, route, parameter, and method constraints.",
                )
            )

    for sast in sast_findings:
        if sast.mapping_status != "mapped" and sast.mapping_status != "ambiguous":
            continue
        if any(result.sast_finding_id == sast.finding_id for result in results):
            continue
        if sast.mapping_status == "mapped":
            results.append(
                CorrelationResult(
                    sast_finding_id=sast.finding_id,
                    dast_finding_id="",
                    criteria={"status": "code_only"},
                    label="Code only",
                    rationale="SAST finding has no matching DAST alert within the same target and route constraints.",
                )
            )

    for dast in dast_findings:
        if dast.finding_id in used_dast:
            continue
        results.append(
            CorrelationResult(
                sast_finding_id="",
                dast_finding_id=dast.finding_id,
                criteria={"status": "runtime_only"},
                label="Runtime only",
                rationale="DAST alert has no matching SAST finding after the strict correlation checks.",
            )
        )

    return results
