from __future__ import annotations

import html
from pathlib import Path

from engine.models import CorrelationResult, UnifiedFinding


def _label_for_sast(sast: UnifiedFinding, correlations: list[CorrelationResult]) -> str:
    if any(item.sast_finding_id == sast.finding_id and item.label == "Confirmed" for item in correlations):
        return "Confirmed"
    if sast.mapping_status == "mapped":
        return "Code only"
    return "Code only"


def build_scan_report(
    *,
    target: dict,
    profile: dict,
    routes: list[dict],
    semgrep: dict,
    findings: list[dict],
    tasks: list[dict] | None = None,
    zap: dict | None = None,
    correlation: list[CorrelationResult] | None = None,
) -> dict:
    tasks = tasks or []
    zap = zap or {"status": "skipped", "error": "Not run"}
    correlations = correlation or []
    sast_findings = [UnifiedFinding(**item) for item in findings if item.get("source_tool") == "semgrep"]
    dast_findings = []

    summary = {
        "target_id": target.get("target_id"),
        "route_count": len(routes),
        "sast_finding_count": len(sast_findings),
        "dast_finding_count": len(dast_findings),
        "confirmed_count": sum(1 for item in correlations if item.label == "Confirmed"),
        "code_only_count": sum(1 for item in correlations if item.label == "Code only"),
        "runtime_only_count": sum(1 for item in correlations if item.label == "Runtime only"),
    }

    finding_rows = []
    for finding in findings:
        mapped_label = _label_for_sast(UnifiedFinding(**finding), correlations) if finding.get("source_tool") == "semgrep" else "Runtime only"
        finding_rows.append(
            {
                "finding_id": finding.get("finding_id"),
                "source_tool": finding.get("source_tool"),
                "route": finding.get("route"),
                "method": finding.get("method"),
                "status": mapped_label,
                "severity": finding.get("severity"),
                "cwe": finding.get("cwe"),
                "mapping_status": finding.get("mapping_status"),
            }
        )

    untested_tasks = [task for task in tasks if task.get("status") != "completed"]
    failed_tasks = [task for task in tasks if task.get("status") == "failed"]

    payload = {
        "target": target,
        "profile": profile,
        "summary": summary,
        "routes": routes,
        "semgrep": semgrep,
        "zap": zap,
        "findings": finding_rows,
        "correlation": [item.model_dump() for item in correlations],
        "untested_tasks": untested_tasks,
        "failed_tasks": failed_tasks,
        "model_status": {
            "graphcodebert": "not_run",
            "status": "not_implemented",
        },
    }
    return payload


def write_scan_report(payload: dict, report_dir: str | Path) -> dict:
    report_path = Path(report_dir)
    report_path.mkdir(parents=True, exist_ok=True)
    json_path = report_path / "report.json"
    html_path = report_path / "report.html"
    json_path.write_text(__import__("json").dumps(payload, indent=2), encoding="utf-8")
    html_path.write_text(_render_html(payload), encoding="utf-8")
    return {"json_path": str(json_path), "html_path": str(html_path)}


def _render_html(payload: dict) -> str:
    rows = []
    for item in payload.get("findings", []):
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                html.escape(str(item.get("finding_id", ""))),
                html.escape(str(item.get("source_tool", ""))),
                html.escape(str(item.get("route", ""))),
                html.escape(str(item.get("method", ""))),
                html.escape(str(item.get("status", ""))),
                html.escape(str(item.get("severity", ""))),
            )
        )
    html_text = """
    <html><head><meta charset="utf-8"><title>SAST/DAST Correlation Report</title></head>
    <body>
      <h1>SAST/DAST Correlation Report</h1>
      <p>Target: {target}</p>
      <p>Summary: {summary}</p>
      <table border="1">
        <thead><tr><th>ID</th><th>Source</th><th>Route</th><th>Method</th><th>Status</th><th>Severity</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </body></html>
    """.format(
        target=html.escape(str(payload.get("target", {}).get("target_id", ""))),
        summary=html.escape(str(payload.get("summary", {}))),
        rows="".join(rows),
    )
    return html_text
