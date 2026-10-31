import json
from pathlib import Path
from types import SimpleNamespace

from engine.ast_flask import discover_flask_routes
from engine.models import HelperScope, RouteNode, UnifiedFinding
from engine.route_matcher import match_findings_to_routes
from engine.semgrep_runner import run_semgrep


ROOT = Path(__file__).resolve().parents[1]
TARGET_SOURCE = ROOT / "targets" / "flask-demo" / "app"


def _finding(file_path: Path, line: int, finding_id: str) -> UnifiedFinding:
    return UnifiedFinding(
        finding_id=finding_id,
        target_id="flask-demo",
        source_tool="semgrep",
        tool_rule_id="test-rule",
        cwe=78,
        severity="error",
        file=str(file_path),
        line=line,
        evidence="test evidence",
        raw_ref=f"{file_path}:{line}",
    )


def test_flask_adapter_consolidates_methods_and_maps_inputs():
    routes = discover_flask_routes(TARGET_SOURCE, "flask-demo")

    profile = next(route for route in routes if route.path == "/profile")
    assert profile.methods == ["GET", "POST"]
    assert {item.name for item in profile.inputs} == {"name"}
    assert {item.location for item in profile.inputs} == {"body", "query"}
    assert len(routes) == 5


def test_route_matcher_uses_handler_and_helper_scopes():
    source_file = ROOT / "targets" / "flask-demo" / "app" / "app.py"
    helper_file = ROOT / "helper.py"
    routes = [
        RouteNode(
            route_id="flask-demo:/one:handler:10",
            target_id="flask-demo",
            path="/one",
            methods=["GET"],
            handler="handler",
            file=str(source_file),
            start_line=10,
            end_line=20,
            helper_scopes=[
                HelperScope(file=str(helper_file), start_line=5, end_line=9)
            ],
        ),
        RouteNode(
            route_id="flask-demo:/two:other:30",
            target_id="flask-demo",
            path="/two",
            methods=["POST"],
            handler="other",
            file=str(source_file),
            start_line=30,
            end_line=40,
            helper_scopes=[
                HelperScope(file=str(helper_file), start_line=5, end_line=9)
            ],
        ),
    ]
    findings = [
        _finding(source_file, 14, "handler"),
        _finding(helper_file, 7, "shared-helper"),
        _finding(source_file, 50, "outside"),
    ]
    other_target_finding = _finding(source_file, 14, "other-target")
    other_target_finding.target_id = "juice-shop"
    findings.append(other_target_finding)

    mapped = match_findings_to_routes(routes, findings)

    assert mapped[0].mapping_status == "mapped"
    assert mapped[0].route == "/one"
    assert mapped[0].method == "GET"
    assert mapped[1].mapping_status == "ambiguous"
    assert mapped[1].candidate_routes == ["/one", "/two"]
    assert mapped[2].mapping_status == "unmapped"
    assert mapped[3].mapping_status == "unmapped"


def test_semgrep_results_become_unified_findings(monkeypatch):
    source_file = TARGET_SOURCE / "app.py"
    payload = {
        "errors": [],
        "results": [
            {
                "check_id": "custom.python.sqli",
                "path": "targets/flask-demo/app/app.py",
                "start": {"line": 31},
                "extra": {
                    "severity": "ERROR",
                    "message": "Test finding",
                    "lines": "cursor.execute(query)",
                    "metadata": {"cwe": "CWE-89"},
                },
            }
        ],
    }
    monkeypatch.setattr("engine.semgrep_runner.shutil.which", lambda _: "semgrep")
    monkeypatch.setattr(
        "engine.semgrep_runner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(payload), stderr=""
        ),
    )

    result = run_semgrep(TARGET_SOURCE, "flask-demo")

    assert result.status == "ok"
    assert result.error is None
    assert len(result.findings) == 1
    assert result.findings[0].target_id == "flask-demo"
    assert result.findings[0].cwe == 89
    assert result.findings[0].severity == "error"
    assert result.findings[0].evidence == "cursor.execute(query)"


def test_missing_semgrep_is_a_failed_stage_not_a_finding(monkeypatch):
    monkeypatch.setattr("engine.semgrep_runner.shutil.which", lambda _: None)

    result = run_semgrep(TARGET_SOURCE, "flask-demo")

    assert result.status == "failed"
    assert "Docker were not found" in result.error
    assert result.findings == []


def test_semgrep_uses_pinned_docker_image_when_local_binary_is_unavailable(monkeypatch):
    source_file = TARGET_SOURCE / "app.py"
    payload = {
        "errors": [],
        "results": [
            {
                "check_id": "custom.python.sqli",
                "path": "/workspace/targets/flask-demo/app/app.py",
                "start": {"line": 18},
                "extra": {
                    "severity": "ERROR",
                    "message": "Test finding",
                    "lines": "connection.execute(query)",
                    "metadata": {"cwe": "CWE-89"},
                },
            }
        ],
    }
    captured = {}
    monkeypatch.setattr(
        "engine.semgrep_runner.shutil.which",
        lambda name: "docker" if name == "docker" else None,
    )

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr("engine.semgrep_runner.subprocess.run", fake_run)

    result = run_semgrep(
        TARGET_SOURCE,
        "flask-demo",
        ROOT / "config" / "semgrep",
        semgrep_version="1.82.0",
    )

    assert result.status == "ok"
    assert len(result.findings) == 1
    assert result.findings[0].file == str(source_file.resolve())
    assert result.findings[0].cwe == 89
    assert "semgrep/semgrep:1.82.0" in captured["command"]
    assert "--network" in captured["command"]
    assert "none" in captured["command"]
