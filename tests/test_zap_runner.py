import json
import re
from types import SimpleNamespace

from engine.models import UnifiedFinding
from engine.zap_runner import (
    _build_request,
    _target_scope_regex,
    build_scan_tasks,
    parse_alerts,
    run_zap_scan,
)


def test_build_scan_tasks_priority_and_queues():
    routes = [
        type(
            "Route",
            (),
            {
                "path": "/search",
                "methods": ["POST"],
                "inputs": [type("Input", (), {"name": "q", "location": "body"})()],
            },
        )()
    ]
    findings = [
        UnifiedFinding(
            finding_id="s1",
            target_id="flask-demo",
            source_tool="semgrep",
            tool_rule_id="sql",
            cwe=89,
            severity="error",
            file="app.py",
            line=10,
            route="/search",
            method="POST",
            parameter="q",
            mapping_status="mapped",
            evidence="SELECT",
            raw_ref="app.py:10",
        )
    ]

    tasks = build_scan_tasks(routes, findings, "flask-demo", {"weights": {"map": 0.4, "severity": 0.3, "graphcodebert": 0.2, "has_input": 0.1}})
    assert len(tasks) >= 1
    assert tasks[0].route == "/search"
    assert tasks[0].queue == "focused"
    assert tasks[0].priority > 0
    assert len({task.task_id for task in tasks}) == len(tasks)


def test_unmapped_findings_and_other_inputs_use_broad_queue():
    routes = [
        SimpleNamespace(
            path="/search",
            methods=["GET", "POST"],
            inputs=[
                SimpleNamespace(name="q", location="query"),
                SimpleNamespace(name="q", location="body"),
            ],
            unresolved=False,
        )
    ]
    finding = UnifiedFinding(
        finding_id="unmapped",
        target_id="flask-demo",
        source_tool="semgrep",
        tool_rule_id="test",
        cwe=89,
        severity="high",
        file="helper.py",
        line=1,
        mapping_status="unmapped",
        evidence="query",
        raw_ref="helper.py:1",
    )

    tasks = build_scan_tasks(routes, [finding], "flask-demo")

    assert tasks
    assert all(task.queue == "broad" for task in tasks)
    assert {task.method for task in tasks} == {"GET", "POST"}
    assert all(task.task_id.startswith("flask-demo:") for task in tasks)


def test_request_builder_seeds_query_and_body_inputs():
    route = SimpleNamespace(
        path="/search",
        inputs=[
            SimpleNamespace(name="q", location="query"),
            SimpleNamespace(name="q", location="body"),
        ],
        unresolved=False,
    )

    get_request = _build_request("http://flask-demo:5000", route, "GET")
    post_request = _build_request("http://flask-demo:5000", route, "POST", "q")

    assert get_request["url"] == "http://flask-demo:5000/search?q=zap-seed"
    assert post_request["url"] == "http://flask-demo:5000/search"
    assert post_request["post_data"] == "q=zap-seed"
    assert "POST /search HTTP/1.1" in post_request["raw_request"]


def test_target_scope_is_anchored_to_the_selected_target():
    scope = _target_scope_regex("http://flask-demo:5000")
    assert re.fullmatch(scope, "http://flask-demo:5000/search")
    assert not re.fullmatch(scope, "http://flask-demo.evil.test:5000/search")


def test_parse_alerts_creates_unified_findings():
    alerts = [{
        "pluginId": "40018",
        "alert": "SQL Injection",
        "url": "http://127.0.0.1:5000/search",
        "method": "POST",
        "parameter": "q",
        "risk": "High",
        "description": "SQL injection found.",
        "cweid": "89",
    }]

    findings = parse_alerts(alerts, "flask-demo")
    assert len(findings) == 1
    assert findings[0].source_tool == "zap"
    assert findings[0].tool_rule_id == "40018"
    assert findings[0].severity == "high"
    assert findings[0].cwe == 89


def test_zap_scan_records_completed_and_untested_tasks(monkeypatch):
    routes = [
        SimpleNamespace(
            path="/search",
            methods=["POST"],
            inputs=[
                SimpleNamespace(name="q", location="query"),
                SimpleNamespace(name="q", location="body"),
            ],
            unresolved=False,
        )
    ]
    finding = UnifiedFinding(
        finding_id="s1",
        target_id="flask-demo",
        source_tool="semgrep",
        tool_rule_id="sql",
        cwe=89,
        severity="high",
        file="app.py",
        line=10,
        route="/search",
        method="POST",
        parameter="q",
        mapping_status="mapped",
        evidence="query",
        raw_ref="app.py:10",
    )
    original = {
        "40018": True,
        "40019": True,
        "40020": True,
        "40021": True,
        "40022": True,
        "40024": True,
        "40027": True,
    }
    accessed_urls = []
    seeded_requests = []

    class FakeZAPClient:
        def __init__(self, base_url, api_key):
            self.enabled = set(original)

        def wait_until_ready(self, timeout=120.0):
            return "2.16.0"

        def new_session(self, name):
            return None

        def new_context(self, context_name):
            return "1"

        def include_in_context(self, context_name, regex):
            assert re.fullmatch(regex, "http://flask-demo:5000/search")

        def seed_request(self, raw_request):
            seeded_requests.append(raw_request)
            if "sast-runtime-identity-check" in raw_request:
                body = {"status": "ok", "query": "sast-runtime-identity-check"}
            else:
                body = {"status": "ok", "query": "zap-seed"}
            return {"responseBody": json.dumps(body)}

        def access_url(self, url):
            accessed_urls.append(url)

        def scanners(self):
            return [{"id": rule_id, "enabled": True} for rule_id in original]

        def disable_scanners(self, rule_ids):
            self.enabled.difference_update(rule_ids)

        def enable_scanners(self, rule_ids):
            self.enabled.update(rule_ids)

        def active_scan(self, url, **kwargs):
            return "1"

        def wait_for_scan(self, scan_id, timeout):
            return None

        def alerts(self, base_url=None):
            return []

    monkeypatch.setattr("engine.zap_runner.ZAPClient", FakeZAPClient)

    result = run_zap_scan(
        "flask-demo",
        routes,
        [finding],
        {"total_minutes": 1, "focused_share": 0.6, "per_task_timeout_seconds": 1, "max_retries": 0},
        target_url="http://flask-demo:5000",
    )

    assert result["status"] == "ok"
    assert all(task["status"] == "completed" for task in result["tasks"])
    assert result["untested_tasks"] == []
    assert accessed_urls == [
        "http://flask-demo:5000/search?q=zap-seed",
        "http://flask-demo:5000/search",
    ]
    assert any("POST /search?q=zap-seed HTTP/1.1" in request for request in seeded_requests)
    assert any("POST /search HTTP/1.1" in request for request in seeded_requests)


def test_zap_scan_rejects_missing_identity_response_body(monkeypatch):
    class IdentityMismatchClient:
        def __init__(self, base_url, api_key):
            pass

        def wait_until_ready(self, timeout=120.0):
            return "2.16.0"

        def new_session(self, name):
            pass

        def new_context(self, context_name):
            return "1"

        def include_in_context(self, context_name, regex):
            pass

        def seed_request(self, raw_request):
            return {"responseHeader": "HTTP/1.1 200 OK"}

    monkeypatch.setattr("engine.zap_runner.ZAPClient", IdentityMismatchClient)
    result = run_zap_scan(
        "flask-demo",
        [],
        [],
        {"total_minutes": 1},
        target_url="http://flask-demo:5000",
    )

    assert result["status"] == "failed"
    assert "identity response body" in result["error"]
