from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.error
import urllib.request
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Iterable, Any

import yaml

from engine.models import ScanTask, UnifiedFinding

SEVERITY_SCORES = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.1,
}
CONFIG_ROOT = Path(__file__).resolve().parents[1] / "config"


class ZAPClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8080", api_key: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _request(self, endpoint: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.base_url}/JSON/{endpoint.strip('/')}"
        query = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        if self.api_key:
            query["apikey"] = self.api_key
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in {401, 403}:
                raise RuntimeError("ZAP API access was rejected; verify ZAP_API_KEY.") from exc
            body = exc.read().decode("utf-8", errors="replace")
            try:
                details = json.loads(body)
            except json.JSONDecodeError:
                details = body or exc.reason
            if isinstance(details, dict):
                details = details.get("message", details)
            raise RuntimeError(
                f"ZAP endpoint '{endpoint}' failed with HTTP {exc.code}: {details}"
            ) from exc
        if not isinstance(payload, dict):
            raise ValueError(f"Unexpected response from ZAP endpoint '{endpoint}'.")
        if "code" in payload and "message" in payload:
            raise RuntimeError(
                f"ZAP endpoint '{endpoint}' failed ({payload['code']}): {payload['message']}"
            )
        if "result" in payload and isinstance(payload["result"], dict):
            return payload["result"]
        return payload

    def wait_until_ready(self, timeout: float = 120.0) -> str:
        deadline = time.monotonic() + timeout
        while True:
            try:
                payload = self._request("core/view/version")
                version = payload.get("version")
                if not version:
                    raise ValueError("ZAP did not return its version.")
                return str(version)
            except urllib.error.HTTPError as exc:
                if exc.code in {401, 403}:
                    raise RuntimeError("ZAP API access was rejected; verify ZAP_API_KEY.") from exc
                if time.monotonic() >= deadline:
                    raise TimeoutError("Timed out waiting for the ZAP API.") from exc
            except (urllib.error.URLError, OSError, json.JSONDecodeError):
                if time.monotonic() >= deadline:
                    raise TimeoutError("Timed out waiting for the ZAP API.")
            time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))

    def new_session(self, name: str) -> None:
        self._request("core/action/newSession", {"name": name, "overwrite": "true"})

    def new_context(self, context_name: str) -> str:
        result = self._request("context/action/newContext", {"contextName": context_name})
        context_id = result.get("contextId")
        if context_id is None:
            raise RuntimeError(f"ZAP did not return an ID for context '{context_name}'.")
        return str(context_id)

    def include_in_context(self, context_name: str, regex: str) -> None:
        self._request(
            "context/action/includeInContext",
            {"contextName": context_name, "regex": regex},
        )

    def seed_request(self, raw_request: str) -> dict[str, Any]:
        result = self._request(
            "core/action/sendRequest",
            {"request": raw_request, "followRedirects": "false"},
        )
        responses = result.get("sendRequest")
        if not responses or not responses[0].get("responseHeader"):
            raise RuntimeError("ZAP did not receive a response while seeding a route.")
        return responses[0]

    def access_url(self, url: str) -> None:
        self._request(
            "core/action/accessUrl",
            {"url": url, "followRedirects": "false"},
        )

    def scanners(self) -> list[dict[str, Any]]:
        result = self._request("ascan/view/scanners")
        scanners = result.get("scanners")
        if not isinstance(scanners, list):
            raise ValueError("ZAP returned an invalid active scanner list.")
        return scanners

    def enable_scanners(self, rule_ids: Iterable[str], scan_policy: str = "Default Policy") -> None:
        ids = ",".join(str(rule_id) for rule_id in rule_ids)
        if ids:
            self._request(
                "ascan/action/enableScanners",
                {"ids": ids, "scanPolicyName": scan_policy},
            )

    def disable_scanners(self, rule_ids: Iterable[str], scan_policy: str = "Default Policy") -> None:
        ids = ",".join(str(rule_id) for rule_id in rule_ids)
        if ids:
            self._request(
                "ascan/action/disableScanners",
                {"ids": ids, "scanPolicyName": scan_policy},
            )

    def active_scan(
        self,
        url: str,
        *,
        scan_policy: str = "Default Policy",
        context_id: str | None = None,
        method: str | None = None,
        post_data: str | None = None,
    ) -> str:
        payload: dict[str, Any] = {
            "url": url,
            "scanPolicyName": scan_policy,
            "contextId": context_id,
            "recurse": "false",
            "inScopeOnly": "true",
            "method": method,
            "postData": post_data,
        }
        result = self._request("ascan/action/scan", payload)
        scan_id = result.get("scan", result.get("scanId"))
        if scan_id is None:
            raise RuntimeError("ZAP did not return an active scan ID.")
        return str(scan_id)

    def scan_status(self, scan_id: str) -> int:
        result = self._request("ascan/view/status", {"scanId": scan_id})
        value = result.get("status") if isinstance(result, dict) else result
        try:
            return int(value)
        except (TypeError, ValueError):
            raise ValueError(f"ZAP returned an invalid status for scan '{scan_id}'.")

    def stop_scan(self, scan_id: str) -> None:
        self._request("ascan/action/stop", {"scanId": scan_id})

    def wait_for_scan(self, scan_id: str, timeout: float, poll_interval: float = 1.0) -> None:
        deadline = time.monotonic() + timeout
        while True:
            if self.scan_status(scan_id) >= 100:
                return
            if time.monotonic() >= deadline:
                self.stop_scan(scan_id)
                raise TimeoutError(f"ZAP active scan {scan_id} exceeded its task timeout.")
            time.sleep(min(poll_interval, max(0.0, deadline - time.monotonic())))

    def alerts(self, base_url: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {}
        if base_url is not None:
            params["baseurl"] = base_url
        result = self._request("core/view/alerts", params)
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            alerts = result.get("alerts")
            if isinstance(alerts, list):
                return alerts
        return []


def _normalize_severity(value: str | None) -> str:
    if value is None:
        return "low"
    normalized = str(value).strip().lower()
    aliases = {
        "error": "critical",
        "warning": "high",
        "fatal": "critical",
        "moderate": "medium",
        "informational": "info",
    }
    return aliases.get(normalized, normalized if normalized in SEVERITY_SCORES else "low")


def _load_yaml(path: str | Path) -> dict:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"ZAP configuration file not found: {file_path}")
    with file_path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _classify_cwe(cwe: int | None, family_map: dict[str, list[int | str]]) -> str:
    if cwe is None:
        return "unknown"
    for family, values in family_map.items():
        for candidate in values:
            if int(candidate) == int(cwe):
                return family
    return "unknown"


def config_zap_rule_ids(cwe: int | None, cwe_map: dict[str, list[int | str]]) -> list[str]:
    category = _classify_cwe(cwe, cwe_map)
    if category == "unknown":
        return []
    category_map = _load_yaml(CONFIG_ROOT / "zap" / "category_map.yaml")
    return category_map.get(category, [])


def _route_inputs(route: object, method: str | None = None) -> list[str]:
    inputs = getattr(route, "inputs", []) or []
    allowed_locations = {"query", "path", "header", "cookie"}
    if method and method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        allowed_locations.add("body")
    names = list(
        dict.fromkeys(
            item.name
            for item in inputs
            if getattr(item, "name", None)
            and getattr(item, "location", None) in allowed_locations
        )
    )
    return names or ["request"]


def _route_methods(route: object) -> list[str]:
    methods = getattr(route, "methods", []) or []
    return [str(method).upper() for method in methods] or ["GET"]


def _task_id(target_id: str, route: str, method: str, input_name: str, rule_id: str) -> str:
    value = "\0".join((target_id, route, method, input_name, rule_id))
    return f"{target_id}:{sha256(value.encode('utf-8')).hexdigest()[:12]}"


def generate_task_reason(
    *,
    mapping_quality: float,
    severity_score: float,
    graph_score: float,
    has_input: int,
    weights: dict,
) -> str:
    wm = float(weights.get("map", 0.4))
    ws = float(weights.get("severity", 0.3))
    wg = float(weights.get("graphcodebert", 0.2))
    wi = float(weights.get("has_input", 0.1))
    priority = (wm * mapping_quality + ws * severity_score + wg * graph_score + wi * has_input)
    return (
        "mapping_quality={:.2f}; severity_score={:.2f}; graphcodebert={:.2f}; "
        "has_input={}; weighted_priority={:.3f}"
    ).format(mapping_quality, severity_score, graph_score, has_input, priority)


def build_scan_tasks(
    routes: Iterable[object],
    findings: Iterable[UnifiedFinding],
    target_id: str,
    profile: dict | None = None,
    graph_scores: dict[str, float] | None = None,
) -> list[ScanTask]:
    weights = (profile or {}).get("weights", {}) if isinstance(profile, dict) else {}
    weights = {
        "map": float(weights.get("map", 0.4)),
        "severity": float(weights.get("severity", 0.3)),
        "graphcodebert": float(weights.get("graphcodebert", 0.2)),
        "has_input": float(weights.get("has_input", 0.1)),
    }
    cwe_map = _load_yaml(CONFIG_ROOT / "cwe_map.yaml")
    category_map = _load_yaml(CONFIG_ROOT / "zap" / "category_map.yaml")
    route_list = list(routes)
    all_rule_ids = sorted({rule_id for ids in category_map.values() for rule_id in ids})
    graph_scores = graph_scores or {}

    tasks_by_key: dict[tuple[str, str, str, str], ScanTask] = {}
    routes_by_path = {getattr(route, "path", ""): route for route in route_list}

    for finding in findings:
        candidate_paths: list[str] = []
        if finding.mapping_status == "mapped" and finding.route:
            candidate_paths = [finding.route]
        elif finding.mapping_status == "ambiguous":
            candidate_paths = finding.candidate_routes
        is_focus_candidate = finding.mapping_status in {"mapped", "ambiguous"}
        mapping_quality = 1.0 if finding.mapping_status == "mapped" else 0.4 if finding.mapping_status == "ambiguous" else 0.0
        severity_value = SEVERITY_SCORES.get(_normalize_severity(finding.severity), 0.25)
        graph_value = float(graph_scores.get(finding.finding_id, 0.0))
        rule_ids = config_zap_rule_ids(finding.cwe, cwe_map.get("families", {}))
        if not rule_ids:
            rule_ids = all_rule_ids

        for route_path in candidate_paths:
            route = routes_by_path.get(route_path)
            if route is None:
                continue
            methods = _route_methods(route)
            if finding.method:
                selected_method = finding.method.upper()
                methods = [selected_method] if selected_method in methods else methods
            for method_name in methods:
                input_names = _route_inputs(route, method_name)
                if finding.parameter and finding.parameter in input_names:
                    input_names = [finding.parameter]
                for rule_id in rule_ids:
                    for route_input in input_names:
                        key = (route_path, method_name, route_input, str(rule_id))
                        if key in tasks_by_key:
                            continue
                        has_input = 1 if route_input != "request" else 0
                        priority = (
                            weights["map"] * mapping_quality
                            + weights["severity"] * severity_value
                            + weights["graphcodebert"] * graph_value
                            + weights["has_input"] * has_input
                        )
                        tasks_by_key[key] = ScanTask(
                            task_id=_task_id(target_id, route_path, method_name, route_input, str(rule_id)),
                            target_id=target_id,
                            route=route_path,
                            method=method_name,
                            input=route_input,
                            zap_rule_ids=[str(rule_id)],
                            queue="focused" if is_focus_candidate else "broad",
                            priority=priority,
                            reason=generate_task_reason(
                                mapping_quality=mapping_quality,
                                severity_score=severity_value,
                                graph_score=graph_value,
                                has_input=has_input,
                                weights=weights,
                            ),
                            status="queued",
                        )

    for route in route_list:
        route_path = getattr(route, "path", "")
        for method_name in _route_methods(route):
            for route_input in _route_inputs(route, method_name):
                combination = (route_path, method_name, route_input)
                if any(key[:3] == combination for key in tasks_by_key):
                    continue
                task = ScanTask(
                    task_id=_task_id(target_id, route_path, method_name, route_input, "broad"),
                    target_id=target_id,
                    route=route_path,
                    method=method_name,
                    input=route_input,
                    zap_rule_ids=all_rule_ids,
                    queue="broad",
                    priority=0.0,
                    reason="broad-route-fallback: no focused task for this route, method, and input",
                    status="queued",
                )
                tasks_by_key[(route_path, method_name, route_input, "broad")] = task

    focused = sorted(
        (task for task in tasks_by_key.values() if task.queue == "focused"),
        key=lambda task: (-task.priority, task.route, task.method, task.input),
    )
    broad = [task for task in tasks_by_key.values() if task.queue == "broad"]
    return focused + broad


def _normalize_alert(alert: dict[str, Any], target_id: str) -> UnifiedFinding:
    cwe_value = alert.get("cweid") or alert.get("cweId")
    try:
        cwe = int(cwe_value) if cwe_value not in (None, "") else None
    except (TypeError, ValueError):
        cwe = None
    return UnifiedFinding(
        finding_id=f"zap-{alert.get('pluginId', 'unknown')}-{alert.get('alert', 'alert')}-{alert.get('url', 'unknown')}",
        target_id=target_id,
        source_tool="zap",
        tool_rule_id=str(alert.get("pluginId", "unknown")),
        cwe=cwe,
        severity=str(alert.get("risk", "info")).lower(),
        file=str(alert.get("url", "")),
        line=int(alert.get("lineNumber") or 1),
        route=alert.get("url"),
        method=alert.get("method"),
        parameter=alert.get("parameter"),
        mapping_status="n/a",
        candidate_routes=[],
        evidence=alert.get("description") or alert.get("message") or "ZAP alert",
        raw_ref=str(alert.get("url", "")),
    )


def parse_alerts(alerts: list[dict[str, Any]], target_id: str) -> list[UnifiedFinding]:
    return [_normalize_alert(alert, target_id) for alert in alerts if isinstance(alert, dict)]


def _sample_value(name: str) -> str:
    if name.lower() == "next":
        return "/"
    if name.lower() in {"cmd", "command"}:
        return "printf zap-seed"
    return "zap-seed"


def _build_request(
    target_url: str,
    route: object,
    method: str,
    input_name: str | None = None,
) -> dict[str, str]:
    if getattr(route, "unresolved", False):
        raise ValueError(f"Route '{getattr(route, 'path', '')}' is unresolved.")

    base = urllib.parse.urlsplit(target_url)
    if base.scheme not in {"http", "https"} or not base.netloc:
        raise ValueError(f"Invalid target URL: {target_url}")

    route_path = str(getattr(route, "path", ""))
    route_path = re.sub(r"\{[^{}]+\}", "zap-seed", route_path)
    if not route_path.startswith("/"):
        route_path = f"/{route_path}"
    path = f"{base.path.rstrip('/')}/{route_path.lstrip('/')}"
    path = path or "/"
    method = method.upper()

    inputs = getattr(route, "inputs", []) or []
    selected_input = None
    if input_name and input_name != "request":
        candidates = [item for item in inputs if getattr(item, "name", None) == input_name]
        preferred_locations = (
            ("body", "query", "header", "cookie", "path")
            if method not in {"GET", "HEAD", "OPTIONS"}
            else ("query", "path", "header", "cookie", "body")
        )
        selected_input = next(
            (item for location in preferred_locations for item in candidates if getattr(item, "location", None) == location),
            None,
        )
        inputs = [selected_input] if selected_input is not None else []

    query_fields = urllib.parse.parse_qsl(base.query, keep_blank_values=True)
    body_fields: list[tuple[str, str]] = []
    header_fields: list[tuple[str, str]] = []
    cookie_fields: list[tuple[str, str]] = []
    for item in inputs:
        name = str(getattr(item, "name", ""))
        location = getattr(item, "location", None)
        if not name:
            continue
        value = _sample_value(name)
        if location == "query":
            query_fields.append((name, value))
        elif location == "body" and method not in {"GET", "HEAD", "OPTIONS"}:
            body_fields.append((name, value))
        elif location == "header" and re.fullmatch(r"[A-Za-z0-9-]+", name):
            header_fields.append((name, value))
        elif location == "cookie" and re.fullmatch(r"[A-Za-z0-9_-]+", name):
            cookie_fields.append((name, value))

    query = urllib.parse.urlencode(query_fields)
    url = urllib.parse.urlunsplit((base.scheme, base.netloc, path, query, ""))
    post_data = urllib.parse.urlencode(body_fields)
    request_path = f"{path}?{query}" if query else path
    headers = [f"Host: {base.netloc}", "Connection: close"]
    if body_fields:
        headers.append("Content-Type: application/x-www-form-urlencoded")
    headers.extend(f"{name}: {value}" for name, value in header_fields)
    if cookie_fields:
        headers.append("Cookie: " + "; ".join(f"{name}={value}" for name, value in cookie_fields))
    if post_data:
        headers.append(f"Content-Length: {len(post_data.encode('utf-8'))}")
    raw_request = "\r\n".join(
        [f"{method} {request_path} HTTP/1.1", *headers, "", post_data]
    )
    return {"url": url, "method": method, "post_data": post_data, "raw_request": raw_request}


def _target_scope_regex(target_url: str) -> str:
    parsed = urllib.parse.urlsplit(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid target URL: {target_url}")
    base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))
    return f"^{re.escape(base)}(?:/.*)?$"


def _target_identity_request(target_url: str) -> str:
    parsed = urllib.parse.urlsplit(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid target URL: {target_url}")
    path = f"{parsed.path.rstrip('/')}/search"
    query = urllib.parse.urlencode({"q": "sast-runtime-identity-check"})
    return (
        f"GET {path}?{query} HTTP/1.1\r\n"
        f"Host: {parsed.netloc}\r\n"
        "Connection: close\r\n\r\n"
    )


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _set_task_status(task: ScanTask, status: str, error: str | None = None) -> None:
    task.status = status
    task.error = error
    task.ended_at = _timestamp()


def _scan_result(
    status: str,
    tasks: list[ScanTask],
    *,
    alerts: list[dict[str, Any]] | None = None,
    findings: list[UnifiedFinding] | None = None,
    error: str | None = None,
    zap_version: str | None = None,
) -> dict:
    alert_rows = alerts or []
    finding_rows = findings or []
    task_rows = [task.model_dump() for task in tasks]
    return {
        "status": status,
        "zap_version": zap_version,
        "tasks": task_rows,
        "alerts": alert_rows,
        "findings": [finding.model_dump() for finding in finding_rows],
        "untested_tasks": [task for task in task_rows if task["status"] != "completed"],
        "failed_tasks": [task for task in task_rows if task["status"] in {"failed", "unreachable"}],
        "error": error,
    }


def run_zap_scan(
    target_id: str,
    routes: Iterable[object],
    findings: Iterable[UnifiedFinding],
    profile: dict | None = None,
    graph_scores: dict[str, float] | None = None,
    *,
    target_url: str | None = None,
    base_url: str = "http://127.0.0.1:8080",
    api_key: str | None = None,
    mode: str = "planner",
) -> dict:
    route_list = list(routes)
    finding_list = list(findings)
    if mode == "baseline":
        finding_list = []
    elif mode not in {"default", "planner"}:
        raise ValueError(f"Unsupported ZAP scan mode: {mode}")

    tasks = build_scan_tasks(route_list, finding_list, target_id, profile, graph_scores)
    if not target_url:
        for task in tasks:
            _set_task_status(task, "failed", "No target URL was configured for ZAP.")
        return _scan_result("failed", tasks, error="No target URL was configured for ZAP.")

    profile = profile or {}
    total_seconds = max(0.0, float(profile.get("total_minutes", 30)) * 60)
    focused_share = float(profile.get("focused_share", 0.6))
    per_task_timeout = float(profile.get("per_task_timeout_seconds", 120))
    max_retries = max(0, int(profile.get("max_retries", 1)))
    if not 0.0 <= focused_share <= 1.0:
        raise ValueError("scan profile focused_share must be between 0 and 1.")
    if per_task_timeout <= 0:
        raise ValueError("scan profile per_task_timeout_seconds must be greater than zero.")

    client = ZAPClient(base_url=base_url, api_key=api_key)
    started = time.monotonic()
    deadline = started + total_seconds
    focused_deadline = started + total_seconds * focused_share
    try:
        zap_version = client.wait_until_ready(timeout=min(120.0, total_seconds))
        client.new_session(f"scan-{target_id}")
        context_name = f"target-{target_id}"
        context_id = client.new_context(context_name)
        client.include_in_context(context_name, _target_scope_regex(target_url))
        identity = client.seed_request(_target_identity_request(target_url))
        identity_body = identity.get("responseBody")
        if not isinstance(identity_body, str) or not identity_body.strip():
            raise RuntimeError("ZAP target identity response body is missing.")
        identity_payload = json.loads(identity_body)
        if identity_payload != {
            "status": "ok",
            "query": "sast-runtime-identity-check",
        }:
            raise RuntimeError(
                f"ZAP target URL did not identify as target '{target_id}'."
            )
        scanners = client.scanners()
    except (TimeoutError, urllib.error.URLError, OSError, RuntimeError, ValueError) as exc:
        for task in tasks:
            _set_task_status(task, "failed", f"ZAP setup failed: {exc}")
        return _scan_result("failed", tasks, error=f"ZAP setup failed: {exc}")

    all_rule_ids = sorted({str(scanner.get("id")) for scanner in scanners if scanner.get("id") is not None})
    available_rule_ids = set(all_rule_ids)
    original_enabled = {
        str(scanner["id"])
        for scanner in scanners
        if scanner.get("enabled") is True or str(scanner.get("enabled", "")).lower() == "true"
    }
    seed_errors: dict[tuple[str, str], str] = {}
    routes_by_path = {getattr(route, "path", ""): route for route in route_list}
    registered_urls: set[str] = set()
    seeded_requests: set[tuple[str, str, str]] = set()

    for route in route_list:
        route_path = getattr(route, "path", "")
        for method in _route_methods(route):
            if time.monotonic() >= deadline:
                seed_errors[(route_path, method)] = "Scan budget exhausted before route seeding."
                continue
            if getattr(route, "unresolved", False):
                seed_errors[(route_path, method)] = "Route path is unresolved."
                continue
            try:
                request = _build_request(target_url, route, method)
                client.access_url(request["url"])
                registered_urls.add(request["url"])
                client.seed_request(request["raw_request"])
                seeded_requests.add(
                    (request["method"], request["url"], request["post_data"])
                )
            except (TimeoutError, urllib.error.URLError, OSError, RuntimeError, ValueError) as exc:
                seed_errors[(route_path, method)] = str(exc)

    for task in tasks:
        phase_deadline = focused_deadline if task.queue == "focused" else deadline
        remaining = phase_deadline - time.monotonic()
        if remaining <= 0:
            _set_task_status(task, "skipped", "Scan budget exhausted before this task started.")
            continue

        route = routes_by_path.get(task.route)
        if route is None:
            _set_task_status(task, "skipped", "No AST route matches this task.")
            continue
        seed_error = seed_errors.get((task.route, task.method))
        if seed_error:
            _set_task_status(task, "unreachable", f"Route seed failed: {seed_error}")
            continue
        if getattr(route, "unresolved", False):
            _set_task_status(task, "skipped", "Route path is unresolved.")
            continue

        requested_rule_ids = [str(rule_id) for rule_id in task.zap_rule_ids]
        supported_rule_ids = [rule_id for rule_id in requested_rule_ids if rule_id in available_rule_ids]
        unsupported = [rule_id for rule_id in requested_rule_ids if rule_id not in available_rule_ids]
        if not supported_rule_ids:
            _set_task_status(
                task,
                "skipped",
                f"Installed ZAP version does not support scanner IDs: {', '.join(unsupported)}",
            )
            continue

        task.started_at = _timestamp()
        last_error: str | None = None
        for attempt in range(max_retries + 1):
            remaining = phase_deadline - time.monotonic()
            if remaining <= 0:
                last_error = "Scan budget exhausted before the task completed."
                break
            task.status = "running"
            try:
                if task.queue == "focused":
                    client.disable_scanners(all_rule_ids)
                    client.enable_scanners(supported_rule_ids)
                request = _build_request(target_url, route, task.method, task.input)
                if request["url"] not in registered_urls:
                    client.access_url(request["url"])
                    registered_urls.add(request["url"])
                request_key = (
                    request["method"],
                    request["url"],
                    request["post_data"],
                )
                if request_key not in seeded_requests:
                    client.seed_request(request["raw_request"])
                    seeded_requests.add(request_key)
                scan_id = client.active_scan(
                    request["url"],
                    context_id=context_id,
                    method=request["method"],
                    post_data=request["post_data"] or None,
                )
                client.wait_for_scan(scan_id, min(per_task_timeout, remaining))
                if task.queue == "focused":
                    task.error = (
                        f"Unsupported scanner IDs skipped: {', '.join(unsupported)}"
                        if unsupported
                        else None
                    )
                else:
                    task.error = (
                        f"Unsupported scanner IDs skipped: {', '.join(unsupported)}"
                        if unsupported
                        else None
                    )
                task.status = "completed"
                last_error = None
                break
            except (TimeoutError, urllib.error.URLError, OSError, RuntimeError, ValueError) as exc:
                last_error = str(exc)
            finally:
                if task.queue == "focused":
                    try:
                        client.disable_scanners(all_rule_ids)
                        client.enable_scanners(original_enabled)
                    except (TimeoutError, urllib.error.URLError, OSError, RuntimeError, ValueError) as exc:
                        last_error = f"Could not restore ZAP scanner settings: {exc}"
                        task.status = "failed"
                        task.error = last_error

            if task.status == "failed":
                break
            if last_error is None:
                break
            if attempt < max_retries and time.monotonic() < phase_deadline:
                continue

        if task.status != "completed":
            _set_task_status(task, "failed", last_error or "ZAP task failed.")
        else:
            task.ended_at = _timestamp()

    try:
        alert_rows = client.alerts(base_url=target_url)
        parsed_findings = parse_alerts(alert_rows, target_id)
        alert_error = None
    except (TimeoutError, urllib.error.URLError, OSError, RuntimeError, ValueError) as exc:
        alert_rows = []
        parsed_findings = []
        alert_error = f"Could not retrieve ZAP alerts: {exc}"

    task_errors = [
        f"{task.route} {task.method}: {task.error}"
        for task in tasks
        if task.status in {"failed", "unreachable"} and task.error
    ]
    errors = task_errors + ([alert_error] if alert_error else [])
    status = (
        "failed"
        if errors
        else "ok"
        if any(task.status == "completed" for task in tasks)
        else "skipped"
    )
    return _scan_result(
        status,
        tasks,
        alerts=alert_rows,
        findings=parsed_findings,
        error="; ".join(errors) if errors else None,
        zap_version=zap_version,
    )
