import json
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock

import pytest

from engine.targets import (
    RUNTIME_PROBE_VALUE,
    ensure_target_ready,
    load_scan_profile,
    load_target_profile,
)


def test_target_profile_loads():
    target = load_target_profile("flask-demo")
    assert target.target_id == "flask-demo"
    assert target.app_type == "flask"
    assert Path(target.source_path).exists()


def test_target_runtime_url_can_be_overridden_for_container_network(monkeypatch):
    monkeypatch.setenv("RUNTIME_URL", "http://flask-demo:5000")

    target = load_target_profile("flask-demo")

    assert target.runtime_url == "http://flask-demo:5000"


def test_scan_profile_loads():
    profile = load_scan_profile("config/scan_profile.yaml")
    assert profile["total_minutes"] == 30
    assert profile["weights"]["map"] == 0.4


def test_target_readiness_accepts_matching_flask_runtime(monkeypatch):
    target = load_target_profile("flask-demo")
    response = Mock(status=200)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = json.dumps(
        {"status": "ok", "query": RUNTIME_PROBE_VALUE}
    ).encode()
    request_seen = {}

    def fake_urlopen(request, timeout):
        request_seen["url"] = request.full_url
        request_seen["timeout"] = timeout
        return response

    monkeypatch.setattr("engine.targets.urlopen", fake_urlopen)

    ensure_target_ready(target)

    assert request_seen["url"].endswith(
        f"/search?q={RUNTIME_PROBE_VALUE}"
    )
    assert request_seen["timeout"] == 2.0


def test_target_readiness_rejects_an_unrelated_http_response(monkeypatch):
    target = load_target_profile("flask-demo")
    response = Mock(status=404)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    monkeypatch.setattr("engine.targets.urlopen", lambda *_args, **_kwargs: response)

    with pytest.raises(RuntimeError, match="did not identify as target"):
        ensure_target_ready(target)
