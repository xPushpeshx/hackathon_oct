from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml

from engine.models import TargetProfile

ROOT_DIR = Path(__file__).resolve().parents[1]
TARGETS_DIR = ROOT_DIR / "targets"
RUNTIME_PROBE_VALUE = "sast-runtime-identity-check"


def load_target_profile(target_name: str) -> TargetProfile:
    target_file = TARGETS_DIR / target_name / "target.yaml"
    if not target_file.exists():
        raise FileNotFoundError(f"Target '{target_name}' not found at {target_file}")

    with target_file.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    profile = TargetProfile(**raw)
    profile.source_path = str((ROOT_DIR / profile.source_path).resolve())
    runtime_url = os.environ.get("RUNTIME_URL")
    if runtime_url:
        profile.runtime_url = runtime_url
    return profile


def load_scan_profile(profile_path: str | Path) -> dict:
    path = Path(profile_path)
    if not path.exists():
        raise FileNotFoundError(f"Scan profile not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def runtime_matches_target(profile: TargetProfile, timeout: float = 2.0) -> bool:
    if profile.app_type != "flask":
        raise ValueError(
            f"No target identity probe is configured for app type '{profile.app_type}'."
        )

    endpoint = urljoin(profile.runtime_url.rstrip("/") + "/", "search")
    probe_url = f"{endpoint}?{urlencode({'q': RUNTIME_PROBE_VALUE})}"
    request = Request(probe_url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                return False
            payload = json.loads(response.read())
            return payload == {
                "status": "ok",
                "query": RUNTIME_PROBE_VALUE,
            }
    except (HTTPError, URLError, OSError, ValueError):
        return False


def ensure_target_ready(profile: TargetProfile) -> None:
    source_dir = Path(profile.source_path)
    if not source_dir.exists():
        raise FileNotFoundError(f"Source path does not exist: {source_dir}")

    parsed_url = urlparse(profile.runtime_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ValueError(f"Invalid runtime URL for target '{profile.target_id}': {profile.runtime_url}")
    if not runtime_matches_target(profile):
        raise RuntimeError(
            f"Runtime at {profile.runtime_url} did not identify as target "
            f"'{profile.target_id}' through its Flask /search probe. "
            "Start the target and verify its configured URL."
        )
