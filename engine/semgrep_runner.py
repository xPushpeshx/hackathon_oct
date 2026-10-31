from __future__ import annotations

import json
import shutil
import subprocess
from hashlib import sha256
from pathlib import Path, PurePosixPath

from engine.models import SemgrepRunResult, UnifiedFinding

REPO_ROOT = Path(__file__).resolve().parents[1]


def _parse_cwe(metadata: dict) -> int | None:
    value = metadata.get("cwe")
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        digits = value.rsplit("-", 1)[-1]
        if digits.isdigit():
            return int(digits)
    return None


def _resolve_result_path(result_path: str, source_dir: Path) -> Path:
    path = Path(result_path)
    if path.is_absolute():
        return path.resolve()

    working_directory_path = (Path.cwd() / path).resolve()
    if working_directory_path.exists():
        return working_directory_path
    return (source_dir / path).resolve()


def run_semgrep(
    target_source_path: str | Path,
    target_id: str,
    config_path: str | Path = "config/semgrep",
    semgrep_version: str | None = None,
) -> SemgrepRunResult:
    source_dir = Path(target_source_path)
    semgrep_bin = shutil.which("semgrep")
    using_container = semgrep_bin is None
    if semgrep_bin is not None:
        command = [
            semgrep_bin,
            "scan",
            "--json",
            "--config",
            str(Path(config_path).resolve()),
            str(source_dir.resolve()),
        ]
    else:
        docker_bin = shutil.which("docker")
        if docker_bin is None:
            return SemgrepRunResult(
                status="failed",
                error="Semgrep executable and Docker were not found; SAST did not run.",
            )
        if not semgrep_version:
            return SemgrepRunResult(
                status="failed",
                error="A pinned Semgrep version is required for the Docker fallback.",
            )

        try:
            source_relative = source_dir.resolve().relative_to(REPO_ROOT)
            config_relative = Path(config_path).resolve().relative_to(REPO_ROOT)
        except ValueError:
            return SemgrepRunResult(
                status="failed",
                error="Docker Semgrep requires the target source and rules to be inside the repository.",
            )

        command = [
            docker_bin,
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "semgrep",
            "--mount",
            f"type=bind,source={REPO_ROOT},target=/workspace,readonly",
            f"semgrep/semgrep:{semgrep_version}",
            "scan",
            "--json",
            "--metrics=off",
            "--config",
            f"/workspace/{config_relative.as_posix()}",
            f"/workspace/{source_relative.as_posix()}",
        ]

    try:
        result = subprocess.run(
            command,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as exc:
        return SemgrepRunResult(status="failed", error=f"Could not run Semgrep: {exc}")

    if result.returncode not in (0, 1):
        message = result.stderr.strip() or f"Semgrep exited with status {result.returncode}."
        return SemgrepRunResult(status="failed", error=message)

    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        return SemgrepRunResult(
            status="failed",
            error=f"Semgrep returned invalid JSON: {exc}",
        )

    if payload.get("errors"):
        messages = [
            error.get("message", "Semgrep reported an error.")
            for error in payload["errors"]
        ]
        return SemgrepRunResult(status="failed", error="; ".join(messages))

    findings: list[UnifiedFinding] = []
    for idx, item in enumerate(payload.get("results", [])):
        result_path = item.get("path", str(source_dir))
        if using_container and result_path.startswith("/workspace/"):
            relative_path = PurePosixPath(result_path.removeprefix("/workspace/"))
            file_path = (REPO_ROOT / Path(*relative_path.parts)).resolve()
        else:
            file_path = _resolve_result_path(result_path, source_dir.resolve())
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        rule_id = item.get("check_id", "unknown-rule")
        line = item.get("start", {}).get("line", 1)
        finding_key = f"{rule_id}:{file_path}:{line}:{idx}"
        severity = str(extra.get("severity", "unknown")).lower()
        lines = extra.get("lines", "")
        findings.append(
            UnifiedFinding(
                finding_id=f"semgrep-{sha256(finding_key.encode()).hexdigest()[:12]}",
                target_id=target_id,
                source_tool="semgrep",
                tool_rule_id=rule_id,
                cwe=_parse_cwe(metadata),
                severity=severity,
                file=str(file_path),
                line=line,
                route=None,
                method=None,
                parameter=None,
                mapping_status="n/a",
                evidence=lines or extra.get("message", "Semgrep match"),
                raw_ref=f"{file_path}:{line}:{rule_id}",
            )
        )
    return SemgrepRunResult(status="ok", findings=findings)
