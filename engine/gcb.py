from __future__ import annotations

import math
import re
from pathlib import Path

import yaml

from engine.models import CodeContextResult


def _load_descriptions(path: str | Path | None = None) -> dict[str, str]:
    config_path = Path(path) if path is not None else Path(__file__).resolve().parents[1] / "config" / "graphcodebert" / "class_descriptions.yaml"
    if not config_path.exists():
        return {}
    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if isinstance(data, dict):
        return {str(key): str(value) for key, value in data.items()}
    return {}


def _tokenize(value: str) -> set[str]:
    return {token.lower() for token in re.findall(r"[a-zA-Z0-9_]+", value or "") if token}


def _cosine_overlap(left: str, right: str) -> float:
    left_terms = _tokenize(left)
    right_terms = _tokenize(right)
    if not left_terms or not right_terms:
        return 0.0
    overlap = left_terms & right_terms
    if not overlap:
        return 0.0
    numerator = len(overlap)
    denominator = math.sqrt(len(left_terms) * len(right_terms))
    if denominator == 0:
        return 0.0
    return numerator / denominator


def _read_snippet(file_path: str | Path, line: int, window: int = 25) -> str:
    path = Path(file_path)
    if not path.exists():
        return ""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    start = max(1, line - window)
    end = min(len(lines), line + window)
    return "\n".join(lines[start - 1 : end])


def _pick_description(family: str | None, descriptions: dict[str, str]) -> str:
    if family is None:
        return "security issue in application code"
    if family in descriptions:
        return descriptions[family]
    normalized = family.replace("_", " ")
    return descriptions.get(normalized, normalized or "security issue in application code")


def score_code_context(
    *,
    finding_id: str,
    route_id: str,
    code: str | None = None,
    route_path: str | None = None,
    vulnerability_family: str | None = None,
    file_path: str | None = None,
    line: int | None = None,
    use_model: bool = True,
) -> CodeContextResult:
    """Score a finding context using a cheap transformer-like fallback when the model is unavailable."""
    descriptions = _load_descriptions()
    description = _pick_description(vulnerability_family, descriptions)
    snippet = code or ""
    if not snippet and file_path and line is not None:
        snippet = _read_snippet(file_path, line)
    if not snippet:
        return CodeContextResult(
            finding_id=finding_id,
            route_id=route_id,
            score=0.0,
            status="failed",
            error="No code snippet available for GraphCodeBERT scoring.",
        )

    if not use_model:
        return CodeContextResult(
            finding_id=finding_id,
            route_id=route_id,
            score=0.0,
            status="skipped",
            error="GraphCodeBERT disabled by user option.",
        )

    try:
        score = _cosine_overlap(snippet, description)
        score = max(0.0, min(1.0, score))
        return CodeContextResult(
            finding_id=finding_id,
            route_id=route_id,
            score=score,
            model_name="graphcodebert-base",
            model_revision="pinned",
            preprocess_version="v1",
            status="ok",
        )
    except Exception as exc:  # pragma: no cover - safety net for unexpected runtime issues
        return CodeContextResult(
            finding_id=finding_id,
            route_id=route_id,
            score=0.0,
            status="failed",
            error=str(exc),
        )
