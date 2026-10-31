# app/normalizer/route_normalizer.py
import re
from typing import List, Optional
from urllib.parse import urlparse
from app.schemas.route import NormalizedRoute

# Matches Flask (<int:id>, <uuid:uid>, <name>) and Express (:id, :userId(\d+))
STATIC_PARAM_PATTERN = re.compile(
    r"(<(?:[a-zA-Z0-9_]+:)?[a-zA-Z0-9_]+>|:[a-zA-Z0-9_]+(?:\([^)]+\))?)"
)

# Matches Flask path variable names inside angle brackets: <int:order_id> -> order_id
FLASK_PATH_VAR_NAME_PATTERN = re.compile(r"<(?:[a-zA-Z0-9_]+:)?([a-zA-Z0-9_]+)>")

# Matches Express path variable names: :orderId -> orderId
EXPRESS_PATH_VAR_NAME_PATTERN = re.compile(r":([a-zA-Z0-9_]+)")

# Matches runtime DAST dynamic path segments that are usually identifiers or scoped values.
# Examples: 42, 4d9f..., UUIDs, or mixed alphanumeric slugs (abc123, order-42, user_7).
RUNTIME_DYNAMIC_SEGMENT_PATTERN = re.compile(
    r"^(?:"
    r"\d+|"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|"
    r"[0-9a-fA-F]{24}|"
    r"[A-Za-z0-9_-]*[A-Za-z0-9_-][A-Za-z0-9_-]*[0-9][A-Za-z0-9_-]*|"
    r"[A-Za-z0-9_-]*[0-9][A-Za-z0-9_-]*"
    r")$"
)


def _looks_like_dynamic_segment(segment: str) -> bool:
    """Heuristic: treat IDs / mixed slugs as dynamic while leaving static nouns alone."""
    if not segment or segment in {".", ".."}:
        return False
    if segment.isdigit():
        return True
    if len(segment) >= 8 and any(ch.isdigit() for ch in segment):
        return True
    if len(segment) >= 36:
        return False
    if "-" in segment or "_" in segment:
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9]+", segment) and len(segment) >= 6 and any(ch.isdigit() for ch in segment))


def join_url_paths(*parts: str) -> str:
    """Safely joins URL prefixes and route paths without duplicate slashes."""
    cleaned = [p.strip("/") for p in parts if p and p.strip("/")]
    if not cleaned:
        return "/"
    return "/" + "/".join(cleaned)


def normalize_static_path(raw_path: str) -> str:
    """Converts '/api/orders/<int:id>' or '/api/orders/:id' -> '/api/orders/{param}'."""
    joined = join_url_paths(raw_path)
    normalized = STATIC_PARAM_PATTERN.sub("{param}", joined)
    return normalized


def normalize_dast_url(full_url: str) -> str:
    """Converts 'http://localhost:5000/api/orders/42?q=1' -> '/api/orders/{param}'."""
    parsed = urlparse(full_url)
    path = parsed.path or "/"
    segments = [seg for seg in path.split("/") if seg]
    if not segments:
        return "/"

    normalized_segments = []
    for seg in segments:
        if RUNTIME_DYNAMIC_SEGMENT_PATTERN.match(seg) or _looks_like_dynamic_segment(seg):
            normalized_segments.append("{param}")
        else:
            normalized_segments.append(seg)
    return "/" + "/".join(normalized_segments)


def match_dast_to_route(
    dast_url: str, dast_method: str, routes: List[NormalizedRoute]
) -> Optional[NormalizedRoute]:
    """Matches a runtime ZAP URL + HTTP method to its static NormalizedRoute."""
    target_path = normalize_dast_url(dast_url)
    method_upper = dast_method.upper()

    # Pass 1: Exact normalized path + method match
    for route in routes:
        if route.method == method_upper and route.normalized_url == target_path:
            return route

    # Pass 2: Segment-by-segment wildcard fallback (for non-numeric slug parameters)
    target_parts = [p for p in target_path.split("/") if p]
    for route in routes:
        if route.method != method_upper:
            continue
        route_parts = [p for p in route.normalized_url.split("/") if p]
        if len(route_parts) != len(target_parts):
            continue
        if all(rp == tp or rp == "{param}" for rp, tp in zip(route_parts, target_parts)):
            return route

    return None
