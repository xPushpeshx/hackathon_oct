from __future__ import annotations

from pathlib import Path

from app.parsers.base_parser import get_parser
from engine.models import HelperScope, RouteInput, RouteNode


def discover_flask_routes(source_dir: str | Path, target_id: str) -> list[RouteNode]:
    """Adapt the source parser's routes to the engine's stable route contract."""
    root = Path(source_dir).resolve()
    parsed_routes = get_parser("python").parse_project(root)
    grouped: dict[tuple[str, str, int, int, str], RouteNode] = {}

    for parsed in parsed_routes:
        source_file = (root / parsed.file).resolve()
        key = (
            str(source_file),
            parsed.normalized_url,
            parsed.start_line,
            parsed.end_line,
            parsed.handler_function,
        )
        route = grouped.get(key)
        if route is None:
            route = RouteNode(
                route_id=f"{target_id}:{parsed.normalized_url}:{parsed.handler_function}:{parsed.start_line}",
                target_id=target_id,
                path=parsed.normalized_url,
                methods=[],
                handler=parsed.handler_function,
                file=str(source_file),
                start_line=parsed.start_line,
                end_line=parsed.end_line,
                inputs=[],
            )
            grouped[key] = route

        if parsed.method not in route.methods:
            route.methods.append(parsed.method)
        for parameter in parsed.parameters:
            route_input = RouteInput(
                name=parameter.name,
                location=parameter.source,
                line=parameter.line,
            )
            if route_input not in route.inputs:
                route.inputs.append(route_input)
        for callee in parsed.callees:
            if callee.start_line is None or callee.end_line is None:
                continue
            helper_file = (root / callee.file).resolve()
            scope = HelperScope(
                file=str(helper_file),
                start_line=callee.start_line,
                end_line=callee.end_line,
            )
            if scope not in route.helper_scopes:
                route.helper_scopes.append(scope)

    return list(grouped.values())
