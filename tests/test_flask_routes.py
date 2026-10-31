from pathlib import Path

from app.parsers.base_parser import get_parser


def test_flask_route_parser_discovers_vulnerable_routes():
    routes = get_parser("python").parse_project(Path("targets/flask-demo/app"))
    normalized_paths = {route.normalized_url for route in routes}
    assert "/search" in normalized_paths
    assert "/profile" in normalized_paths
    assert "/download/{param}" in normalized_paths
    assert "/exec" in normalized_paths
    assert "/redirect" in normalized_paths

    route_map = {route.normalized_url: route for route in routes}
    assert any("q" == parameter.name for parameter in route_map["/search"].parameters)
    assert any("name" == parameter.name for parameter in route_map["/profile"].parameters)
