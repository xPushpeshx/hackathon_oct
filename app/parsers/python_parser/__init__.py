# app/parsers/python_parser/__init__.py
from pathlib import Path
from typing import List
from app.parsers.base_parser import BaseSourceParser
from app.parsers.python_parser.ast_parser import PythonASTIndexer
from app.parsers.python_parser.dataflow_analyzer import FlaskDataflowAnalyzer
from app.parsers.python_parser.flask_route_mapper import FlaskRouteMapper
from app.schemas.route import NormalizedRoute


class PythonSourceParser(BaseSourceParser):
    """Runs the 3-Pass AST + Route Mapping pipeline for Python/Flask applications."""

    def __init__(self) -> None:
        self.indexer = PythonASTIndexer()
        self.route_mapper = FlaskRouteMapper()
        self.dataflow_analyzer = FlaskDataflowAnalyzer()

    def parse_project(self, source_dir: Path) -> List[NormalizedRoute]:
        # Pass 1: Index all symbols & imports
        project_index = self.indexer.index_project(source_dir)
        # Pass 2: Stitch Blueprint prefixes & @route decorators
        raw_routes = self.route_mapper.extract_routes(project_index)
        # Pass 3: Extract HTTP parameters & 1-hop callees
        return self.dataflow_analyzer.enrich_routes(raw_routes, project_index)
