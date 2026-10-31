# app/parsers/javascript_parser/__init__.py
from pathlib import Path
from typing import List
from app.parsers.base_parser import BaseSourceParser
from app.parsers.javascript_parser.dataflow_analyzer import ExpressDataflowAnalyzer
from app.parsers.javascript_parser.express_route_mapper import ExpressRouteMapper
from app.parsers.javascript_parser.ts_ast_parser import TypeScriptASTIndexer
from app.schemas.route import NormalizedRoute


class JavascriptSourceParser(BaseSourceParser):
    """Runs the 3-Pass AST + Route Mapping pipeline for JS/TS Express & OWASP Juice Shop."""

    def __init__(self) -> None:
        self.indexer = TypeScriptASTIndexer()
        self.route_mapper = ExpressRouteMapper()
        self.dataflow_analyzer = ExpressDataflowAnalyzer()

    def parse_project(self, source_dir: Path) -> List[NormalizedRoute]:
        # Pass 1: Run TypeScript Compiler API bridge & index symbols/imports
        project_index = self.indexer.index_project(source_dir)
        # Pass 2: Stitch app.use prefixes, routers, and Juice Shop factory handlers
        raw_routes = self.route_mapper.extract_routes(project_index)
        # Pass 3: Populate HTTP input parameters & 1-hop callees
        return self.dataflow_analyzer.enrich_routes(raw_routes, project_index)
