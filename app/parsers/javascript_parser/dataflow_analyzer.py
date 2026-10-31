# app/parsers/javascript_parser/dataflow_analyzer.py
from typing import List, Set, Tuple
from app.normalizer.route_normalizer import EXPRESS_PATH_VAR_NAME_PATTERN
from app.parsers.javascript_parser.express_route_mapper import RawExpressRoute
from app.parsers.javascript_parser.ts_ast_parser import TSFunctionSymbol, TSProjectIndex
from app.schemas.route import CalleeScope, NormalizedRoute, RouteParameter


class ExpressDataflowAnalyzer:
    """Pass 3: Populates RouteParameters and 1-hop CalleeScopes for Express routes."""

    def enrich_routes(
        self, raw_routes: List[RawExpressRoute], index: TSProjectIndex
    ) -> List[NormalizedRoute]:
        normalized_routes: List[NormalizedRoute] = []

        for raw in raw_routes:
            params = self._extract_parameters(raw.raw_url, raw.handler)
            callees = self._extract_callees(raw.handler, index)

            normalized_routes.append(
                NormalizedRoute(
                    raw_url=raw.raw_url,
                    normalized_url=raw.normalized_url,
                    method=raw.method,
                    handler_function=raw.handler.name,
                    file=raw.handler.file,
                    start_line=raw.handler.start_line,
                    end_line=raw.handler.end_line,
                    middlewares=raw.middlewares,
                    parameters=params,
                    callees=callees,
                )
            )

        return normalized_routes

    @staticmethod
    def _extract_parameters(raw_url: str, handler: TSFunctionSymbol) -> List[RouteParameter]:
        seen: Set[Tuple[str, str]] = set()
        parameters: List[RouteParameter] = []

        def add_param(name: str, source: str, line: int) -> None:
            if name and (name, source) not in seen:
                seen.add((name, source))
                parameters.append(RouteParameter(name=name, source=source, line=line))

        # 1. URL path parameters (:id, :orderId)
        for path_var in EXPRESS_PATH_VAR_NAME_PATTERN.findall(raw_url):
            add_param(path_var, "path", handler.start_line)

        # 2. AST-extracted req.query / req.body / req.params / req.headers reads
        for p in handler.params:
            add_param(p["name"], p["source"], p["line"])

        return parameters

    @staticmethod
    def _extract_callees(handler: TSFunctionSymbol, index: TSProjectIndex) -> List[CalleeScope]:
        callees: List[CalleeScope] = []
        seen: Set[Tuple[str, int]] = set()

        for call_info in handler.calls:
            callee_name = call_info["callee"]
            call_line = call_info["line"]

            resolved = index.resolve_handler_symbol(handler.file, callee_name)
            if resolved and (resolved.file != handler.file or resolved.name != handler.name):
                key = (resolved.name, call_line)
                if key not in seen:
                    seen.add(key)
                    callees.append(
                        CalleeScope(
                            function_name=resolved.name,
                            file=resolved.file,
                            call_line=call_line,
                            start_line=resolved.start_line,
                            end_line=resolved.end_line,
                        )
                    )

        return callees
