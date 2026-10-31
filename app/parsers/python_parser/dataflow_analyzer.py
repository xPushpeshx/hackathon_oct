# app/parsers/python_parser/dataflow_analyzer.py
import ast
from typing import Dict, List, Set, Tuple
from app.normalizer.route_normalizer import FLASK_PATH_VAR_NAME_PATTERN
from app.parsers.python_parser.ast_parser import PythonProjectIndex
from app.parsers.python_parser.flask_route_mapper import RawFlaskRoute
from app.schemas.route import CalleeScope, NormalizedRoute, RouteParameter

REQUEST_ATTR_SOURCE_MAP = {
    "args": "query",
    "values": "query",
    "form": "body",
    "json": "body",
    "data": "body",
    "files": "body",
    "headers": "header",
    "cookies": "cookie",
}


class FlaskDataflowAnalyzer:
    """Pass 3: Extracts HTTP input parameters and 1-hop callees from Flask route handlers."""

    def enrich_routes(
        self, raw_routes: List[RawFlaskRoute], index: PythonProjectIndex
    ) -> List[NormalizedRoute]:
        normalized_routes: List[NormalizedRoute] = []

        for raw in raw_routes:
            fn_node = raw.handler.node
            params = self._extract_parameters(raw.raw_url, fn_node)
            callees = self._extract_callees(raw.handler.file, fn_node, index)

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

    def _extract_parameters(self, raw_url: str, fn_node: ast.AST) -> List[RouteParameter]:
        seen: Set[Tuple[str, str]] = set()
        parameters: List[RouteParameter] = []

        def add_param(name: str, source: str, line: int) -> None:
            if name and (name, source) not in seen:
                seen.add((name, source))
                parameters.append(RouteParameter(name=name, source=source, line=line))

        # 1. Path parameters from URL template (<int:order_id>) matched with function arguments
        path_vars = set(FLASK_PATH_VAR_NAME_PATTERN.findall(raw_url))
        if isinstance(fn_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in fn_node.args.args:
                if arg.arg in path_vars:
                    add_param(arg.arg, "path", fn_node.lineno)

        # 2. Track local aliases of request containers, e.g., `data = request.get_json()` or `args = request.args`
        alias_sources: Dict[str, str] = {}
        for node in ast.walk(fn_node):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                var_name = node.targets[0].id
                src = self._resolve_request_container_source(node.value)
                if src:
                    alias_sources[var_name] = src

        # 3. Find parameter reads via .get('key') or ['key'] on `request.<attr>` or aliased variables
        for node in ast.walk(fn_node):
            # Case A: request.args.get("q") or data.get("email")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("get", "getlist") and node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                        src = self._resolve_expr_source(node.func.value, alias_sources)
                        if src:
                            add_param(first_arg.value, src, node.lineno)

            # Case B: request.args["q"] or request.form["username"] or data["email"]
            elif isinstance(node, ast.Subscript):
                key_str = self._extract_subscript_key(node.slice)
                if key_str:
                    src = self._resolve_expr_source(node.value, alias_sources)
                    if src:
                        add_param(key_str, src, node.lineno)

        return parameters

    def _resolve_request_container_source(self, expr: ast.AST) -> str:
        # request.get_json()
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
            if isinstance(expr.func.value, ast.Name) and expr.func.value.id == "request":
                if expr.func.attr == "get_json":
                    return "body"
        # request.args / request.form / request.json
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name) and expr.value.id == "request":
            return REQUEST_ATTR_SOURCE_MAP.get(expr.attr, "")
        return ""

    def _resolve_expr_source(self, expr: ast.AST, alias_sources: Dict[str, str]) -> str:
        direct = self._resolve_request_container_source(expr)
        if direct:
            return direct
        if isinstance(expr, ast.Name) and expr.id in alias_sources:
            return alias_sources[expr.id]
        return ""

    @staticmethod
    def _extract_subscript_key(slice_node: ast.AST) -> str:
        if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
            return slice_node.value
        # Python < 3.9 compatibility fallback
        if hasattr(ast, "Index") and isinstance(slice_node, getattr(ast, "Index")):
            val = getattr(slice_node, "value", None)
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                return val.value
        return ""

    def _extract_callees(
        self, current_file: str, fn_node: ast.AST, index: PythonProjectIndex
    ) -> List[CalleeScope]:
        callees: List[CalleeScope] = []
        seen_calls: Set[Tuple[str, int]] = set()

        for node in ast.walk(fn_node):
            if not isinstance(node, ast.Call):
                continue

            call_name = self._get_call_name(node.func)
            if not call_name:
                continue

            # Resolve against Pass 1 project symbol table
            resolved_sym = index.resolve_imported_function(current_file, call_name)
            if resolved_sym:
                key = (resolved_sym.name, node.lineno)
                if key not in seen_calls:
                    seen_calls.add(key)
                    callees.append(
                        CalleeScope(
                            function_name=resolved_sym.name,
                            file=resolved_sym.file,
                            call_line=node.lineno,
                            start_line=resolved_sym.start_line,
                            end_line=resolved_sym.end_line,
                        )
                    )

        return callees

    @staticmethod
    def _get_call_name(func_expr: ast.AST) -> str:
        if isinstance(func_expr, ast.Name):
            return func_expr.id
        if isinstance(func_expr, ast.Attribute) and isinstance(func_expr.value, ast.Name):
            return f"{func_expr.value.id}.{func_expr.attr}"
        return ""
