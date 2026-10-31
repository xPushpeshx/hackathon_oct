# app/parsers/javascript_parser/ts_ast_parser.py
from dataclasses import dataclass, field
import json
from pathlib import Path
import subprocess
from typing import Any, Dict, List, Optional


@dataclass
class TSFunctionSymbol:
    name: str
    file: str
    start_line: int
    end_line: int
    params: List[Dict[str, Any]] = field(default_factory=list)
    calls: List[Dict[str, Any]] = field(default_factory=list)
    is_default_export: bool = False


@dataclass
class TSFileContext:
    rel_path: str
    imports: Dict[str, Dict[str, str]] = field(default_factory=dict)  # local -> {"from": ..., "imported": ...}
    functions: Dict[str, TSFunctionSymbol] = field(default_factory=dict)
    mounts: List[Dict[str, Any]] = field(default_factory=list)
    routes: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class TSProjectIndex:
    root_dir: Path
    files: Dict[str, TSFileContext] = field(default_factory=dict)

    def resolve_import_target_file(self, current_file: str, import_specifier: str) -> Optional[str]:
        """Resolves './routes/search' from 'server.ts' -> 'routes/search.ts' or 'routes/search.js'."""
        if not import_specifier.startswith("."):
            return None

        base_dir = Path(current_file).parent
        candidate_base = (self.root_dir / base_dir / import_specifier).resolve()
        try:
            rel_candidate = candidate_base.relative_to(self.root_dir).as_posix()
        except ValueError:
            return None

        for candidate in (
            rel_candidate,
            f"{rel_candidate}.ts",
            f"{rel_candidate}.js",
            f"{rel_candidate}/index.ts",
            f"{rel_candidate}/index.js",
        ):
            if candidate in self.files:
                return candidate
        return None

    def resolve_handler_symbol(self, current_file: str, handler_ref: str) -> Optional[TSFunctionSymbol]:
        """Resolves a handler reference (local function, imported factory, or module.method) to TSFunctionSymbol."""
        ctx = self.files.get(current_file)
        if not ctx or not handler_ref:
            return None

        # 1. Local function inside the same file
        if handler_ref in ctx.functions:
            return ctx.functions[handler_ref]

        # 2. Direct imported symbol or Juice Shop factory: `import search = require('./routes/search')`
        base_symbol = handler_ref.split(".")[0]
        attr_symbol = handler_ref.split(".")[1] if "." in handler_ref else None

        if base_symbol in ctx.imports:
            imp = ctx.imports[base_symbol]
            target_file = self.resolve_import_target_file(current_file, imp["from"])
            if not target_file or target_file not in self.files:
                return None
            target_ctx = self.files[target_file]

            # If called as `security.isAuthorized` or `login.userLogin`
            if attr_symbol and attr_symbol in target_ctx.functions:
                return target_ctx.functions[attr_symbol]

            # If imported by named export: `import { getOrders } from './routes/orders'`
            imported_name = imp.get("imported", "default")
            if imported_name != "default" and imported_name in target_ctx.functions:
                return target_ctx.functions[imported_name]

            # Default export or single exported handler in that route file
            for fn_sym in target_ctx.functions.values():
                if fn_sym.is_default_export:
                    return fn_sym
            if len(target_ctx.functions) == 1:
                return next(iter(target_ctx.functions.values()))

        return None


class TypeScriptASTIndexer:
    """Pass 1: Invokes the TypeScript Compiler API bridge and indexes all JS/TS files."""

    def __init__(self, bridge_script: Optional[Path] = None) -> None:
        self.bridge_script = bridge_script or (Path(__file__).parent / "ts_compiler_bridge.js")

    def index_project(self, source_dir: Path) -> TSProjectIndex:
        root = source_dir.resolve()
        proc = subprocess.run(
            ["node", str(self.bridge_script.resolve()), str(root)],
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
            errors="replace",
        )
        raw_data: Dict[str, Any] = json.loads(proc.stdout)
        index = TSProjectIndex(root_dir=root)

        for rel_path, file_payload in raw_data.items():
            functions: Dict[str, TSFunctionSymbol] = {}
            for fn_name, fn_data in file_payload.get("functions", {}).items():
                functions[fn_name] = TSFunctionSymbol(
                    name=fn_data["name"],
                    file=rel_path,
                    start_line=fn_data["start_line"],
                    end_line=fn_data["end_line"],
                    params=fn_data.get("params", []),
                    calls=fn_data.get("calls", []),
                    is_default_export=fn_data.get("is_default_export", False),
                )

            index.files[rel_path] = TSFileContext(
                rel_path=rel_path,
                imports=file_payload.get("imports", {}),
                functions=functions,
                mounts=file_payload.get("mounts", []),
                routes=file_payload.get("routes", []),
            )

        return index
