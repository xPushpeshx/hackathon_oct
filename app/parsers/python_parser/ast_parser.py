# app/parsers/python_parser/ast_parser.py
import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple

IGNORED_DIRS = {".git", ".venv", "venv", "env", "__pycache__", "node_modules", "tests", "test"}


@dataclass
class FunctionSymbol:
    name: str
    file: str                  # Relative POSIX path, e.g. "utils/db.py"
    start_line: int
    end_line: int
    node: ast.AST              # ast.FunctionDef or ast.AsyncFunctionDef


@dataclass
class FileASTContext:
    rel_path: str              # e.g. "routes/orders.py"
    module_name: str           # e.g. "routes.orders"
    tree: ast.Module
    functions: Dict[str, FunctionSymbol] = field(default_factory=dict)
    # Maps local symbol name -> (target_module_dot_path, original_symbol_name)
    imports: Dict[str, Tuple[str, str]] = field(default_factory=dict)


@dataclass
class PythonProjectIndex:
    root_dir: Path
    files: Dict[str, FileASTContext] = field(default_factory=dict)          # rel_path -> FileASTContext
    module_to_file: Dict[str, str] = field(default_factory=dict)            # "utils.db" -> "utils/db.py"
    global_functions: Dict[Tuple[str, str], FunctionSymbol] = field(default_factory=dict)  # (rel_path, fn) -> Symbol
    parse_errors: Dict[str, str] = field(default_factory=dict)

    def resolve_imported_function(self, current_file: str, called_name: str) -> Optional[FunctionSymbol]:
        """Resolves a function call inside current_file to its FunctionSymbol (same-file or imported)."""
        ctx = self.files.get(current_file)
        if not ctx:
            return None

        # 1. Same-file function definition
        if called_name in ctx.functions:
            return ctx.functions[called_name]

        # 2. Direct import: from utils.db import fetch_order
        if called_name in ctx.imports:
            target_mod, orig_name = ctx.imports[called_name]
            target_file = self._resolve_module_path(target_mod)
            if target_file and (target_file, orig_name) in self.global_functions:
                return self.global_functions[(target_file, orig_name)]

        # 3. Module attribute call: db.fetch_order() where `import utils.db as db`
        if "." in called_name:
            prefix, attr = called_name.split(".", 1)
            if prefix in ctx.imports:
                target_mod, orig_target = ctx.imports[prefix]
                full_mod = f"{target_mod}.{orig_target}" if orig_target != "*" else target_mod
                target_file = self._resolve_module_path(full_mod) or self._resolve_module_path(target_mod)
                if target_file and (target_file, attr) in self.global_functions:
                    return self.global_functions[(target_file, attr)]

        return None

    def _resolve_module_path(self, module_dot_path: str) -> Optional[str]:
        if module_dot_path in self.module_to_file:
            return self.module_to_file[module_dot_path]
        # Suffix match in case target app is nested inside a package subfolder
        for mod_key, rel_file in self.module_to_file.items():
            if mod_key.endswith(f".{module_dot_path}") or mod_key == module_dot_path:
                return rel_file
        return None


class PythonASTIndexer:
    """Pass 1: Parses all Python files and indexes functions and imports."""

    def index_project(self, source_dir: Path) -> PythonProjectIndex:
        root = source_dir.resolve()
        index = PythonProjectIndex(root_dir=root)

        for py_file in sorted(root.rglob("*.py")):
            if any(part in IGNORED_DIRS for part in py_file.relative_to(root).parts):
                continue

            rel_path = py_file.relative_to(root).as_posix()
            mod_name = self._path_to_module(rel_path)

            try:
                source_code = py_file.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source_code, filename=rel_path)
            except (OSError, SyntaxError) as exc:
                index.parse_errors[rel_path] = str(exc)
                continue

            file_ctx = FileASTContext(rel_path=rel_path, module_name=mod_name, tree=tree)
            self._extract_imports_and_functions(tree, file_ctx)

            index.files[rel_path] = file_ctx
            index.module_to_file[mod_name] = rel_path
            for fn_name, fn_sym in file_ctx.functions.items():
                index.global_functions[(rel_path, fn_name)] = fn_sym

        return index

    @staticmethod
    def _path_to_module(rel_posix_path: str) -> str:
        no_ext = rel_posix_path[:-3] if rel_posix_path.endswith(".py") else rel_posix_path
        if no_ext.endswith("/__init__"):
            no_ext = no_ext[:-9]
        return no_ext.replace("/", ".")

    def _extract_imports_and_functions(self, tree: ast.Module, file_ctx: FileASTContext) -> None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start_line = node.lineno
                end_line = getattr(node, "end_lineno", start_line)
                # Include decorator lines in the handler range so SAST findings on decorators correlate
                if node.decorator_list:
                    start_line = min(start_line, min(d.lineno for d in node.decorator_list))

                sym = FunctionSymbol(
                    name=node.name,
                    file=file_ctx.rel_path,
                    start_line=start_line,
                    end_line=end_line,
                    node=node,
                )
                file_ctx.functions[node.name] = sym

            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    file_ctx.imports[local_name] = (alias.name, "*")

            elif isinstance(node, ast.ImportFrom):
                base_mod = node.module or ""
                if node.level > 0 and file_ctx.module_name:
                    parts = file_ctx.module_name.split(".")
                    parent_parts = parts[: max(0, len(parts) - node.level)]
                    base_mod = ".".join(parent_parts + ([base_mod] if base_mod else []))

                for alias in node.names:
                    local_name = alias.asname or alias.name
                    file_ctx.imports[local_name] = (base_mod, alias.name)
