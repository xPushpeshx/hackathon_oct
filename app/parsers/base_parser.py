# app/parsers/base_parser.py
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Literal
from app.schemas.route import NormalizedRoute


class BaseSourceParser(ABC):
    """Abstract adapter that all language-specific source parsers must implement."""

    @abstractmethod
    def parse_project(self, source_dir: Path) -> List[NormalizedRoute]:
        """Runs the 3-pass AST & Route Mapping pipeline on source_dir."""
        raise NotImplementedError


def get_parser(language: Literal["python", "javascript", "typescript"]) -> BaseSourceParser:
    """Factory returning the appropriate language parser adapter."""
    lang = language.lower().strip()
    if lang == "python":
        from app.parsers.python_parser import PythonSourceParser
        return PythonSourceParser()
    if lang in ("javascript", "typescript", "js", "ts", "express"):
        from app.parsers.javascript_parser import JavascriptSourceParser
        return JavascriptSourceParser()
    raise ValueError(f"Unsupported parser language: {language}")
