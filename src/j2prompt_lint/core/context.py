from __future__ import annotations
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
import jinja2
from jinja2 import nodes
from j2prompt_lint.core.dataflow import context_read_lines
from j2prompt_lint.core.directives import NO_DIRECTIVES, Directives, parse_directives
from j2prompt_lint.core.variables import undeclared_candidates
MARKDOWN_SUFFIXES: tuple[str, ...] = ('.md', '.markdown')

def is_markdown(path: Path) -> bool:
    return path.suffix.lower() in MARKDOWN_SUFFIXES

@dataclass(frozen=True, slots=True)
class ParseError:
    file: str
    line: int
    message: str

@dataclass(frozen=True, slots=True)
class TemplateContext:
    file: str
    source: str
    ast: nodes.Template
    undeclared: frozenset[str]
    directives: Directives = NO_DIRECTIVES
    markdown: bool = False
    undeclared_lines: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        if frozenset(self.undeclared_lines) != self.undeclared:
            raise ValueError('undeclared_lines must be keyed by exactly the undeclared names')

def build_context(file: str, source: str) -> TemplateContext | ParseError:
    env = jinja2.Environment()
    try:
        ast = env.parse(source)
    except jinja2.TemplateSyntaxError as exc:
        message = exc.message or str(exc)
        return ParseError(file=file, line=exc.lineno or 1, message=message)
    try:
        library = undeclared_candidates(ast)
    except (jinja2.TemplateError, AssertionError):
        library = frozenset()
    lines = context_read_lines(ast, library)
    return TemplateContext(file=file, source=source, ast=ast, undeclared=frozenset(lines), undeclared_lines=lines, directives=parse_directives(source), markdown=is_markdown(Path(file)))

def text_only_context(file: str, source: str) -> TemplateContext:
    return TemplateContext(file=file, source=source, ast=jinja2.Environment().parse(''), undeclared=frozenset(), directives=NO_DIRECTIVES, markdown=True)

def first_load_line(ast: nodes.Template, name: str) -> int:
    for node in ast.find_all(nodes.Name):
        if node.name == name and node.ctx == 'load':
            return node.lineno
    return 1
