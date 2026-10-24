from __future__ import annotations
import os
import re
from pathlib import Path, PurePath
from jinja2 import nodes
from j2prompt_lint.core.context import ParseError, TemplateContext, build_context
MAX_INCLUDE_BYTES = 1 << 20
_PATH_ERRORS = (OSError, ValueError, RuntimeError)
_DEVICE_NAMES = frozenset({'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'} | {f'{port}{digit}' for port in ('COM', 'LPT') for digit in '0123456789¹²³'})
_ASCII_UPPER = str.maketrans('abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')

def _names_a_device(component: str) -> bool:
    stem = component.partition('.')[0].partition(':')[0].rstrip(' ')
    return stem.translate(_ASCII_UPPER) in _DEVICE_NAMES

def _contained(root: Path, target: str) -> bool:
    if PurePath(target).anchor:
        return False
    if any((os.path.splitdrive(part)[0] or _names_a_device(part) for part in re.split('[\\\\/]', target))):
        return False
    base = os.path.abspath(root)
    joined = os.path.abspath(os.path.join(base, target))
    try:
        return os.path.commonpath([base, joined]) == base
    except ValueError:
        return False

def const_target(node: nodes.Node) -> str | None:
    target = getattr(node, 'template', None)
    if isinstance(target, nodes.Const) and isinstance(target.value, str):
        return target.value
    return None

def resolve(file: str, target: str, roots: tuple[Path, ...]) -> Path | None:
    if not target or PurePath(target).anchor:
        return None
    for root in (Path(file).parent, *roots):
        try:
            if not _contained(root, target):
                continue
            candidate = (root / target).resolve()
            if not candidate.is_file():
                continue
            if not candidate.is_relative_to(root.resolve()):
                continue
            if candidate.stat().st_size > MAX_INCLUDE_BYTES:
                continue
        except _PATH_ERRORS:
            continue
        return candidate
    return None

def parse_unit(file: str, target: str, roots: tuple[Path, ...], *, cache: UnitCache | None=None) -> TemplateContext | None:
    if cache is not None:
        return cache.parse(file, target)
    path = resolve(file, target, roots)
    if path is None:
        return None
    return _parse_path(path)

def _parse_path(path: Path) -> TemplateContext | None:
    try:
        source = path.read_bytes().decode('utf-8')
    except _PATH_ERRORS:
        return None
    try:
        ctx = build_context(path.as_posix(), source)
    except RecursionError:
        return None
    if isinstance(ctx, ParseError):
        return None
    return ctx

def crossing_vars(file: str, target: str, roots: tuple[Path, ...], depth: int, seen: frozenset[str]=frozenset(), *, cache: UnitCache | None=None) -> frozenset[str]:
    if depth <= 0:
        return frozenset()
    if not seen:
        return (cache or UnitCache(roots)).crossing(file, target, depth)
    path = resolve(file, target, roots)
    if path is None or path.as_posix() in seen:
        return frozenset()
    ctx = parse_unit(file, target, roots)
    if ctx is None:
        return frozenset()
    out = set(ctx.undeclared)
    seen = seen | {path.as_posix()}
    for sub in ctx.ast.find_all(nodes.Include):
        sub_target = const_target(sub)
        if sub_target:
            out |= crossing_vars(path.as_posix(), sub_target, roots, depth - 1, seen)
    return frozenset(out)

class UnitCache:

    def __init__(self, roots: tuple[Path, ...]) -> None:
        self.roots = roots
        self.paths: dict[tuple[str, str], Path | None] = {}
        self.units: dict[Path, TemplateContext | None] = {}
        self.names: dict[int, frozenset[str]] = {}
        self.children: dict[Path, tuple[Path, ...]] = {}
        self.crossings: dict[tuple[Path, int], frozenset[str]] = {}

    def path(self, file: str, target: str) -> Path | None:
        key = (file, target)
        if key not in self.paths:
            self.paths[key] = resolve(file, target, self.roots)
        return self.paths[key]

    def unit(self, path: Path) -> TemplateContext | None:
        if path not in self.units:
            self.units[path] = _parse_path(path)
        return self.units[path]

    def parse(self, file: str, target: str) -> TemplateContext | None:
        path = self.path(file, target)
        return None if path is None else self.unit(path)

    def macros(self, ctx: TemplateContext) -> frozenset[str]:
        key = id(ctx)
        if key not in self.names:
            self.names[key] = frozenset((m.name for m in ctx.ast.find_all(nodes.Macro)))
        return self.names[key]

    def _children(self, path: Path, ctx: TemplateContext) -> tuple[Path, ...]:
        if path not in self.children:
            found: dict[Path, None] = {}
            for sub in ctx.ast.find_all(nodes.Include):
                target = const_target(sub)
                resolved = self.path(path.as_posix(), target) if target else None
                if resolved is not None:
                    found[resolved] = None
            self.children[path] = tuple(found)
        return self.children[path]

    def crossing(self, file: str, target: str, depth: int) -> frozenset[str]:
        path = self.path(file, target)
        if path is None or depth <= 0:
            return frozenset()
        start = (path, depth)
        stack = [(path, depth, False)]
        while stack:
            current, remaining, ready = stack.pop()
            key = (current, remaining)
            if key in self.crossings:
                continue
            ctx = self.unit(current)
            if ctx is None:
                self.crossings[key] = frozenset()
                continue
            children = self._children(current, ctx) if remaining > 1 else ()
            if not ready and children:
                stack.append((current, remaining, True))
                stack.extend(((child, remaining - 1, False) for child in children))
            else:
                out = set(ctx.undeclared)
                for child in children:
                    out.update(self.crossings[child, remaining - 1])
                self.crossings[key] = frozenset(out)
        return self.crossings[start]
