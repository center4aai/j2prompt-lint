from __future__ import annotations
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import Enum
from types import MappingProxyType
from jinja2 import nodes
from jinja2.compiler import find_undeclared
__all__ = ['Binder', 'Read', 'context_read_lines', 'context_reads', 'first_unbound_read', 'reads']

class Binder(Enum):
    SET = 'set'
    LOOP_TARGET = 'loop target'
    MACRO_PARAM = 'macro parameter'
    WITH_TARGET = 'with target'

@dataclass(frozen=True, slots=True)
class Read:
    name: str
    lineno: int
    guarded: bool
    assigned: bool
    binder: Binder
    macro: str | None
_EXISTENCE_TESTS = frozenset({'defined', 'undefined'})
_DEFAULTING_FILTERS = frozenset({'default', 'd'})
_SPECIAL_PARAMS = ('caller', 'varargs', 'kwargs')
_NOTHING: frozenset[str] = frozenset()

def _is_existence_probe(node: nodes.Node) -> bool:
    return isinstance(node, nodes.Test) and node.name in _EXISTENCE_TESTS and isinstance(node.node, nodes.Name)

def _is_defaulted(node: nodes.Node) -> bool:
    return isinstance(node, nodes.Filter) and node.name in _DEFAULTING_FILTERS and isinstance(node.node, nodes.Name)

def _existence_refinement(test: nodes.Node) -> tuple[set[str], set[str]]:
    if isinstance(test, nodes.Not):
        then_names, else_names = _existence_refinement(test.node)
        return (else_names, then_names)
    if isinstance(test, nodes.And):
        left_then, left_else = _existence_refinement(test.left)
        right_then, right_else = _existence_refinement(test.right)
        return (left_then | right_then, left_else & right_else)
    if isinstance(test, nodes.Or):
        left_then, left_else = _existence_refinement(test.left)
        right_then, right_else = _existence_refinement(test.right)
        return (left_then & right_then, left_else | right_else)
    if isinstance(test, nodes.Test) and test.name in _EXISTENCE_TESTS and isinstance(test.node, nodes.Name):
        name = {test.node.name}
        return (name, set()) if test.name == 'defined' else (set(), name)
    return (set(), set())

def _expr_loads(node: nodes.Node, known: frozenset[str]=frozenset()) -> list[nodes.Name]:
    if isinstance(node, nodes.Name):
        return [] if node.ctx != 'load' or node.name in known else [node]
    if _is_existence_probe(node):
        return []
    if _is_defaulted(node):
        found = []
        for child in node.iter_child_nodes(exclude=('node',)):
            found.extend(_expr_loads(child, known))
        return found
    if isinstance(node, nodes.And | nodes.Or):
        proved_true, proved_false = _existence_refinement(node.left)
        carried = proved_true if isinstance(node, nodes.And) else proved_false
        return _expr_loads(node.left, known) + _expr_loads(node.right, known | frozenset(carried))
    if isinstance(node, nodes.CondExpr):
        proved_true, proved_false = _existence_refinement(node.test)
        found = _expr_loads(node.test, known)
        found.extend(_expr_loads(node.expr1, known | frozenset(proved_true)))
        if node.expr2 is not None:
            found.extend(_expr_loads(node.expr2, known | frozenset(proved_false)))
        return found
    found = []
    for child in node.iter_child_nodes():
        found.extend(_expr_loads(child, known))
    return found

def _all_loads(node: nodes.Node) -> list[nodes.Name]:
    if isinstance(node, nodes.Name):
        return [node] if node.ctx == 'load' else []
    found = []
    for child in node.iter_child_nodes():
        found.extend(_all_loads(child))
    return found

def _target_names(target: nodes.Node) -> set[str]:
    if isinstance(target, nodes.Name):
        return {target.name}
    return {node.name for node in target.find_all(nodes.Name)}

def _nsrefs(target: nodes.Node) -> list[nodes.NSRef]:
    if isinstance(target, nodes.NSRef):
        return [target]
    return list(target.find_all(nodes.NSRef))

def _calls(node: nodes.Node) -> list[nodes.Call]:
    calls = [node] if isinstance(node, nodes.Call) else []
    calls.extend(node.find_all(nodes.Call))
    return calls

def _macro_calls(node: nodes.Node) -> list[str]:
    called: list[str] = []
    for call in _calls(node):
        callee = call.node
        if isinstance(callee, nodes.Name):
            called.append(callee.name)
        elif isinstance(callee, nodes.Getattr):
            called.append(callee.attr)
    return called

def _assigned_by(target: nodes.Node) -> frozenset[str]:
    if isinstance(target, nodes.Name):
        return frozenset({target.name})
    if isinstance(target, nodes.Tuple):
        return frozenset((node.name for node in target.find_all(nodes.Name)))
    return _NOTHING

def _imported_names(node: nodes.Import | nodes.FromImport) -> frozenset[str]:
    if isinstance(node, nodes.Import):
        return frozenset({node.target})
    return frozenset((name[1] if isinstance(name, tuple) else name for name in node.names))

def _params(node: nodes.Macro | nodes.CallBlock) -> dict[str, Binder]:
    bound = {arg.name: Binder.MACRO_PARAM for arg in node.args}
    for name in find_undeclared(node.body, _SPECIAL_PARAMS):
        bound.setdefault(name, Binder.MACRO_PARAM)
    return bound

def _declares_loop(node: nodes.For) -> bool:
    return node.recursive or 'loop' in find_undeclared(node.body, ('loop',)) or any((block.scoped for block in node.find_all(nodes.Block)))
_FrameId = tuple[int, str]

@dataclass(frozen=True, slots=True)
class _Frame:
    ident: _FrameId
    bound: Mapping[str, Binder]
    assigned: frozenset[str]

@dataclass(frozen=True, slots=True)
class _State:
    frames: tuple[_Frame, ...]
    proved: frozenset[str]
    guarded: bool
    macro: str | None

    @property
    def local(self) -> frozenset[str]:
        return self.frames[-1].assigned

    @property
    def chain(self) -> tuple[_FrameId, ...]:
        return tuple((frame.ident for frame in self.frames))

    def is_assigned(self, name: str) -> bool:
        return name in self.proved or any((name in frame.assigned for frame in self.frames))

    def binder(self, name: str) -> Binder:
        for frame in reversed(self.frames):
            if name in frame.bound:
                return frame.bound[name]
        return Binder.SET

    def with_local(self, assigned: frozenset[str]) -> _State:
        innermost = replace(self.frames[-1], assigned=assigned)
        return replace(self, frames=(*self.frames[:-1], innermost))

    def with_proved(self, proved: frozenset[str]) -> _State:
        return replace(self, proved=proved)

    def with_guarded(self) -> _State:
        return replace(self, guarded=True)

    def enter(self, ident: _FrameId, bound: Mapping[str, Binder]) -> _State:
        return replace(self, frames=(*self.frames, _Frame(ident, bound, _NOTHING)))

    def forgotten(self) -> _State:
        frames = tuple((replace(frame, assigned=_NOTHING) for frame in self.frames))
        return replace(self, frames=frames, proved=_NOTHING)

@dataclass(frozen=True, slots=True)
class _CallSite:
    chain: tuple[_FrameId, ...]
    levels: tuple[frozenset[str], ...]
    proved: frozenset[str]

def _site(state: _State) -> _CallSite:
    return _CallSite(chain=state.chain, levels=tuple((frame.assigned for frame in state.frames)), proved=state.proved)

@dataclass(frozen=True, slots=True)
class _MacroDef:
    node: nodes.Macro
    frames: tuple[_Frame, ...]

    @property
    def chain(self) -> tuple[_FrameId, ...]:
        return tuple((frame.ident for frame in self.frames))
_Entry = tuple[tuple[frozenset[str], ...], frozenset[str]]

def _intersect(entries: list[_Entry]) -> _Entry:
    levels, proved = entries[0]
    for other_levels, other_proved in entries[1:]:
        levels = tuple((a & b for a, b in zip(levels, other_levels, strict=True)))
        proved = proved & other_proved
    return (levels, proved)

class _Walker:

    def __init__(self, targets: frozenset[str], *, lookups: bool) -> None:
        self.targets = targets
        self.lookups = lookups
        self.template_reads: list[Read] = []
        self.sink: list[Read] = self.template_reads
        self.call_sites: dict[str, list[_CallSite]] = {}
        self.macros: dict[int, _MacroDef] = {}
        self.macro_reads: dict[int, list[Read]] = {}

    def _record(self, name: str, lineno: int, state: _State) -> None:
        if name not in self.targets:
            return
        self.sink.append(Read(name=name, lineno=lineno, guarded=state.guarded, assigned=state.is_assigned(name), binder=state.binder(name), macro=state.macro))

    def _read(self, node: nodes.Node, state: _State) -> None:
        loads = _all_loads(node) if self.lookups else _expr_loads(node)
        for name_node in loads:
            self._record(name_node.name, name_node.lineno, state)
        for macro_name in _macro_calls(node):
            self.call_sites.setdefault(macro_name, []).append(_site(state))

    def _read_target(self, target: nodes.Node, state: _State) -> None:
        for ref in _nsrefs(target):
            self._record(ref.name, ref.lineno, state)

    def _refine(self, test: nodes.Node) -> tuple[set[str], set[str]]:
        if self.lookups:
            return (set(), set())
        return _existence_refinement(test)

    def block(self, body: list[nodes.Node], state: _State) -> _State:
        for node in body:
            state = self._statement(node, state)
        return state

    def _statement(self, node: nodes.Node, state: _State) -> _State:
        if isinstance(node, nodes.Assign):
            self._read(node.node, state)
            self._read_target(node.target, state)
            return state.with_local(state.local | _assigned_by(node.target))
        if isinstance(node, nodes.AssignBlock):
            self._filtered_body(node, state)
            self._read_target(node.target, state)
            return state.with_local(state.local | _assigned_by(node.target))
        if isinstance(node, nodes.If):
            return self._if(node, state)
        if isinstance(node, nodes.Macro):
            self.macros[id(node)] = _MacroDef(node, state.frames)
            return state.with_local(state.local | {node.name})
        if isinstance(node, nodes.Import | nodes.FromImport):
            self._read(node.template, state)
            return state.with_local(state.local | _imported_names(node))
        if isinstance(node, nodes.For):
            self._for(node, state)
        elif isinstance(node, nodes.With):
            self._with(node, state)
        elif isinstance(node, nodes.CallBlock):
            self._call_block(node, state)
        elif isinstance(node, nodes.FilterBlock):
            self._filtered_body(node, state)
        elif isinstance(node, nodes.Block):
            self._block_statement(node, state)
        elif isinstance(node, nodes.Output | nodes.ExprStmt):
            self._read(node, state)
        else:
            self._other(node, state)
        return state

    def _other(self, node: nodes.Node, state: _State) -> None:
        for child in node.iter_child_nodes(exclude=('body',)):
            self._read(child, state)
        inner = getattr(node, 'body', None)
        if isinstance(inner, list):
            self.block(inner, state.enter((id(node), 'body'), {}))

    def _with(self, node: nodes.With, state: _State) -> None:
        for value in node.values:
            self._read(value, state)
        names = {name for target in node.targets for name in _target_names(target)}
        bound = dict.fromkeys(names, Binder.WITH_TARGET)
        self.block(node.body, state.enter((id(node), 'body'), bound))

    def _call_block(self, node: nodes.CallBlock, state: _State) -> None:
        self._read(node.call, state)
        outer = state.forgotten() if self.lookups else state
        inner = outer.enter((id(node), 'body'), _params(node))
        for default in node.defaults:
            self._read(default, inner)
        self.block(node.body, inner)

    def _filtered_body(self, node: nodes.FilterBlock | nodes.AssignBlock, state: _State) -> None:
        end = self.block(node.body, state.enter((id(node), 'body'), {}))
        if node.filter is not None:
            self._read(node.filter, end)

    def _block_statement(self, node: nodes.Block, state: _State) -> None:
        ident = (id(node), 'block')
        if self.lookups:
            fresh = _State(frames=(_Frame(ident, {}, _NOTHING),), proved=_NOTHING, guarded=False, macro=state.macro)
            self.block(node.body, fresh)
        else:
            self.block(node.body, state.enter(ident, {}))

    def _if(self, node: nodes.If, state: _State) -> _State:
        self._read(node.test, state)
        guarded = state.with_guarded()
        then_names, else_names = self._refine(node.test)
        carried = frozenset(state.proved)
        ends = [self.block(node.body, guarded.with_proved(carried | then_names))]
        carried |= else_names
        for elif_ in node.elif_:
            self._read(elif_.test, guarded.with_proved(carried))
            elif_then, elif_else = self._refine(elif_.test)
            at_body = guarded.with_proved(carried | elif_then)
            ends.append(self.block(elif_.body, at_body))
            carried |= elif_else
        ends.append(self.block(node.else_, guarded.with_proved(carried)))
        assigned = frozenset.intersection(*(end.local for end in ends))
        known = frozenset.intersection(*(end.local | end.proved for end in ends))
        return state.with_local(assigned).with_proved(known)

    def _for(self, node: nodes.For, state: _State) -> None:
        self._read(node.iter, state)
        targets = dict.fromkeys(_target_names(node.target), Binder.LOOP_TARGET)
        closure = state.forgotten() if self.lookups and node.recursive else state
        if node.test is not None:
            self._read(node.test, closure.enter((id(node), 'test'), targets))
        bound = dict(targets)
        if _declares_loop(node):
            bound['loop'] = Binder.LOOP_TARGET
        self.block(node.body, closure.enter((id(node), 'body'), bound))
        if node.else_:
            self.block(node.else_, closure.enter((id(node), 'else'), {}))

    def _entry(self, macro: _MacroDef) -> _Entry | None:
        depth = len(macro.frames)
        nothing: _Entry = ((_NOTHING,) * depth, _NOTHING)
        if self.lookups:
            return nothing
        sites = self.call_sites.get(macro.node.name, [])
        if not sites:
            return None
        return _intersect([(site.levels[:depth], site.proved) if site.chain[:depth] == macro.chain else nothing for site in sites])

    def macro_pass(self) -> None:
        walked: dict[int, _Entry] = {}
        changed = True
        while changed:
            changed = False
            for key, macro in list(self.macros.items()):
                entry = self._entry(macro)
                if entry is None or walked.get(key) == entry:
                    continue
                walked[key] = entry
                self._walk_macro(key, macro, entry)
                changed = True

    def _walk_macro(self, key: int, macro: _MacroDef, entry: _Entry) -> None:
        levels, proved = entry
        frames = tuple((replace(frame, assigned=assigned) for frame, assigned in zip(macro.frames, levels, strict=True)))
        state = _State(frames=(*frames, _Frame((key, 'body'), _params(macro.node), _NOTHING)), proved=proved, guarded=False, macro=macro.node.name)
        self.macro_reads[key] = self.sink = []
        try:
            for child in macro.node.iter_child_nodes(exclude=('body', 'args')):
                self._read(child, state)
            self.block(macro.node.body, state)
        finally:
            self.sink = self.template_reads

    def run(self, ast: nodes.Template) -> tuple[Read, ...]:
        root = _State(frames=(_Frame((id(ast), 'root'), {}, _NOTHING),), proved=_NOTHING, guarded=False, macro=None)
        self.block(ast.body, root)
        self.macro_pass()
        ordered = sorted(self.macro_reads, key=lambda key: self.macros[key].node.lineno)
        return (*self.template_reads, *(read for key in ordered for read in self.macro_reads[key]))

def reads(ast: nodes.Template, targets: frozenset[str]) -> tuple[Read, ...]:
    return _Walker(targets, lookups=False).run(ast)

def context_read_lines(ast: nodes.Template, names: Iterable[str]) -> Mapping[str, int]:
    tracked = frozenset(names)
    lines: dict[str, int] = {}
    if tracked:
        for read in _Walker(tracked, lookups=True).run(ast):
            if read.binder is Binder.SET and (not read.assigned):
                lines[read.name] = min(read.lineno, lines.get(read.name, read.lineno))
    return MappingProxyType(lines)

def context_reads(ast: nodes.Template, names: Iterable[str]) -> frozenset[str]:
    return frozenset(context_read_lines(ast, names))

def first_unbound_read(reads_: tuple[Read, ...], name: str) -> Read | None:
    candidates = [read for read in reads_ if read.name == name and read.binder is Binder.SET and (not read.assigned)]
    if not candidates:
        return None
    return min(candidates, key=lambda read: read.lineno)
