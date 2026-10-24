from __future__ import annotations
import dataclasses
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from pathlib import Path
from jinja2 import nodes
from j2prompt_lint.core.config import LintConfig
from j2prompt_lint.core.context import TemplateContext
from j2prompt_lint.core.model import Diagnostic, PinjCheckState, RuleId
from j2prompt_lint.core.subcodes import ONLY, anchor_for, render, severity_for
from j2prompt_lint.rules.pchat import _PACKS, ChatPack
from j2prompt_lint.rules.pinj_resolve import UnitCache, const_target, crossing_vars, parse_unit, resolve
_SCOPE_REF = 'rules.PINJ.scope'
PINJ_SCOPE = 'PINJ flags template positions where untrusted variables reach instruction contexts — an over-approximation of prompt-injection enabling patterns — and certifies neither the presence nor the absence of an exploitable attack.'
_OPEN_TAG = re.compile('<([A-Za-z][\\w-]*)>\\s*$')
_ROLE_RE = re.compile('<\\|im_start\\|>\\s*(\\w+)|<\\|start_header_id\\|>\\s*(\\w+)\\s*<\\|end_header_id\\|>|<\\|(system|user|assistant)\\|>|(<<SYS>>)|(<\\|im_end\\|>|<\\|eot_id\\|>|<\\|end\\|>|<</SYS>>|\\[/INST\\])|(\\[INST\\])')
_NON_PACK_MARKERS: tuple[str, ...] = ('<<SYS>>',)
_CHAT_MARKERS: tuple[str, ...] = tuple(sorted({marker for pack in _PACKS for marker in pack.open_markers}.union(_NON_PACK_MARKERS)))
_SINK_META: dict[str, tuple[str, int]] = {'s1-chat-system': ('taint-surface', 1), 's2-named-instruction': ('taint-surface', 1), 'tier2-whole-prompt': ('taint-surface-whole-prompt', 2), 'cross-template': ('cross-template-surface', 1), 'dynamic-role': ('dynamic-role-surface', 1)}
_VAR_BEARING_SUB_CODES: frozenset[str] = frozenset({'taint-surface', 'taint-surface-whole-prompt', 'dynamic-role-surface'})
_BASIS_ANNOTATION = 'j2pl-annotation'
_BASIS_LEXICON = 'untrusted-lexicon'
_BASIS_UNDECLARED = 'undeclared-default'
_BASIS_PROPAGATED = 'propagated'

def _sink_message(sub_code: str, sink_kind: str, label: str, include_path: str | None) -> tuple[str, dict[str, object]]:
    if sub_code == 'taint-surface-whole-prompt':
        return render(RuleId.PINJ, sub_code, untrusted_var=label)
    if sub_code == 'cross-template-surface':
        return render(RuleId.PINJ, sub_code, ONLY, include_path=include_path)
    if sub_code == 'dynamic-role-surface':
        return render(RuleId.PINJ, sub_code, untrusted_var=label)
    return render(RuleId.PINJ, sub_code, ONLY, untrusted_var=label, sink_kind=sink_kind)

def _reachable(node: nodes.Node) -> Iterator[nodes.Node]:
    yield node
    if isinstance(node, nodes.Name):
        return
    children: Sequence[nodes.Node | None]
    if isinstance(node, nodes.CondExpr):
        children = (node.expr1, node.expr2)
    elif isinstance(node, nodes.If):
        children = [*node.body, *node.elif_, *node.else_]
    elif isinstance(node, nodes.For):
        children = [node.target, node.iter, *node.body, *node.else_]
    elif isinstance(node, nodes.Getitem):
        children = (node.node,)
    elif isinstance(node, nodes.Call):
        callee = [] if isinstance(node.node, nodes.Name) else [node.node]
        children = [*callee, *node.args, *node.kwargs, node.dyn_args, node.dyn_kwargs]
    else:
        children = list(node.iter_child_nodes())
    for child in children:
        if child is not None:
            yield from _reachable(child)

def _name_nodes(node: nodes.Node) -> list[nodes.Name]:
    return [n for n in _reachable(node) if isinstance(n, nodes.Name)]

def _refs_tainted(node: nodes.Node, tainted: AbstractSet[str], cleared: AbstractSet[int]=frozenset()) -> bool:
    return any((name.name in tainted and id(name) not in cleared for name in _name_nodes(node)))
_MacroMap = Mapping[str, tuple[nodes.Macro, ...]]
_SUPPLIED_CALLABLES: frozenset[str] = frozenset({'caller', 'namespace', 'range', 'dict', 'lipsum', 'cycler', 'joiner', 'super', 'loop', 'varargs', 'kwargs', 'raise_exception', 'strftime_now', 'self'})
_CALLEE_PATH = (nodes.Getattr, nodes.Getitem, nodes.Call, nodes.Filter)
_MAX_MACRO_WORK = 200000

class _MacroWorkExhausted(Exception):
    pass

class _MacroWork:

    def __init__(self) -> None:
        self.spent = 0
        self.by_kind: dict[str, int] = {}

    def charge(self, amount: int, kind: str) -> None:
        if amount > _MAX_MACRO_WORK - self.spent:
            raise _MacroWorkExhausted(kind)
        self.spent += amount
        self.by_kind[kind] = self.by_kind.get(kind, 0) + amount

class _Macros(dict[str, tuple[nodes.Macro, ...]]):

    def __init__(self, definitions: Mapping[str, tuple[nodes.Macro, ...]], escaping: tuple[nodes.Macro, ...]=(), supplied: frozenset[str]=frozenset(), rebound: frozenset[str]=frozenset(), *, following: bool=True) -> None:
        super().__init__(definitions)
        self.escaping = escaping
        self.supplied = supplied
        self.rebound = rebound
        self.following = following
        self.work = _MacroWork() if following else None
        self._union: _Union | None = None
        self._groups: dict[int, _Union] = {}
        self._signatures: dict[int, _Signature] = {}
        self._bindings: dict[tuple[int, int, tuple[str, ...], bool, bool], tuple[frozenset[str], dict[str, nodes.Expr]]] = {}
        self._callers: dict[int, tuple[tuple[nodes.Call, ...], bool]] = {}
        self._caller_groups: dict[int, tuple[tuple[nodes.Call, ...], bool]] = {}
        self._resolved: dict[tuple[int, bool], tuple[nodes.Macro, ...]] = {}

    def charge(self, amount: int, kind: str) -> None:
        if self.work is not None:
            self.work.charge(amount, kind)

    def signature(self, macro: nodes.Macro | nodes.CallBlock) -> _Signature:
        key = id(macro)
        if key not in self._signatures:
            self.charge(len(macro.args) + len(macro.defaults), 'signature')
            self._signatures[key] = _Signature(macro)
        return self._signatures[key]

    def binding(self, macro: nodes.Macro, call: nodes.Call) -> tuple[frozenset[str], dict[str, nodes.Expr]]:
        key = (id(macro), len(call.args), tuple((kw.key for kw in call.kwargs)), call.dyn_args is not None, call.dyn_kwargs is not None)
        if key not in self._bindings:
            signature = self.signature(macro)
            self.charge(len(signature.params), 'call-binding')
            self._bindings[key] = _call_binding(macro, call, signature)
        return self._bindings[key]

    def caller(self, macro: nodes.Macro) -> tuple[tuple[nodes.Call, ...], bool]:
        if not self.following:
            return ((), False)
        key = id(macro)
        if key not in self._callers:
            self._callers[key] = _caller_calls(macro, self)
        return self._callers[key]

    def callers(self, definitions: tuple[nodes.Macro, ...]) -> tuple[nodes.Call, ...]:
        key = id(definitions)
        if key not in self._caller_groups:
            self.charge(len(definitions), 'caller-definitions')
            calls: list[nodes.Call] = []
            escapes = False
            for macro in definitions:
                own, escaped = self.caller(macro)
                escapes = escapes or escaped
                self.charge(len(own), 'caller-group')
                calls.extend(own)
            self._caller_groups[key] = (tuple(calls), escapes)
        return self._caller_groups[key][0]

    def caller_escapes(self, definitions: tuple[nodes.Macro, ...]) -> bool:
        self.callers(definitions)
        return self._caller_groups[id(definitions)][1]

    def resolve_parts(self, callee: nodes.Node) -> tuple[tuple[nodes.Macro, ...], bool]:
        if isinstance(callee, nodes.Name):
            found = super().get(callee.name)
            if found is not None:
                return (found, bool(self.escaping) and callee.name in self.rebound)
            supplied = callee.name in self.supplied and callee.name not in self.rebound and (callee.name not in {'varargs', 'kwargs'})
            return ((), bool(self.escaping) and (not supplied))
        if not self.escaping:
            return ((), False)
        root = callee.node if isinstance(callee, nodes.Getattr) else None
        supplied = isinstance(root, nodes.Name) and root.name in self.supplied and (root.name not in self.rebound) and (root.name not in {'varargs', 'kwargs'}) and (not (root.name == 'loop' and isinstance(callee, nodes.Getattr) and (callee.attr in {'previtem', 'nextitem'})))
        return ((), not supplied)

    def targets(self, callee: nodes.Node) -> tuple[nodes.Macro, ...]:
        direct, escapes = self.resolve_parts(callee)
        if not escapes:
            return direct
        key = (id(direct), escapes)
        if key not in self._resolved:
            self.charge(len(direct) + len(self.escaping), 'resolved-definitions')
            merged = {id(macro): macro for macro in (*direct, *self.escaping)}
            self._resolved[key] = tuple(merged.values())
        return self._resolved[key]

    def union(self) -> _Union:
        if self._union is None:
            self._union = self.group(self.escaping)
        return self._union

    def group(self, definitions: tuple[nodes.Macro, ...]) -> _Union:
        key = id(definitions)
        if key not in self._groups:
            self.charge(len(definitions), 'definition-group')
            positions: list[dict[str, None]] = []
            slots: list[list[tuple[int, str]]] = []
            by_name: dict[str, list[int]] = {}
            for macro in definitions:
                for index, name in enumerate(self.signature(macro).params):
                    if index == len(positions):
                        positions.append({})
                        slots.append([])
                    positions[index][name] = None
                    slots[index].append((id(macro), name))
                    by_name.setdefault(name, []).append(id(macro))
            self._groups[key] = _Union(definitions, tuple((tuple(position) for position in positions)), tuple((tuple(slot) for slot in slots)), {name: tuple(ids) for name, ids in by_name.items()}, frozenset(by_name), tuple(by_name), key)
        return self._groups[key]

@dataclass(frozen=True, slots=True)
class _Union:
    macros: tuple[nodes.Macro, ...]
    positions: tuple[tuple[str, ...], ...]
    slots: tuple[tuple[tuple[int, str], ...], ...]
    by_name: Mapping[str, tuple[int, ...]]
    declared: frozenset[str]
    names: tuple[str, ...]
    ident: int

def _resolve(macros: _MacroMap, callee: nodes.Node) -> tuple[nodes.Macro, ...]:
    if isinstance(macros, _Macros):
        return macros.targets(callee)
    if isinstance(callee, nodes.Name):
        return macros.get(callee.name, ())
    return ()

def _resolve_parts(macros: _MacroMap, callee: nodes.Node) -> tuple[tuple[nodes.Macro, ...], bool]:
    if isinstance(macros, _Macros):
        return macros.resolve_parts(callee)
    if isinstance(callee, nodes.Name):
        return (macros.get(callee.name, ()), False)
    return ((), False)

def _escaping(macros: _MacroMap) -> tuple[nodes.Macro, ...]:
    return macros.escaping if isinstance(macros, _Macros) else ()

def _macro_map(ast: nodes.Template, *, following: bool=True) -> _Macros:
    macros: dict[str, list[nodes.Macro]] = {}
    callees: set[int] = set()
    imported: set[str] = set()
    names: list[nodes.Name] = []
    kinds = (nodes.Macro, nodes.Call, nodes.Name, nodes.FromImport, nodes.Import)
    for node in _find(ast, kinds):
        if isinstance(node, nodes.Macro):
            macros.setdefault(node.name, []).append(node)
        elif isinstance(node, nodes.Call):
            callees.add(id(node.node))
        elif isinstance(node, nodes.Name):
            names.append(node)
        elif isinstance(node, nodes.FromImport):
            imported.update((str(name[1] if isinstance(name, tuple) else name) for name in node.names))
        elif isinstance(node, nodes.Import):
            imported.add(node.target)
    escaping = tuple((macro for name in dict.fromkeys((node.name for node in names if node.ctx == 'load' and node.name in macros and (id(node) not in callees))) for macro in macros[name]))
    rebound = frozenset((node.name for node in names if node.ctx != 'load'))
    return _Macros({name: tuple(definitions) for name, definitions in macros.items()}, escaping, _SUPPLIED_CALLABLES | imported, rebound, following=following)
_IMPLICIT_MACRO_LOCALS: frozenset[str] = frozenset({'varargs', 'kwargs', 'caller'})
_MAX_MACRO_EVALUATIONS = 256
_MAX_MACRO_DEPTH = 24
_MAX_ESCAPING_PAIRS = 10000

def _macro_parameters(macro: nodes.Macro) -> frozenset[str]:
    return frozenset((param.name for param in macro.args)) | _IMPLICIT_MACRO_LOCALS

class _Signature:

    def __init__(self, macro: nodes.Macro | nodes.CallBlock) -> None:
        self.params = tuple((param.name for param in macro.args))
        self.declared = frozenset(self.params)
        self.parameters = self.declared | _IMPLICIT_MACRO_LOCALS
        offset = len(self.params) - len(macro.defaults)
        self.defaults = dict(zip(self.params[offset:], macro.defaults, strict=True))

def _call_binding(macro: nodes.Macro, call: nodes.Call, signature: _Signature | None=None) -> tuple[frozenset[str], dict[str, nodes.Expr]]:
    signature = signature or _Signature(macro)
    params = signature.params
    if call.dyn_args is not None or call.dyn_kwargs is not None:
        bound = set(params)
        omitted = set(params)
    else:
        bound = set(params[:len(call.args)])
        bound.update((kw.key for kw in call.kwargs if kw.key in signature.declared))
        omitted = set(params) - bound
    defaults = {param: default for param, default in signature.defaults.items() if param in omitted}
    return (frozenset(bound), defaults)

def _emitted_values(statements: Sequence[nodes.Node], wrapped: AbstractSet[int]=frozenset()) -> Iterator[nodes.Node]:
    for statement in statements:
        if id(statement) in wrapped:
            continue
        if isinstance(statement, nodes.Output):
            yield from statement.nodes
        elif isinstance(statement, nodes.If):
            branches = [*statement.body, *statement.elif_, *statement.else_]
            yield from _emitted_values(branches, wrapped)
        elif isinstance(statement, nodes.For):
            yield from _emitted_values([*statement.body, *statement.else_], wrapped)
        elif isinstance(statement, nodes.With | nodes.Scope | nodes.OverlayScope | nodes.ScopedEvalContextModifier | nodes.Block):
            yield from _emitted_values(statement.body, wrapped)
        elif isinstance(statement, nodes.FilterBlock):
            yield statement.filter
            yield from _emitted_values(statement.body, wrapped)
        elif isinstance(statement, nodes.CallBlock):
            yield statement.call
            yield from _emitted_values(statement.body, wrapped)

def _shadowed(macro: nodes.Macro) -> frozenset[str]:
    read: set[str] = set()
    uncovered: set[str] = set()

    def statements(body: Sequence[nodes.Node], covered: frozenset[str]) -> None:
        local = set(covered)
        for statement in body:
            walk(statement, frozenset(local))
            if isinstance(statement, nodes.Assign | nodes.AssignBlock) and (not isinstance(statement.target, nodes.NSRef)):
                local.update(_bound_names(statement.target))

    def walk(node: nodes.Node, covered: frozenset[str]) -> None:
        if isinstance(node, nodes.Name):
            if node.ctx == 'load':
                read.add(node.name)
                if node.name not in covered:
                    uncovered.add(node.name)
            return
        if isinstance(node, nodes.Macro):
            for name in node.find_all(nodes.Name):
                if name.ctx == 'load':
                    read.add(name.name)
                    uncovered.add(name.name)
            return
        if isinstance(node, nodes.For):
            walk(node.iter, covered)
            inner = covered | frozenset(_bound_names(node.target))
            if node.test is not None:
                walk(node.test, inner)
            statements(node.body, inner)
            statements(node.else_, covered)
            return
        if isinstance(node, nodes.If):
            walk(node.test, covered)
            statements(node.body, covered)
            for branch in node.elif_:
                walk(branch, covered)
            statements(node.else_, covered)
            return
        if isinstance(node, nodes.With):
            for value in node.values:
                walk(value, covered)
            targets = frozenset((n for t in node.targets for n in _bound_names(t)))
            statements(node.body, covered | targets)
            return
        if isinstance(node, nodes.CallBlock):
            walk(node.call, covered)
            for default in node.defaults:
                walk(default, covered)
            statements(node.body, covered | frozenset((p.name for p in node.args)))
            return
        body = getattr(node, 'body', None)
        if isinstance(body, list):
            for field in node.fields:
                if field == 'body':
                    continue
                attribute = getattr(node, field, None)
                items = attribute if isinstance(attribute, list) else [attribute]
                for item in items:
                    if isinstance(item, nodes.Node):
                        walk(item, covered)
            statements(body, covered)
            return
        for descendant in node.iter_child_nodes():
            walk(descendant, covered)
    for default in macro.defaults:
        walk(default, frozenset())
    statements(macro.body, frozenset())
    return frozenset(read - uncovered)

class _MacroReturns:

    def __init__(self, macros: _MacroMap, cleared: AbstractSet[int]=frozenset(), wrapped: AbstractSet[int]=frozenset()) -> None:
        self.macros = macros
        self.cleared = cleared
        self.wrapped = wrapped
        self.template: AbstractSet[str] = frozenset()
        self.seeds: frozenset[str] = frozenset()
        self.stores: Mapping[int, _Store] = {}
        self.flat: AbstractSet[str] = frozenset()
        self.rooted: frozenset[int] = frozenset()
        self._memo: dict[tuple[int, frozenset[str], frozenset[str], frozenset[str], frozenset[str]], bool] = {}
        self._environments: dict[tuple[int, frozenset[str], frozenset[str], frozenset[str], frozenset[str]], frozenset[str]] = {}
        self._closures: dict[int, tuple[frozenset[str], frozenset[str]]] = {}
        self._directs: dict[int, tuple[frozenset[str], tuple[nodes.Macro, ...]]] = {}
        self._reached_macros: dict[int, tuple[nodes.Macro, ...]] = {}
        self._rooted_closures: dict[int, bool] = {}
        self._states: dict[tuple[int, frozenset[str], frozenset[str], frozenset[str], frozenset[str]], frozenset[str]] = {}
        self._restrictions: dict[int, tuple[tuple[int, int], frozenset[str], frozenset[str]]] = {}
        self._declared_seeds: dict[int, frozenset[str]] = {}
        self._default_keys: dict[int, frozenset[str]] = {}
        self._sizes: dict[int, int] = {}
        self._shadows: dict[int, frozenset[str]] = {}
        self._macro_sites: dict[int, _BindingSites] = {}
        self._budget = _MAX_MACRO_EVALUATIONS
        self._depth = 0
        self._escaping = _escaping(macros)
        self.escaping_pairs_left = _MAX_ESCAPING_PAIRS
        self._coarse_memo: tuple[tuple[int, int, int], bool] | None = None
        self._escaping_names: frozenset[str] | None = None

    def _charge(self, amount: int, kind: str) -> None:
        if isinstance(self.macros, _Macros):
            self.macros.charge(amount, kind)

    def calls(self, node: nodes.Node, excluded: AbstractSet[str]=frozenset()) -> Iterator[tuple[nodes.Call, nodes.Macro | None]]:
        if isinstance(self.macros, _Macros) and (not self.macros.following):
            return
        for candidate in _reachable(node):
            if not isinstance(candidate, nodes.Call):
                continue
            direct, escapes = _resolve_parts(self.macros, candidate.node)
            if len(direct) > 1:
                self._charge(len(direct), 'value-definitions')
            for macro in direct:
                if macro.name not in excluded:
                    yield (candidate, macro)
            if not escapes:
                continue
            if self.escaping_pairs_left < len(self._escaping):
                yield (candidate, None)
                continue
            self.escaping_pairs_left -= len(self._escaping)
            for macro in self._escaping:
                if macro.name not in excluded and all((macro is not d for d in direct)):
                    yield (candidate, macro)

    def _closure(self, macro: nodes.Macro) -> tuple[frozenset[str], frozenset[str]]:
        cached = self._closures.get(id(macro))
        if cached is not None:
            return cached
        names: set[str] = set()
        called: set[str] = set()
        seen: dict[int, nodes.Macro] = {}
        stack = [macro]
        while stack:
            current = stack.pop()
            if id(current) in seen:
                continue
            seen[id(current)] = current
            own, callees = self._direct(current)
            self._charge(len(own) + len(callees), 'closure')
            names.update(own)
            called.update((callee.name for callee in callees))
            stack.extend(callees)
        result = (frozenset(names), frozenset(called))
        self._closures[id(macro)] = result
        self._reached_macros[id(macro)] = tuple(seen.values())
        return result

    def _direct(self, macro: nodes.Macro) -> tuple[frozenset[str], tuple[nodes.Macro, ...]]:
        cached = self._directs.get(id(macro))
        if cached is None:
            names: set[str] = set()
            callees: dict[int, nodes.Macro] = {}
            escapes = False
            size = 0
            for node in _work_find(macro, nodes.Node, self.macros, 'direct-walk'):
                size += 1
                if isinstance(node, nodes.Name):
                    names.add(node.name)
                elif isinstance(node, nodes.Call):
                    direct, through = _resolve_parts(self.macros, node.node)
                    self._charge(len(direct), 'direct-callees')
                    for callee in direct:
                        callees.setdefault(id(callee), callee)
                    escapes = escapes or through
            if escapes:
                self._charge(len(self._escaping), 'direct-escaping')
                for callee in self._escaping:
                    callees.setdefault(id(callee), callee)
            cached = (frozenset(names), tuple(callees.values()))
            self._directs[id(macro)] = cached
            self._sizes[id(macro)] = size
        return cached

    def guard(self, macro: nodes.Macro, excluded: AbstractSet[str]) -> frozenset[str]:
        _, called = self._closure(macro)
        self._charge(len(excluded), 'guard')
        return frozenset((name for name in excluded if name in called))

    def _shadowed(self, macro: nodes.Macro) -> frozenset[str]:
        cached = self._shadows.get(id(macro))
        if cached is None:
            self._charge(self._sizes[id(macro)], 'shadow-walk')
            cached = _shadowed(macro)
            self._shadows[id(macro)] = cached
        return cached

    def refs_tainted(self, node: nodes.Node, tainted: AbstractSet[str], excluded: AbstractSet[str]=frozenset()) -> bool:
        if _refs_tainted(node, tainted, self.cleared):
            return True
        return any((self.emits(macro, call, excluded) if macro is not None else self._coarse() for call, macro in self.calls(node, excluded) if id(call) not in self.cleared))

    def depends_on(self, macro: nodes.Macro | None) -> frozenset[str]:
        if macro is not None:
            if isinstance(self.macros, _Macros) and (not self.macros.following):
                return frozenset()
            names = self._closure(macro)[0]
            self._charge(len(names), 'closure-read')
            return names
        if self._escaping_names is None:
            escaping_names: set[str] = set()
            for escaping in self._escaping:
                own = self._closure(escaping)[0]
                self._charge(len(own), 'closure-read')
                escaping_names.update(own)
            self._escaping_names = frozenset(escaping_names)
        return self._escaping_names

    def _sees_taint(self, macro: nodes.Macro) -> bool:
        names, _ = self._closure(macro)
        self._charge(len(names), 'coarse-restriction')
        return bool(self.seeds & names) or any((name in self.template or name in self.flat for name in names))

    def _coarse(self) -> bool:
        key = (len(self.template), len(self.flat), len(self.seeds))
        if self._coarse_memo is not None and self._coarse_memo[0] == key:
            return self._coarse_memo[1]
        result = any((self._sees_taint(macro) for macro in self._escaping))
        self._coarse_memo = (key, result)
        return result

    def _state(self, macro: nodes.Macro, call: nodes.Call, excluded: AbstractSet[str]) -> tuple[frozenset[str], frozenset[str], frozenset[str], frozenset[str]]:
        scope = self._scope(macro)
        epoch = (len(scope), len(self.template))
        cached = self._restrictions.get(id(macro))
        if cached is None or cached[0] != epoch:
            names, _ = self._closure(macro)
            self._charge(2 * len(names), 'restriction')
            restriction = frozenset((name for name in names if name in scope))
            template = frozenset((name for name in names if name in self.template))
            self._restrictions[id(macro)] = (epoch, restriction, template)
        else:
            _, restriction, template = cached
        guard = self.guard(macro, excluded)
        declared = self._declared_seeds.get(id(macro))
        if declared is None:
            names, _ = self._closure(macro)
            self._charge(min(len(self.seeds), len(names)), 'seed-restriction')
            declared = self.seeds & names
            self._declared_seeds[id(macro)] = declared
        if not restriction and (not declared):
            return (restriction, template, guard, declared)
        _, defaults = self.macros.binding(macro, call) if isinstance(self.macros, _Macros) else _call_binding(macro, call)
        default_key = self._default_keys.get(id(defaults)) if isinstance(self.macros, _Macros) else None
        if default_key is None:
            self._charge(len(defaults), 'default-key')
            default_key = frozenset(defaults)
            if isinstance(self.macros, _Macros):
                self._default_keys[id(defaults)] = default_key
        key = (id(macro), default_key, restriction, template, guard)
        seeded = self._states.get(key)
        if seeded is None:
            inside = guard | {macro.name}
            seeded = frozenset((param for param, default in defaults.items() if self.refs_tainted(default, scope, inside)))
            self._states[key] = seeded
        return (restriction, template, guard, seeded | declared)

    def _scope(self, macro: nodes.Macro) -> AbstractSet[str]:
        rooted = self._rooted_closures.get(id(macro))
        if rooted is None:
            self._closure(macro)
            self._charge(len(self._reached_macros[id(macro)]), 'scope')
            rooted = all((id(reached) in self.rooted for reached in self._reached_macros[id(macro)]))
            self._rooted_closures[id(macro)] = rooted
        return self.template if rooted else self.flat

    def _sites(self, macro: nodes.Macro) -> _BindingSites:
        cached = self._macro_sites.get(id(macro))
        if cached is None:
            self._charge(self._sizes[id(macro)], 'binding-sites')
            cached = _collect_sites(macro, self.macros, _refs_tainted, self.stores, self.depends_on)
            self._macro_sites[id(macro)] = cached
        return cached

    def environment(self, macro: nodes.Macro, call: nodes.Call, excluded: AbstractSet[str]=frozenset()) -> frozenset[str]:
        restriction, template, guard, seeded = self._state(macro, call, excluded)
        if not restriction and (not seeded):
            return frozenset()
        key = (id(macro), seeded, restriction, template, guard)
        cached = self._environments.get(key)
        if cached is not None:
            return cached
        inner = guard | {macro.name}
        sites = dataclasses.replace(self._sites(macro), refs=lambda node, names: self.refs_tainted(node, names, inner))
        parameters = self.macros.signature(macro).parameters if isinstance(self.macros, _Macros) else _macro_parameters(macro)
        seeds = restriction - parameters - self._shadowed(macro)
        result = frozenset(_fixpoint(sites, seeds | seeded))
        self._environments[key] = result
        return result

    def emits(self, macro: nodes.Macro, call: nodes.Call, excluded: AbstractSet[str]=frozenset()) -> bool:
        if self._depth >= _MAX_MACRO_DEPTH:
            return self._sees_taint(macro)
        self._depth += 1
        try:
            return self._emits(macro, call, excluded)
        finally:
            self._depth -= 1

    def _emits(self, macro: nodes.Macro, call: nodes.Call, excluded: AbstractSet[str]) -> bool:
        restriction, template, guard, seeded = self._state(macro, call, excluded)
        if not restriction and (not seeded):
            return False
        key = (id(macro), seeded, restriction, template, guard)
        cached = self._memo.get(key)
        if cached is not None:
            return cached
        if self._budget <= 0:
            result = True
        else:
            self._budget -= 1
            env = self.environment(macro, call, guard)
            inner = guard | {macro.name}
            result = any((self.refs_tainted(value, env, inner) for value in _emitted_values(macro.body, self.wrapped)))
        self._memo[key] = result
        return result

def _bound_names(target: nodes.Node) -> list[str]:
    if isinstance(target, nodes.NSRef):
        return [target.name]
    return [name.name for name in _name_nodes(target)]
_Unit = tuple[tuple[nodes.Node, ...], tuple[str, ...]]

@dataclass(frozen=True, slots=True)
class _BindingSites:
    assigns: tuple[nodes.Assign, ...]
    assign_blocks: tuple[nodes.AssignBlock, ...]
    loops: tuple[nodes.For, ...]
    with_blocks: tuple[nodes.With, ...]
    macro_calls: tuple[tuple[nodes.Call, nodes.Macro], ...]
    signatures: tuple[tuple[list[nodes.Name], list[nodes.Expr]], ...]
    refs: Callable[[nodes.Node, set[str]], bool]
    macro_groups: tuple[tuple[tuple[nodes.Call, ...], _Union], ...] = ()
    caller_bindings: tuple[_CallerBinding, ...] = ()
    stores: tuple[_Store, ...] = ()
    units: tuple[_Unit, ...] = ()
    readers: Mapping[str, tuple[int, ...]] = dataclasses.field(default_factory=dict)
    volatile: tuple[int, ...] = ()
    depends: Mapping[int, tuple[int, ...]] = dataclasses.field(default_factory=dict)
    watch: Mapping[str, tuple[int, ...]] = dataclasses.field(default_factory=dict)
    escaping_calls: tuple[nodes.Call, ...] = ()
    union: _Union | None = None

@dataclass(frozen=True, slots=True)
class _CallerBinding:
    params: tuple[nodes.Name, ...]
    calls: tuple[nodes.Call, ...]
    values: tuple[nodes.Node, ...]

def _caller_calls(macro: nodes.Macro, macros: _Macros | None=None) -> tuple[tuple[nodes.Call, ...], bool]:
    calls: list[nodes.Call] = []
    escapes = False
    stack: list[nodes.Node] = []

    def extend(children: Iterable[nodes.Node]) -> None:
        for child in children:
            if macros is not None:
                macros.charge(1, 'caller-walk')
            stack.append(child)
    extend(macro.defaults)
    extend(macro.body)
    while stack:
        node = stack.pop()
        if isinstance(node, nodes.Macro):
            extend(node.defaults)
            continue
        if isinstance(node, nodes.CallBlock):
            extend((node.call,))
            extend(node.defaults)
            continue
        if isinstance(node, nodes.Name):
            escapes = escapes or (node.name == 'caller' and node.ctx == 'load')
            continue
        if isinstance(node, nodes.Call) and isinstance(node.node, nodes.Name):
            if node.node.name == 'caller':
                calls.append(node)
            extend(node.args)
            extend(node.kwargs)
            extend((child for child in (node.dyn_args, node.dyn_kwargs) if child is not None))
            continue
        extend(node.iter_child_nodes())
    calls.sort(key=lambda call: (call.lineno, id(call)))
    return (tuple(calls), escapes)

def _block_callee(block: nodes.CallBlock, macros: _MacroMap) -> tuple[tuple[nodes.Macro, ...], bool]:
    callee = block.call.node
    local = isinstance(callee, nodes.Name) and callee.name in macros and (callee.name not in getattr(macros, 'rebound', frozenset()))
    return (_resolve(macros, callee), local)

def _find(root: nodes.Node, kinds: type[nodes.Node] | tuple[type[nodes.Node], ...]) -> list[nodes.Node]:
    found: list[nodes.Node] = []
    stack = list(root.iter_child_nodes())
    stack.reverse()
    while stack:
        node = stack.pop()
        if isinstance(node, kinds):
            found.append(node)
        children = list(node.iter_child_nodes())
        children.reverse()
        stack.extend(children)
    return found

def _work_find(root: nodes.Node, kinds: type[nodes.Node], macros: _MacroMap, kind: str) -> Iterator[nodes.Node]:
    stack: list[nodes.Node] = []

    def children(node: nodes.Node) -> None:
        found: list[nodes.Node] = []
        for child in node.iter_child_nodes():
            if isinstance(macros, _Macros):
                macros.charge(1, kind)
            found.append(child)
        stack.extend(reversed(found))
    children(root)
    while stack:
        node = stack.pop()
        if isinstance(node, kinds):
            yield node
        children(node)

def _caller_bindings(blocks: Iterable[nodes.Node], macros: _MacroMap) -> tuple[_CallerBinding, ...]:
    bindings: list[_CallerBinding] = []
    for block in blocks:
        if not isinstance(block, nodes.CallBlock):
            continue
        definitions, local = _block_callee(block, macros)
        if isinstance(macros, _Macros):
            calls = macros.callers(definitions)
            macros.charge(len(calls), 'caller-pairs')
        else:
            calls = tuple((call for macro in definitions for call in _caller_calls(macro)[0]))
        values: tuple[nodes.Node, ...] = ()
        if not local:
            call = block.call
            dynamic = [d for d in (call.dyn_args, call.dyn_kwargs) if d is not None]
            values = (*call.args, *(kw.value for kw in call.kwargs), *dynamic)
        bindings.append(_CallerBinding(tuple(block.args), calls, values))
    return tuple(bindings)

def _caller_seeds(ast: nodes.Template, macros: _MacroMap, imported: Mapping[str, _ImportedUnit]) -> frozenset[str]:
    seeds: set[str] = set()
    for block in _find(ast, nodes.CallBlock):
        if not isinstance(block, nodes.CallBlock):
            continue
        definitions, local = _block_callee(block, macros)
        untrusted = macros.caller_escapes(definitions) if isinstance(macros, _Macros) else any((_caller_calls(macro)[1] for macro in definitions))
        if not local:
            unit = imported.get(_callee_name(block.call) or '')
            untrusted = untrusted or (unit is not None and bool(unit.crossing))
        if untrusted:
            seeds.update((param.name for param in block.args))
            seeds.update(('varargs', 'kwargs'))
    return frozenset(seeds)
_MUTATING_METHODS: frozenset[str] = frozenset({'append', 'extend', 'insert', 'update', 'setdefault', 'add', 'symmetric_difference_update', '__setitem__', '__iadd__', '__ior__', '__ixor__', '__init__'})
_MAX_OBJECT_STEPS = 100000
_SCALAR_NODES: tuple[type[nodes.Node], ...] = (nodes.Const, nodes.TemplateData, nodes.Concat, nodes.Compare, nodes.Not, nodes.Neg, nodes.Pos, nodes.Test, nodes.Sub, nodes.Div, nodes.FloorDiv, nodes.Pow, nodes.Mod, nodes.MarkSafe, nodes.MarkSafeIfAutoescape, nodes.Slice)
_Object = tuple[str, int | str]
_Key = str | tuple[int, str] | tuple[int, str, str]
_Edge = tuple[tuple[_Key, ...], bool, nodes.Node]
_StoreSite = tuple[nodes.Node, tuple[nodes.Node, ...], nodes.Node]

def _key_name(key: _Key) -> str:
    return key if isinstance(key, str) else key[1]

@dataclass(frozen=True, slots=True)
class _Store:
    values: tuple[nodes.Node, ...]
    names: frozenset[str]
    scope: frozenset[str]
_BODY_FRAMES: dict[type[nodes.Node], bool] = {nodes.With: False, nodes.FilterBlock: False, nodes.AssignBlock: False, nodes.ScopedEvalContextModifier: False, nodes.Scope: False, nodes.OverlayScope: False, nodes.Block: True, nodes.Macro: True, nodes.CallBlock: True}

def _own_bindings(statements: Sequence[nodes.Node]) -> frozenset[str]:
    names: set[str] = set()
    stack = list(statements)
    while stack:
        node = stack.pop()
        if isinstance(node, nodes.Assign | nodes.AssignBlock):
            if not isinstance(node.target, nodes.NSRef):
                names.update(_bound_names(node.target))
        elif isinstance(node, nodes.If):
            stack.extend([*node.body, *node.elif_, *node.else_])
        elif not isinstance(node, nodes.For) and type(node) not in _BODY_FRAMES:
            children = node.iter_child_nodes()
            stack.extend((child for child in children if isinstance(child, nodes.Stmt)))
    return frozenset(names)

@dataclass(slots=True)
class _Frame:
    ident: int
    state: dict[str, _Key]
    late: bool
    parent: _Frame | None

class _FrameKeys:

    def __init__(self, ast: nodes.Template) -> None:
        self.keys: dict[int, _Key] = {}
        self.joins: list[tuple[_Key, _Key]] = []
        self._entry: dict[tuple[int, str], _Key] = {}
        self._eithers: set[_Key] = set()
        self._frame: _Frame | None = None
        self._logs: list[dict[str, _Key]] = []
        self.steps = 0
        self._statements(ast.body)

    def _statements(self, statements: Sequence[nodes.Node]) -> None:
        for statement in statements:
            self._statement(statement)

    def _statement(self, node: nodes.Node) -> None:
        if isinstance(node, nodes.Assign):
            self._read(node.node)
            self._bind(node.target)
        elif isinstance(node, nodes.If):
            self._read(node.test)
            branches = [node.body]
            for clause in node.elif_:
                self._read(clause.test)
                branches.append(clause.body)
            self._branches([*branches, node.else_])
        elif isinstance(node, nodes.For):
            self._read(node.iter)
            self._enter(id(node), node.body, [node.target], [node.test], late=False)
            self._enter(id(node.else_), node.else_, [], [], late=False)
        elif isinstance(node, nodes.With):
            for value in node.values:
                self._read(value)
            self._enter(id(node), node.body, node.targets, [], late=False)
        elif isinstance(node, nodes.Macro | nodes.CallBlock):
            if isinstance(node, nodes.CallBlock):
                self._read(node.call)
            self._enter(id(node), node.body, node.args, node.defaults, True, _IMPLICIT_MACRO_LOCALS)
        else:
            self._other(node)

    def _other(self, node: nodes.Node) -> None:
        if isinstance(node, nodes.FilterBlock):
            self._enter(id(node), node.body, [], [], False, after=(node.filter,))
            return
        if isinstance(node, nodes.Block):
            outer = self._frame
            if not node.scoped:
                self._frame = None
            try:
                self._enter(id(node), node.body, [], [], True)
            finally:
                self._frame = outer
            return
        children = list(node.iter_child_nodes())
        for child in children:
            if not isinstance(child, nodes.Stmt):
                self._read(child)
        body = [child for child in children if isinstance(child, nodes.Stmt)]
        late = _BODY_FRAMES.get(type(node))
        if late is not None:
            self._enter(id(node), body, [], [], late)
            if isinstance(node, nodes.AssignBlock):
                self._bind(node.target)
        elif body:
            self._branches([body, []])

    def _enter(self, ident: int, statements: Sequence[nodes.Node], targets: Sequence[nodes.Node], reads: Sequence[nodes.Node | None], late: bool, implicit: Iterable[str]=(), after: Sequence[nodes.Node]=()) -> None:
        frame = _Frame(ident, {}, late, self._frame)
        params = [node for target in targets for node in _names_in(target)]
        entry = {*implicit, *(param.name for param in params)}
        for name in entry | _own_bindings(statements):
            self.steps += 1
            where = self._lookup(self._frame, name, late)
            self._entry[ident, name] = where
            frame.state[name] = (ident, name) if name in entry else where
        for param in params:
            self.keys[id(param)] = (ident, param.name)
        outer_frame, outer_logs = (self._frame, self._logs)
        self._frame, self._logs = (frame, [])
        for node in reads:
            if node is not None:
                self._read(node)
        self._statements(statements)
        for node in after:
            self._read(node)
        self._frame, self._logs = (outer_frame, outer_logs)

    def _branches(self, branches: Sequence[Sequence[nodes.Node]]) -> None:
        frame = self._frame
        if frame is None:
            for body in branches:
                self._statements(body)
            return
        ends: list[dict[str, _Key]] = []
        for body in branches:
            self._logs.append({})
            self._statements(body)
            log = self._logs.pop()
            ends.append({name: frame.state[name] for name in log})
            frame.state.update(log)
        for name in {name for end in ends for name in end}:
            self.steps += 1
            current = frame.state[name]
            found = {end.get(name, current) for end in ends}
            key = found.pop() if len(found) == 1 else self._either(frame.ident, name)
            if key != current:
                self._assign(name, key)

    def _lookup(self, frame: _Frame | None, name: str, late: bool=False) -> _Key:
        while frame is not None:
            self.steps += 1
            key = frame.state.get(name)
            if key is not None:
                if late and key != (frame.ident, name):
                    return self._either(frame.ident, name)
                return key
            late = late or frame.late
            frame = frame.parent
        return name

    def _either(self, ident: int, name: str) -> _Key:
        key: _Key = (ident, name, 'either')
        if key not in self._eithers:
            self._eithers.add(key)
            self.joins.append(((ident, name), key))
            self.joins.append((self._entry[ident, name], key))
        return key

    def _bind(self, target: nodes.Node) -> None:
        if isinstance(target, nodes.NSRef):
            self._read(target)
            return
        if self._frame is None:
            return
        for name in _names_in(target):
            key: _Key = (self._frame.ident, name.name)
            self.keys[id(name)] = key
            self._assign(name.name, key)

    def _assign(self, name: str, key: _Key) -> None:
        frame = self._frame
        assert frame is not None
        if self._logs and name not in self._logs[-1]:
            self._logs[-1][name] = frame.state[name]
        frame.state[name] = key

    def _read(self, node: nodes.Node) -> None:
        if self._frame is None:
            return
        for name in (node, *_find(node, (nodes.Name, nodes.NSRef))):
            if isinstance(name, nodes.Name | nodes.NSRef):
                key = self._lookup(self._frame, name.name)
                if key != name.name:
                    self.keys[id(name)] = key

def _names_in(target: nodes.Node) -> list[nodes.Name]:
    found = [target] if isinstance(target, nodes.Name) else _find(target, nodes.Name)
    return [name for name in found if isinstance(name, nodes.Name)]

def _frame_keys(ast: nodes.Template) -> tuple[dict[int, _Key], tuple[tuple[_Key, _Key], ...]]:
    walk = _FrameKeys(ast)
    return (walk.keys, tuple(walk.joins))

class _Objects:
    _KINDS: tuple[type[nodes.Node], ...] = (nodes.Name, nodes.NSRef, nodes.Assign, nodes.AssignBlock, nodes.For, nodes.With, nodes.Macro, nodes.CallBlock, nodes.Call)

    def __init__(self, ast: nodes.Template, macros: _MacroMap) -> None:
        self.macros = macros
        self._grew: set[_Key] = set()
        self._aliases: dict[_Key, list[_Key]] = {}
        self._reaching: dict[_Key, list[_Key]] = {}
        self._version = 0
        self._reached: dict[frozenset[_Object], tuple[int, frozenset[_Object]]] = {}
        self.content: dict[_Object, set[_Object]] = {}
        self.is_: dict[_Key, set[_Object]] = {}
        self.stores: dict[int, _Store] = {}
        self.steps = 0
        self.exhausted = False
        self._union_keys: set[_Key] = set()
        walked = _find(ast, self._KINDS)
        sites = self._store_sites(walked)
        if not sites:
            return
        self._keys, joins = _frame_keys(ast)
        for node in walked:
            if isinstance(node, nodes.Name | nodes.NSRef):
                self._variable(self._key(node))
        for source, either in joins:
            self._aliases.setdefault(source, []).append(either)
        self._fixpoint(self._edges(walked), sites)
        if self.exhausted:
            names = frozenset((_key_name(key) for key in self.is_))
            scope = frozenset((key for key in self.is_ if isinstance(key, str)))
            self.stores = {id(node): _Store(values, names, scope) for node, values, _ in sites}
            return
        observers = self._observers({key: self.reach(held) for key, held in self.is_.items()})
        template = self._observers(self._template_reach(ast))
        self.stores = {id(node): self._store(values, receiver, observers, template) for node, values, receiver in sites}

    def _key(self, node: nodes.Name | nodes.NSRef) -> _Key:
        return self._keys.get(id(node), node.name)

    def _variable(self, key: _Key) -> set[_Object]:
        held = self.is_.get(key)
        if held is None:
            held = {('input', key)} if isinstance(key, str) else set()
            self.is_[key] = held
        return held

    def _grow(self, key: _Key, objects: AbstractSet[_Object]) -> None:
        stack: list[tuple[_Key, AbstractSet[_Object]]] = [(key, objects)]
        while stack:
            if self.steps > _MAX_OBJECT_STEPS:
                self.exhausted = True
                return
            current, offered = stack.pop()
            held = self._variable(current)
            new = offered - held
            if not new:
                continue
            held.update(new)
            self.steps += len(new)
            self._grew.add(current)
            stack.extend(((target, new) for target in self._aliases.get(current, ())))
            reaching = self._reaching.get(current, ())
            if reaching:
                reached = self.reach(new)
                stack.extend(((target, reached) for target in reaching))

    def _edges(self, walked: Sequence[nodes.Node]) -> list[_Edge]:
        edges: list[_Edge] = []

        def targets(target: nodes.Node) -> tuple[_Key, ...]:
            return tuple((self._key(name) for name in _walk_self(target) if isinstance(name, nodes.Name)))

        def bind(target: nodes.Node, value: nodes.Node) -> None:
            if isinstance(target, nodes.Name):
                edges.append(((self._key(target),), False, value))
            elif isinstance(target, nodes.Tuple):
                edges.append((targets(target), True, value))

        def arguments(call: nodes.Call, frame: nodes.Node, params: Sequence[nodes.Name]) -> None:
            names = [param.name for param in params]
            own = id(frame)
            for index, arg in enumerate(call.args):
                name = names[index] if index < len(names) else 'varargs'
                edges.append((((own, name),), False, arg))
            for keyword in call.kwargs:
                name = keyword.key if keyword.key in names else 'kwargs'
                edges.append((((own, name),), False, keyword.value))
            every = tuple(((own, name) for name in (*names, 'varargs', 'kwargs')))
            for dynamic in (call.dyn_args, call.dyn_kwargs):
                if dynamic is not None:
                    edges.append((every, True, dynamic))
        blocks: list[nodes.CallBlock] = []
        for node in walked:
            if isinstance(node, nodes.Assign):
                bind(node.target, node.node)
            elif isinstance(node, nodes.For):
                for value in _recursive_inputs(node):
                    edges.append((targets(node.target), True, value))
                    edges.append((('loop',), True, value))
            elif isinstance(node, nodes.With):
                for target, value in zip(node.targets, node.values, strict=False):
                    bind(target, value)
            elif isinstance(node, nodes.Macro | nodes.CallBlock):
                offset = len(node.args) - len(node.defaults)
                for param, default in zip(node.args[offset:], node.defaults, strict=False):
                    edges.append((((id(node), param.name),), False, default))
                if isinstance(node, nodes.CallBlock):
                    blocks.append(node)
            elif isinstance(node, nodes.Call):
                direct, escapes = _resolve_parts(self.macros, node.node)
                if direct and isinstance(self.macros, _Macros):
                    self._union_arguments(node, self.macros.group(direct), edges)
                else:
                    for macro in direct:
                        arguments(node, macro, macro.args)
                if escapes and isinstance(self.macros, _Macros):
                    self._union_arguments(node, self.macros.union(), edges)
        for block, binding in zip(blocks, _caller_bindings(blocks, self.macros), strict=True):
            for call in binding.calls:
                arguments(call, block, binding.params)
            every = tuple(((id(block), name) for name in (*(param.name for param in binding.params), 'varargs', 'kwargs')))
            edges.extend(((every, True, value) for value in binding.values))
        return edges

    def _union_arguments(self, call: nodes.Call, union: _Union, edges: list[_Edge]) -> None:
        for index, arg in enumerate(call.args):
            edges.append(((self._union_key(union, f'#{index}'),), False, arg))
        for keyword in call.kwargs:
            key = self._union_key(union, f'={keyword.key}')
            edges.append(((key,), False, keyword.value))
        for dynamic in (call.dyn_args, call.dyn_kwargs):
            if dynamic is not None:
                edges.append(((self._union_key(union, '*'),), True, dynamic))

    def _union_key(self, union: _Union, slot: str) -> _Key:
        key: _Key = (union.ident, f'{_UNION_NAME}{slot}')
        if key in self._union_keys:
            return key
        self._union_keys.add(key)
        count = len(union.macros)
        targets: list[_Key]
        if slot == '*':
            targets = [(id(macro), name) for macro in union.macros for name in (*(param.name for param in macro.args), 'varargs', 'kwargs')]
        elif slot.startswith('#'):
            index = int(slot[1:])
            held = union.slots[index] if index < len(union.slots) else ()
            targets = list(held)
            if len(held) < count:
                targets.append(self._union_spill(union, 'varargs'))
        else:
            name = slot[1:]
            ids = union.by_name.get(name, ())
            targets = [(ident, name) for ident in ids]
            if len(ids) < count:
                targets.append(self._union_spill(union, 'kwargs'))
        self._aliases.setdefault(key, []).extend(targets)
        return key

    def _union_spill(self, union: _Union, local: str) -> _Key:
        key: _Key = (union.ident, f'{_UNION_NAME}{local}')
        if key not in self._union_keys:
            self._union_keys.add(key)
            targets: list[_Key] = [(id(macro), local) for macro in union.macros]
            self._aliases.setdefault(key, []).extend(targets)
        return key

    @staticmethod
    def _store_sites(walked: Sequence[nodes.Node]) -> list[_StoreSite]:
        sites: list[_StoreSite] = []
        for node in walked:
            if isinstance(node, nodes.Assign) and isinstance(node.target, nodes.NSRef):
                sites.append((node, (node.node,), node.target))
            elif isinstance(node, nodes.AssignBlock) and isinstance(node.target, nodes.NSRef):
                values = [*node.body, *([node.filter] if node.filter else [])]
                sites.append((node, tuple(values), node.target))
            elif isinstance(node, nodes.Call):
                receiver = _mutated_receiver(node.node)
                if receiver is not None:
                    dynamic = [d for d in (node.dyn_args, node.dyn_kwargs) if d is not None]
                    values = [*node.args, *(kw.value for kw in node.kwargs), *dynamic]
                    sites.append((node, tuple(values), receiver))
        return sites

    def _fixpoint(self, edges: Sequence[_Edge], sites: Sequence[_StoreSite]) -> None:
        readers: dict[_Key, set[int]] = {}
        store_readers: dict[_Key, set[int]] = {}
        through_edges: set[int] = set()
        through_stores: set[int] = set()
        pending_edges: set[int] = set()
        for index, (targets, element, value) in enumerate(edges):
            if not element and isinstance(value, nodes.Name):
                source = self._key(value)
                for target in targets:
                    self._aliases.setdefault(source, []).append(target)
                continue
            root = _reach_root(value, element)
            if root is not None:
                source = self._key(root)
                for target in targets:
                    self._reaching.setdefault(source, []).append(target)
                through_edges.add(index)
                continue
            pending_edges.add(index)
            for key in self._reads(value):
                readers.setdefault(key, set()).add(index)
            through_edges.add(index)
        for index, (_, values, receiver) in enumerate(sites):
            read = [*values, *([] if isinstance(receiver, nodes.NSRef) else [receiver])]
            for key in {k for node in read for k in self._reads(node)}:
                store_readers.setdefault(key, set()).add(index)
            if isinstance(receiver, nodes.NSRef):
                store_readers.setdefault(self._key(receiver), set()).add(index)
            if not all((isinstance(node, nodes.Name) for node in read)):
                through_stores.add(index)
        for source in list(self._aliases):
            for target in self._aliases[source]:
                self._grow(target, frozenset(self._variable(source)))
        for source in list(self._reaching):
            for target in self._reaching[source]:
                self._grow(target, self.reach(self._variable(source)))
        if self.exhausted:
            return
        pending_stores: set[int] = set(range(len(sites)))
        while pending_edges or pending_stores:
            self._grew = set()
            version = self._version
            for index in sorted(pending_edges):
                self._apply_edge(edges[index])
            for index in sorted(pending_stores):
                self._apply_store(sites[index])
            if self.steps > _MAX_OBJECT_STEPS:
                self.exhausted = True
                return
            pending_edges = {i for key in self._grew for i in readers.get(key, ())}
            pending_stores = {i for key in self._grew for i in store_readers.get(key, ())}
            if self._version != version:
                pending_edges |= through_edges
                pending_stores |= through_stores
        if self.steps > _MAX_OBJECT_STEPS:
            self.exhausted = True

    def _reads(self, node: nodes.Node) -> set[_Key]:
        return {self._key(name) for name in _walk_self(node) if isinstance(name, nodes.Name)}

    def _apply_edge(self, edge: _Edge) -> None:
        self.steps += 1
        targets, element, value = edge
        held = self.value(value)
        if element:
            held = self.reach(held)
        for target in targets:
            self._grow(target, held)

    def _apply_store(self, site: _StoreSite) -> None:
        self.steps += 1
        _, values, receiver = site
        stored = frozenset().union(*(self.value(value) for value in values))
        for obj in self._receivers(receiver):
            self._hold(obj, stored)

    def _hold(self, obj: _Object, objects: AbstractSet[_Object]) -> None:
        held = self.content.setdefault(obj, set())
        if not objects <= held:
            self.steps += len(objects - held)
            held.update(objects)
            self._version += 1

    def _receivers(self, receiver: nodes.Node) -> frozenset[_Object]:
        if isinstance(receiver, nodes.NSRef):
            return frozenset(self.is_.get(self._key(receiver), ()))
        return self.value(receiver)

    def reach(self, objects: AbstractSet[_Object]) -> frozenset[_Object]:
        key = frozenset(objects)
        cached = self._reached.get(key)
        if cached is not None and cached[0] == self._version:
            return cached[1]
        seen = set(key)
        stack = list(key)
        while stack:
            for held in self.content.get(stack.pop(), ()):
                if held not in seen:
                    seen.add(held)
                    stack.append(held)
        result = frozenset(seen)
        self._reached[key] = (self._version, result)
        return result

    def _allocate(self, node: nodes.Node, parts: Iterable[nodes.Node | None]) -> frozenset[_Object]:
        site: _Object = ('site', id(node))
        self.content.setdefault(site, set())
        for part in parts:
            if part is not None:
                self._hold(site, self.value(part))
        return frozenset({site})

    def value(self, node: nodes.Node) -> frozenset[_Object]:
        if isinstance(node, nodes.Name):
            return frozenset(self.is_.get(self._key(node), ()))
        if isinstance(node, _SCALAR_NODES):
            return frozenset()
        if isinstance(node, nodes.Getattr | nodes.Getitem):
            return self.reach(self.value(node.node))
        if isinstance(node, nodes.CondExpr):
            other = frozenset() if node.expr2 is None else self.value(node.expr2)
            return self.value(node.expr1) | other
        if isinstance(node, nodes.And | nodes.Or):
            return self.value(node.left) | self.value(node.right)
        if isinstance(node, nodes.List | nodes.Tuple):
            return self._allocate(node, node.items)
        if isinstance(node, nodes.Dict):
            pairs = [part for pair in node.items for part in (pair.key, pair.value)]
            return self._allocate(node, pairs)
        if isinstance(node, nodes.Add | nodes.Mul):
            return self._allocate(node, (node.left, node.right))
        if isinstance(node, nodes.Keyword):
            return self.value(node.value)
        if isinstance(node, nodes.Filter | nodes.Call):
            return self._call(node)
        children = [self.value(child) for child in node.iter_child_nodes()]
        return self.reach(frozenset().union(*children))

    def _call(self, node: nodes.Filter | nodes.Call) -> frozenset[_Object]:
        dynamic = [d for d in (node.dyn_args, node.dyn_kwargs) if d is not None]
        args = [*node.args, *(kw.value for kw in node.kwargs), *dynamic]
        callee = node.node
        received: list[nodes.Node] = []
        if isinstance(node, nodes.Call) and isinstance(callee, nodes.Name):
            rebound: frozenset[str] = getattr(self.macros, 'rebound', frozenset())
            local = callee.name in self.macros and callee.name not in rebound
            if local or callee.name == 'caller':
                for arg in args:
                    self.value(arg)
                return frozenset()
            if callee.name == 'namespace':
                return self._allocate(node, args)
        elif isinstance(node, nodes.Call) and isinstance(callee, nodes.Getattr):
            received.append(callee.node)
        elif callee is not None:
            received.append(callee)
        parts = [*received, *args]
        passed = frozenset().union(*(self.reach(self.value(part)) for part in parts))
        return passed | self._allocate(node, parts)

    def _template_reach(self, ast: nodes.Template) -> dict[_Key, frozenset[_Object]]:
        level: dict[_Key, set[_Object]] = {key: {('input', key)} for key in self.is_ if isinstance(key, str)}
        for node in _root_frame_bindings(ast.body):
            if isinstance(node, nodes.Assign):
                held = self.value(node.node)
                if isinstance(node.target, nodes.Tuple):
                    held = self.reach(held)
                for name in _bound_names(node.target):
                    level.setdefault(name, {('input', name)}).update(held)
        return {key: self.reach(held) for key, held in level.items()}

    @staticmethod
    def _observers(reached: Mapping[_Key, frozenset[_Object]]) -> dict[_Object, set[_Key]]:
        observers: dict[_Object, set[_Key]] = {}
        for key, held in reached.items():
            for obj in held:
                observers.setdefault(obj, set()).add(key)
        return observers

    def _store(self, values: tuple[nodes.Node, ...], receiver: nodes.Node, observers: Mapping[_Object, set[_Key]], template: Mapping[_Object, set[_Key]]) -> _Store:
        written = self._receivers(receiver)
        names = {_key_name(key) for obj in written for key in observers.get(obj, ())}
        scope = {key for obj in written for key in template.get(obj, ()) if isinstance(key, str)}
        if isinstance(receiver, nodes.NSRef):
            names.add(receiver.name)
        return _Store(values, frozenset(names), frozenset(scope))

def _reach_root(value: nodes.Node, element: bool) -> nodes.Name | None:
    node = value
    while isinstance(node, nodes.Getattr | nodes.Getitem):
        node = node.node
    if not isinstance(node, nodes.Name):
        return None
    if node is value and (not element):
        return None
    return node

def _mutated_receiver(callee: nodes.Node) -> nodes.Node | None:
    if isinstance(callee, nodes.Getattr) and callee.attr in _MUTATING_METHODS:
        return callee.node
    if isinstance(callee, nodes.Getitem) and isinstance(callee.arg, nodes.Const) and (callee.arg.value in _MUTATING_METHODS):
        return callee.node
    if isinstance(callee, nodes.Filter) and callee.name == 'attr' and (callee.node is not None) and (len(callee.args) == 1) and isinstance(callee.args[0], nodes.Const) and (callee.args[0].value in _MUTATING_METHODS):
        return callee.node
    return None
_SITE_KINDS: tuple[type[nodes.Node], ...] = (nodes.Assign, nodes.AssignBlock, nodes.For, nodes.With, nodes.Call, nodes.Macro, nodes.CallBlock)

def _collect_sites(ast: nodes.Node, macros: _MacroMap, refs: Callable[[nodes.Node, set[str]], bool], stores: Mapping[int, _Store] | None=None, depends_on: Callable[[nodes.Macro | None], AbstractSet[str]] | None=None) -> _BindingSites:
    assigns: list[nodes.Assign] = []
    assign_blocks: list[nodes.AssignBlock] = []
    loops: list[nodes.For] = []
    with_blocks: list[nodes.With] = []
    calls: list[nodes.Call] = []
    macro_defs: list[nodes.Macro] = []
    call_blocks: list[nodes.CallBlock] = []
    found: list[_Store] = []
    for node in _find(ast, _SITE_KINDS):
        if stores and (store := stores.get(id(node))) is not None:
            found.append(store)
        if isinstance(node, nodes.Assign):
            assigns.append(node)
        elif isinstance(node, nodes.AssignBlock):
            assign_blocks.append(node)
        elif isinstance(node, nodes.For):
            loops.append(node)
        elif isinstance(node, nodes.With):
            with_blocks.append(node)
        elif isinstance(node, nodes.Call):
            calls.append(node)
        elif isinstance(node, nodes.Macro):
            macro_defs.append(node)
        elif isinstance(node, nodes.CallBlock):
            call_blocks.append(node)
    escaping_calls = tuple((call for call in calls if _resolve_parts(macros, call.node)[1]))
    groups: dict[int, tuple[tuple[nodes.Macro, ...], list[nodes.Call]]] = {}
    pairs: list[tuple[nodes.Call, nodes.Macro]] = []
    for call in calls:
        direct, _ = _resolve_parts(macros, call.node)
        if direct and isinstance(macros, _Macros):
            groups.setdefault(id(direct), (direct, []))[1].append(call)
        else:
            pairs.extend(((call, macro) for macro in direct))
    return _indexed(_BindingSites(refs=refs, assigns=tuple(assigns), assign_blocks=tuple(assign_blocks), loops=tuple(loops), with_blocks=tuple(with_blocks), macro_calls=tuple(pairs), macro_groups=tuple(((tuple(group_calls), macros.group(definitions)) for definitions, group_calls in groups.values() if isinstance(macros, _Macros))), escaping_calls=escaping_calls, union=macros.union() if escaping_calls and isinstance(macros, _Macros) else None, signatures=(*((macro.args, macro.defaults) for macro in macro_defs), *((block.args, block.defaults) for block in call_blocks)), caller_bindings=_caller_bindings(call_blocks, macros), stores=tuple(found)), macros, depends_on)

def _indexed(sites: _BindingSites, macros: _MacroMap, depends_on: Callable[[nodes.Macro | None], AbstractSet[str]] | None=None) -> _BindingSites:
    units = tuple((unit for rule in _BINDING_RULES for unit in rule(sites)))
    readers: dict[str, list[int]] = {}
    volatile: list[int] = []
    depends: dict[int, list[int]] = {}
    called: dict[int, nodes.Macro | None] = {}
    for index, (values, _) in enumerate(units):
        keys: dict[int, nodes.Macro | None] = {}
        for value in values:
            for node in (value, *_find(value, (nodes.Name, nodes.Call))):
                if isinstance(node, nodes.Name):
                    readers.setdefault(node.name, []).append(index)
                elif isinstance(node, nodes.Call):
                    if isinstance(macros, _Macros) and (not macros.following):
                        continue
                    direct, escapes = _resolve_parts(macros, node.node)
                    if len(direct) > 1 and isinstance(macros, _Macros):
                        macros.charge(len(direct), 'index-definitions')
                    keys.update(((id(macro), macro) for macro in direct))
                    if escapes:
                        keys[0] = None
        if not keys:
            continue
        if depends_on is None:
            volatile.append(index)
            continue
        called.update(keys)
        for key in keys:
            depends.setdefault(key, []).append(index)
    watch: dict[str, list[int]] = {}
    if depends_on is not None:
        for key, macro in called.items():
            for name in depends_on(macro):
                watch.setdefault(name, []).append(key)
    return dataclasses.replace(sites, units=units, readers={name: tuple(dict.fromkeys(found)) for name, found in readers.items()}, volatile=tuple(volatile), depends={key: tuple(found) for key, found in depends.items()}, watch={name: tuple(keys) for name, keys in watch.items()})
_BindingRule = Callable[[_BindingSites], Iterator[_Unit]]

def _bind_assign(sites: _BindingSites) -> Iterator[_Unit]:
    for assign in sites.assigns:
        yield ((assign.node,), tuple(_bound_names(assign.target)))

def _bind_assign_block(sites: _BindingSites) -> Iterator[_Unit]:
    for block in sites.assign_blocks:
        sources: list[nodes.Node] = list(block.body)
        if block.filter is not None:
            sources.append(block.filter)
        yield (tuple(sources), tuple(_bound_names(block.target)))

def _recursive_inputs(loop: nodes.For) -> tuple[nodes.Node, ...]:
    values: list[nodes.Node] = [loop.iter]
    if not loop.recursive:
        return tuple(values)
    stack = list(reversed(loop.body))
    while stack:
        node = stack.pop()
        if isinstance(node, nodes.For):
            outer: list[nodes.Node] = [node.iter]
            if node.test is not None:
                outer.append(node.test)
            outer.extend(node.else_)
            stack.extend(reversed(outer))
            continue
        if isinstance(node, nodes.Block) and (not node.scoped):
            continue
        if isinstance(node, nodes.Macro | nodes.CallBlock) and any((param.name == 'loop' for param in node.args)):
            stack.extend(reversed(node.defaults))
            if isinstance(node, nodes.CallBlock):
                stack.append(node.call)
            continue
        if isinstance(node, nodes.Call) and isinstance(node.node, nodes.Name) and (node.node.name == 'loop'):
            if node.args:
                values.append(node.args[0])
            else:
                values.extend((kw.value for kw in node.kwargs if kw.key == 'iterable'))
            if node.dyn_args is not None:
                values.append(node.dyn_args)
            if node.dyn_kwargs is not None:
                values.append(node.dyn_kwargs)
        stack.extend(reversed(list(node.iter_child_nodes())))
    return tuple(values)

def _bind_for(sites: _BindingSites) -> Iterator[_Unit]:
    for loop in sites.loops:
        yield (_recursive_inputs(loop), tuple(_bound_names(loop.target)))

def _bind_with(sites: _BindingSites) -> Iterator[_Unit]:
    for block in sites.with_blocks:
        for target, value in zip(block.targets, block.values, strict=False):
            yield ((value,), tuple(_bound_names(target)))

def _bind_arguments(call: nodes.Call, params: Sequence[nodes.Name], *, implicit: bool=False) -> Iterator[_Unit]:
    declared = tuple((param.name for param in params))
    for index, arg in enumerate(call.args):
        if index < len(declared):
            yield ((arg,), (declared[index],))
        elif implicit:
            yield ((arg,), ('varargs',))
    for keyword in call.kwargs:
        if keyword.key in declared:
            yield ((keyword.value,), (keyword.key,))
        elif implicit:
            yield ((keyword.value,), ('kwargs',))
    dynamic = tuple((d for d in (call.dyn_args, call.dyn_kwargs) if d is not None))
    if dynamic:
        yield (dynamic, (*declared, 'varargs', 'kwargs') if implicit else declared)

def _bind_macro_call(sites: _BindingSites) -> Iterator[_Unit]:
    for call, macro in sites.macro_calls:
        yield from _bind_arguments(call, macro.args)
    for calls, group in sites.macro_groups:
        yield from _bind_union(calls, group)
    if sites.union is not None:
        yield from _bind_union(sites.escaping_calls, sites.union)
_UNION_NAME = '\x00escaping'

def _bind_union(calls: Sequence[nodes.Call], union: _Union) -> Iterator[_Unit]:
    used: dict[str, tuple[str, ...]] = {}
    prefix = f'{_UNION_NAME}{union.ident}:'
    for call in calls:
        for index, arg in enumerate(call.args):
            if index < len(union.positions):
                name = f'{prefix}#{index}'
                used[name] = union.positions[index]
                yield ((arg,), (name,))
        for keyword in call.kwargs:
            if keyword.key in union.declared:
                yield ((keyword.value,), (keyword.key,))
        dynamic = tuple((d for d in (call.dyn_args, call.dyn_kwargs) if d is not None))
        if dynamic and union.names:
            used[f'{prefix}*'] = union.names
            yield (dynamic, (f'{prefix}*',))
    for name, targets in used.items():
        yield ((nodes.Name(name, 'load'),), targets)

def _bind_caller(sites: _BindingSites) -> Iterator[_Unit]:
    for binding in sites.caller_bindings:
        for call in binding.calls:
            yield from _bind_arguments(call, binding.params, implicit=True)
        if binding.values:
            yield (binding.values, (*(param.name for param in binding.params), 'varargs', 'kwargs'))

def _bind_defaults(sites: _BindingSites) -> Iterator[_Unit]:
    for params, defaults in sites.signatures:
        offset = max(0, len(params) - len(defaults))
        for param, default in zip(params[offset:], defaults, strict=False):
            yield ((default,), (param.name,))

def _bind_stores(sites: _BindingSites) -> Iterator[_Unit]:
    for store in sites.stores:
        yield (store.values, tuple(store.names))
_BINDING_RULES: tuple[_BindingRule, ...] = (_bind_assign, _bind_assign_block, _bind_for, _bind_with, _bind_macro_call, _bind_caller, _bind_defaults, _bind_stores)

def _root_frame_bindings(statements: Sequence[nodes.Node]) -> Iterator[nodes.Assign | nodes.AssignBlock]:
    for statement in statements:
        if isinstance(statement, nodes.Assign | nodes.AssignBlock):
            if not isinstance(statement.target, nodes.NSRef):
                yield statement
        elif isinstance(statement, nodes.If):
            yield from _root_frame_bindings([*statement.body, *statement.elif_, *statement.else_])

def _root_macros(statements: Sequence[nodes.Node]) -> Iterator[nodes.Macro]:
    for statement in statements:
        if isinstance(statement, nodes.Macro):
            yield statement
        elif isinstance(statement, nodes.If):
            yield from _root_macros([*statement.body, *statement.elif_, *statement.else_])

def _compute_tainted(ast: nodes.Template, initial: AbstractSet[str], macros: _MacroMap, returns: _MacroReturns | None=None, seeds: AbstractSet[str]=frozenset()) -> set[str]:
    if returns is None:
        returns = _MacroReturns(macros)
    returns.seeds = frozenset(seeds)
    objects = _Objects(ast, macros)
    returns.stores = objects.stores
    root = tuple(_root_frame_bindings(ast.body))
    root_sites = _indexed(_BindingSites(assigns=tuple((node for node in root if isinstance(node, nodes.Assign))), assign_blocks=tuple((node for node in root if isinstance(node, nodes.AssignBlock))), loops=(), with_blocks=(), macro_calls=(), signatures=(), refs=returns.refs_tainted), macros, returns.depends_on)
    template: set[str] = set(initial)
    returns.template = template
    flat: set[str] = set(initial) | set(seeds)
    returns.flat = flat
    returns.rooted = frozenset((id(macro) for macro in _root_macros(ast.body)))
    sites = _collect_sites(ast, macros, returns.refs_tainted, objects.stores, returns.depends_on)
    join_sites = _indexed(dataclasses.replace(root_sites, assigns=(), assign_blocks=(), stores=tuple((dataclasses.replace(store, names=store.scope) for store in objects.stores.values() if store.scope))), macros, returns.depends_on)
    root_fold = _Fold(root_sites, template)
    flat_fold = _Fold(sites, flat)
    joins = _Fold(join_sites, flat, output=template)
    while root_fold.pending or flat_fold.pending or joins.pending:
        rooted = root_fold.run()
        flat_fold.seed(rooted)
        flat_fold.notify(rooted, external=True)
        joins.notify(rooted)
        flattened = flat_fold.run()
        root_fold.notify(flattened, external=True)
        joins.notify(flattened)
        joined = joins.run()
        root_fold.notify(joined)
        flat_fold.seed(joined)
        flat_fold.notify(joined, external=True)
        joins.notify(joined)
    return flat

def _fixpoint(sites: _BindingSites, initial: AbstractSet[str]) -> set[str]:
    return _fold(sites, set(initial))

def _fold(sites: _BindingSites, tainted: set[str]) -> set[str]:
    _Fold(sites, tainted).run()
    return tainted

class _Fold:

    def __init__(self, sites: _BindingSites, tainted: set[str], *, output: set[str] | None=None) -> None:
        self.sites = sites
        self.tainted = tainted
        self.output = tainted if output is None else output
        self.fired = bytearray(len(sites.units))
        self.pending = set(range(len(sites.units)))

    def notify(self, names: Iterable[str], *, external: bool=False) -> None:
        names = tuple(names)
        if not names:
            return
        following = set(self.sites.volatile)
        if not external:
            following.update((i for name in names for i in self.sites.readers.get(name, ())))
        touched = {key for name in names for key in self.sites.watch.get(name, ())}
        for key in touched:
            following.update(self.sites.depends[key])
        self.pending.update((i for i in following if not self.fired[i]))

    def seed(self, names: AbstractSet[str]) -> None:
        added = names - self.tainted
        self.tainted.update(added)
        self.notify(added)

    def run(self) -> set[str]:
        added: set[str] = set()
        while self.pending:
            pending, self.pending = (sorted(self.pending), set())
            grew: set[str] = set()
            for index in pending:
                if self.fired[index]:
                    continue
                values, targets = self.sites.units[index]
                if any((self.sites.refs(value, self.tainted) for value in values)):
                    self.fired[index] = 1
                    new = set(targets) - self.output
                    self.output.update(new)
                    grew.update(new)
            added.update(grew)
            if self.output is self.tainted:
                self.notify(grew)
        return added

def _filter_chain(filt: nodes.Node | None) -> Iterator[nodes.Filter]:
    while isinstance(filt, nodes.Filter):
        yield filt
        filt = filt.node

def _z2_sanitized_ids(ast: nodes.Template, sanitizers: frozenset[str]) -> set[int]:
    sanitized: set[int] = set()
    for filt in ast.find_all(nodes.Filter):
        if filt.name in sanitizers and filt.node is not None:
            sanitized.update((id(name) for name in _name_nodes(filt.node)))
            calls = (n for n in _walk_self(filt.node) if isinstance(n, nodes.Call))
            sanitized.update((id(call) for call in calls))
    return sanitized

def _z2_block_ids(ast: nodes.Template, sanitizers: frozenset[str]) -> set[int]:
    wrapped: set[int] = set()

    def mark(node: nodes.Node) -> None:
        if isinstance(node, nodes.AssignBlock):
            return
        wrapped.add(id(node))
        for child in node.iter_child_nodes():
            mark(child)
    for block in ast.find_all(nodes.FilterBlock):
        if any((link.name in sanitizers for link in _filter_chain(block.filter))):
            for statement in block.body:
                mark(statement)
    return wrapped

def _z1_between(parts: Sequence[nodes.Node], index: int, delimiter_tags: frozenset[str] | None) -> bool:
    if index == 0 or index + 1 >= len(parts):
        return False
    prev_node, next_node = (parts[index - 1], parts[index + 1])
    if not isinstance(prev_node, nodes.TemplateData):
        return False
    if not isinstance(next_node, nodes.TemplateData):
        return False
    opening = _OPEN_TAG.search(prev_node.data)
    if opening is None:
        return False
    tag = opening.group(1)
    if delimiter_tags is not None and tag not in delimiter_tags:
        return False
    return next_node.data.lstrip().startswith(f'</{tag}>')

def _z1_wrapped(template: nodes.Template, delimiter_tags: frozenset[str] | None) -> set[int]:
    wrapped: set[int] = set()

    def mark(node: nodes.Node) -> None:
        wrapped.add(id(node))
        for child in node.iter_child_nodes():
            mark(child)

    def scan(seq: Sequence[nodes.Node]) -> None:
        flat: list[nodes.Node] = []
        for child in seq:
            if isinstance(child, nodes.Output):
                flat.extend(child.nodes)
            else:
                flat.append(child)
        for index, part in enumerate(flat):
            if not isinstance(part, nodes.TemplateData):
                continue
            opening = _OPEN_TAG.search(part.data)
            if opening is None:
                continue
            tag = opening.group(1)
            if delimiter_tags is not None and tag not in delimiter_tags:
                continue
            close = next((k for k in range(index + 1, len(flat)) if isinstance(flat[k], nodes.TemplateData)), None)
            if close is None:
                continue
            closing = flat[close]
            if not isinstance(closing, nodes.TemplateData):
                continue
            if not closing.data.lstrip().startswith(f'</{tag}>'):
                continue
            for inner in flat[index + 1:close]:
                mark(inner)

    def walk(node: nodes.Node) -> None:
        if not isinstance(node, nodes.Output):
            for field in node.fields:
                value = getattr(node, field, None)
                if isinstance(value, list) and all((isinstance(item, nodes.Node) for item in value)):
                    scan(value)
        for child in node.iter_child_nodes():
            walk(child)
    walk(template)
    return wrapped

def _is_instruction_name(node: nodes.Node, lexicon: frozenset[str]) -> bool:
    if not isinstance(node, nodes.Name):
        return False
    lowered = node.name.lower()
    return any((term in lowered for term in lexicon))
_ROLE_FIELDS: frozenset[str] = frozenset({'role', 'from'})

def _walk_self(node: nodes.Node) -> Iterator[nodes.Node]:
    yield node
    for child in node.iter_child_nodes():
        yield from _walk_self(child)

def _is_role_ref(node: nodes.Node) -> bool:
    if isinstance(node, nodes.Getitem):
        return isinstance(node.arg, nodes.Const) and node.arg.value in _ROLE_FIELDS
    if isinstance(node, nodes.Getattr):
        return node.attr in _ROLE_FIELDS
    return isinstance(node, nodes.Name) and node.name in _ROLE_FIELDS
_SYSTEM_ROLE = 'system'
_SELECTING_OPS: frozenset[str] = frozenset({'eq', 'in'})
_EXCLUDING_OPS: frozenset[str] = frozenset({'ne', 'notin'})
_SELECTING_TESTS: frozenset[str] = frozenset({'eq', 'equalto', '==', 'in'})
_EXCLUDING_TESTS: frozenset[str] = frozenset({'ne', '!='})

def _names_system(node: nodes.Node) -> bool:
    if isinstance(node, nodes.Const):
        value = node.value
        if isinstance(value, str):
            return value == _SYSTEM_ROLE
        if isinstance(value, list | tuple | set | frozenset):
            return _SYSTEM_ROLE in value
        return False
    if isinstance(node, nodes.List | nodes.Tuple):
        return any((isinstance(item, nodes.Const) and item.value == _SYSTEM_ROLE for item in node.items))
    return False

def _compare_polarity(node: nodes.Compare) -> str | None:
    for operand in node.ops:
        forward = _is_role_ref(node.expr) and _names_system(operand.expr)
        reverse = _is_role_ref(operand.expr) and _names_system(node.expr)
        if not (forward or reverse):
            continue
        if operand.op in _SELECTING_OPS:
            return 'eq'
        if operand.op in _EXCLUDING_OPS:
            return 'ne'
    return None

def _test_polarity(node: nodes.Test) -> str | None:
    if not _is_role_ref(node.node):
        return None
    if not any((_names_system(argument) for argument in node.args)):
        return None
    if node.name in _SELECTING_TESTS:
        return 'eq'
    if node.name in _EXCLUDING_TESTS:
        return 'ne'
    return None

def _role_filter_polarity(iterable: nodes.Node) -> str | None:
    for node in _walk_self(iterable):
        if not isinstance(node, nodes.Filter) or node.name not in {'selectattr', 'rejectattr'}:
            continue
        arguments = node.args
        if len(arguments) < 3:
            continue
        attribute, test = (arguments[0], arguments[1])
        if not (isinstance(attribute, nodes.Const) and attribute.value in _ROLE_FIELDS):
            continue
        if not (isinstance(test, nodes.Const) and isinstance(test.value, str)):
            continue
        if not any((_names_system(argument) for argument in arguments[2:])):
            continue
        selects = test.value in _SELECTING_TESTS
        excludes = test.value in _EXCLUDING_TESTS
        if node.name == 'selectattr' and selects or (node.name == 'rejectattr' and excludes):
            return 'eq'
    return None

def _system_guard_polarity(test: nodes.Node) -> str | None:
    for node in _walk_self(test):
        if isinstance(node, nodes.Compare):
            polarity = _compare_polarity(node)
        elif isinstance(node, nodes.Test):
            polarity = _test_polarity(node)
        else:
            continue
        if polarity is not None:
            return polarity
    return None

def _role_after(text: str, role: str | None) -> str | None:
    for match in _ROLE_RE.finditer(text):
        if match.group(1) is not None:
            role = match.group(1)
        elif match.group(2) is not None:
            role = match.group(2)
        elif match.group(3) is not None:
            role = match.group(3)
        elif match.group(4) is not None:
            role = 'system'
        elif match.group(5) is not None:
            role = None
        else:
            role = 'user'
    return role

def _block_roles(parent: nodes.Template) -> dict[str, str | None]:
    roles: dict[str, str | None] = {}
    role: str | None = None

    def walk(node: nodes.Node) -> None:
        nonlocal role
        if isinstance(node, nodes.TemplateData):
            role = _role_after(node.data, role)
            return
        if isinstance(node, nodes.Block):
            roles[node.name] = role
        for child in node.iter_child_nodes():
            walk(child)
    walk(parent)
    return roles

@dataclass(frozen=True, slots=True)
class _ImportedUnit:
    path: str
    crossing: frozenset[str]
    callees: frozenset[str]

def _imported_units(ast: nodes.Template, file: str, roots: tuple[Path, ...], cache: UnitCache | None=None) -> dict[str, _ImportedUnit]:
    units: dict[str, _ImportedUnit] = {}
    for node in ast.find_all(nodes.Import):
        target = const_target(node)
        if target is None:
            continue
        unit = parse_unit(file, target, roots, cache=cache)
        if unit is None:
            continue
        macros = cache.macros(unit) if cache is not None else frozenset((macro.name for macro in unit.ast.find_all(nodes.Macro)))
        entry = _ImportedUnit(path=target, crossing=frozenset(unit.undeclared), callees=frozenset((f'{node.target}.{name}' for name in macros)))
        for callee in entry.callees:
            units[callee] = entry
    for from_node in ast.find_all(nodes.FromImport):
        target = const_target(from_node)
        if target is None:
            continue
        unit = parse_unit(file, target, roots, cache=cache)
        if unit is None:
            continue
        macros = cache.macros(unit) if cache is not None else frozenset((macro.name for macro in unit.ast.find_all(nodes.Macro)))
        local: set[str] = set()
        for name in from_node.names:
            if isinstance(name, tuple):
                if name[0] in macros:
                    local.add(str(name[1]))
            elif name in macros:
                local.add(str(name))
        entry = _ImportedUnit(path=target, crossing=frozenset(unit.undeclared), callees=frozenset(local))
        for callee in local:
            units[callee] = entry
    return units

def _extends_parent(ast: nodes.Template, file: str, roots: tuple[Path, ...], cache: UnitCache | None=None) -> TemplateContext | None:
    for node in ast.find_all(nodes.Extends):
        target = const_target(node)
        if target is None:
            continue
        parent = parse_unit(file, target, roots, cache=cache)
        if parent is not None:
            return parent
    return None

def _callee_name(node: nodes.Call) -> str | None:
    if isinstance(node.node, nodes.Name):
        return node.node.name
    if isinstance(node.node, nodes.Getattr) and isinstance(node.node.node, nodes.Name):
        return f'{node.node.node.name}.{node.node.attr}'
    return None

def _has_chat_markers(ast: nodes.Template) -> bool:
    return any((any((marker in data.data for marker in _CHAT_MARKERS)) for data in ast.find_all(nodes.TemplateData)))

def _rendered_operands(node: nodes.Node) -> Iterator[nodes.Node]:
    if isinstance(node, nodes.Concat):
        for operand in node.nodes:
            yield from _rendered_operands(operand)
    elif isinstance(node, nodes.Add):
        yield from _rendered_operands(node.left)
        yield from _rendered_operands(node.right)
    else:
        yield node

def _include_path(node: nodes.Include) -> str | None:
    return const_target(node)

@dataclass(frozen=True, slots=True)
class _Boundary:
    resolved: bool
    crossing: frozenset[str]

def _include_boundaries(ast: nodes.Template, file: str, roots: tuple[Path, ...], depth: int, cache: UnitCache | None=None) -> dict[int, _Boundary]:
    boundaries: dict[int, _Boundary] = {}
    for node in ast.find_all(nodes.Include):
        target = const_target(node)
        path = (cache.path(file, target) if cache is not None else resolve(file, target, roots)) if target is not None else None
        if path is None:
            boundaries[id(node)] = _Boundary(resolved=False, crossing=frozenset())
            continue
        assert target is not None
        boundaries[id(node)] = _Boundary(resolved=True, crossing=crossing_vars(file, target, roots, depth, cache=cache))
    return boundaries

def _role_taking_markers(packs: Iterable[ChatPack]) -> tuple[str, ...]:
    return tuple(sorted({pack.role_prefix for pack in packs if pack.role_prefix is not None}))
_ROLE_TAKING_MARKERS: tuple[str, ...] = _role_taking_markers(_PACKS)

def _linear_parts(node: nodes.Node, bindings: Mapping[str, nodes.Node] | None=None, active: frozenset[str]=frozenset()) -> Iterator[str | None]:
    if isinstance(node, nodes.TemplateData):
        yield node.data
    elif isinstance(node, nodes.Const):
        yield (node.value if isinstance(node.value, str) else None)
    elif isinstance(node, nodes.Concat):
        for child in node.nodes:
            yield from _linear_parts(child, bindings, active)
    elif isinstance(node, nodes.Add):
        yield from _linear_parts(node.left, bindings, active)
        yield from _linear_parts(node.right, bindings, active)
    elif isinstance(node, nodes.CondExpr):
        yield from _linear_parts(node.expr1, bindings, active)
        yield None
        if node.expr2 is not None:
            yield from _linear_parts(node.expr2, bindings, active)
    elif isinstance(node, nodes.Name) and node.ctx == 'load' and (bindings is not None) and (node.name in bindings) and (node.name not in active):
        yield from _linear_parts(bindings[node.name], bindings, active | {node.name})
    else:
        yield None
_MAX_BINDING_PATHS = 32

def _literal_bindings(loop: nodes.For) -> dict[str, tuple[nodes.Node, ...]]:
    bindings: dict[str, list[nodes.Node]] = {}
    for assign in loop.find_all(nodes.Assign):
        if isinstance(assign.target, nodes.Name):
            bindings.setdefault(assign.target.name, []).append(assign.node)
    return {name: tuple(values) for name, values in bindings.items()}

def _binding_paths(loop: nodes.For) -> list[dict[str, nodes.Node]]:
    paths: list[dict[str, nodes.Node]] = [{}]
    for name, values in _literal_bindings(loop).items():
        if len(values) == 1:
            paths = [{**path, name: values[0]} for path in paths]
            continue
        expanded = [{**path, name: value} for path in paths for value in values][:_MAX_BINDING_PATHS]
        paths = expanded or paths
    return paths

def _emitted_literals(loop: nodes.For) -> Iterator[str]:
    for bindings in _binding_paths(loop):
        for output in loop.find_all(nodes.Output):
            buffered: list[str] = []
            for part in output.nodes:
                for piece in _linear_parts(part, bindings):
                    if piece is None:
                        if buffered:
                            yield ''.join(buffered)
                            buffered = []
                    else:
                        buffered.append(piece)
            if buffered:
                yield ''.join(buffered)
_Candidate = tuple[int, str, str | None, str | None]
_MAX_RELOCATION_SCANS = 512

class _Scanner:

    def __init__(self, file: str, tainted: set[str], sources: frozenset[str], lexicon: frozenset[str], annotated: frozenset[str], z2_ids: set[int], z2_block: set[int], tier2: bool, instruction_names: frozenset[str], delimiter_tags: frozenset[str] | None, dynamic_role_loops: bool, cross_template: bool, boundaries: dict[int, _Boundary], imported: dict[str, _ImportedUnit], block_roles: dict[str, str | None], returns: _MacroReturns) -> None:
        self.file = file
        self.tainted: AbstractSet[str] = tainted
        self.returns = returns
        self._relocating: frozenset[str] = frozenset()
        self._capture: dict[_Candidate, None] = {}
        self._relocations: dict[tuple[int, frozenset[str], str | None, bool, bool, frozenset[str], bool], tuple[tuple[_Candidate, ...], str | None]] = {}
        self._scans_left = _MAX_RELOCATION_SCANS
        self._relocated: list[tuple[int, int, str, str | None, str | None]] = []
        self._def_site: set[tuple[int, str]] = set()
        self.sources = sources
        self.lexicon = lexicon
        self.annotated = annotated
        self.z2_ids = z2_ids
        self.z2_block = z2_block
        self.z1_wrapped: set[int] = set()
        self.tier2 = tier2
        self.instruction_names = instruction_names
        self.delimiter_tags = delimiter_tags
        self.dynamic_role_loops = dynamic_role_loops
        self.cross_template = cross_template
        self.boundaries = boundaries
        self.imported = imported
        self.block_roles = block_roles
        self.role: str | None = None
        self.role_guard_depth: int = 0
        self._dynamic_region = False
        self.diagnostics: list[Diagnostic] = []
        self._seen: set[tuple[str, str, int]] = set()

    def run(self, template: nodes.Template) -> None:
        self.z1_wrapped = _z1_wrapped(template, self.delimiter_tags)
        self._walk(template, sink=False)
        for key, line, sink_kind, name, include_path in self._relocated:
            if (key, _SINK_META[sink_kind][0]) not in self._def_site:
                self._flag(line, sink_kind, name, include_path)

    def _walk(self, node: nodes.Node, sink: bool) -> None:
        for child in node.iter_child_nodes():
            self._visit(child, sink)

    def _visit(self, node: nodes.Node, sink: bool) -> None:
        if self._relocating and isinstance(node, nodes.Macro | nodes.AssignBlock | nodes.Assign):
            return
        if isinstance(node, nodes.Output):
            self._handle_output(node, sink)
        elif isinstance(node, nodes.TemplateData):
            self._update_role(node.data)
        elif isinstance(node, nodes.CallBlock):
            self._handle_call_block(node, sink)
        elif isinstance(node, nodes.AssignBlock):
            instruction = _is_instruction_name(node.target, self.instruction_names)
            self._flag_filter_args(node.filter, sink or instruction)
            self._walk(node, sink or instruction)
        elif isinstance(node, nodes.FilterBlock):
            if id(node) not in self.z2_block and id(node) not in self.z1_wrapped:
                self._flag_filter_args(node.filter, sink)
            self._walk(node, sink)
        elif isinstance(node, nodes.Assign):
            self._handle_assign(node)
        elif isinstance(node, nodes.If):
            polarity = _system_guard_polarity(node.test)
            self._visit_arm(node.body, sink, guard=polarity == 'eq')
            self._visit_arm([*node.elif_, *node.else_], sink, guard=polarity == 'ne')
        elif isinstance(node, nodes.For):
            if self.dynamic_role_loops and (not self._relocating) and self._is_dynamic_role_loop(node):
                self._flag_dynamic_role(node)
            self._visit_arm(node.body, sink, guard=_role_filter_polarity(node.iter) == 'eq')
            for child in node.else_:
                self._visit(child, sink)
        elif isinstance(node, nodes.Macro):
            saved, self.role = (self.role, None)
            self._walk(node, sink)
            self.role = saved
        elif isinstance(node, nodes.Include):
            self._handle_include(node, sink)
        elif isinstance(node, nodes.Block) and node.name in self.block_roles:
            saved, self.role = (self.role, self.block_roles[node.name])
            self._walk(node, sink)
            self.role = saved
        else:
            self._walk(node, sink)

    def _handle_include(self, node: nodes.Include, sink: bool) -> None:
        if not self.cross_template or self._sink_kind(sink) is None:
            return
        if id(node) in self.z2_block:
            return
        boundary = self.boundaries.get(id(node))
        if boundary is None or not boundary.resolved or (not boundary.crossing):
            return
        self._report(id(node), node.lineno, 'cross-template', None, _include_path(node))

    def _visit_arm(self, arm: Sequence[nodes.Node], sink: bool, guard: bool) -> None:
        if guard:
            self.role_guard_depth += 1
        try:
            for child in arm:
                self._visit(child, sink)
        finally:
            if guard:
                self.role_guard_depth -= 1

    def _sink_kind(self, sink_struct: bool) -> str | None:
        if self._dynamic_region:
            return 'dynamic-role'
        if self.role == 'system' or self.role_guard_depth > 0:
            return 's1-chat-system'
        if sink_struct:
            return 's2-named-instruction'
        if self.tier2:
            return 'tier2-whole-prompt'
        return None

    def _update_role(self, text: str) -> None:
        self.role = _role_after(text, self.role)

    def _handle_output(self, output: nodes.Output, sink: bool) -> None:
        parts = list(output.nodes)
        block_wrapped = id(output) in self.z2_block
        for index, part in enumerate(parts):
            if isinstance(part, nodes.TemplateData):
                self._update_role(part.data)
                continue
            z1 = _z1_between(parts, index, self.delimiter_tags) or id(part) in self.z1_wrapped
            for operand in _rendered_operands(part):
                if isinstance(operand, nodes.Const) and isinstance(operand.value, str):
                    self._update_role(operand.value)
                    continue
                sink_kind = self._sink_kind(sink)
                wrapped = z1 or block_wrapped
                if sink_kind is not None and (not wrapped):
                    self._flag_imported_calls(operand)
                    self._flag_names(_name_nodes(operand), sink_kind)
                self._relocate_calls(operand, sink, suppressed=wrapped, printed=True)

    def _flag_names(self, names: Iterable[nodes.Name], sink_kind: str) -> None:
        for name in names:
            if name.name in self.tainted and name.ctx == 'load' and (id(name) not in self.z2_ids):
                self._report(id(name), name.lineno, sink_kind, name.name)

    def _handle_call_block(self, node: nodes.CallBlock, sink: bool) -> None:
        wrapped = id(node) in self.z2_block or id(node) in self.z1_wrapped
        sink_kind = self._sink_kind(sink)
        if sink_kind is not None and (not wrapped):
            self._flag_imported_calls(node.call)
            self._flag_names(_name_nodes(node.call), sink_kind)
        role_at_call = self.role
        self._walk(node, sink)
        role_after_body = self.role
        self.role = role_at_call
        self._relocate_calls(node.call, sink, suppressed=wrapped, printed=False)
        self.role = role_after_body

    def _relocate_calls(self, node: nodes.Node, sink: bool, suppressed: bool, printed: bool) -> None:
        grouped: dict[int, tuple[nodes.Call, list[nodes.Macro]]] = {}
        for call, macro in self.returns.calls(node, self._relocating):
            if macro is not None:
                grouped.setdefault(id(call), (call, []))[1].append(macro)
        for call, definitions in grouped.values():
            start = self.role
            exits: list[str | None] = []
            for macro in definitions:
                self.role = start
                self._relocate(macro, call, sink, suppressed or id(call) in self.z2_ids)
                exits.append(self.role)
            if printed and call is node:
                if _resolve_parts(self.returns.macros, call.node)[1]:
                    exits.append(start)
                self.role = _SYSTEM_ROLE if _SYSTEM_ROLE in exits else exits[-1]
            else:
                self.role = start

    def _relocate(self, macro: nodes.Macro, call: nodes.Call, sink: bool, suppressed: bool) -> None:
        if len(self._relocating) >= _MAX_MACRO_DEPTH:
            return
        env = self.returns.environment(macro, call, self._relocating)
        guard = self.returns.guard(macro, self._relocating)
        key = (id(macro), env, self.role, self.role_guard_depth > 0, sink, guard, self._dynamic_region)
        cached = self._relocations.get(key)
        if cached is None:
            if self._scans_left <= 0:
                return
            self._scans_left -= 1
            self.returns._charge(self.returns._sizes[id(macro)], 'body-scan')
            cached = self._scan_relocated(macro, env, sink)
            self._relocations[key] = cached
        candidates, self.role = cached
        if suppressed:
            return
        if self._relocating:
            self._capture.update(dict.fromkeys(candidates))
        else:
            self._relocated.extend(((node_id, call.lineno, sink_kind, name, include_path) for node_id, sink_kind, name, include_path in candidates))

    def _scan_relocated(self, macro: nodes.Macro, env: frozenset[str], sink: bool) -> tuple[tuple[_Candidate, ...], str | None]:
        saved = (self.tainted, self._relocating, self._capture)
        self.tainted = env
        self._relocating = self._relocating | {macro.name}
        self._capture = {}
        try:
            for statement in macro.body:
                self._visit(statement, sink)
            return (tuple(self._capture), self.role)
        finally:
            self.tainted, self._relocating, self._capture = saved

    def _report(self, key: int, line: int, sink_kind: str, name: str | None, include_path: str | None=None) -> None:
        if self._relocating:
            self._capture[key, sink_kind, name, include_path] = None
            return
        self._def_site.add((key, _SINK_META[sink_kind][0]))
        self._flag(line, sink_kind, name, include_path)

    def _flag_imported_calls(self, node: nodes.Node) -> None:
        for candidate in _walk_self(node):
            if not isinstance(candidate, nodes.Call) or id(candidate) in self.z2_ids:
                continue
            unit = self.imported.get(_callee_name(candidate) or '')
            if unit is not None and unit.crossing:
                self._report(id(candidate), candidate.lineno, 'cross-template', None, unit.path)

    def _flag_filter_args(self, filt: nodes.Filter | None, sink: bool) -> None:
        if filt is None:
            return
        operands = [operand for link in _filter_chain(filt) for operand in (*link.args, *link.kwargs, *(d for d in (link.dyn_args, link.dyn_kwargs) if d is not None))]
        for operand in operands:
            self._relocate_calls(operand, sink, suppressed=False, printed=False)
        sink_kind = self._sink_kind(sink)
        if sink_kind is None:
            return
        for operand in operands:
            for name in _name_nodes(operand):
                if name.name in self.tainted and name.ctx == 'load' and (id(name) not in self.z2_ids):
                    self._report(id(name), name.lineno, sink_kind, name.name)

    def _handle_assign(self, assign: nodes.Assign) -> None:
        if not _is_instruction_name(assign.target, self.instruction_names):
            return
        for name in _name_nodes(assign.node):
            if name.name in self.tainted and id(name) not in self.z2_ids:
                self._report(id(name), name.lineno, 's2-named-instruction', name.name)
        self._relocate_calls(assign.node, True, suppressed=False, printed=False)

    def _is_dynamic_role_loop(self, loop: nodes.For) -> bool:
        if not self.returns.refs_tainted(loop.iter, self.tainted):
            return False
        chunks = list(_emitted_literals(loop))
        has_turn_open = any((chunk.endswith(_ROLE_TAKING_MARKERS) for chunk in chunks))
        has_literal_system = any(('system' in chunk.lower() for chunk in chunks))
        has_guard = any((_system_guard_polarity(if_node.test) == 'eq' for if_node in loop.find_all(nodes.If)))
        return has_turn_open and (not has_literal_system) and (not has_guard)

    def _flag_dynamic_role(self, loop: nodes.For) -> None:
        for output in loop.find_all(nodes.Output):
            if id(output) in self.z2_block:
                continue
            parts = list(output.nodes)
            for index, part in enumerate(parts):
                if _z1_between(parts, index, self.delimiter_tags) or id(part) in self.z1_wrapped:
                    continue
                for name in _name_nodes(part):
                    if name.name in self.tainted and name.ctx == 'load' and (id(name) not in self.z2_ids):
                        self._report(id(name), name.lineno, 'dynamic-role', name.name)
                self._dynamic_region = True
                try:
                    self._relocate_calls(part, False, suppressed=False, printed=False)
                finally:
                    self._dynamic_region = False

    def _basis(self, name: str) -> str:
        if name in self.annotated:
            return _BASIS_ANNOTATION
        if name in self.lexicon:
            return _BASIS_LEXICON
        if name in self.sources:
            return _BASIS_UNDECLARED
        return _BASIS_PROPAGATED

    def _flag(self, line: int, sink_kind: str, name: str | None, include_path: str | None=None) -> None:
        sub_code, tier = _SINK_META[sink_kind]
        label = name or 'included content'
        key = (sub_code, label, line)
        if key in self._seen:
            return
        self._seen.add(key)
        message, asserted = _sink_message(sub_code, sink_kind, label, include_path)
        extra: dict[str, object] = {'tier': tier, 'sink_kind': sink_kind, **asserted}
        if name is not None and sub_code in _VAR_BEARING_SUB_CODES:
            extra['untrusted_basis'] = self._basis(name)
        self.diagnostics.append(Diagnostic(rule=RuleId.PINJ, sub_code=sub_code, severity=severity_for(RuleId.PINJ, sub_code), message=message, file=self.file, line=line, m2_anchor=anchor_for(RuleId.PINJ, sub_code), scope_ref=_SCOPE_REF, extra=extra))

def _sources(ctx: TemplateContext, config: LintConfig) -> frozenset[str]:
    base = config.untrusted_vars
    if config.pinj_source_model == 'undeclared':
        base = ctx.undeclared | base
    directives = ctx.directives
    return (base | directives.untrusted) - (directives.trusted - directives.untrusted)

class PinjRule:
    id: RuleId = RuleId.PINJ

    def check(self, ctx: TemplateContext, config: LintConfig) -> list[Diagnostic]:
        diagnostics, _state = self.check_with_state(ctx, config)
        return diagnostics

    def check_with_state(self, ctx: TemplateContext, config: LintConfig) -> tuple[list[Diagnostic], PinjCheckState]:
        sources = _sources(ctx, config)
        if not sources and config.pinj_source_model != 'undeclared':
            return ([], PinjCheckState.NO_SOURCES)
        roots = tuple((Path(root) for root in config.template_search_path))
        cross = config.cross_template != 'off'
        cache = UnitCache(roots)
        boundaries = _include_boundaries(ctx.ast, ctx.file, roots, config.cross_template_depth, cache) if cross else {}
        imported = _imported_units(ctx.ast, ctx.file, roots, cache) if cross else {}
        parent = _extends_parent(ctx.ast, ctx.file, roots, cache) if cross else None
        crossing: frozenset[str] = frozenset().union(*(boundary.crossing for boundary in boundaries.values()))
        if not sources and (not crossing) and (not any((unit.crossing for unit in imported.values()))):
            return ([], PinjCheckState.NO_SOURCES)
        z2_ids = _z2_sanitized_ids(ctx.ast, config.sanitizer_filters)
        z2_block = _z2_block_ids(ctx.ast, config.sanitizer_filters)
        for following in (True, False):
            try:
                diagnostics = self._trace(ctx, config, sources, crossing, boundaries, imported, parent, z2_ids, z2_block, following=following)
                return (diagnostics, PinjCheckState.ENABLED)
            except _MacroWorkExhausted:
                if not following:
                    raise
        raise AssertionError('a PINJ trace must either return or refuse')

    @staticmethod
    def _trace(ctx: TemplateContext, config: LintConfig, sources: frozenset[str], crossing: frozenset[str], boundaries: dict[int, _Boundary], imported: dict[str, _ImportedUnit], parent: TemplateContext | None, z2_ids: set[int], z2_block: set[int], *, following: bool) -> list[Diagnostic]:
        macros = _macro_map(ctx.ast, following=following)
        returns = _MacroReturns(macros, cleared=z2_ids, wrapped=z2_block)
        tainted = _compute_tainted(ctx.ast, sources | crossing, macros, returns, seeds=_caller_seeds(ctx.ast, macros, imported))
        scanner = _Scanner(file=ctx.file, tainted=tainted, sources=sources, lexicon=config.untrusted_vars, annotated=ctx.directives.untrusted, z2_ids=z2_ids, z2_block=z2_block, tier2=not _has_chat_markers(ctx.ast) and (not (parent is not None and _has_chat_markers(parent.ast))), instruction_names=config.instruction_names, delimiter_tags=config.delimiter_tags, dynamic_role_loops=config.dynamic_role_loops, cross_template=config.cross_template != 'off', boundaries=boundaries, imported=imported, block_roles={} if parent is None else _block_roles(parent.ast), returns=returns)
        scanner.run(ctx.ast)
        return scanner.diagnostics
_BUILTIN_CHECK = PinjRule.check
