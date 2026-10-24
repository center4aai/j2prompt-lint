from __future__ import annotations
import dataclasses
import operator
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Generic, Protocol, TypeVar, cast
from jinja2 import nodes
from markupsafe import Markup, escape
if TYPE_CHECKING:
    from j2prompt_lint.rules.pchat import _Emission
GUARDED = 1
BOUND = 2
CONTAINED = 4
ITERATED = 8
MAX_PATHS = 256
MAX_STEPS = 50000
_NODE_FIELDS: dict[type[nodes.Node], tuple[str, ...]] = {nodes.Template: ('body',), nodes.Output: ('nodes',), nodes.If: ('test', 'body', 'elif_', 'else_'), nodes.For: ('target', 'iter', 'body', 'else_', 'test', 'recursive'), nodes.Assign: ('target', 'node'), nodes.Macro: ('name', 'args', 'defaults', 'body'), nodes.AssignBlock: ('target', 'filter', 'body'), nodes.FilterBlock: ('body', 'filter'), nodes.CallBlock: ('call', 'args', 'defaults', 'body'), nodes.ScopedEvalContextModifier: ('options', 'body'), nodes.OverlayScope: ('context', 'body'), nodes.With: ('targets', 'values', 'body'), nodes.Scope: ('body',), nodes.ExprStmt: ('node',), nodes.EvalContextModifier: ('options',), nodes.TemplateData: ('data',), nodes.Const: ('value',), nodes.Name: ('name', 'ctx'), nodes.CondExpr: ('test', 'expr1', 'expr2'), nodes.And: ('left', 'right'), nodes.Or: ('left', 'right'), nodes.List: ('items',), nodes.Tuple: ('items', 'ctx'), nodes.Dict: ('items',), nodes.Add: ('left', 'right'), nodes.Concat: ('nodes',), nodes.Pow: ('left', 'right'), nodes.Mod: ('left', 'right'), nodes.FloorDiv: ('left', 'right'), nodes.Div: ('left', 'right'), nodes.Sub: ('left', 'right'), nodes.Mul: ('left', 'right'), nodes.Neg: ('node',), nodes.Pos: ('node',), nodes.Getitem: ('node', 'arg', 'ctx'), nodes.Slice: ('start', 'stop', 'step'), nodes.Getattr: ('node', 'attr', 'ctx'), nodes.Filter: ('node', 'name', 'args', 'kwargs', 'dyn_args', 'dyn_kwargs'), nodes.Call: ('node', 'args', 'kwargs', 'dyn_args', 'dyn_kwargs'), nodes.Not: ('node',), nodes.Test: ('node', 'name', 'args', 'kwargs', 'dyn_args', 'dyn_kwargs'), nodes.Compare: ('expr', 'ops'), nodes.Pair: ('key', 'value'), nodes.Keyword: ('key', 'value'), nodes.Operand: ('op', 'expr'), nodes.NSRef: ('name', 'attr')}
_LIST_FIELDS = frozenset(('body', 'nodes', 'elif_', 'else_', 'args', 'defaults', 'options', 'targets', 'values', 'items', 'kwargs', 'ops'))
_STRING_FIELDS = frozenset(('name', 'ctx', 'attr', 'op', 'data'))
_LIST_ITEM_TYPES: dict[tuple[type[nodes.Node], str], type[nodes.Node]] = {(nodes.Dict, 'items'): nodes.Pair, (nodes.Compare, 'ops'): nodes.Operand, (nodes.If, 'elif_'): nodes.If, (nodes.Macro, 'args'): nodes.Name, (nodes.CallBlock, 'args'): nodes.Name, (nodes.ScopedEvalContextModifier, 'options'): nodes.Keyword, (nodes.EvalContextModifier, 'options'): nodes.Keyword, (nodes.Call, 'kwargs'): nodes.Keyword, (nodes.Filter, 'kwargs'): nodes.Keyword, (nodes.Test, 'kwargs'): nodes.Keyword}
_CHILD_TYPES: dict[tuple[type[nodes.Node], str], type[nodes.Node]] = {(nodes.CallBlock, 'call'): nodes.Call, (nodes.AssignBlock, 'filter'): nodes.Filter, (nodes.FilterBlock, 'filter'): nodes.Filter, (nodes.Pair, 'key'): nodes.Expr, (nodes.Pair, 'value'): nodes.Expr, (nodes.Keyword, 'value'): nodes.Expr, (nodes.Operand, 'expr'): nodes.Expr, (nodes.Slice, 'start'): nodes.Expr, (nodes.Slice, 'stop'): nodes.Expr, (nodes.Slice, 'step'): nodes.Expr}
SYNTHETIC_ROLE = '_pchat_synthetic_role'
ORIGIN_WORK = '_pchat_origin_work'
ORIGIN_COMPLETE = '_pchat_origin_complete'

def schema_work(node: nodes.Node) -> int:
    fields = _NODE_FIELDS.get(type(node), ())
    return 1 + len(fields) + sum((len(value) for name in fields if isinstance((value := getattr(node, name, None)), list)))

def known_schema(node: nodes.Node) -> bool:
    fields = _NODE_FIELDS.get(type(node))
    if fields is None or node.fields != fields:
        return False
    if type(getattr(node, SYNTHETIC_ROLE, False)) is not bool:
        return False
    allowed = (*fields, *node.attributes, SYNTHETIC_ROLE, ORIGIN_WORK, ORIGIN_COMPLETE)
    if len(vars(node)) > len(allowed) or any((name not in allowed for name in vars(node))):
        return False
    for name in fields:
        if not hasattr(node, name):
            return False
        value = getattr(node, name)
        if name in _LIST_FIELDS:
            item_type = _LIST_ITEM_TYPES.get((type(node), name), nodes.Node)
            if not isinstance(value, list) or any((not isinstance(v, item_type) for v in value)):
                return False
        elif isinstance(node, nodes.Const):
            pass
        elif name in _STRING_FIELDS or (isinstance(node, nodes.Keyword) and name == 'key'):
            if not isinstance(value, str):
                return False
        elif name == 'recursive':
            if type(value) is not bool:
                return False
        elif value is None:
            if name not in ('dyn_args', 'dyn_kwargs', 'expr2', 'filter', 'test') and (not (isinstance(node, nodes.Filter) and name == 'node' or (isinstance(node, nodes.Slice) and name in ('start', 'stop', 'step')))):
                return False
        elif not isinstance(value, _CHILD_TYPES.get((type(node), name), nodes.Node)):
            return False
    return not (isinstance(node, nodes.With) and len(node.targets) != len(node.values))

def named_role_syntax(node: nodes.Node) -> bool:
    if isinstance(node, nodes.Name):
        return node.ctx == 'load' and (node.name == 'role' or node.name.startswith('role#'))
    if isinstance(node, nodes.Getattr):
        return node.attr == 'role'
    return isinstance(node, nodes.Getitem) and isinstance(node.arg, nodes.Const) and (node.arg.value == 'role')

@dataclass(frozen=True, slots=True)
class RoleEvidence:
    named: bool
    available: bool
    positional: bool
_UNAVAILABLE_ROLES = tuple((RoleEvidence(bool(index & 1), False, bool(index & 2)) for index in range(4)))

@dataclass(slots=True)
class _RoleCollector:
    named: bool = False
    unavailable: bool = False
    initial_available: bool = True
    finished: bool = False
_SILENT = (nodes.Assign, nodes.AssignBlock, nodes.Macro, nodes.Import, nodes.FromImport, nodes.ExprStmt)
_IN_PLACE = (nodes.With, nodes.Scope, nodes.OverlayScope)

@dataclass(frozen=True, slots=True)
class Mark:
    line: int
    order: int
    at: int
    flags: int

@dataclass(frozen=True, slots=True)
class Carry:
    text: str = ''
    marks: tuple[Mark, ...] = ()
    digest: int = dataclasses.field(default=0, compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, 'digest', hash((self.text, self.marks)))

    def __hash__(self) -> int:
        return self.digest
EMPTY = Carry()

@dataclass(frozen=True, slots=True)
class Occurrence:
    pattern: str
    start: int
    marks: tuple[Mark, ...]

    @property
    def line(self) -> int:
        return self.marks[0].line

    @property
    def rank(self) -> tuple[int, int]:
        return (self.marks[0].order, self.marks[0].at)

    @property
    def flags(self) -> int:
        flags = 0
        for mark in self.marks:
            flags |= mark.flags
        return flags

    @property
    def identity(self) -> tuple[str, tuple[tuple[int, int], ...]]:
        return (self.pattern, tuple(((mark.order, mark.at) for mark in self.marks)))

@dataclass(frozen=True, slots=True)
class Lexicon:
    patterns: tuple[str, ...]
    prefixes: frozenset[str]
    longest: int

    @classmethod
    def of(cls, patterns: Iterable[str], keep: Iterable[str]=()) -> Lexicon:
        reported = tuple(sorted(set(patterns)))
        strings = (*reported, *keep)
        prefixes = frozenset((s[:n] for s in strings for n in range(1, len(s) + 1)))
        return cls(reported, prefixes, max((len(s) for s in strings), default=0))

@dataclass(frozen=True, slots=True)
class Model:
    rendered: Mapping[int, Sequence[_Emission]]
    base: Mapping[int, int]
    guards: frozenset[int]
    lexicon: Lexicon
    complete: bool = True
    semantic: bool = False
    order: Mapping[int, int] = dataclasses.field(default_factory=dict)
    work_left: int | None = None
    alias_steps: int = 0
    named_syntax_absent: bool | None = None
    origin_work: int = 0
    origin_complete: bool = False

@dataclass(frozen=True, slots=True)
class Value:
    kind: str
    data: object
    origin: nodes.Node = dataclasses.field(compare=False, hash=False)
    safe: bool = False
    flags: int = 0
    generation: bool = False
    lazy_observation: bool = dataclasses.field(default=False, compare=False, hash=False)
    _hash: int = dataclasses.field(init=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, '_hash', hash((self.kind, self.data, self.safe, self.flags, self.generation)))

    def __hash__(self) -> int:
        return self._hash

@dataclass(frozen=True, slots=True)
class Frame:
    identity: int
    bindings: tuple[tuple[str, Value], ...] = ()
    _hash: int = dataclasses.field(init=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, '_hash', hash((self.identity, self.bindings)))

    def __hash__(self) -> int:
        return self._hash

@dataclass(frozen=True, slots=True)
class Closure:
    node: nodes.Node
    frames: tuple[Frame, ...]
    autoescape: bool | None

@dataclass(frozen=True, slots=True)
class Fragment:
    emission: _Emission
    order: int
    flags: int = 0
S = TypeVar('S')
T = TypeVar('T')

@dataclass(frozen=True, slots=True)
class Path(Generic[S]):
    carry: Carry
    state: S
    frames: tuple[Frame, ...] = ()
    facts: frozenset[tuple[object, bool]] = frozenset()
    autoescape: bool | None = False
    stopped: str | None = None
    role_available: bool | None = None

class Algebra(Protocol[S]):
    iterates: bool
    exact: bool
    budget: int

    def literal(self, state: S, found: Sequence[Occurrence]) -> S | None:
        ...

    def emitted(self, path: Path[S], emission: _Emission, order: int, flags: int) -> S | None:
        ...

    def value(self, path: Path[S], emission: _Emission) -> S | None:
        ...

    def branch(self, guard: bool, entry: Sequence[Path[S]], arms: Sequence[Sequence[Path[S]]]) -> list[Path[S]] | None:
        ...

    def settle(self, paths: list[Path[S]]) -> list[Path[S]] | None:
        ...

    def statement(self, node: nodes.Node, paths: list[Path[S]]) -> list[Path[S]] | None:
        ...

    def container(self, node: nodes.Node, paths: list[Path[S]]) -> list[Path[S]] | None:
        ...

    def loop_pass(self, entry: Sequence[Path[S]], exits: Sequence[Path[S]]) -> bool:
        ...

    def later_pass_failed(self, entry: Sequence[Path[S]]) -> None:
        ...

    def overflow(self) -> None:
        ...

def _scalar_comparison(op: str, left: object, right: object) -> bool:
    if op == 'eq':
        return left == right
    if op == 'ne':
        return left != right
    if op in ('in', 'notin'):
        if not isinstance(left, str) or not isinstance(right, str):
            raise TypeError('non-string membership')
        return (left in right) == (op == 'in')
    if not (isinstance(left, str) and isinstance(right, str) or (isinstance(left, (int, float)) and isinstance(right, (int, float)))):
        raise TypeError('unrepresented comparison')
    operation = {'gt': operator.gt, 'lt': operator.lt, 'gteq': operator.ge, 'lteq': operator.le}.get(op)
    if operation is None:
        raise TypeError('unrepresented comparison')
    return cast(Callable[[object, object], bool], operation)(left, right)

def _compatible_facts(facts: frozenset[tuple[object, bool]], key: object, wanted: bool) -> bool:
    all_facts = (*facts, (key, wanted))
    comparisons = [(cast(tuple[object, ...], k), truth) for k, truth in all_facts if isinstance(k, tuple) and len(k) == 4 and (k[0] == 'compare')]
    variable = key[2] if isinstance(key, tuple) and len(key) in (3, 4) and (key[0] in ('compare', 'test')) else key
    relevant = [(k[1], k[3], truth) for k, truth in comparisons if k[2] == variable]
    fixed = [constant for op, constant, truth in relevant if op == 'eq' and truth]
    tests = [(str(k[1]), truth) for k, truth in all_facts if isinstance(k, tuple) and len(k) == 3 and (k[0] == 'test') and (k[2] == variable)]
    identities = [{'none': None, 'true': True, 'false': False}[name] for name, truth in tests if truth and name in ('none', 'true', 'false')]

    def permits(constants: Sequence[object]) -> bool:
        for constant in constants:
            try:
                if any((_scalar_comparison(str(op), constant, other) != truth for op, other, truth in relevant)):
                    continue
            except TypeError:
                continue
            if any((k == variable and truth != bool(constant) for k, truth in all_facts)):
                continue
            if any((k == ('defined', variable) and (not truth) for k, truth in all_facts)):
                continue
            if any((_scalar_test(name, constant) != truth for name, truth in tests)):
                continue
            return True
        return False
    if identities:
        if any((constant is not identities[0] for constant in identities)):
            return False
        if not permits(identities[:1]):
            return False
    elif fixed:
        constant = fixed[0]
        candidates = [constant]
        if type(constant) in (bool, int, float) and constant in (0, 1):
            candidates.extend((bool(constant), int(constant), float(constant)))
        if not permits(candidates):
            return False
    elif ('boolean', True) in tests and (not permits((False, True))):
        return False
    lower: tuple[object, bool] | None = None
    upper: tuple[object, bool] | None = None
    for op, constant, truth in relevant:
        try:
            if op == 'gt' and truth or (op == 'lt' and (not truth)):
                if lower is None or _scalar_comparison('gt', constant, lower[0]):
                    lower = (constant, truth)
                elif constant == lower[0]:
                    lower = (constant, truth or lower[1])
            elif op == 'lt' and truth or (op == 'gt' and (not truth)):
                if upper is None or _scalar_comparison('lt', constant, upper[0]):
                    upper = (constant, truth)
                elif constant == upper[0]:
                    upper = (constant, truth or upper[1])
        except TypeError:
            return False
    if lower is not None and upper is not None:
        try:
            if _scalar_comparison('gt', lower[0], upper[0]) or (lower[0] == upper[0] and (lower[1] or upper[1])):
                return False
        except TypeError:
            return False
        if lower[0] == upper[0] and (not lower[1]) and (not upper[1]):
            constant = lower[0]
            candidates = [constant]
            if type(constant) in (bool, int, float) and constant in (0, 1):
                candidates.extend((bool(constant), int(constant), float(constant)))
            if not permits(candidates):
                return False
    return True

def _scalar_test(name: str, data: object) -> bool:
    return {'none': data is None, 'boolean': type(data) is bool, 'true': data is True, 'false': data is False, 'number': isinstance(data, (int, float)), 'string': isinstance(data, str), 'mapping': False, 'sequence': isinstance(data, str), 'iterable': isinstance(data, str), 'callable': False}[name]

class Flow(Generic[S]):

    def __init__(self, model: Model, algebra: Algebra[S], observer: _RoleCollector | None=None) -> None:
        self.model = model
        self.algebra = algebra
        self.observer = observer
        self._calls: tuple[tuple[object, ...], ...] = ()
        self._sites: dict[tuple[object, ...], int] = {}
        self._slices: dict[Value, None] = {}
        self._scope: tuple[object, ...] = ()
        self._output_site = 0
        self._guard_probe: list[bool] | None = None
        self._guard_seen = [False]

    def run(self, statements: Sequence[nodes.Node], paths: list[Path[S]], flags: int=0) -> list[Path[S]] | None:
        if self.model.semantic:
            return self._semantic_run(statements, paths, flags)
        current: list[Path[S]] | None = paths
        for statement in statements:
            if current is None or self._spent():
                return None if self.algebra.exact else current
            current = self._statement(statement, current, flags)
        return current

    def _charge(self, amount: int=1) -> bool:
        if amount < 0 or self.algebra.budget < amount:
            self.algebra.budget = -1
            self.algebra.overflow()
            if self.observer is not None:
                self.observer.unavailable = True
            return False
        self.algebra.budget -= amount
        return True

    def _role_gap(self, path: Path[S]) -> Path[S]:
        if self.observer is None:
            return path
        self.observer.unavailable = True
        if path.role_available is False or not self._charge():
            return path
        return dataclasses.replace(path, role_available=False)

    def _role_result(self, path: Path[S], value: Value, *, binding: bool=False) -> Path[S]:
        if value.kind == 'refuse' and (not (binding and value.lazy_observation)):
            return self._role_gap(path)
        return path

    def _child_path(self, parent: Path[S], child: Path[T]) -> Path[S] | None:
        if self.observer is not None and (not self._charge()):
            return None
        return dataclasses.replace(parent, facts=child.facts, role_available=child.role_available)

    def _schema(self, node: nodes.Node) -> bool:
        return self.observer is None or (self._charge(schema_work(node)) and known_schema(node))

    def _role_results(self, node: nodes.Node, pairs: list[tuple[Path[S], Value]]) -> list[tuple[Path[S], Value]]:
        if self.observer is None:
            return pairs
        for index, (path, value) in enumerate(pairs):
            if not self._charge():
                return pairs
            path = self._role_result(path, value)
            pairs[index] = (path, value)
            if path.role_available is True and (not path.stopped) and (value.kind != 'refuse') and named_role_syntax(node) and (not getattr(node, SYNTHETIC_ROLE, False)) and self._charge():
                self.observer.named = True
        return pairs

    def _stop(self, paths: Sequence[Path[S]], reason: str) -> list[Path[S]]:
        if not self.algebra.exact:
            self.algebra.overflow()
        return [dataclasses.replace(self._role_gap(path), stopped=reason) for path in paths]

    def _semantic_run(self, statements: Sequence[nodes.Node], paths: list[Path[S]], flags: int) -> list[Path[S]] | None:
        if self.observer is not None and (not self._charge(len(paths))):
            return None
        current = []
        for path in paths:
            if self.observer is not None and path.role_available is None:
                path = dataclasses.replace(path, role_available=self.model.origin_complete and self.observer.initial_available)
                if not self.model.origin_complete:
                    self.observer.unavailable = True
            current.append(path if path.frames else dataclasses.replace(path, frames=(Frame(0),)))
        for node in statements:
            if not self._charge(len(current)):
                return None
            stopped = [path for path in current if path.stopped]
            active = [path for path in current if not path.stopped]
            if active:
                result = self._semantic_statement(node, active, flags)
                if result is None:
                    if self.observer is not None:
                        self.observer.unavailable = True
                    return None
                joined = self._settled([*stopped, *result])
                if joined is None:
                    return None
                current = joined
                completed = getattr(self.algebra, 'completed', None)
                if completed is not None:
                    current = completed(current)
                if self.algebra.budget < 0:
                    return None
        return current

    def _lookup(self, path: Path[S], name: str, origin: nodes.Node) -> Value:
        for frame in reversed(path.frames):
            for key, value in reversed(frame.bindings):
                if not self._charge():
                    return Value('refuse', 'budget', origin)
                if key == name:
                    self._note_guard(value)
                    return self._identity_value(value, path)
        value = Value('symbol', ('context', name), origin)
        self._note_guard(value)
        return self._identity_value(value, path)

    def _note_guard(self, value: Value) -> None:
        if self._guard_probe is None or self._guard_probe[0]:
            return
        self._guard_probe[0] = self._generation_value(value)

    def _generation_value(self, value: Value) -> bool:
        from j2prompt_lint.rules.pchat import _GEN_PROMPT_HINT
        if value.generation:
            return True
        if value.kind == 'scalar' and isinstance(value.origin, nodes.Name):
            return _GEN_PROMPT_HINT in value.origin.name.lower()
        if value.kind != 'symbol':
            return False
        pending = [value.data]
        while pending:
            if not self._charge():
                return False
            part = pending.pop()
            if isinstance(part, tuple):
                if len(part) == 2 and part[0] == 'context' and isinstance(part[1], str) and (_GEN_PROMPT_HINT in part[1].lower()):
                    return True
                if not self._charge(len(part)):
                    return False
                pending.extend(part)
            elif isinstance(part, Value) and part.kind == 'symbol':
                if not self._charge():
                    return False
                pending.append(part.data)
        return False

    @staticmethod
    def _identity_value(value: Value, path: Path[S]) -> Value:
        if value.kind == 'symbol':
            for name, data in (('none', None), ('true', True), ('false', False)):
                if (('test', name, value.data), True) in path.facts:
                    return dataclasses.replace(value, kind='scalar', data=data)
            if (('compare', 'eq', value.data, None), True) in path.facts:
                return dataclasses.replace(value, kind='scalar', data=None)
        return value

    def _bind(self, path: Path[S], name: str, value: Value) -> Path[S] | None:
        path = self._role_result(path, value, binding=True)
        frame = path.frames[-1]
        if not self._charge(len(frame.bindings) + len(path.frames) + len(name) + 1):
            return None
        old = dict(frame.bindings)
        if old.get(name) == value:
            return path
        old[name] = value
        updated = Frame(frame.identity, tuple(old.items()))
        return dataclasses.replace(path, frames=(*path.frames[:-1], updated))

    def _target(self, path: Path[S], target: nodes.Node, value: Value) -> Path[S] | None:
        if not self._schema(target):
            return self._role_gap(path)
        if isinstance(target, nodes.Name):
            return self._bind(path, target.name, value)
        if isinstance(target, nodes.Tuple) and value.kind == 'sequence':
            values = cast(tuple[Value, ...], value.data)
            if len(values) == len(target.items):
                current: Path[S] | None = path
                for sub, item in zip(target.items, values, strict=True):
                    if current is None:
                        return None
                    current = self._target(current, sub, item)
                return current
        path = self._role_gap(path)
        if isinstance(target, nodes.NSRef):
            return self._stop([path], 'namespace-mutation')[0]
        for name in target.find_all(nodes.Name):
            bound = self._bind(path, name.name, Value('refuse', 'binder', target))
            if bound is None:
                return None
            path = bound
        return path

    def _semantic_statement(self, node: nodes.Node, paths: list[Path[S]], flags: int) -> list[Path[S]] | None:
        if not self._schema(node):
            return self._stop(paths, 'node-schema')
        if isinstance(node, nodes.Output):
            current = paths
            for expression in node.nodes:
                entry = current
                guarded_value = False
                self._output_site = id(expression)
                out: list[Path[S]] = []
                for path in current:
                    if path.stopped:
                        out.append(path)
                        continue
                    for reached, value in self._evaluate(expression, path, flags):
                        guarded_value |= bool(value.flags & GUARDED) or (value.kind == 'text' and any((part.flags & GUARDED for part in cast(tuple[Fragment, ...], value.data))))
                        result = self._output(value, reached, flags)
                        if result is None:
                            return None
                        out.extend(result)
                joined = self._settled(out)
                if joined is None:
                    return None
                current = joined
                if guarded_value:
                    guarded = self.algebra.branch(True, entry, [current])
                    if guarded is None:
                        return None
                    current = guarded
            return current
        if isinstance(node, nodes.If):
            remaining = paths
            arms: list[list[Path[S]]] = []
            for branch in (node, *node.elif_):
                if not self._schema(branch):
                    return self._stop(paths, 'elif-schema')
                no: list[Path[S]] = []
                for path in remaining:
                    yes, yes_guard = self._guarded_condition(branch.test, path, True)
                    skipped, no_guard = self._guarded_condition(branch.test, path, False)
                    guard = yes_guard or no_guard
                    result = self.run(branch.body, yes, flags | (GUARDED if guard else 0))
                    if result is None:
                        return None
                    if guard:
                        guarded = self.algebra.branch(True, [path], [result, skipped])
                        if guarded is None:
                            return None
                        result, skipped = (guarded[:len(result)], guarded[len(result):])
                    arms.append(result)
                    no.extend(skipped)
                remaining = no
            otherwise = self.run(node.else_, remaining, flags)
            if otherwise is None:
                return None
            arms.append(otherwise)
            return self._settled(self.algebra.branch(False, paths, arms))
        if isinstance(node, nodes.For):
            out = []
            for path in paths:
                for entered, iterable in self._evaluate(node.iter, path, flags):
                    result = self._semantic_for(node, entered, iterable, flags)
                    if result is None:
                        return None
                    out.extend(result)
            return self._settled(out)
        if isinstance(node, nodes.Assign):
            out = []
            for path in paths:
                for reached, value in self._evaluate(node.node, path, flags):
                    updated = self._target(reached, node.target, value)
                    if updated is None:
                        return None
                    out.append(updated)
            return self._settled(out)
        if isinstance(node, nodes.Macro):
            out = []
            for path in paths:
                value = Value('macro', Closure(node, path.frames, path.autoescape), node)
                updated = self._bind(path, node.name, value)
                if updated is None:
                    return None
                out.append(updated)
            return out
        if isinstance(node, nodes.AssignBlock | nodes.FilterBlock):
            out = []
            for path in paths:
                for reached, value in self._capture(node.body, path, flags):
                    variants = self._captured_filter(node.filter, value, reached) if node.filter is not None else [(reached, value)]
                    for at, filtered in variants:
                        if isinstance(node, nodes.AssignBlock):
                            updated = self._target(at, node.target, filtered)
                            if updated is None:
                                return None
                            out.append(updated)
                        else:
                            result = self._output(filtered, at, flags)
                            if result is None:
                                return None
                            out.extend(result)
            return self._settled(out)
        if isinstance(node, nodes.CallBlock):
            out = []
            for path in paths:
                caller = Value('caller', Closure(node, path.frames, path.autoescape), node)
                for reached, value in self._call(node.call, path, flags, caller):
                    result = self._output(value, reached, flags)
                    if result is None:
                        return None
                    out.extend(result)
            return self._settled(out)
        if isinstance(node, nodes.ScopedEvalContextModifier):
            if self.observer is not None and any((not self._schema(option) for option in node.options)):
                return self._stop(paths, 'option-schema')
            autoescape: bool | None = paths[0].autoescape if paths else False
            for option in node.options:
                if option.key == 'autoescape':
                    autoescape = option.value.value if isinstance(option.value, nodes.Const) and isinstance(option.value.value, bool) else None
            out = []
            for path in paths:
                selected = [path]
                if self.observer is not None:
                    for option in node.options:
                        selected = [p for at in selected for p, _value in self._evaluate(option.value, at, flags)]
                for reached in selected:
                    changed = dataclasses.replace(reached, autoescape=autoescape)
                    result = self.run(node.body, [changed], flags)
                    if result is None:
                        return None
                    out.extend((dataclasses.replace(p, autoescape=path.autoescape) for p in result))
            return self._settled(out)
        if isinstance(node, nodes.OverlayScope):
            return self._stop(paths, 'overlay-context')
        if isinstance(node, nodes.With | nodes.Scope):
            out = []
            for path in paths:
                with_variants = self._arguments(node.values, path, flags) if isinstance(node, nodes.With) else [(path, ())]
                for reached, values in with_variants:
                    if not self._charge(len(path.frames) + 1):
                        return None
                    entered = dataclasses.replace(reached, frames=(*path.frames, Frame(id(node))))
                    if isinstance(node, nodes.With):
                        for target, value in zip(node.targets, values, strict=True):
                            updated = self._target(entered, target, value)
                            if updated is None:
                                return None
                            entered = updated
                    result = self.run(node.body, [entered], flags)
                    if result is None:
                        return None
                    out.extend((dataclasses.replace(p, frames=path.frames) for p in result))
            return self._settled(out)
        if isinstance(node, nodes.ExprStmt):
            if any(node.find_all(nodes.Call)):
                return self._stop(paths, 'effectful-statement')
            if self.observer is not None:
                return [p for path in paths for p, _value in self._evaluate(node.node, path, flags)]
            return paths
        if isinstance(node, nodes.EvalContextModifier):
            return self._stop(paths, 'unscoped-context-modifier')
        return self._stop(paths, type(node).__name__)

    def _atom(self, path: Path[S], key: object, wanted: bool) -> list[Path[S]]:
        if (key, not wanted) in path.facts:
            return []
        if (key, wanted) in path.facts:
            return [path]
        if not self._charge(20 * len(path.facts) + 1):
            return []
        if not _compatible_facts(path.facts, key, wanted):
            return []
        return [dataclasses.replace(path, facts=path.facts | {(key, wanted)})]

    def _condition(self, node: nodes.Node, path: Path[S], wanted: bool) -> list[Path[S]]:
        if not self._charge():
            return []
        if not self._schema(node):
            return self._stop([path], 'condition-schema')
        if isinstance(node, nodes.Not):
            return self._condition(node.node, path, not wanted)
        if isinstance(node, nodes.And | nodes.Or):
            conjunction = isinstance(node, nodes.And)
            if wanted == conjunction:
                return [r for p in self._condition(node.left, path, wanted) for r in self._condition(node.right, p, wanted)]
            return [*self._condition(node.left, path, wanted), *(r for p in self._condition(node.left, path, not wanted) for r in self._condition(node.right, p, wanted))]
        out = []
        for reached, value in self._evaluate(node, path, 0):
            if value.kind == 'scalar' or value.kind in ('sequence', 'mapping'):
                if bool(value.data) == wanted:
                    out.append(reached)
            elif value.kind == 'text':
                parts = self._parts(value)
                if any((part.emission.text is None for part in parts)):
                    out.extend(self._stop([reached], 'text-truth'))
                elif any((part.emission.text for part in parts)) == wanted:
                    out.append(reached)
            elif value.kind == 'symbol':
                conflict = self._slice_conflict(value, reached)
                if conflict is not False:
                    out.extend(self._stop([reached], 'slice-cardinality-correlation'))
                    continue
                bounds = self._slice_bounds(value)
                if bounds is not None:
                    bounds = self._known_slice_bounds(value, reached)
                    if bounds is None:
                        out.extend(self._stop([reached], 'budget'))
                        continue
                    if bounds[0] > 0 and (not wanted):
                        continue
                    if bounds[1] == 0 and wanted:
                        continue
                out.extend(self._atom(reached, value.data, wanted))
            elif value.kind == 'refuse':
                out.extend(self._stop([reached], str(value.data)))
            else:
                out.extend(self._stop([reached], 'unrepresented-predicate'))
        return out

    def _guarded_condition(self, node: nodes.Node, path: Path[S], wanted: bool, *, emission_guard: bool=True) -> tuple[list[Path[S]], bool]:
        previous = self._guard_probe
        probe = [False]
        self._guard_probe = probe
        try:
            result = self._condition(node, path, wanted)
        finally:
            self._guard_probe = previous
            if previous is not None:
                previous[0] |= probe[0]
        if emission_guard:
            self._guard_seen[0] |= probe[0]
        return (result, probe[0])

    def _mapping(self, pairs: Iterable[tuple[Value, Value]], node: nodes.Node) -> Value:
        unique: list[tuple[Value, Value]] = []
        for key, value in pairs:
            if key.kind != 'scalar' or type(key.data) not in (str, int, float, bool, type(None)):
                return Value('refuse', 'mapping-key', node)
            if not self._charge(len(unique) + 1):
                return Value('refuse', 'budget', node)
            position = next((i for i, (old, _) in enumerate(unique) if old.data == key.data), None)
            if position is None:
                unique.append((key, value))
            else:
                unique[position] = (unique[position][0], value)
        return Value('mapping', tuple(unique), node)

    def _constant(self, data: object, node: nodes.Node) -> Value:
        from j2prompt_lint.rules.pchat import MAX_SPLICE_DEPTH
        stack: list[tuple[object, bool, int]] = [(data, False, 0)]
        values: dict[int, Value] = {}
        while stack:
            if not self._charge():
                return Value('refuse', 'budget', node)
            item, expanded, depth = stack.pop()
            if depth >= MAX_SPLICE_DEPTH:
                self.algebra.budget = -1
                self.algebra.overflow()
                return Value('refuse', 'constant-depth', node)
            if type(item) in (list, tuple, dict):
                container = cast(list[object] | tuple[object, ...] | dict[object, object], item)
                if not self._charge(len(container) + 1):
                    return Value('refuse', 'budget', node)
                if expanded:
                    children: Iterable[object]
                    if isinstance(container, dict):
                        abstract = Value('mapping', tuple(((values[id(k)], values[id(v)]) for k, v in container.items())), node)
                    else:
                        abstract = Value('sequence', tuple((values[id(v)] for v in container)), node)
                    values[id(item)] = abstract
                else:
                    stack.append((item, True, depth))
                    if isinstance(container, dict):
                        children = (child for pair in container.items() for child in pair)
                    else:
                        children = iter(container)
                    for child in children:
                        if not self._charge():
                            return Value('refuse', 'budget', node)
                        stack.append((child, False, depth + 1))
            elif item is None or type(item) in (str, Markup, int, float, bool):
                size = len(item) if isinstance(item, str) else item.bit_length() // 8 + 1 if type(item) is int else 1
                if not self._charge(size):
                    return Value('refuse', 'budget', node)
                values[id(item)] = Value('scalar', item, node, safe=type(item) is Markup)
            else:
                return Value('refuse', 'constant-type', node)
        return values[id(data)]

    def _evaluate(self, node: nodes.Node, path: Path[S], flags: int) -> list[tuple[Path[S], Value]]:
        if not self._schema(node):
            return [(self._role_gap(path), Value('refuse', 'node-schema', node))]
        return self._role_results(node, self._evaluated(node, path, flags))

    def _evaluated(self, node: nodes.Node, path: Path[S], flags: int) -> list[tuple[Path[S], Value]]:
        if not self._charge():
            return [(path, Value('refuse', 'budget', node))]
        if isinstance(node, nodes.TemplateData):
            return [(path, dataclasses.replace(self._constant(node.data, node), safe=True))]
        if isinstance(node, nodes.Const):
            return [(path, self._constant(node.value, node))]
        if isinstance(node, nodes.Name):
            return [(path, self._lookup(path, node.name, node))]
        if isinstance(node, nodes.CondExpr):
            result = []
            for truth, expression in ((True, node.expr1), (False, node.expr2)):
                reachable, guard = self._guarded_condition(node.test, path, truth)
                for reached in reachable:
                    if expression is None:
                        result.append((reached, Value('scalar', '', node)))
                    else:
                        for end, value in self._evaluate(expression, reached, flags):
                            result.append((end, dataclasses.replace(value, flags=value.flags | (GUARDED if guard else 0), generation=value.generation or guard)))
            return result
        if isinstance(node, nodes.And | nodes.Or):
            result = []
            take_right = isinstance(node, nodes.And)
            for truth, expression in ((take_right, node.right), (not take_right, node.left)):
                alternatives, generation = self._guarded_condition(node.left, path, truth, emission_guard=False)
                for at in alternatives:
                    result.extend(((end, dataclasses.replace(value, generation=value.generation or generation)) for end, value in self._evaluate(expression, at, flags)))
            return result
        if isinstance(node, nodes.List | nodes.Tuple):
            return [(p, Value('sequence', values, node)) for p, values in self._arguments(node.items, path, flags)]
        if isinstance(node, nodes.Dict):
            if self.observer is not None and any((not self._schema(pair) for pair in node.items)):
                return [(self._role_gap(path), Value('refuse', 'pair-schema', node))]
            expressions = [expression for pair in node.items for expression in (pair.key, pair.value)]
            return [(p, self._mapping(zip(values[::2], values[1::2], strict=True), node)) for p, values in self._arguments(expressions, path, flags)]
        if isinstance(node, nodes.Add | nodes.Concat):
            operands = node.nodes if isinstance(node, nodes.Concat) else [node.left, node.right]
            return [(p, self._concatenated(values, node, p)) for p, values in self._arguments(operands, path, flags)]
        if isinstance(node, nodes.Sub | nodes.Mul | nodes.Div | nodes.FloorDiv | nodes.Mod | nodes.Pow):
            out = []
            for p, values in self._arguments([node.left, node.right], path, flags):
                if len(values) != 2:
                    return []
                if isinstance(node, nodes.Mul):
                    text_value = next((v for v in values if v.kind == 'scalar' and isinstance(v.data, str)), None)
                    count_value = next((v for v in values if v.kind == 'scalar' and type(v.data) is int), None)
                    if text_value is not None and count_value is not None:
                        text = cast(str, text_value.data)
                        count = cast(int, count_value.data)
                        if not self._charge(len(text) * max(0, count)):
                            return []
                        out.append((p, Value('scalar', text * count, text_value.origin, safe=text_value.safe)))
                        continue
                if all((v.kind == 'scalar' and type(v.data) in (int, float) for v in values)) and (not isinstance(node, nodes.Pow)):
                    left, right = (cast(int | float, v.data) for v in values)
                    cost = sum((n.bit_length() // 8 + 1 if type(n) is int else 8 for n in (left, right)))
                    if not self._charge(cost):
                        return []
                    try:
                        operation = {'Sub': operator.sub, 'Mul': operator.mul, 'Div': operator.truediv, 'FloorDiv': operator.floordiv, 'Mod': operator.mod}[type(node).__name__]
                        value = operation(left, right)
                    except (ZeroDivisionError, OverflowError):
                        out.append((p, Value('refuse', 'arithmetic', node)))
                    else:
                        out.append((p, Value('scalar', value, node)))
                else:
                    out.append((p, Value('refuse', 'arithmetic', node)))
            return out
        if isinstance(node, nodes.Neg | nodes.Pos):
            out = []
            for p, value in self._evaluate(node.node, path, flags):
                if value.kind == 'scalar' and type(value.data) in (int, float):
                    number = cast(int | float, value.data)
                    out.append((p, Value('scalar', -number if isinstance(node, nodes.Neg) else number, node)))
                else:
                    out.append((p, Value('opaque', id(node), node)))
            return out
        if isinstance(node, nodes.Getitem) and isinstance(node.arg, nodes.Slice):
            return self._sliced(node, path, flags)
        if isinstance(node, nodes.Getitem | nodes.Getattr):
            expressions = [node.node, node.arg] if isinstance(node, nodes.Getitem) else [node.node]
            out = []
            for p, values in self._arguments(expressions, path, flags):
                if len(values) != len(expressions):
                    return []
                base = values[0]
                key = values[1].data if isinstance(node, nodes.Getitem) and values[1].kind == 'scalar' else node.attr if isinstance(node, nodes.Getattr) else None
                if base.kind == 'refuse' or any((v.kind == 'refuse' for v in values)):
                    out.append((p, next((v for v in values if v.kind == 'refuse'))))
                elif self._slice_conflict(base, p) is not False:
                    out.append((p, Value('refuse', 'slice-cardinality-correlation', node)))
                elif base.kind == 'loop' and isinstance(key, str):
                    metadata = cast(tuple[tuple[str, Value], ...], cast(tuple[object, ...], base.data)[0])
                    out.append((p, next((v for k, v in metadata if k == key), Value('refuse', 'loop-metadata', node))))
                elif self._slice_bounds(base) is not None:
                    bounds = self._known_slice_bounds(base, p)
                    if bounds is None:
                        out.append((p, Value('refuse', 'budget', node)))
                        continue
                    lower, upper = bounds
                    if type(key) not in (int, bool):
                        out.append((p, Value('refuse', 'slice-index', node)))
                    elif not self._charge(cast(int, key).bit_length() + 2):
                        out.append((p, Value('refuse', 'budget', node)))
                    elif upper is not None and (not -upper <= cast(int, key) < upper):
                        out.append((p, Value('refuse', 'index', node)))
                    elif not -lower <= cast(int, key) < lower:
                        out.append((p, Value('refuse', 'index-availability', node)))
                    else:
                        out.append((p, Value('symbol', ('item', base, int(cast(int, key))), node)))
                elif base.kind == 'sequence' and type(key) in (int, bool):
                    sequence = cast(tuple[Value, ...], base.data)
                    out.append((p, sequence[cast(int, key)] if -len(sequence) <= cast(int, key) < len(sequence) else Value('refuse', 'index', node)))
                elif type(key) in (int, bool) and (base.kind == 'text' or (base.kind == 'scalar' and type(base.data) in (str, Markup))):
                    out.append((p, self._text_index(base, int(cast(int, key)), node)))
                elif base.kind == 'mapping' and key is not None:
                    found = next((v for k, v in cast(tuple[tuple[Value, Value], ...], base.data) if k.kind == 'scalar' and k.data == key), None)
                    out.append((p, found or Value('refuse', 'key', node)))
                elif base.kind in ('sequence', 'mapping', 'text', 'macro', 'caller', 'recursive'):
                    out.append((p, Value('refuse', 'derived-selection', node)))
                elif base.kind == 'symbol' and key is not None:
                    out.append((p, self._identity_value(Value('symbol', ('item', base.data, key), node), p)))
                else:
                    out.append((p, Value('opaque', id(node), node)))
            return out
        if isinstance(node, nodes.Filter):
            if node.node is None:
                return [(path, Value('refuse', 'filter-input', node))]
            return [variant for p, value in self._evaluate(node.node, path, flags) for variant in self._filter_variants(node, value, p, flags)]
        if isinstance(node, nodes.Call):
            return self._call(node, path, flags)
        if isinstance(node, nodes.Not):
            result = []
            for truth in (False, True):
                paths, generation = self._guarded_condition(node.node, path, not truth, emission_guard=False)
                result.extend(((p, Value('scalar', truth, node, generation=generation)) for p in paths))
            return result
        if isinstance(node, nodes.Test):
            return self._test(node, path, flags)
        if isinstance(node, nodes.Compare):
            return self._compare(node, path, flags)
        return [(self._role_gap(path), Value('opaque', id(node), node))]

    @staticmethod
    def _slice_bounds(value: Value) -> tuple[int, int | None] | None:
        data = value.data
        if value.kind == 'symbol' and isinstance(data, tuple) and (len(data) == 7) and (data[0] == 'slice'):
            return cast(tuple[int, int | None], (data[5], data[6]))
        return None

    def _known_slice_bounds(self, value: Value, path: Path[S]) -> tuple[int, int | None] | None:
        bounds = self._slice_bounds(value)
        assert bounds is not None
        if not self._charge(len(path.facts) + 2):
            return None
        lower, upper = bounds
        for key, truth in path.facts:
            if truth and isinstance(key, tuple) and (len(key) == 3) and (key[0] == 'slice-length') and (key[1] == value.data):
                length = cast(int, key[2])
                return (length, length)
        if (value.data, True) in path.facts:
            lower = max(1, lower)
        if (value.data, False) in path.facts:
            upper = 0
        return (lower, upper)

    def _slice_root(self, value: Value) -> Value | None:
        current = value
        while self._slice_bounds(current) is not None:
            if not self._charge(2):
                return None
            current = cast(Value, cast(tuple[object, ...], current.data)[1])
        return current

    def _same_slice_data(self, left: object, right: object, *, metadata: bool=False) -> bool | None:
        if not self._charge(10):
            return None
        primitive_types = (type(None), str, Markup, int, float, bool, tuple, Value)
        pending = [(left, right)]
        while pending:
            if not self._charge(3):
                return None
            first, second = pending.pop()
            if type(first) not in primitive_types or type(second) not in primitive_types:
                return None
            if type(first) is float and first != first or (type(second) is float and second != second):
                return None
            if first is second:
                continue
            if isinstance(first, Value) and isinstance(second, Value):
                if first.kind != second.kind or (metadata and (first.safe, first.flags, first.generation) != (second.safe, second.flags, second.generation)):
                    return False
                if not self._charge():
                    return None
                pending.append((first.data, second.data))
            elif isinstance(first, tuple) and isinstance(second, tuple):
                if len(first) != len(second):
                    return False
                if not self._charge(3 * len(first) + 1):
                    return None
                pending.extend(zip(first, second, strict=True))
            elif isinstance(first, str) and isinstance(second, str):
                if not self._charge(len(first) + len(second) + 1):
                    return None
                if first != second:
                    return False
            elif (first is None or type(first) in (int, bool, float)) and (second is None or type(second) in (int, bool, float)):
                if not self._charge(sum((8 if type(n) is float else cast(int, n).bit_length() + 1 for n in (first, second) if n is not None))):
                    return None
                if first != second:
                    return False
            elif isinstance(first, str) and (second is None or type(second) in (int, bool, float)) or (isinstance(second, str) and (first is None or type(first) in (int, bool, float))):
                return False
            else:
                return None
        return True

    def _slice_conflict(self, value: Value, path: Path[S], selected: Value | None=None) -> bool | None:
        if value.kind != 'symbol' or not self._slices:
            return False
        if self._slice_bounds(value) is not None:
            bounds = self._known_slice_bounds(value, path)
            if bounds is None:
                return None
            if bounds[0] == bounds[1]:
                return False
        root = self._slice_root(value)
        if root is None or not self._charge(2 * len(self._slices) + 1):
            return None
        for previous in self._slices:
            if (('slice-value', previous), True) not in path.facts:
                continue
            same = self._same_slice_data((selected or value).data, previous.data, metadata=True)
            if same is None:
                return None
            if same:
                continue
            previous_root = self._slice_root(previous)
            if previous_root is None:
                return None
            shared = self._same_slice_data(root.data, previous_root.data)
            if shared is not False:
                return shared
        return False

    def _slice_lengths(self, selection: slice, lower: int, upper: int | None) -> tuple[int, int | None] | None:
        bounds = (selection.start, selection.stop, selection.step)
        bits = sum(((n.bit_length() + 1) ** 2 for n in bounds if n is not None))
        bits += (lower.bit_length() + 1) ** 2
        if upper is not None:
            bits += (upper.bit_length() + 1) ** 2
        if not self._charge(12 * bits + 32):
            return None
        points = {lower}
        if upper is not None:
            points.add(upper)
        for endpoint in (selection.start, selection.stop):
            if endpoint is not None:
                boundary = abs(endpoint)
                for n in (boundary - 1, boundary, boundary + 1):
                    if n >= lower and (upper is None or n <= upper):
                        points.add(n)
        tail = max(points)
        if upper is None:
            points.add(tail + 1)
        if not self._charge(12 * len(points)):
            return None

        def length(n: int) -> int:
            start, stop, step = selection.indices(n)
            distance = stop - start if step > 0 else start - stop
            return max(0, (distance + abs(step) - 1) // abs(step))
        lengths = [length(n) for n in points]
        minimum = min(lengths)
        maximum: int | None = max(lengths)
        if upper is None:
            start0, stop0, step = selection.indices(tail)
            start1, stop1, _ = selection.indices(tail + 1)
            difference = stop1 - start1 - (stop0 - start0)
            if difference * step > 0:
                maximum = None
            elif difference * step < 0:
                minimum = 0
        return (minimum, maximum)

    def _sliced(self, node: nodes.Getitem, path: Path[S], flags: int) -> list[tuple[Path[S], Value]]:
        helper = cast(nodes.Slice, node.arg)
        out: list[tuple[Path[S], Value]] = []

        def append(at: Path[S], value: Value) -> bool:
            if len(out) >= MAX_PATHS or not self._charge(2):
                self.algebra.budget = -1
                self.algebra.overflow()
                return False
            out.append((at, value))
            return True
        for at, base in self._evaluate(node.node, path, flags):
            if not self._schema(helper):
                if not append(self._role_gap(at), Value('refuse', 'slice-schema', node)):
                    return []
                continue
            if not self._charge(8):
                return []
            expressions = [bound for bound in (helper.start, helper.stop, helper.step) if bound is not None]
            for reached, values in self._arguments(expressions, at, flags):
                if base.kind == 'refuse' or any((v.kind == 'refuse' for v in values)):
                    refused = base if base.kind == 'refuse' else next((v for v in values if v.kind == 'refuse'))
                    if not append(reached, refused):
                        return []
                    continue
                if any((v.kind != 'scalar' or (v.data is not None and type(v.data) not in (int, bool)) for v in values)):
                    if not append(reached, Value('refuse', 'slice-bound', node)):
                        return []
                    continue
                if not self._charge(sum(((cast(int, v.data).bit_length() + 1) ** 2 for v in values if v.data is not None)) + 4):
                    if not append(reached, Value('refuse', 'budget', node)):
                        return []
                    continue
                present = iter(values)
                normalized = [None if bound is None else next(present).data for bound in (helper.start, helper.stop, helper.step)]
                start, stop, step = (None if value is None else int(cast(int, value)) for value in normalized)
                if step == 0:
                    if not append(reached, Value('refuse', 'slice-zero-step', node)):
                        return []
                    continue
                value = self._slice_value(base, slice(start, stop, step), node, reached)
                if value.kind != 'symbol':
                    if not append(reached, value):
                        return []
                    continue
                if self._slice_conflict(base, reached, value) is not False:
                    if not append(reached, Value('refuse', 'slice-cardinality-correlation', node)):
                        return []
                    continue
                if not self._charge(3):
                    return []
                self._slices[value] = None
                registered = self._atom(reached, ('slice-value', value), True)
                for active in registered:
                    bounds = self._slice_bounds(value)
                    assert bounds is not None
                    if bounds[1] is None:
                        if not append(active, value):
                            return []
                        continue
                    known = self._known_slice_bounds(value, active)
                    if known is None:
                        return []
                    lower, upper = known
                    assert upper is not None
                    count = upper - lower + 1
                    if count > MAX_PATHS or not self._charge(4 * count + 1):
                        self.algebra.budget = -1
                        self.algebra.overflow()
                        return []
                    for length in range(lower, upper + 1):
                        for chosen in self._atom(active, ('slice-length', value.data, length), True):
                            if not append(chosen, value):
                                return []
        return out

    def _text_index(self, value: Value, key: int, node: nodes.Node) -> Value:
        if not self._charge((key.bit_length() + 1) ** 2 + 2):
            return Value('refuse', 'budget', node)
        if value.kind == 'text':
            parts = cast(tuple[Fragment, ...], value.data)
            if not self._charge(len(parts) + 1):
                return Value('refuse', 'budget', node)
            if any((part.emission.text is None for part in parts)):
                return Value('refuse', 'slice-nonliteral-text', node)
            size = sum((len(part.emission.text or '') for part in parts))
        else:
            size = len(cast(str, value.data))
        if not -size <= key < size:
            return Value('refuse', 'index', node)
        index = key if key >= 0 else size + key
        return self._slice_value(value, slice(index, index + 1), node)

    def _slice_value(self, value: Value, selection: slice, node: nodes.Node, path: Path[S] | None=None) -> Value:
        if value.kind == 'symbol':
            lower, upper = self._slice_bounds(value) or (0, None)
            if path is not None and self._slice_bounds(value) is not None:
                known = self._known_slice_bounds(value, path)
                if known is None:
                    return Value('refuse', 'budget', node)
                lower, upper = known
            lengths = self._slice_lengths(selection, lower, upper)
            if lengths is None:
                return Value('refuse', 'budget', node)
            lower, upper = lengths
            if upper == 0:
                return Value('sequence', (), node)
            if not self._charge(12):
                return Value('refuse', 'budget', node)
            return Value('symbol', ('slice', value, selection.start, selection.stop, selection.step, lower, upper), node, flags=value.flags, generation=value.generation)
        if value.kind == 'sequence' or (value.kind == 'scalar' and type(value.data) in (str, Markup)):
            data = cast(tuple[Value, ...] | str, value.data)
            lengths = self._slice_lengths(selection, len(data), len(data))
            if lengths is None or not self._charge(3 * lengths[0] + 1):
                return Value('refuse', 'budget', node)
            return dataclasses.replace(value, data=data[selection])
        if value.kind != 'text':
            return Value('refuse', 'slice-base', node)
        parts = cast(tuple[Fragment, ...], value.data)
        if not self._charge(len(parts) + 1):
            return Value('refuse', 'budget', node)
        if any((part.emission.text is None for part in parts)):
            return Value('refuse', 'slice-nonliteral-text', node)
        size = sum((len(part.emission.text or '') for part in parts))
        lengths = self._slice_lengths(selection, size, size)
        if lengths is None:
            return Value('refuse', 'budget', node)
        selected = lengths[0]
        piece_count = sum((len(part.emission.pieces) for part in parts))
        if not self._charge(6 * size + 12 * selected + 3 * piece_count + 3 * len(parts) + 1):
            return Value('refuse', 'budget', node)
        characters: list[tuple[int, str, int]] = []
        for part_index, part in enumerate(parts):
            pieces = part.emission.pieces
            piece_index = 0
            line = part.emission.line
            for offset, char in enumerate(part.emission.text or ''):
                while piece_index < len(pieces) and pieces[piece_index].offset <= offset:
                    line = pieces[piece_index].line
                    piece_index += 1
                characters.append((part_index, char, line))
        output: list[Fragment] = []
        active: tuple[int, int] | None = None
        run: list[str] = []

        def flush() -> None:
            if active is not None:
                part = parts[active[0]]
                emission = dataclasses.replace(part.emission, text=''.join(run), line=active[1], pieces=())
                output.append(dataclasses.replace(part, emission=emission))
        for index in range(*selection.indices(size)):
            part_index, char, line = characters[index]
            if active != (part_index, line):
                flush()
                active = (part_index, line)
                run = []
            run.append(char)
        flush()
        return dataclasses.replace(value, data=tuple(output))

    def _arguments(self, expressions: Sequence[nodes.Node], path: Path[S], flags: int) -> list[tuple[Path[S], tuple[Value, ...]]]:
        current: list[tuple[Path[S], tuple[Value, ...]]] = [(path, ())]
        for expression in expressions:
            out: list[tuple[Path[S], tuple[Value, ...]]] = []
            for reached, values in current:
                for end, value in self._evaluate(expression, reached, flags):
                    if len(out) >= MAX_PATHS or not self._charge(len(values) + 1):
                        self.algebra.budget = -1
                        self.algebra.overflow()
                        return []
                    out.append((end, (*values, value)))
            current = out
        return current

    def _normalized_arguments(self, node: nodes.Call | nodes.Filter | nodes.Test, path: Path[S], flags: int) -> list[tuple[Path[S], tuple[Value, ...], dict[str, Value], str | None]]:
        if self.observer is not None and any((not self._schema(keyword) for keyword in node.kwargs)):
            return [(self._role_gap(path), (), {}, 'keyword-schema')]
        if not self._charge(len(node.args) + len(node.kwargs) + 2):
            return []
        expressions = [*node.args, *(kw.value for kw in node.kwargs)]
        if node.dyn_args is not None:
            expressions.append(node.dyn_args)
        if node.dyn_kwargs is not None:
            expressions.append(node.dyn_kwargs)
        out = []
        for reached, values in self._arguments(expressions, path, flags):
            if len(values) != len(expressions):
                return []
            if not self._charge(len(values) + 1):
                return []
            args = list(values[:len(node.args)])
            kwargs = {cast(nodes.Keyword, kw).key: value for kw, value in zip(node.kwargs, values[len(node.args):len(node.args) + len(node.kwargs)], strict=True)}
            error = 'keyword-conflict' if len(kwargs) != len(node.kwargs) else None
            at = len(node.args) + len(node.kwargs)
            if node.dyn_args is not None:
                extra = values[at]
                at += 1
                if extra.kind != 'sequence':
                    error = 'star-arguments'
                elif not self._charge(len(cast(tuple[Value, ...], extra.data))):
                    return []
                else:
                    args.extend(cast(tuple[Value, ...], extra.data))
            if node.dyn_kwargs is not None:
                extra = values[at]
                if extra.kind != 'mapping':
                    error = 'star-keywords'
                else:
                    for key, value in cast(tuple[tuple[Value, Value], ...], extra.data):
                        if key.kind != 'scalar' or not isinstance(key.data, str) or key.data in kwargs:
                            error = 'keyword-conflict'
                            break
                        if not self._charge(len(key.data) + 1):
                            return []
                        kwargs[key.data] = value
            if not self._charge(len(args) + len(kwargs) + 1):
                return []
            out.append((reached, tuple(args), kwargs, error))
        return out

    def _parts(self, value: Value) -> tuple[Fragment, ...]:
        from j2prompt_lint.rules.pchat import _Emission
        if value.kind == 'text':
            return cast(tuple[Fragment, ...], value.data)
        text = None
        if value.kind == 'scalar':
            cost = value.data.bit_length() + 1 if type(value.data) is int else len(value.data) + 1 if isinstance(value.data, str) else 32
            if not self._charge(cost):
                return ()
            try:
                text = str(value.data)
            except ValueError:
                self.algebra.budget = -1
                self.algebra.overflow()
                return ()
        emission = _Emission(value.origin.lineno or 1, text, value.origin)
        return (Fragment(emission, self.model.order.get(id(value.origin), 0), value.flags),)

    def _escaped(self, parts: tuple[Fragment, ...]) -> tuple[Fragment, ...]:
        out = []
        for part in parts:
            if not self._charge(6 * len(part.emission.text or '') + 1):
                return ()
            emission = dataclasses.replace(part.emission, text=str(escape(part.emission.text)) if part.emission.text is not None else None, escaped=True)
            out.append(dataclasses.replace(part, emission=emission))
        return tuple(out)

    def _concatenated(self, values: tuple[Value, ...], node: nodes.Node, path: Path[S]) -> Value:
        if any((v.kind == 'refuse' for v in values)):
            return next((v for v in values if v.kind == 'refuse'))
        if isinstance(node, nodes.Add) and all((v.kind == 'scalar' and type(v.data) in (int, float) for v in values)):
            if not self._charge(sum((v.data.bit_length() // 8 + 1 if type(v.data) is int else 8 for v in values))):
                return Value('refuse', 'budget', node)
            return Value('scalar', sum((cast(int | float, v.data) for v in values)), node)
        if isinstance(node, nodes.Add) and all((v.kind == 'sequence' for v in values)):
            if not self._charge(sum((len(cast(tuple[Value, ...], v.data)) for v in values))):
                return Value('refuse', 'budget', node)
            return Value('sequence', tuple((item for v in values for item in cast(tuple[Value, ...], v.data))), node)
        if any((v.kind in ('sequence', 'mapping', 'macro', 'caller', 'recursive') for v in values)):
            return Value('refuse', 'derived-concatenation', node)
        if isinstance(node, nodes.Add) and any((v.kind == 'scalar' and (not isinstance(v.data, str)) for v in values)):
            return Value('refuse', 'add-operands', node)
        safe = any((v.safe for v in values)) and (isinstance(node, nodes.Add) or bool(path.autoescape))
        parts: list[Fragment] = []
        for value in values:
            additions = self._parts(value)
            if safe and (isinstance(node, nodes.Add) or path.autoescape) and (not value.safe):
                additions = self._escaped(additions)
            if not self._charge(len(additions)):
                return Value('refuse', 'budget', node)
            parts.extend(additions)
        return Value('text', tuple(parts), node, safe=safe)

    def _output(self, value: Value, path: Path[S], flags: int) -> list[Path[S]] | None:
        path = self._role_result(path, value)
        if path.stopped:
            return [path]
        if value.kind == 'refuse':
            return self._stop([path], str(value.data))
        if value.kind in ('sequence', 'mapping', 'macro', 'caller', 'recursive', 'loop'):
            return self._stop([path], 'derived-display')
        if path.autoescape is None and (not value.safe):
            return self._stop([path], 'dynamic-autoescape')
        parts = self._parts(value)
        if path.autoescape and (not value.safe):
            parts = self._escaped(parts)
        current = [path]
        for ordinal, part in enumerate(parts):
            result = self._emit(part.emission, part.order, current, flags | value.flags | part.flags, fragment=ordinal)
            if result is None:
                return None
            current = result
        return current

    def _capture(self, statements: Sequence[nodes.Node], path: Path[S], flags: int) -> list[tuple[Path[S], Value]]:
        origin = statements[0] if statements else nodes.Const('').set_lineno(1)
        if self.observer is not None and (not self._charge()):
            return [(path, Value('refuse', 'capture-budget', origin))]
        capture = _Capture(self.algebra.budget)
        flow = Flow(self.model, capture, self.observer)
        flow._calls = self._calls
        flow._sites = self._sites
        flow._slices = self._slices
        flow._scope = self._scope
        flow._guard_probe = self._guard_probe
        flow._guard_seen = self._guard_seen
        entered: Path[tuple[Fragment, ...]] = Path(EMPTY, (), path.frames, path.facts, path.autoescape, role_available=path.role_available)
        result = flow.run(statements, [entered], flags)
        self.algebra.budget = capture.budget
        if result is None:
            if capture.resource_refused:
                self.algebra.budget = -1
            return [(self._role_gap(path), Value('refuse', 'capture-budget', origin))]
        returned = []
        for end in result:
            parent = self._child_path(path, end)
            if parent is None:
                return [(path, Value('refuse', 'capture-budget', origin))]
            value = Value('refuse', end.stopped, origin) if end.stopped else Value('text', end.state, origin, safe=bool(path.autoescape))
            returned.append((self._role_result(parent, value), value))
        return returned

    def _literal_scalar(self, value: Value) -> Value:
        if value.kind != 'text':
            return value
        parts = self._parts(value)
        if any((part.emission.text is None for part in parts)):
            return Value('refuse', 'nonliteral-text', value.origin)
        if not self._charge(sum((len(p.emission.text or '') for p in parts)) + len(parts)):
            return Value('refuse', 'budget', value.origin)
        return dataclasses.replace(value, kind='scalar', data=''.join((p.emission.text or '' for p in parts)))

    def _filter_variants(self, node: nodes.Filter, value: Value, path: Path[S], flags: int) -> list[tuple[Path[S], Value]]:
        if value.kind == 'refuse':
            return [(path, value)]
        return [(p, Value('refuse', error, node) if error else self._filter(node, value, p, args, kwargs)) for p, args, kwargs, error in self._normalized_arguments(node, path, flags)]

    def _filter(self, node: nodes.Filter, value: Value, path: Path[S], arguments: tuple[Value, ...], keywords: dict[str, Value]) -> Value:
        if value.kind == 'refuse':
            return value
        if value.kind in ('symbol', 'opaque') and node.name in ('trim', 'string') and (not arguments) and (not keywords):
            return value
        parts = self._parts(value)
        if node.name == 'safe' and (not arguments) and (not keywords):
            return Value('text', parts, node, safe=True)
        if node.name in ('escape', 'e', 'forceescape') and (not arguments) and (not keywords):
            return Value('text', parts if value.safe and node.name != 'forceescape' else self._escaped(parts), node, safe=True)
        values = tuple((self._literal_scalar(v) for v in (*arguments, *keywords.values())))
        if node.name == 'length' and value.kind in ('sequence', 'mapping'):
            if values:
                return Value('refuse', 'filter-arguments', node)
            return Value('scalar', len(cast(tuple[object, ...], value.data)), node)
        if any((v.kind != 'scalar' for v in values)) or any((part.emission.text is None for part in parts)):
            return Value('refuse', 'filter-nonliteral', node)
        size = sum((len(part.emission.text or '') for part in parts))
        if not self._charge(size + len(parts)):
            return Value('refuse', 'budget', node)
        text = ''.join((part.emission.text or '' for part in parts))
        args = [v.data for v in values[:len(arguments)]]
        kwargs: dict[str, object] = {key: v.data for key, v in zip(keywords, values[len(arguments):], strict=True)}
        result_safe = value.safe
        try:
            if node.name == 'trim':
                if len(args) > 1 or set(kwargs) - {'chars'} or (args and kwargs):
                    return Value('refuse', 'trim-arguments', node)
                chars = args[0] if args else kwargs.get('chars')
                if chars is not None and (not isinstance(chars, str)):
                    return Value('refuse', 'trim-argument', node)
                changed = text.strip(chars)
            elif node.name in ('upper', 'lower', 'title', 'capitalize') and (not args) and (not kwargs):
                if not self._charge(3 * len(text)):
                    return Value('refuse', 'budget', node)
                changed = getattr(text, node.name)()
            elif node.name == 'replace':
                if len(args) > 3 or set(kwargs) - {'old', 'new', 'count'} or any((name in kwargs for name in ('old', 'new', 'count')[:len(args)])):
                    return Value('refuse', 'replace-arguments', node)
                old = args[0] if args else kwargs['old']
                new = args[1] if len(args) > 1 else kwargs['new']
                count = args[2] if len(args) > 2 else kwargs.get('count', -1)
                if count is None:
                    count = -1
                if not isinstance(old, str) or not isinstance(new, str) or type(count) is not int:
                    return Value('refuse', 'replace-argument', node)
                if path.autoescape is None:
                    return Value('refuse', 'replace-autoescape', node)
                if path.autoescape:
                    old_value = values[0] if arguments else self._literal_scalar(keywords['old'])
                    new_value = values[1] if len(arguments) > 1 else self._literal_scalar(keywords['new'])
                    if not self._charge(6 * (len(text) + len(old) + len(new)) + 1):
                        return Value('refuse', 'budget', node)
                    result_safe = value.safe or old_value.safe or new_value.safe
                    if result_safe:
                        if not value.safe:
                            text = str(escape(text))
                        if not old_value.safe:
                            old = str(escape(old))
                        if not new_value.safe:
                            new = str(escape(new))
                else:
                    result_safe = False
                occurrences = text.count(old) if count < 0 else min(text.count(old), count)
                if not self._charge(max(0, len(new) - len(old)) * occurrences):
                    return Value('refuse', 'budget', node)
                changed = text.replace(old, new, count)
            elif node.name == 'string' and (not args) and (not kwargs):
                changed = text
            elif node.name == 'length' and (not args) and (not kwargs):
                return Value('scalar', len(text), node)
            else:
                return Value('refuse', 'filter:' + node.name, node)
        except (KeyError, IndexError, ValueError):
            return Value('refuse', 'filter-arguments', node)
        origin = parts[0].emission.node if parts else node
        return Value('scalar', changed, origin, safe=result_safe, flags=value.flags)

    def _captured_filter(self, node: nodes.Filter, value: Value, path: Path[S]) -> list[tuple[Path[S], Value]]:
        chain = []
        current: nodes.Filter | None = node
        while current is not None:
            if not self._schema(current):
                return [(self._role_gap(path), Value('refuse', 'filter-schema', node))]
            if not self._charge(2):
                return []
            chain.append(current)
            if isinstance(current.node, nodes.Filter):
                current = current.node
            elif current.node is None:
                current = None
            else:
                return [(path, Value('refuse', 'captured-filter-input', node))]
        variants = [(path, value)]
        for operation in reversed(chain):
            following: list[tuple[Path[S], Value]] = []
            for p, v in variants:
                p = self._role_result(p, v)
                for item in self._filter_variants(operation, v, p, 0):
                    if len(following) >= MAX_PATHS or not self._charge():
                        self.algebra.budget = -1
                        self.algebra.overflow()
                        return []
                    at, produced = item
                    following.append((self._role_result(at, produced), produced))
            variants = following
        return variants

    def _test(self, node: nodes.Test, path: Path[S], flags: int) -> list[tuple[Path[S], Value]]:
        out = []
        if node.args or node.kwargs or node.dyn_args is not None or (node.dyn_kwargs is not None):
            return [(path, Value('refuse', 'test-arguments', node))]
        for reached, value in self._evaluate(node.node, path, flags):
            if self._slice_conflict(value, reached) is not False:
                out.append((self._role_gap(reached), Value('refuse', 'slice-cardinality-correlation', node)))
                continue
            known = value.kind in ('scalar', 'text', 'sequence', 'mapping', 'macro', 'caller', 'recursive')
            data = value.data
            truth: bool | None = None
            if node.name == 'defined' and known:
                truth = True
            elif node.name == 'undefined' and known:
                truth = False
            elif node.name in ('sequence', 'iterable') and known:
                truth = value.kind in ('sequence', 'mapping', 'text') or isinstance(data, str)
            elif node.name == 'mapping' and known:
                truth = value.kind == 'mapping'
            elif node.name == 'number' and known:
                truth = value.kind == 'scalar' and isinstance(data, (int, float))
            elif node.name == 'string' and known:
                truth = value.kind == 'text' or (value.kind == 'scalar' and isinstance(data, str))
            elif node.name == 'callable' and known:
                truth = value.kind in ('macro', 'caller', 'recursive')
            elif node.name in ('none', 'boolean', 'true', 'false') and known:
                truth = {'none': data is None, 'boolean': type(data) is bool, 'true': data is True, 'false': data is False}[node.name]
            elif node.name in ('odd', 'even') and value.kind == 'scalar' and (type(data) is int):
                truth = bool(data % 2) == (node.name == 'odd')
            if truth is not None:
                out.append((reached, Value('scalar', truth, node, generation=self._generation_value(value))))
            elif value.kind == 'symbol' and (not node.args) and (node.name in ('defined', 'undefined', 'none', 'boolean', 'true', 'false', 'sequence', 'mapping', 'number', 'string', 'iterable', 'callable')):
                key = ('defined', value.data) if node.name in ('defined', 'undefined') else ('test', node.name, value.data)
                if node.name == 'undefined':
                    for wanted in (False, True):
                        out.extend(((p, Value('scalar', not wanted, node)) for p in self._atom(reached, key, wanted)))
                else:
                    out.append((reached, Value('symbol', key, node)))
            else:
                out.append((reached, Value('refuse', 'test:' + node.name, node)))
        return out

    def _compare(self, node: nodes.Compare, path: Path[S], flags: int) -> list[tuple[Path[S], Value]]:
        variants = [(p, value, True, self._generation_value(value)) for p, value in self._evaluate(node.expr, path, flags)]
        out: list[tuple[Path[S], Value]] = []
        for operand in node.ops:
            if not self._schema(operand):
                return [(self._role_gap(path), Value('refuse', 'operand-schema', node))]
            following: list[tuple[Path[S], Value, bool, bool]] = []
            for current, left, prior, generation in variants:
                if not prior:
                    following.append((current, left, False, generation))
                    continue
                for reached, right in self._evaluate(operand.expr, current, flags):
                    for refined, value in self._comparison_pair(node, operand.op, left, right, reached):
                        if value.kind == 'refuse':
                            out.append((refined, value))
                        else:
                            following.append((refined, right, cast(bool, value.data), generation or self._generation_value(right)))
                        if len(following) + len(out) > MAX_PATHS or not self._charge():
                            self.algebra.budget = -1
                            self.algebra.overflow()
                            return []
            variants = following
        out.extend(((p, Value('scalar', truth, node, generation=generation)) for p, _, truth, generation in variants))
        return out

    def _comparison_pair(self, node: nodes.Node, op: str, left: Value, right: Value, path: Path[S]) -> list[tuple[Path[S], Value]]:
        if self._slice_conflict(left, path) is not False or self._slice_conflict(right, path) is not False:
            return [(self._role_gap(path), Value('refuse', 'slice-cardinality-correlation', node))]
        left, right = (self._literal_scalar(left), self._literal_scalar(right))
        if left.kind == 'refuse' or right.kind == 'refuse':
            return [(path, left if left.kind == 'refuse' else right)]
        if op in ('in', 'notin') and right.kind in ('sequence', 'mapping'):
            items = cast(tuple[Value, ...], right.data) if right.kind == 'sequence' else tuple((k for k, _ in cast(tuple[tuple[Value, Value], ...], right.data)))
            if not self._charge(len(items)):
                return []
            if any((item.kind != 'scalar' for item in items)):
                return [(path, Value('refuse', 'membership-items', node))]
            remaining = [path]
            out: list[tuple[Path[S], Value]] = []
            for item in items:
                following = []
                for current in remaining:
                    for refined, result in self._comparison_pair(node, 'eq', left, item, current):
                        if result.kind == 'refuse':
                            return [(refined, result)]
                        if result.data:
                            out.append((refined, Value('scalar', op == 'in', node)))
                        else:
                            following.append(refined)
                    if len(out) + len(following) > MAX_PATHS or not self._charge():
                        self.algebra.budget = -1
                        self.algebra.overflow()
                        return []
                remaining = following
            out.extend(((p, Value('scalar', op != 'in', node)) for p in remaining))
            return out
        if left.kind == right.kind == 'scalar':
            try:
                truth = _scalar_comparison(op, left.data, right.data)
            except (TypeError, KeyError):
                return [(path, Value('refuse', 'comparison', node))]
            return [(path, Value('scalar', truth, node))]
        if left.kind == 'scalar' and right.kind == 'symbol':
            reverse = {'eq': 'eq', 'ne': 'ne', 'gt': 'lt', 'lt': 'gt', 'gteq': 'lteq', 'lteq': 'gteq'}
            if op in reverse:
                return self._comparison_pair(node, reverse[op], right, left, path)
        if left.kind == 'symbol' and right.kind == 'scalar' and (op in ('eq', 'ne', 'gt', 'gteq', 'lt', 'lteq')):
            normalized = {'ne': 'eq', 'lteq': 'gt', 'gteq': 'lt'}.get(op, op)
            inverse = op in ('ne', 'lteq', 'gteq')
            key = ('compare', normalized, left.data, right.data)
            return [(p, Value('scalar', wanted != inverse, node)) for wanted in (False, True) for p in self._atom(path, key, wanted)]
        return [(path, Value('refuse', 'comparison', node))]

    def _semantic_for(self, node: nodes.For, path: Path[S], iterable: Value, flags: int) -> list[Path[S]] | None:
        if self._slice_conflict(iterable, path) is not False:
            return self._stop([path], 'slice-cardinality-correlation')
        bounds = self._slice_bounds(iterable)
        if bounds is not None:
            bounds = self._known_slice_bounds(iterable, path)
            if bounds is None:
                return None
        if bounds is not None and bounds[1] is not None:
            lower, upper = bounds
            assert upper is not None
            if lower > upper:
                return []
            count = upper - lower + 1
            if count > MAX_PATHS or not self._charge(count * (upper + 3)):
                self.algebra.budget = -1
                self.algebra.overflow()
                return None
            output: list[Path[S]] = []
            for length in range(lower, upper + 1):
                items = tuple((Value('symbol', ('item', iterable, index), iterable.origin) for index in range(length)))
                variants = [selected for truth_path in self._atom(path, iterable.data, bool(length)) for selected in self._atom(truth_path, ('slice-length', iterable.data, length), True)]
                for variant in variants:
                    walked = self._semantic_for(node, variant, Value('sequence', items, iterable.origin), flags)
                    if walked is None:
                        return None
                    if len(output) + len(walked) > MAX_PATHS or not self._charge(len(walked)):
                        self.algebra.budget = -1
                        self.algebra.overflow()
                        return None
                    output.extend(walked)
            return self._settled(output)
        iterable = self._literal_scalar(iterable)
        if iterable.kind == 'refuse':
            return self._stop([path], str(iterable.data))
        if iterable.kind == 'scalar' and isinstance(iterable.data, str):
            if not self._charge(len(iterable.data)):
                return None
            iterable = Value('sequence', tuple((Value('scalar', ch, iterable.origin) for ch in iterable.data)), iterable.origin)
        elif iterable.kind == 'mapping':
            pairs = cast(tuple[tuple[Value, Value], ...], iterable.data)
            if not self._charge(len(pairs)):
                return None
            iterable = Value('sequence', tuple((key for key, _ in pairs)), iterable.origin)
        elif iterable.kind not in ('sequence', 'symbol', 'opaque'):
            return self._stop([path], 'noniterable')
        if isinstance(self.algebra, _Capture) and iterable.kind != 'sequence':
            return self._stop([path], 'unknown-length-capture')
        frame = Frame(id(node))
        entered = dataclasses.replace(path, frames=(*path.frames, frame))
        if iterable.kind == 'sequence':
            selected = self._filtered(node, path, cast(tuple[Value, ...], iterable.data))
            if selected is None:
                return None
            results: list[Path[S]] = []
            for filtered_path, items in selected:
                if filtered_path.stopped:
                    results.append(filtered_path)
                    continue
                if not items:
                    other = self.run(node.else_, [filtered_path], flags)
                    if other is None:
                        return None
                    results.extend(other)
                    continue
                current = [filtered_path]
                for index, item in enumerate(items):
                    body_paths = []
                    for at in current:
                        entered = dataclasses.replace(at, frames=(*path.frames, frame))
                        bound = self._target(entered, node.target, item)
                        if bound is None:
                            return None
                        loop = self._loop(node, path, index, items)
                        updated = self._bind(bound, 'loop', loop)
                        if updated is None:
                            return None
                        body_paths.append(updated)
                    saved_scope = self._scope
                    self._scope = (*self._scope, id(node), index)
                    try:
                        walked = self.run(node.body, body_paths, flags)
                    finally:
                        self._scope = saved_scope
                    if walked is None:
                        return None
                    current = [dataclasses.replace(end, frames=path.frames) for end in walked]
                results.extend(current)
            return self._settled(results)
        item = Value('symbol', ('iteration', id(node)), node.target)
        bound = self._target(entered, node.target, item)
        if bound is None:
            return None
        body_paths = self._condition(node.test, bound, True) if node.test else [bound]
        exits: list[Path[S]] = []
        seen: set[Path[S]] = set()
        frontier = body_paths
        taken_flags = flags
        unresolved = False
        while frontier:
            fresh = [p for p in dict.fromkeys(frontier) if p not in seen]
            if not fresh:
                break
            if not self._charge(len(fresh)) or len(seen) + len(fresh) > MAX_PATHS:
                self.algebra.budget = -1
                self.algebra.overflow()
                return None
            seen.update(fresh)
            iteration = 0 if not taken_flags & ITERATED else None
            active = []
            for at in fresh:
                updated = self._bind(at, 'loop', self._loop(node, path, iteration, None))
                if updated is None:
                    return None
                active.append(updated)
            saved_scope = self._scope
            self._scope = (*self._scope, id(node), 'later' if iteration is None else 'first')
            try:
                walked = self.run(node.body, active, taken_flags)
            finally:
                self._scope = saved_scope
            if walked is None:
                return None
            if not self.algebra.loop_pass([bound], walked):
                walked = self._stop(walked, 'unknown-loop-depth')
            if any((p.stopped for p in walked)):
                unresolved = True
            last_key = ('loop-last', id(node), iteration)
            exits.extend((p for end in walked for p in ([end] if end.stopped else self._atom(end, last_key, True))))
            if not self.algebra.iterates or all((p.stopped for p in walked)):
                break
            frontier = []
            for end in walked:
                for continuing in self._atom(end, last_key, False):
                    facts = self._outside_iteration(continuing.facts, id(node))
                    if facts is None:
                        return None
                    frontier.append(dataclasses.replace(continuing, frames=bound.frames, facts=facts | bound.facts))
            taken_flags = flags | ITERATED
        other = [] if bounds is not None and bounds[0] > 0 and (node.test is None) else self.run(node.else_, [path], flags)
        if other is None:
            return None
        restored = []
        for end in exits:
            facts = self._outside_iteration(end.facts, id(node))
            if facts is None:
                return None
            restored.append(dataclasses.replace(end, frames=path.frames, facts=facts))
        exits = restored
        combined = self.algebra.branch(False, [path], [exits, other])
        if combined is None:
            return None
        if unresolved:
            combined = self._stop(combined, 'unknown-loop-suffix')
        loop_exit = getattr(self.algebra, 'loop_exit', None)
        if loop_exit is not None:
            combined = loop_exit(combined)
        return self._settled(combined)

    def _outside_iteration(self, facts: frozenset[tuple[object, bool]], identity: int) -> frozenset[tuple[object, bool]] | None:
        kept = []
        for key, truth in facts:
            pending = [key]
            local = False
            while pending:
                current = pending.pop()
                if not self._charge():
                    return None
                if isinstance(current, tuple):
                    if len(current) >= 2 and current[0] in ('iteration', 'loop-last') and (current[1] == identity):
                        local = True
                        break
                    if not self._charge(len(current)):
                        return None
                    pending.extend(current)
                elif isinstance(current, Value) and current.kind == 'symbol':
                    if not self._charge():
                        return None
                    pending.append(current.data)
            if not local:
                if not self._charge():
                    return None
                kept.append((key, truth))
        return frozenset(kept)

    def _filtered(self, node: nodes.For, path: Path[S], items: tuple[Value, ...]) -> list[tuple[Path[S], tuple[Value, ...]]] | None:
        current: list[tuple[Path[S], tuple[Value, ...]]] = [(path, ())]
        if node.test is None:
            return [(path, items)]
        for item in items:
            out: list[tuple[Path[S], tuple[Value, ...]]] = []
            for at, kept in current:
                if not self._charge(len(kept) + 1):
                    return None
                entered = dataclasses.replace(at, frames=(*path.frames, Frame(id(node))))
                bound = self._target(entered, node.target, item)
                if bound is None:
                    return None
                for wanted in (False, True):
                    for refined in self._condition(node.test, bound, wanted):
                        if len(out) >= MAX_PATHS or not self._charge(len(kept) + 1):
                            self.algebra.budget = -1
                            self.algebra.overflow()
                            return None
                        exited = dataclasses.replace(refined, frames=path.frames)
                        out.append((exited, (*kept, item) if wanted else kept))
            current = out
        return current

    def _loop(self, node: nodes.For, path: Path[S], index: int | None, items: tuple[Value, ...] | None) -> Value:
        if not self._charge(15):
            return Value('refuse', 'budget', node)
        unknown = Value('refuse', 'loop-cardinality', node)
        length = len(items) if items is not None else None
        depth = 1 + sum((signature[0] == id(node) for signature in self._calls))
        data: dict[str, Value] = {'first': Value('scalar', index == 0, node), 'last': Value('scalar', index == length - 1, node) if length is not None else Value('symbol', ('loop-last', id(node), index), node), 'depth': Value('scalar', depth, node), 'depth0': Value('scalar', depth - 1, node), 'cycle': Value('cycle', index, node)}
        for name, number in (('index0', index), ('index', index + 1 if index is not None else None), ('length', length), ('revindex0', length - index - 1 if length is not None and index is not None else None), ('revindex', length - index if length is not None and index is not None else None)):
            data[name] = Value('scalar', number, node) if number is not None else unknown
        data['previtem'] = items[index - 1] if items is not None and index is not None and (index > 0) else unknown
        data['nextitem'] = items[index + 1] if items is not None and index is not None and (index + 1 < len(items)) else unknown
        recursive = Value('recursive', Closure(node, path.frames, path.autoescape), node) if node.recursive else None
        return Value('loop', (tuple(data.items()), recursive), node)

    def _call(self, node: nodes.Call, path: Path[S], flags: int, caller: Value | None=None) -> list[tuple[Path[S], Value]]:
        if not self._schema(node):
            return [(self._role_gap(path), Value('refuse', 'call-schema', node))]
        out = []
        for reached, callee in self._evaluate(node.node, path, flags):
            if callee.kind == 'loop':
                recursive = cast(tuple[object, ...], callee.data)[1]
                callee = cast(Value, recursive) if recursive is not None else Value('refuse', 'nonrecursive-loop-call', node)
            reached = self._role_result(reached, callee)
            for at, args, kwargs, error in self._normalized_arguments(node, reached, flags):
                if error:
                    out.append((at, Value('refuse', error, node)))
                    continue
                if caller is not None:
                    if 'caller' in kwargs:
                        out.append((at, Value('refuse', 'caller-conflict', node)))
                        continue
                    kwargs['caller'] = caller
                if any((v.kind == 'refuse' for v in (*args, *kwargs.values()))):
                    out.append((at, next((v for v in (*args, *kwargs.values()) if v.kind == 'refuse'))))
                elif callee.kind == 'cycle' and type(callee.data) is int and args and (not kwargs):
                    out.append((at, args[callee.data % len(args)]))
                elif callee.kind in ('macro', 'caller', 'recursive'):
                    out.extend(self._local_call(node, callee, at, tuple(args), kwargs, flags))
                elif callee.kind == 'symbol' and callee.data == ('context', 'dict'):
                    pairs: list[tuple[Value, Value]] = []
                    if args:
                        if len(args) != 1 or args[0].kind != 'mapping':
                            out.append((at, Value('refuse', 'dict-positional', node)))
                            continue
                        entries = cast(tuple[tuple[Value, Value], ...], args[0].data)
                        if not self._charge(len(entries)):
                            return [(at, Value('refuse', 'budget', node))]
                        pairs.extend(entries)
                    if not self._charge(len(kwargs)):
                        return [(at, Value('refuse', 'budget', node))]
                    pairs.extend(((Value('scalar', key, node), value) for key, value in kwargs.items()))
                    out.append((at, self._mapping(pairs, node)))
                elif callee.kind == 'symbol' and callee.data == ('context', 'range') and (not kwargs) and all((v.kind == 'scalar' and type(v.data) is int for v in args)):
                    try:
                        numbers = range(*(cast(int, v.data) for v in args))
                        length = len(numbers)
                    except (TypeError, ValueError, OverflowError):
                        out.append((at, Value('refuse', 'range', node)))
                    else:
                        if not self._charge(length):
                            return [(at, Value('refuse', 'budget', node))]
                        out.append((at, Value('sequence', tuple((Value('scalar', n, node) for n in numbers)), node)))
                elif callee.kind == 'refuse':
                    out.append((at, callee))
                else:
                    out.append((at, Value('refuse', 'external-call', node)))
        return out

    def _local_call(self, call: nodes.Call, callee: Value, path: Path[S], args: tuple[Value, ...], kwargs: dict[str, Value], flags: int) -> list[tuple[Path[S], Value]]:
        from j2prompt_lint.rules.pchat import MAX_SPLICE_DEPTH
        closure = cast(Closure, callee.data)
        signature = (id(closure.node), args, tuple(sorted(kwargs.items())))
        if signature in self._calls:
            return [(path, Value('refuse', 'local-recursion', call))]
        if len(self._calls) >= MAX_SPLICE_DEPTH:
            self.algebra.budget = -1
            self.algebra.overflow()
            return [(path, Value('refuse', 'call-depth', call))]
        if not self._charge(len(args) + len(kwargs) + len(self._calls) + len(closure.frames) + 1):
            return [(path, Value('refuse', 'budget', call))]
        lexical = closure.frames
        if lexical and len(path.frames) >= len(lexical) and all((old.identity == new.identity for old, new in zip(lexical, path.frames, strict=False))):
            lexical = path.frames[:len(lexical)]
        entered = dataclasses.replace(path, frames=lexical, autoescape=closure.autoescape)
        self._calls = (*self._calls, signature)
        saved_scope = self._scope
        self._scope = (*self._scope, id(call))
        try:
            if callee.kind == 'recursive':
                if len(args) == 1 and (not kwargs):
                    iterable = args[0]
                elif not args and set(kwargs) == {'iterable'}:
                    iterable = kwargs['iterable']
                else:
                    return [(path, Value('refuse', 'recursive-arguments', call))]
                if self.observer is not None and (not self._charge()):
                    return [(path, Value('refuse', 'capture-budget', call))]
                capture = _Capture(self.algebra.budget)
                flow = Flow(self.model, capture, self.observer)
                flow._calls = self._calls
                flow._sites = self._sites
                flow._slices = self._slices
                flow._scope = self._scope
                flow._guard_probe = self._guard_probe
                flow._guard_seen = self._guard_seen
                initial: Path[tuple[Fragment, ...]] = Path(EMPTY, (), entered.frames, entered.facts, entered.autoescape, role_available=entered.role_available)
                result = flow._semantic_for(cast(nodes.For, closure.node), initial, iterable, flags)
                self.algebra.budget = capture.budget
                if result is None:
                    return [(self._role_gap(path), Value('refuse', 'capture-budget', call))]
                returned = []
                for end in result:
                    parent = self._child_path(path, end)
                    if parent is None:
                        return [(path, Value('refuse', 'capture-budget', call))]
                    value = Value('refuse', end.stopped, call) if end.stopped else Value('text', end.state, call, safe=bool(path.autoescape))
                    returned.append((self._role_result(parent, value), value))
                return returned
            macro = cast(nodes.Macro | nodes.CallBlock, closure.node)
            framed = dataclasses.replace(entered, frames=(*entered.frames, Frame(id(macro))))
            current = [(framed, dict(kwargs))]
            for index, target in enumerate(macro.args):
                if not self._schema(target):
                    return [(self._role_gap(path), Value('refuse', 'parameter-schema', call))]
                next_ = []
                for at, unused in current:
                    if index < len(args):
                        if target.name in unused:
                            return [(path, Value('refuse', 'macro-argument-conflict', call))]
                        options = [(at, args[index])]
                    elif target.name in unused:
                        options = [(at, unused.pop(target.name))]
                    else:
                        default_index = index - (len(macro.args) - len(macro.defaults))
                        if default_index < 0 and self.observer is not None and (not self._charge()):
                            return [(self._role_gap(path), Value('refuse', 'budget', call))]
                        options = self._evaluate(macro.defaults[default_index], at, flags) if default_index >= 0 else [(at, Value('refuse', 'missing-macro-argument', target, lazy_observation=True))]
                    for at_, value in options:
                        bound = self._target(at_, target, value)
                        if bound is None:
                            return [(path, Value('refuse', 'budget', call))]
                        next_.append((bound, dict(unused)))
                current = next_
            out = []
            names: set[str] = set()
            available = {'caller', 'kwargs', 'varargs'}
            explicit = {argument.name for argument in macro.args}
            pending: list[nodes.Node] = list(reversed(macro.body))
            while pending:
                if not self._charge():
                    return [(path, Value('refuse', 'budget', call))]
                item = pending.pop()
                if not self._schema(item):
                    current = [(self._role_gap(p), unused) for p, unused in current]
                if isinstance(item, nodes.Block):
                    continue
                if isinstance(item, nodes.Name):
                    if item.ctx == 'load' and item.name in available:
                        names.add(item.name)
                    else:
                        available.discard(item.name)
                children = []
                for child in item.iter_child_nodes():
                    if not self._charge():
                        return [(path, Value('refuse', 'budget', call))]
                    children.append(child)
                pending.extend(reversed(children))
            for at, unused in current:
                if not self._charge(len(args) + len(unused) + 1):
                    return [(path, Value('refuse', 'budget', call))]
                bindings = {}
                if 'varargs' in names and 'varargs' not in explicit:
                    bindings['varargs'] = Value('sequence', args[len(macro.args):], call)
                if 'kwargs' in names and 'kwargs' not in explicit:
                    bindings['kwargs'] = Value('mapping', tuple(((Value('scalar', k, call), v) for k, v in unused.items() if k != 'caller')), call)
                if 'caller' in unused:
                    if 'caller' not in names:
                        return [(path, Value('refuse', 'unused-caller', call))]
                    bindings['caller'] = unused.pop('caller')
                if len(args) > len(macro.args) and 'varargs' not in bindings or (unused and 'kwargs' not in bindings):
                    return [(path, Value('refuse', 'macro-extra-arguments', call))]
                for name, value in bindings.items():
                    updated = self._bind(at, name, value)
                    if updated is None:
                        return [(path, Value('refuse', 'budget', call))]
                    at = updated
                for capture_end, value in self._capture(macro.body, at, flags):
                    capture_parent = self._child_path(path, capture_end)
                    if capture_parent is None:
                        return [(path, Value('refuse', 'capture-budget', call))]
                    out.append((self._role_result(capture_parent, value), dataclasses.replace(value, safe=bool(path.autoescape))))
            return out
        finally:
            self._calls = self._calls[:-1]
            self._scope = saved_scope

    def _spent(self) -> bool:
        if self.algebra.budget >= 0:
            return False
        if not self.algebra.exact:
            self.algebra.overflow()
        return True

    def _statement(self, node: nodes.Node, paths: list[Path[S]], flags: int) -> list[Path[S]] | None:
        if isinstance(node, nodes.Output):
            base = self.model.base[id(node)]
            items = [(emission, base + position) for position, emission in enumerate(self.model.rendered[id(node)])]
            return self._items(items, paths, flags)
        if isinstance(node, nodes.If):
            return self._if(node, paths, flags)
        if isinstance(node, nodes.For):
            return self._for(node, paths, flags)
        if isinstance(node, _IN_PLACE):
            entered = self.algebra.container(node, paths)
            if entered is None:
                return None
            return self.run(node.body, entered, flags | CONTAINED)
        passed = paths if isinstance(node, _SILENT) else self._reset(paths)
        return self.algebra.statement(node, passed)

    def _items(self, items: Sequence[tuple[_Emission, int]], paths: list[Path[S]], flags: int, level: int=0) -> list[Path[S]] | None:
        current: list[Path[S]] | None = paths
        index = 0
        while index < len(items) and current is not None and (not self._spent()):
            emission, order = items[index]
            if len(emission.arms) <= level:
                current = self._emit(emission, order, current, flags)
                index += 1
                continue
            branch, _, count, bound = emission.arms[level]
            end = index
            while end < len(items) and len(items[end][0].arms) > level and (items[end][0].arms[level][0] == branch):
                end += 1
            self.algebra.budget -= end - index
            if self._spent():
                return None if self.algebra.exact else current
            guard = branch in self.model.guards
            buckets: list[list[tuple[_Emission, int]]] = [[] for _ in range(count)]
            for item in items[index:end]:
                buckets[item[0].arms[level][1]].append(item)
            arms: list[list[Path[S]]] = []
            for arm, sub in enumerate(buckets):
                arm_flags = flags | (GUARDED if guard else 0) | (BOUND if bound and arm else 0)
                result = self._items(sub, current, arm_flags, level + 1)
                if result is None:
                    return None
                arms.append(result)
            current = self._settled(self.algebra.branch(guard, current, arms))
            index = end
        return current

    def _emit(self, emission: _Emission, order: int, paths: list[Path[S]], flags: int, *, fragment: int | None=None) -> list[Path[S]] | None:
        if self.model.semantic:
            site = (self._scope, self._output_site, id(emission.node), order, emission.text, fragment)
            if site not in self._sites:
                if not self._charge():
                    return None
                self._sites[site] = len(self._sites)
            order = self._sites[site]
            if not self._charge(len(paths) * (len(emission.text or '') + 1)):
                return None
        self.algebra.budget -= len(paths)
        if self.algebra.budget < 0:
            if self.algebra.exact:
                return None
            self.algebra.overflow()
            return paths
        out: list[Path[S]] = []
        for path in paths:
            if self.model.semantic and isinstance(self.algebra, _Capture):
                captured = self.algebra.append(cast(tuple[Fragment, ...], path.state), emission, order, flags)
                state = cast(S | None, captured)
                carry = EMPTY
            elif emission.text is None:
                state = self.algebra.value(path, emission)
                carry = EMPTY
            else:
                found, carry = advance(path.carry, emission, order, flags, self.model.lexicon)
                state = self.algebra.literal(path.state, found)
                if state is not None:
                    if not self._charge():
                        return None
                    state = self.algebra.emitted(dataclasses.replace(path, state=state), emission, order, flags)
            if state is None:
                return None
            out.append(dataclasses.replace(path, carry=carry, state=state))
        return self._settled(out)

    def _if(self, node: nodes.If, paths: list[Path[S]], flags: int) -> list[Path[S]] | None:
        guard = id(node) in self.model.guards
        arms: list[list[Path[S]]] = []
        for body in (node.body, *(elif_.body for elif_ in node.elif_)):
            result = self.run(body, paths, flags | (GUARDED if guard else 0))
            if result is None:
                return None
            arms.append(result)
        if node.else_:
            result = self.run(node.else_, paths, flags | (GUARDED if guard else 0))
            if result is None:
                return None
            arms.append(result)
        else:
            arms.append(paths)
        return self._settled(self.algebra.branch(guard, paths, arms))

    def _for(self, node: nodes.For, paths: list[Path[S]], flags: int) -> list[Path[S]] | None:
        exits: list[Path[S]] = []
        seen: set[Path[S]] = set()
        frontier = paths
        taken = flags
        while True:
            fresh = [path for path in dict.fromkeys(frontier) if path not in seen]
            if not fresh:
                break
            seen.update(fresh)
            result = self.run(node.body, fresh, taken)
            if result is None or not self.algebra.loop_pass(paths, result):
                if taken & ITERATED:
                    self.algebra.later_pass_failed(paths)
                return None
            taken = flags | ITERATED
            exits.extend(result)
            if not self.algebra.iterates or self._spent():
                break
            if len(seen) > MAX_PATHS:
                if self.algebra.exact:
                    return None
                self.algebra.overflow()
                break
            frontier = result
        if node.else_:
            other = self.run(node.else_, paths, flags)
            if other is None or not self.algebra.loop_pass(paths, other):
                return None
        else:
            other = paths
        return self._settled(self.algebra.branch(False, paths, [exits, other]))

    def _settled(self, paths: list[Path[S]] | None) -> list[Path[S]] | None:
        if paths is None:
            if self.observer is not None:
                self.observer.unavailable = True
            return None
        self.algebra.budget -= len(paths)
        if self._spent():
            if self.observer is not None:
                self.observer.unavailable = True
            if self.algebra.exact:
                return None
            self.algebra.overflow()
            return list(dict.fromkeys(paths[:MAX_PATHS]))
        unique = list(dict.fromkeys(paths))
        if len(unique) > MAX_PATHS:
            if self.observer is not None:
                self.observer.unavailable = True
            if self.algebra.exact:
                self.algebra.overflow()
                return None
            self.algebra.overflow()
            unique = unique[:MAX_PATHS]
        result = self.algebra.settle(unique)
        if result is None and self.observer is not None:
            self.observer.unavailable = True
        return result

    @staticmethod
    def _reset(paths: list[Path[S]]) -> list[Path[S]]:
        return list(dict.fromkeys((Path(EMPTY, path.state, role_available=path.role_available) for path in paths)))

def advance(carry: Carry, emission: _Emission, order: int, flags: int, lexicon: Lexicon) -> tuple[list[Occurrence], Carry]:
    text = emission.text or ''
    joined = ''.join((carry.text, text))
    base = len(carry.text)

    def mark(index: int) -> Mark:
        if index < base:
            return carry.marks[index]
        at = index - base
        return Mark(_line(emission, at), order, at, flags)
    found: list[Occurrence] = []
    for pattern in lexicon.patterns:
        start = joined.find(pattern, max(0, base - len(pattern) + 1))
        while start != -1:
            end = start + len(pattern)
            found.append(Occurrence(pattern, start, tuple((mark(i) for i in range(start, end)))))
            start = joined.find(pattern, start + 1)
    found.sort(key=lambda occurrence: (occurrence.start, -len(occurrence.pattern)))
    keep = _kept(joined, lexicon)
    kept_from = len(joined) - keep
    marks = tuple((mark(i) for i in range(kept_from, len(joined))))
    return (found, Carry(joined[kept_from:], marks) if keep else EMPTY)

def _kept(text: str, lexicon: Lexicon) -> int:
    for size in range(min(len(text), lexicon.longest), 0, -1):
        if text[-size:] in lexicon.prefixes:
            return size
    return 0

def _line(emission: _Emission, at: int) -> int:
    line = emission.line
    for piece in emission.pieces:
        if piece.offset > at:
            break
        line = piece.line
    return line

def statement_lists(node: nodes.Node) -> list[list[nodes.Node]]:
    return [value for _, value in node.iter_fields() if isinstance(value, list) and any((isinstance(item, nodes.Stmt) for item in value))]

@dataclass(frozen=True, slots=True)
class _RolePending:
    prefix: str
    text: str
    mark: Mark | None
    _hash: int = dataclasses.field(init=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, '_hash', hash((self.prefix, self.text, self.mark)))

    def __hash__(self) -> int:
        return self._hash

@dataclass(frozen=True, slots=True)
class _RoleState:
    pending: tuple[_RolePending, ...] = ()
    _hash: int = dataclasses.field(init=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, '_hash', hash(self.pending))

    def __hash__(self) -> int:
        return self._hash

@dataclass(frozen=True, slots=True)
class EmittedRole:
    prefix: str
    role: str
    mark: Mark
    _hash: int = dataclasses.field(init=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, '_hash', hash((self.prefix, self.role, self.mark)))

    def __hash__(self) -> int:
        return self._hash
_NO_ROLES = _RoleState()

class Presence:
    iterates = True
    exact = False

    def __init__(self, model: Model, prefixes: Iterable[str], role_stop: str | None=None) -> None:
        self.budget = MAX_STEPS
        if model.work_left is not None:
            self.budget = min(model.work_left, MAX_STEPS)
        self.model = model
        self.prefixes = tuple(prefixes)
        self.role_stop = role_stop
        self.roles: tuple[EmittedRole, ...] = ()
        self.found: dict[tuple[str, tuple[tuple[int, int], ...]], Occurrence] = {}
        self.before_value: set[str] = set()
        self.eos_present = False
        self.generation_guard = False
        self.overflowed = not model.complete
        self._rooted: set[int] = set()
        self.named_reads: _RoleCollector | None = None
        if model.semantic and self.budget >= 4:
            self.budget -= 4
            self.named_reads = _RoleCollector(unavailable=not model.origin_complete)
        elif model.semantic:
            self.overflowed = True

    def read(self, statements: Sequence[nodes.Node]) -> None:
        self._read(statements)

    def _read(self, statements: Sequence[nodes.Node]) -> list[Path[_RoleState]] | None:
        if self.model.complete:
            flow = Flow(self.model, self, self.named_reads)
            reached = flow.run(statements, [Path(EMPTY, _NO_ROLES)])
            self.generation_guard |= flow._guard_seen[0]
            if reached is None and self.named_reads is not None:
                self.named_reads.unavailable = True
            return reached
        return None

    def role_evidence(self, prefix: str | None) -> RoleEvidence:
        named = self.named_reads is not None and self.named_reads.named
        positional = prefix is not None and prefix in self.before_value
        if self.budget < 3:
            if self.named_reads is not None:
                self.named_reads.unavailable = True
            return _UNAVAILABLE_ROLES[int(named) + 2 * int(positional)]
        self.budget -= 3
        available = not self.overflowed and self.model.complete and self.model.origin_complete and (self.named_reads is not None) and self.named_reads.finished and (self.model.named_syntax_absent is True or (self.named_reads is not None and (not self.named_reads.unavailable)))
        return RoleEvidence(named, available, positional)

    def read_template(self, ast: nodes.Template) -> None:
        if self.named_reads is not None:
            self.named_reads.finished = False
            if not self._role_charge(schema_work(ast) + 2) or not known_schema(ast):
                self.named_reads.initial_available = False
                self.named_reads.unavailable = True
                return
        reached = self._read(ast.body)
        if reached is None or self.budget < 0 or (not self.model.semantic):
            return
        for path in reached:
            if not path.stopped:
                for pending in path.state.pending:
                    if not self._complete_role(pending):
                        return
        if self.named_reads is not None:
            self.named_reads.finished = True

    def occurrences(self) -> list[Occurrence]:
        return sorted(self.found.values(), key=lambda o: (o.rank, o.pattern))

    def literal(self, state: _RoleState, found: Sequence[Occurrence]) -> _RoleState:
        for occurrence in found:
            self.found.setdefault(occurrence.identity, occurrence)
        return state

    def value(self, path: Path[_RoleState], emission: _Emission) -> _RoleState:
        for prefix in self.prefixes:
            if path.carry.text.endswith(prefix):
                self.before_value.add(prefix)
        if isinstance(emission.node, nodes.Name) and (not emission.escaped):
            self.eos_present |= any((hint in emission.node.name.lower() for hint in ('eos', 'eot')))
        return _NO_ROLES

    def _role_charge(self, amount: int) -> bool:
        if self.budget < amount:
            self.budget = -1
            self.overflow()
            return False
        self.budget -= amount
        return True

    def _complete_role(self, pending: _RolePending) -> bool:
        size = len(pending.text)
        if not self._role_charge(2 * size + 2 * len(self.roles) + 1):
            return False
        role = pending.text.strip()
        if not role or pending.mark is None or (not role.isalpha()):
            return True
        count = len(self.roles) + 1
        longest = max((len(value.role) for value in self.roles), default=0)
        comparison = len(self.roles) * (longest + size + len(pending.prefix) + 1)
        if not self._role_charge(comparison):
            return False
        if any((value.prefix == pending.prefix and value.role == role for value in self.roles)):
            return True
        cost = count * (count.bit_length() + 1) * (longest + size + len(pending.prefix) + 2)
        if not self._role_charge(cost + 2 * count):
            return False
        value = EmittedRole(pending.prefix, role, pending.mark)
        self.roles = tuple(sorted((*self.roles, value), key=lambda item: (item.prefix, item.role)))
        return True

    def _role_part(self, pending: _RolePending, emission: _Emission, order: int, flags: int, start: int) -> tuple[_RolePending | None, bool]:
        text = emission.text or ''
        stop = start
        while stop < len(text):
            if not self._role_charge(1):
                return (None, False)
            if text[stop] in (self.role_stop or ''):
                break
            if not text[stop].isalpha() and (not text[stop].isspace()):
                return (None, True)
            stop += 1
        size = len(pending.text) + stop - start
        if not self._role_charge(4 * size + len(emission.pieces) + 4):
            return (None, False)
        mark = pending.mark
        if mark is None:
            for at in range(start, stop):
                if not text[at].isspace():
                    mark = Mark(_line(emission, at), order, at, flags)
                    break
        value = _RolePending(pending.prefix, pending.text + text[start:stop], mark)
        if stop < len(text):
            return (None, self._complete_role(value))
        return (value, True)

    def emitted(self, path: Path[_RoleState], emission: _Emission, order: int, flags: int) -> _RoleState | None:
        if not self.model.semantic or self.role_stop is None:
            return path.state
        text = emission.text or ''
        base = len(path.carry.text)
        if not self._role_charge(base + len(text) + len(path.state.pending) + 1):
            return None
        joined = path.carry.text + text
        pending: list[_RolePending] = []
        for old in path.state.pending:
            value, funded = self._role_part(old, emission, order, flags, 0)
            if not funded:
                return None
            if value is not None:
                pending.append(value)
        for prefix in self.prefixes:
            if not self._role_charge(1):
                return None
            if len(prefix) > len(joined):
                continue
            if not self._role_charge(len(joined)):
                return None
            at = joined.find(prefix, max(0, base - len(prefix) + 1))
            while at != -1:
                end = at + len(prefix)
                if not self._role_charge(2):
                    return None
                value, funded = self._role_part(_RolePending(prefix, '', None), emission, order, flags, end - base)
                if not funded:
                    return None
                if value is not None:
                    pending.append(value)
                at = joined.find(prefix, at + 1)
        if not pending:
            return _NO_ROLES
        if not self._role_charge(len(pending) + 1):
            return None
        return _RoleState(tuple(pending))

    def branch(self, guard: bool, entry: Sequence[Path[_RoleState]], arms: Sequence[Sequence[Path[_RoleState]]]) -> list[Path[_RoleState]]:
        return [path for arm in arms for path in arm]

    def settle(self, paths: list[Path[_RoleState]]) -> list[Path[_RoleState]]:
        return paths

    def statement(self, node: nodes.Node, paths: list[Path[_RoleState]]) -> list[Path[_RoleState]]:
        if not self.model.semantic and id(node) not in self._rooted:
            self._rooted.add(id(node))
            for body in statement_lists(node):
                self.read(body)
        return paths

    def container(self, node: nodes.Node, paths: list[Path[_RoleState]]) -> list[Path[_RoleState]]:
        return paths

    def loop_pass(self, entry: Sequence[Path[_RoleState]], exits: Sequence[Path[_RoleState]]) -> bool:
        return True

    def later_pass_failed(self, entry: Sequence[Path[_RoleState]]) -> None:
        pass

    def overflow(self) -> None:
        self.overflowed = True

class _Capture:
    iterates = True
    exact = True

    def __init__(self, budget: int) -> None:
        self.budget = budget
        self.resource_refused = False

    def append(self, state: tuple[Fragment, ...], emission: _Emission, order: int, flags: int) -> tuple[Fragment, ...] | None:
        amount = len(state) + len(emission.text or '') + 1
        if amount > self.budget:
            self.budget = -1
            return None
        self.budget -= amount
        return (*state, Fragment(emission, order, flags))

    def literal(self, state: tuple[Fragment, ...], found: Sequence[Occurrence]) -> tuple[Fragment, ...]:
        return state

    def emitted(self, path: Path[tuple[Fragment, ...]], emission: _Emission, order: int, flags: int) -> tuple[Fragment, ...]:
        return path.state

    def value(self, path: Path[tuple[Fragment, ...]], emission: _Emission) -> tuple[Fragment, ...]:
        return path.state

    def branch(self, guard: bool, entry: Sequence[Path[tuple[Fragment, ...]]], arms: Sequence[Sequence[Path[tuple[Fragment, ...]]]]) -> list[Path[tuple[Fragment, ...]]]:
        return [path for arm in arms for path in arm]

    def settle(self, paths: list[Path[tuple[Fragment, ...]]]) -> list[Path[tuple[Fragment, ...]]]:
        return paths

    def statement(self, node: nodes.Node, paths: list[Path[tuple[Fragment, ...]]]) -> list[Path[tuple[Fragment, ...]]]:
        return paths

    def container(self, node: nodes.Node, paths: list[Path[tuple[Fragment, ...]]]) -> list[Path[tuple[Fragment, ...]]]:
        return paths

    def loop_pass(self, entry: Sequence[Path[tuple[Fragment, ...]]], exits: Sequence[Path[tuple[Fragment, ...]]]) -> bool:
        return True

    def later_pass_failed(self, entry: Sequence[Path[tuple[Fragment, ...]]]) -> None:
        return None

    def overflow(self) -> None:
        self.resource_refused = True
