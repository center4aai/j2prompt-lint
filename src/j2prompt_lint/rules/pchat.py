from __future__ import annotations
import dataclasses
import itertools
from collections import deque
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from jinja2 import nodes
from j2prompt_lint.core.config import LintConfig
from j2prompt_lint.core.context import TemplateContext
from j2prompt_lint.core.model import Diagnostic, RuleId
from j2prompt_lint.core.subcodes import anchor_for, render, severity_for
from j2prompt_lint.rules import pchat_flow
from j2prompt_lint.rules.pchat_flow import BOUND, CONTAINED, GUARDED, ITERATED, EmittedRole, Flow, Model, Occurrence, Presence, RoleEvidence
from j2prompt_lint.rules.pchat_flow import Path as FlowPath
from j2prompt_lint.rules.pinj_resolve import const_target, parse_unit, resolve

@dataclass(frozen=True, slots=True)
class ChatPack:
    name: str
    open_markers: tuple[str, ...]
    eot_marker: str
    require_eot_to_detect: bool = False
    allowed_roles: frozenset[str] = frozenset()
    bos_marker: str | None = None
    eos_marker: str | None = None
    role_header: str | None = None
    generation_prompt: str | None = None

    @property
    def role_prefix(self) -> str | None:
        if self.role_header is None:
            return None
        return self.role_header.split('{role}')[0] or None
_STANDARD_ROLES: frozenset[str] = frozenset({'system', 'user', 'assistant', 'tool', 'developer', 'ipython', 'environment'})
_PACKS: tuple[ChatPack, ...] = (ChatPack('chatml', ('<|im_start|>',), '<|im_end|>', allowed_roles=_STANDARD_ROLES, role_header='<|im_start|>{role}\n', generation_prompt='<|im_start|>assistant'), ChatPack('llama3', ('<|start_header_id|>',), '<|eot_id|>', allowed_roles=_STANDARD_ROLES, role_header='<|start_header_id|>{role}<|end_header_id|>\n\n', generation_prompt='<|start_header_id|>assistant', bos_marker='<|begin_of_text|>'), ChatPack('mistral', ('[INST]',), '[/INST]', eos_marker='</s>', allowed_roles=_STANDARD_ROLES), ChatPack('phi', ('<|user|>', '<|assistant|>', '<|system|>'), '<|end|>', require_eot_to_detect=True, allowed_roles=_STANDARD_ROLES, role_header='<|{role}|>\n', generation_prompt='<|assistant|>'))
PACK_NAMES: frozenset[str] = frozenset((pack.name for pack in _PACKS))

@dataclass(frozen=True, slots=True)
class _Piece:
    offset: int
    line: int
    order: int

@dataclass(frozen=True, slots=True)
class _Emission:
    line: int
    text: str | None
    node: nodes.Node
    fusable: bool = True
    pieces: tuple[_Piece, ...] = ()
    arms: tuple[tuple[int, int, int, bool], ...] = ()
    escaped: bool = False

def _concat_operands(node: nodes.Node) -> list[nodes.Node]:
    if isinstance(node, nodes.Add):
        return [*_concat_operands(node.left), *_concat_operands(node.right)]
    if isinstance(node, nodes.Concat):
        return [operand for child in node.nodes for operand in _concat_operands(child)]
    return [node]

def _literal_text(node: nodes.Node) -> str | None:
    if isinstance(node, nodes.TemplateData):
        return node.data
    if isinstance(node, nodes.Const) and isinstance(node.value, str):
        return node.value
    return None

def _concat_emissions(node: nodes.Node) -> Iterator[_Emission]:
    texts: list[str] = []
    pieces: list[_Piece] = []
    offset = 0
    for operand in _concat_operands(node):
        text = _literal_text(operand)
        if text is not None:
            pieces.append(_Piece(offset, operand.lineno, 0))
            texts.append(text)
            offset += len(text)
            continue
        if texts:
            yield _Emission(pieces[0].line, ''.join(texts), node, pieces=tuple(pieces))
            texts, pieces, offset = ([], [], 0)
        yield from _emissions(operand)
    if texts:
        yield _Emission(pieces[0].line, ''.join(texts), node, pieces=tuple(pieces))

def _emissions(node: nodes.Node) -> Iterator[_Emission]:
    if isinstance(node, nodes.TemplateData):
        yield _Emission(node.lineno, node.data, node)
        return
    if isinstance(node, nodes.Const):
        value = node.value if isinstance(node.value, str) else None
        yield _Emission(node.lineno, value, node)
        return
    if isinstance(node, nodes.Add | nodes.Concat):
        yield from _concat_emissions(node)
        return
    if isinstance(node, nodes.CondExpr):
        for index, arm in enumerate((node.expr1, node.expr2)):
            if arm is None:
                continue
            for emission in _emissions(arm):
                yield dataclasses.replace(emission, fusable=False, arms=((id(node), index, 2, False), *emission.arms))
        return
    yield _Emission(node.lineno, None, node)

def _bindings(ast: nodes.Template) -> dict[str, list[list[_Emission]]]:
    out: dict[str, list[list[_Emission]]] = {}
    for assign in ast.find_all(nodes.Assign):
        if isinstance(assign.target, nodes.Name):
            out.setdefault(assign.target.name, []).append(list(_emissions(assign.node)))
    for block in ast.find_all(nodes.AssignBlock):
        if not isinstance(block.target, nodes.Name):
            continue
        if block.filter is not None or not all((isinstance(statement, nodes.Output) or _renders_nothing(statement) for statement in block.body)):
            captured = [_Emission(block.lineno, None, block)]
        else:
            captured = [emission for output in block.body for child in getattr(output, 'nodes', []) for emission in _emissions(child)]
        out.setdefault(block.target.name, []).append(captured)
    return out

def _expand(emissions: list[_Emission], bindings: dict[str, list[list[_Emission]]], seen: frozenset[str]=frozenset()) -> list[_Emission]:
    out: list[_Emission] = []
    for emission in emissions:
        node = emission.node
        if emission.text is not None or not isinstance(node, nodes.Name) or node.name in seen or (node.name not in bindings):
            out.append(emission)
            continue
        out.append(emission)
        for alternative in bindings[node.name]:
            out.extend(_expand(alternative, bindings, seen | {node.name}))
    return out
_SILENT = (nodes.Assign, nodes.AssignBlock, nodes.Macro, nodes.Import, nodes.FromImport, nodes.ExprStmt)

def _renders_nothing(node: nodes.Node) -> bool:
    if isinstance(node, _SILENT):
        return True
    if isinstance(node, nodes.If):
        return all((_body_renders_nothing(body) for body in _branch_bodies(node)))
    if isinstance(node, nodes.For):
        return _body_renders_nothing(node.body) and _body_renders_nothing(node.else_)
    if isinstance(node, nodes.With | nodes.Scope):
        return _body_renders_nothing(node.body)
    return False

def _body_renders_nothing(body: list[nodes.Node]) -> bool:
    return all((_renders_nothing(statement) for statement in body))

def _segments(body: list[nodes.Node]) -> list[list[nodes.Node]]:
    segments: list[list[nodes.Node]] = []
    index, count = (0, len(body))
    while index < count:
        if not isinstance(body[index], nodes.Output):
            segments.append([body[index]])
            index += 1
            continue
        end = scan = index + 1
        while scan < count and (isinstance(body[scan], nodes.Output) or _renders_nothing(body[scan])):
            scan += 1
            if isinstance(body[scan - 1], nodes.Output):
                end = scan
        segments.append(body[index:end])
        segments.extend(([statement] for statement in body[end:scan]))
        index = scan
    return segments

def _is_stretch(segment: list[nodes.Node]) -> bool:
    return isinstance(segment[0], nodes.Output)

def _fused(sequence: Iterable[tuple[_Emission, int]]) -> list[_Emission]:
    out: list[_Emission] = []
    head: _Emission | None = None
    texts: list[str] = []
    pieces: list[_Piece] = []
    offset = 0
    for emission, order in sequence:
        if emission.text is not None and emission.fusable:
            head = head or emission
            pieces.extend(_placed(emission, offset, order))
            texts.append(emission.text)
            offset += len(emission.text)
            continue
        if head is not None:
            out.append(_chunk(head, texts, pieces))
            head, texts, pieces, offset = (None, [], [], 0)
        if emission.text is None:
            out.append(emission)
        else:
            out.append(dataclasses.replace(emission, pieces=_placed(emission, 0, order)))
    if head is not None:
        out.append(_chunk(head, texts, pieces))
    return out

def _placed(emission: _Emission, offset: int, order: int) -> tuple[_Piece, ...]:
    own = emission.pieces or (_Piece(0, emission.line, 0),)
    return tuple((_Piece(offset + piece.offset, piece.line, order) for piece in own))

def _chunk(head: _Emission, texts: list[str], pieces: list[_Piece]) -> _Emission:
    return _Emission(head.line, ''.join(texts), head.node, True, tuple(pieces))

def _statement_lists(ast: nodes.Node) -> Iterator[list[nodes.Node]]:
    for owner in itertools.chain((ast,), ast.find_all(nodes.Node)):
        for _, value in owner.iter_fields():
            if isinstance(value, list) and any((isinstance(item, nodes.Output) for item in value)):
                yield value
MAX_SPLICED = pchat_flow.MAX_STEPS
MAX_SPLICE_DEPTH = 64

@dataclass(slots=True)
class _SpliceBudget:
    left: int
    cut: bool = False

def _rendered(output: nodes.Output, bindings: dict[str, list[list[_Emission]]], budget: _SpliceBudget) -> list[_Emission]:
    return [placed for child in output.nodes for emission in _emissions(child) for placed in _spliced(emission, bindings, frozenset(), budget)]

def _spliced(emission: _Emission, bindings: dict[str, list[list[_Emission]]], seen: frozenset[str], budget: _SpliceBudget) -> list[_Emission]:
    node = emission.node
    if emission.text is not None or not isinstance(node, nodes.Name) or node.name in seen or (node.name not in bindings):
        return [emission]
    alternatives = bindings[node.name]
    spliced = sum((len(alternative) for alternative in alternatives))
    if spliced > budget.left or len(seen) >= MAX_SPLICE_DEPTH:
        budget.cut = True
        return [emission]
    budget.left -= spliced
    count = len(alternatives) + 1
    out = [dataclasses.replace(emission, arms=(*emission.arms, (id(node), 0, count, True)))]
    for index, alternative in enumerate(alternatives, start=1):
        tag = (*emission.arms, (id(node), index, count, True))
        for bound in alternative:
            placed = dataclasses.replace(bound, fusable=False, arms=(*tag, *bound.arms))
            out.extend(_spliced(placed, bindings, seen | {node.name}, budget))
    return out

def _emitted_runs(ast: nodes.Template) -> list[list[_Emission]]:
    rendered, base, _ = _render_order(ast)
    runs: list[tuple[int, list[_Emission]]] = []
    for body in _statement_lists(ast):
        for segment in filter(_is_stretch, _segments(body)):
            sequence = [(emission, base[id(output)] + position) for output in segment if isinstance(output, nodes.Output) for position, emission in enumerate(rendered[id(output)])]
            runs.append((sequence[0][1] if sequence else 0, _fused(sequence)))
    return [run for _, run in sorted(runs, key=lambda item: item[0])]

def _emitted_chunks(ast: nodes.Template) -> list[_Emission]:
    return [item for run in _emitted_runs(ast) for item in run if item.text is not None]

def _pairs(chunks: list[_Emission]) -> list[tuple[int, str]]:
    return [(chunk.line, chunk.text) for chunk in chunks if chunk.text is not None]

def _chunks_contain(chunks: list[tuple[int, str]], marker: str) -> bool:
    return any((marker in text for _, text in chunks))

def _chunk_marker_count(chunks: list[tuple[int, str]], markers: tuple[str, ...]) -> int:
    return sum((text.count(marker) for _, text in chunks for marker in markers))

def _literal_chunks(ctx: TemplateContext) -> list[tuple[int, str]]:
    return _pairs(_emitted_chunks(ctx.ast))

def _emitted_tokens(ctx: TemplateContext) -> list[tuple[int, str]]:
    return [(occurrence.line, occurrence.pattern) for occurrence in _presence(ctx.ast, _model(ctx.ast)).occurrences() if occurrence.pattern in _PROJECTION_TOKENS]

def _inside_one_chunk(occurrence: Occurrence, where: Mapping[int, tuple[int, int]]) -> bool:
    positions = []
    for mark in occurrence.marks:
        if mark.order not in where:
            return False
        chunk, offset = where[mark.order]
        positions.append((chunk, offset + mark.at))
    return all((after == (before[0], before[1] + 1) for before, after in itertools.pairwise(positions)))
_CANDIDATE_TOKENS = ('<|im_sep|>', '<|end_of_text|>', '<|eom_id|>', '[AVAILABLE_TOOLS]')
_LEXICON = pchat_flow.Lexicon.of(itertools.chain(_CANDIDATE_TOKENS, (marker for pack in _PACKS for marker in (*pack.open_markers, pack.eot_marker, pack.bos_marker, pack.generation_prompt) if marker)), keep=(pack.role_prefix for pack in _PACKS if pack.role_prefix))
_MARKERS = frozenset((marker for pack in _PACKS for marker in (*pack.open_markers, pack.eot_marker, pack.bos_marker) if marker))
_PROJECTION_TOKENS = _MARKERS | frozenset(_CANDIDATE_TOKENS)

def _render_order(ast: nodes.Template) -> tuple[dict[int, list[_Emission]], dict[int, int], bool]:
    bindings = _bindings(ast)
    budget = _SpliceBudget(MAX_SPLICED)
    rendered: dict[int, list[_Emission]] = {}
    base: dict[int, int] = {}
    total = 0
    for output in ast.find_all(nodes.Output):
        rendered[id(output)] = _rendered(output, bindings, budget)
        base[id(output)] = total
        total += len(rendered[id(output)])
    return (rendered, base, not budget.cut)

def _origin_state(ast: nodes.Template) -> tuple[int | None, bool, bool]:
    has_work = hasattr(ast, pchat_flow.ORIGIN_WORK)
    has_complete = hasattr(ast, pchat_flow.ORIGIN_COMPLETE)
    if not has_work and (not has_complete):
        return (0, True, False)
    work = getattr(ast, pchat_flow.ORIGIN_WORK, None)
    complete = getattr(ast, pchat_flow.ORIGIN_COMPLETE, None)
    if not (has_work and has_complete and (type(work) is int) and (0 < work <= pchat_flow.MAX_STEPS) and (type(complete) is bool)):
        return (None, False, False)
    original_attributes = max(0, len(vars(ast)) - 2)
    if complete and work < 2 * original_attributes + 10:
        return (None, False, False)
    return (work, complete, True)

def _model(ast: nodes.Template) -> Model:
    prepaid, origin_complete, accounted = _origin_state(ast)
    if prepaid is None:
        return Model({}, {}, frozenset(), _LEXICON, False, semantic=True, work_left=0)
    allowance = pchat_flow.MAX_STEPS - prepaid
    funded_metadata = allowance >= 3
    allowance = max(0, allowance - 3)
    analysis = _gen_prompt_analysis(ast, allowance)
    aliases = analysis.aliases
    remaining = allowance - analysis.steps
    rendered: dict[int, list[_Emission]] = {}
    base: dict[int, int] = {}
    order: dict[int, int] = {}
    complete = analysis.complete and funded_metadata
    exhaustive = True
    no_named = True
    synthetic_work = 0
    stack: list[nodes.Node] = [ast]
    ordered: list[nodes.Node] = []
    while stack:
        if remaining < 1:
            complete = False
            break
        remaining -= 1
        node = stack.pop()
        schema_cost = pchat_flow.schema_work(node)
        if remaining < schema_cost:
            complete = False
            break
        remaining -= schema_cost
        exhaustive &= pchat_flow.known_schema(node)
        synthetic = getattr(node, pchat_flow.SYNTHETIC_ROLE, False)
        if synthetic:
            synthetic_work += 2
            if not accounted or prepaid < 2 * max(0, len(vars(ast)) - 2) + 10 + synthetic_work:
                origin_complete = False
        if isinstance(node, _CROSS_TEMPLATE):
            exhaustive = False
        if exhaustive and pchat_flow.named_role_syntax(node) and (not synthetic):
            no_named = False
        order[id(node)] = len(ordered)
        ordered.append(node)
        if isinstance(node, nodes.Output):
            base[id(node)] = order[id(node)]
            rendered[id(node)] = []
        children = []
        for child in node.iter_child_nodes():
            if remaining < 1:
                complete = False
                break
            remaining -= 1
            children.append(child)
        if not complete:
            break
        stack.extend(reversed(children))
    contains: dict[int, bool] = {}
    guards: set[int] = set()
    for node in reversed(ordered):
        if remaining < 1:
            complete = False
            break
        remaining -= 1
        name = getattr(node, 'name', None)
        named = isinstance(node, nodes.Name) and isinstance(name, str) and (_GEN_PROMPT_HINT in name.lower() or name in aliases)
        for child in node.iter_child_nodes():
            if remaining < 1:
                complete = False
                break
            remaining -= 1
            named = named or contains.get(id(child), False)
        contains[id(node)] = named
        if isinstance(node, nodes.If | nodes.CondExpr) and contains.get(id(getattr(node, 'test', None)), False):
            if remaining < 1:
                complete = False
                break
            remaining -= 1
            guards.add(id(node))
    return Model(rendered, base, frozenset(guards), _LEXICON, complete, semantic=True, order=order, work_left=remaining, alias_steps=analysis.steps, named_syntax_absent=True if complete and exhaustive and no_named and origin_complete else None, origin_work=prepaid, origin_complete=origin_complete)

def _presence(ast: nodes.Template, model: Model) -> Presence:
    presence = Presence(model, (pack.role_prefix for pack in _PACKS if pack.role_prefix), _ROLE_STOP)
    presence.read_template(ast)
    return presence

def _marker_texts(occurrences: Iterable[Occurrence]) -> list[tuple[int, str]]:
    return [(occurrence.line, occurrence.pattern) for occurrence in occurrences if occurrence.pattern in _MARKERS]

def _first_line(occurrences: Iterable[Occurrence], markers: tuple[str, ...]) -> int:
    firsts = [occurrence for occurrence in occurrences if occurrence.pattern in markers]
    return min(firsts, key=lambda occurrence: occurrence.rank).line if firsts else 1

def _detects(pack: ChatPack, text: str) -> bool:
    return _detects_in(pack, [(1, text)])

def _detects_in(pack: ChatPack, chunks: list[tuple[int, str]]) -> bool:
    if not any((_chunks_contain(chunks, marker) for marker in pack.open_markers)):
        return False
    return not (pack.require_eot_to_detect and (not _chunks_contain(chunks, pack.eot_marker)))

def _matching_packs_in(chunks: list[tuple[int, str]], enabled: frozenset[str] | None=None) -> list[ChatPack]:
    return [pack for pack in _PACKS if (enabled is None or pack.name in enabled) and _detects_in(pack, chunks)]

def _resolve_pack(chunks: list[tuple[int, str]], enabled: frozenset[str] | None=None) -> tuple[ChatPack, list[ChatPack]] | None:
    matches = _matching_packs_in(chunks, enabled)
    if not matches:
        return None
    pack = max(matches, key=lambda p: _chunk_marker_count(chunks, p.open_markers))
    return (pack, matches)

def _detect_pack(text: str) -> ChatPack | None:
    resolved = _resolve_pack([(1, text)])
    return None if resolved is None else resolved[0]

def _has_role_access(evidence: RoleEvidence) -> bool:
    return evidence.named or evidence.positional
_ROLE_STOP = '<\n\r\t '

def _literal_roles(ast: nodes.Template, pack: ChatPack) -> list[str]:
    prefix = pack.role_prefix
    if prefix is None:
        return []
    roles: list[str] = []
    for node in ast.find_all(nodes.TemplateData):
        text = node.data
        for pos in _positions(text, prefix):
            start = pos + len(prefix)
            chars: list[str] = []
            for ch in text[start:]:
                if ch in _ROLE_STOP:
                    break
                chars.append(ch)
            role = ''.join(chars).strip()
            if role:
                roles.append(role)
    return roles

def _has_gen_prompt_guard(ast: nodes.Template, pack: ChatPack, model: Model, presence: Presence) -> bool:
    if not (presence.generation_guard if model.semantic else model.guards):
        return False
    if pack.generation_prompt is None:
        return True
    return any((occurrence.pattern == pack.generation_prompt and occurrence.flags & GUARDED for occurrence in presence.occurrences()))

def gen_prompt_aliases(ast: nodes.Template) -> frozenset[str]:
    return _gen_prompt_analysis(ast).aliases

@dataclass(frozen=True, slots=True)
class _AliasAnalysis:
    aliases: frozenset[str]
    complete: bool
    steps: int

def _gen_prompt_analysis(ast: nodes.Template, max_steps: int | None=None) -> _AliasAnalysis:
    dependents: dict[str, set[str]] = {}
    ready: deque[str] = deque()
    enqueued: set[str] = set()
    aliases: set[str] = set()
    steps = 0
    limit = pchat_flow.MAX_STEPS if max_steps is None else max_steps

    def charge() -> bool:
        nonlocal steps
        if steps >= limit:
            return False
        steps += 1
        return True
    stack: list[nodes.Node] = [ast]
    while stack:
        if not charge():
            return _AliasAnalysis(frozenset(aliases), False, steps)
        node = stack.pop()
        if isinstance(node, nodes.Assign) and isinstance(getattr(node, 'target', None), nodes.Name):
            target = getattr(node.target, 'name', None)
            if not isinstance(target, str) or not isinstance(getattr(node, 'node', None), nodes.Node):
                return _AliasAnalysis(frozenset(aliases), False, steps)
            values = [node.node]
            while values:
                if not charge():
                    return _AliasAnalysis(frozenset(aliases), False, steps)
                value = values.pop()
                if isinstance(value, nodes.Name):
                    if not isinstance(getattr(value, 'name', None), str):
                        return _AliasAnalysis(frozenset(aliases), False, steps)
                    if value.name not in dependents:
                        if not charge():
                            return _AliasAnalysis(frozenset(aliases), False, steps)
                        dependents[value.name] = set()
                    if target not in dependents[value.name]:
                        if not charge():
                            return _AliasAnalysis(frozenset(aliases), False, steps)
                        dependents[value.name].add(target)
                    if _GEN_PROMPT_HINT in value.name.lower() and target not in enqueued:
                        if not charge():
                            return _AliasAnalysis(frozenset(aliases), False, steps)
                        enqueued.add(target)
                        ready.append(target)
                else:
                    for child in value.iter_child_nodes():
                        if not charge():
                            return _AliasAnalysis(frozenset(aliases), False, steps)
                        values.append(child)
        for child in node.iter_child_nodes():
            if not charge():
                return _AliasAnalysis(frozenset(aliases), False, steps)
            stack.append(child)
    while ready:
        if not charge():
            return _AliasAnalysis(frozenset(aliases), False, steps)
        source = ready.popleft()
        aliases.add(source)
        for target in dependents.get(source, ()):
            if not charge():
                return _AliasAnalysis(frozenset(aliases), False, steps)
            if target not in enqueued:
                if not charge():
                    return _AliasAnalysis(frozenset(aliases), False, steps)
                enqueued.add(target)
                ready.append(target)
    return _AliasAnalysis(frozenset(aliases), True, steps)
_EOS_VAR_HINTS = ('eos', 'eot')
_BOS_VAR_HINT = 'bos'

class _BosCount:
    iterates = False
    exact = False

    def __init__(self, bos: str, model: Model) -> None:
        self.budget = pchat_flow.MAX_STEPS
        if model.work_left is not None:
            self.budget = min(model.work_left, pchat_flow.MAX_STEPS)
        self.bos = bos
        self.model = model
        self._bodies: dict[int, int] = {}

    def literal(self, count: int, found: Sequence[Occurrence]) -> int:
        return count + sum((1 for occurrence in found if occurrence.pattern == self.bos))

    def emitted(self, path: FlowPath[int], emission: _Emission, order: int, flags: int) -> int:
        return path.state

    def value(self, path: FlowPath[int], emission: _Emission) -> int:
        node = emission.node
        hinted = isinstance(node, nodes.Name) and _BOS_VAR_HINT in node.name.lower() and (not emission.escaped)
        return path.state + int(hinted)

    def branch(self, guard: bool, entry: Sequence[FlowPath[int]], arms: Sequence[Sequence[FlowPath[int]]]) -> list[FlowPath[int]]:
        return [path for arm in arms for path in arm]

    def settle(self, paths: list[FlowPath[int]]) -> list[FlowPath[int]]:
        if self.model.semantic:
            heaviest_paths: dict[tuple[object, ...], FlowPath[int]] = {}
            for path in paths:
                key = (path.carry, path.frames, path.facts, path.autoescape, path.stopped)
                previous = heaviest_paths.get(key)
                if previous is None or previous.state < path.state:
                    heaviest_paths[key] = path
            return list(heaviest_paths.values())
        heaviest: dict[pchat_flow.Carry, int] = {}
        for path in paths:
            heaviest[path.carry] = max(heaviest.get(path.carry, 0), path.state)
        return [FlowPath(carry, count) for carry, count in heaviest.items()]

    def statement(self, node: nodes.Node, paths: list[FlowPath[int]]) -> list[FlowPath[int]]:
        extra = 0 if self.model.semantic else self._body(node)
        if not extra:
            return paths
        return [dataclasses.replace(path, state=path.state + extra) for path in paths]

    def container(self, node: nodes.Node, paths: list[FlowPath[int]]) -> list[FlowPath[int]]:
        return paths

    def loop_pass(self, entry: Sequence[FlowPath[int]], exits: Sequence[FlowPath[int]]) -> bool:
        return True

    def later_pass_failed(self, entry: Sequence[FlowPath[int]]) -> None:
        pass

    def overflow(self) -> None:
        pass

    def _body(self, node: nodes.Node) -> int:
        if id(node) not in self._bodies:
            total = 0
            for body in pchat_flow.statement_lists(node):
                paths = Flow(self.model, self).run(body, [FlowPath(pchat_flow.EMPTY, 0)])
                total += max((path.state for path in paths or []), default=0)
            self._bodies[id(node)] = total
        return self._bodies[id(node)]

def _bos_emissions(ast: nodes.Template, bos: str, model: Model) -> int:
    paths = Flow(model, _BosCount(bos, model)).run(ast.body, [FlowPath(pchat_flow.EMPTY, 0)])
    return max((path.state for path in paths or []), default=0)

def _emits_eos_variable(ast: nodes.Template) -> bool:
    return any((hint in name.name.lower() for name in ast.find_all(nodes.Name) for hint in _EOS_VAR_HINTS))
_GEN_PROMPT_HINT = 'generation_prompt'
_BalanceResult = tuple[int, str | None] | None

def _texts(emissions: Iterator[_Emission], bindings: dict[str, list[list[_Emission]]] | None=None) -> Iterator[str]:
    for emission in emissions:
        if emission.text is not None:
            yield emission.text
        elif bindings is not None:
            for bound in _expand([emission], bindings):
                if bound.text is not None:
                    yield bound.text

def _emitted_literals(node: nodes.Node, bindings: dict[str, list[list[_Emission]]] | None=None) -> Iterator[str]:
    if isinstance(node, nodes.Output):
        for child in node.nodes:
            yield from _texts(_emissions(child), bindings)
        return
    if isinstance(node, nodes.Expr):
        yield from _texts(_emissions(node), bindings)
        return
    if isinstance(node, nodes.AssignBlock):
        return
    for statement in node.iter_child_nodes():
        if isinstance(statement, nodes.Stmt):
            yield from _emitted_literals(statement, bindings)

def _region_text(node: nodes.Node) -> str:
    return ''.join(_emitted_literals(node))

def _open_count(text: str, pack: ChatPack) -> int:
    return sum((text.count(marker) for marker in pack.open_markers))

def _close_count(text: str, pack: ChatPack) -> int:
    return text.count(pack.eot_marker)

def _positions(text: str, marker: str) -> list[int]:
    positions: list[int] = []
    start = text.find(marker)
    while start != -1:
        positions.append(start)
        start = text.find(marker, start + 1)
    return positions

def _tests_gen_prompt(tests: list[nodes.Node], aliases: frozenset[str]=frozenset()) -> bool:
    for test in tests:
        candidates = list(test.find_all(nodes.Name))
        if isinstance(test, nodes.Name):
            candidates.append(test)
        for name in candidates:
            if _GEN_PROMPT_HINT in name.name.lower() or name.name in aliases:
                return True
    return False

def _is_gen_prompt_guard(if_node: nodes.If, aliases: frozenset[str]=frozenset()) -> bool:
    return _tests_gen_prompt([if_node.test, *(elif_node.test for elif_node in if_node.elif_)], aliases)

def _branch_bodies(if_node: nodes.If) -> list[list[nodes.Node]]:
    bodies = [if_node.body, *(elif_node.body for elif_node in if_node.elif_)]
    if if_node.else_:
        bodies.append(if_node.else_)
    return bodies

def _deferred_marker_names(ast: nodes.Template, pack: ChatPack) -> frozenset[str]:
    bindings = _bindings(ast)
    rendered = {emission.node.name for run in _emitted_runs(ast) for emission in run if emission.text is None and isinstance(emission.node, nodes.Name)}
    bound: dict[str, list[str]] = {name: [emission.text for alternative in alternatives for emission in alternative if emission.text is not None] for name, alternatives in bindings.items()}
    for block in ast.find_all(nodes.AssignBlock):
        if isinstance(block.target, nodes.Name):
            bound.setdefault(block.target.name, []).extend((text for statement in block.body for text in _emitted_literals(statement)))
    deferred = set()
    for name, texts in bound.items():
        text = ''.join(texts)
        if name in rendered and (_open_count(text, pack) or _close_count(text, pack)):
            deferred.add(name)
    return frozenset(deferred)

def _binds_deferred_marker(node: nodes.Node, deferred: frozenset[str]) -> bool:
    target = getattr(node, 'target', None)
    return isinstance(target, nodes.Name) and target.name in deferred
_CROSS_TEMPLATE = (nodes.Include, nodes.Import, nodes.FromImport, nodes.Extends)

@dataclass(frozen=True, slots=True)
class _Reading:
    file: str
    roots: tuple[Path, ...]
    depth: int
    seen: frozenset[str]
    line: int | None
    names: Mapping[str, str]
    scopes: Iterator[int]
    isolated: str | None = None
    origin: _OriginWork | None = None

class _OriginExhausted(Exception):
    pass

@dataclass(slots=True)
class _OriginWork:
    used: int
    limit: int
    accounted: bool = False
    complete: bool = True

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > self.limit - self.used:
            raise _OriginExhausted
        self.used += amount

def _scoped(name: str, reading: _Reading) -> str:
    if name in reading.names:
        return reading.names[name]
    if reading.isolated is not None:
        return f"{reading.isolated}:{name.encode('utf-8').hex()}"
    return name

def _read_includes(ctx: TemplateContext, config: LintConfig) -> TemplateContext:
    depth = 0 if config.cross_template == 'off' else config.cross_template_depth
    if depth <= 0 or next(ctx.ast.find_all(nodes.Include), None) is None:
        return ctx
    roots = tuple((Path(root) for root in config.template_search_path))
    old_work, old_complete, accounted = _origin_state(ctx.ast)
    if old_work is None:
        return ctx
    initial = 4 + len(vars(ctx.ast)) + 2
    if pchat_flow.MAX_STEPS - old_work < initial:
        return ctx
    work = _OriginWork(old_work + initial, pchat_flow.MAX_STEPS, accounted=accounted, complete=old_complete)
    fallback = nodes.Template(lineno=ctx.ast.lineno, environment=ctx.ast.environment)
    vars(fallback).update(vars(ctx.ast))
    setattr(fallback, pchat_flow.ORIGIN_WORK, work.used)
    setattr(fallback, pchat_flow.ORIGIN_COMPLETE, False)
    reading = _Reading(ctx.file, roots, depth, frozenset(), None, {}, itertools.count(), origin=work)
    try:
        expanded = cast(nodes.Template, _substituted(ctx.ast, reading))
        work.charge(2)
        setattr(expanded, pchat_flow.ORIGIN_WORK, work.used)
        setattr(expanded, pchat_flow.ORIGIN_COMPLETE, work.complete)
    except _OriginExhausted:
        setattr(fallback, pchat_flow.ORIGIN_WORK, work.used)
        expanded = fallback
    return dataclasses.replace(ctx, ast=expanded)

def _substituted(node: nodes.Node, reading: _Reading) -> nodes.Node:
    line = node.lineno if reading.line is None else reading.line
    if reading.origin is not None:
        reading.origin.charge(len(vars(node)) + 2)
        if getattr(node, pchat_flow.SYNTHETIC_ROLE, False) and (not reading.origin.accounted):
            reading.origin.complete = False
    clone = type(node)(lineno=line, environment=node.environment)
    for name, value in vars(node).items():
        if name in node.fields:
            setattr(clone, name, _substituted_value(value, reading))
        elif name != 'lineno':
            setattr(clone, name, value)
    if isinstance(clone, nodes.Name | nodes.NSRef):
        clone.name = _scoped(clone.name, reading)
    return clone

def _substituted_value(value: object, reading: _Reading) -> object:
    if isinstance(value, nodes.Node):
        return _substituted(value, reading)
    if not isinstance(value, list):
        return value
    if reading.origin is not None:
        reading.origin.charge(len(value) + 1)
    out: list[object] = []
    for item in value:
        if isinstance(item, nodes.Include):
            out.extend(_included(item, reading))
        elif isinstance(item, nodes.Node):
            out.append(_substituted(item, reading))
        else:
            out.append(item)
    return out

def _included(node: nodes.Include, reading: _Reading) -> list[object]:
    target = const_target(node)
    if target is None or reading.depth <= 0:
        return [_substituted(node, reading)]
    path = resolve(reading.file, target, reading.roots)
    if path is None or path.as_posix() in reading.seen:
        return [_substituted(node, reading)]
    unit = parse_unit(reading.file, target, reading.roots)
    if unit is None:
        return [_substituted(node, reading)]
    line = node.lineno if reading.line is None else reading.line
    names, isolated, entry = _unit_scope(unit, node.with_context, reading, line)
    inner = _Reading(file=unit.file, roots=reading.roots, depth=reading.depth - 1, seen=reading.seen | {unit.file}, line=line, names=names, scopes=reading.scopes, isolated=isolated, origin=reading.origin)
    body = _substituted_value(unit.ast.body, inner)
    return [*entry, *cast(list[object], body)]

def _unit_scope(unit: TemplateContext, with_context: bool, reading: _Reading, line: int) -> tuple[dict[str, str], str | None, list[nodes.Node]]:
    tag = f'#u{next(reading.scopes)}'
    if not with_context:
        stored = {name.name for name in unit.ast.find_all(nodes.Name) if name.ctx in ('store', 'param')} | {ref.name for ref in unit.ast.find_all(nodes.NSRef)}
        return ({name: f'{name}{tag}' for name in sorted(stored)}, tag, [])
    assigned = {node.target.name for node in unit.ast.find_all((nodes.Assign, nodes.AssignBlock)) if isinstance(node, nodes.Assign | nodes.AssignBlock) and isinstance(node.target, nodes.Name)}
    local = {name: f'{name}{tag}' for name in sorted(assigned)}
    loaded = {name.name for name in unit.ast.find_all(nodes.Name) if name.ctx == 'load'}
    entry: list[nodes.Node] = []
    for name in sorted(assigned & loaded):
        if reading.origin is None:
            raise _OriginExhausted
        reading.origin.charge(2)
        source = nodes.Name(_scoped(name, reading), 'load', lineno=line)
        setattr(source, pchat_flow.SYNTHETIC_ROLE, True)
        entry.append(nodes.Assign(nodes.Name(local[name], 'store', lineno=line), source, lineno=line))
    return ({**reading.names, **local}, reading.isolated, entry)

def _holds_unread_unit(ast: nodes.Template) -> bool:
    return next(ast.find_all(_CROSS_TEMPLATE), None) is not None
_ITERATED_OPEN = ''

class _Walk:
    iterates = True
    exact = True

    def __init__(self, pack: ChatPack, deferred: frozenset[str], model: Model) -> None:
        self.budget = pchat_flow.MAX_STEPS
        self.pack = pack
        self.deferred = deferred
        self.model = model
        self.violator: str | None = None
        self._marked: dict[int, bool] = {}
        self._step: list[str | None] = []
        self.undecided = False
        self.stopped: int | None = None

    def literal(self, depth: int, found: Sequence[Occurrence]) -> int | None:
        violator: str | None = None
        iterated = False
        for occurrence in found:
            if occurrence.pattern == self.pack.eot_marker:
                opens = False
            elif occurrence.pattern in self.pack.open_markers:
                opens = True
            else:
                continue
            if occurrence.flags & (BOUND | CONTAINED):
                return None
            if opens:
                depth += 1
                if depth >= 2:
                    if occurrence.flags & ITERATED:
                        iterated = True
                    elif violator is None:
                        violator = occurrence.pattern
            else:
                depth = max(0, depth - 1)
        self._step.append(violator or (_ITERATED_OPEN if iterated else None))
        return depth

    def value(self, path: FlowPath[int], emission: _Emission) -> int:
        return path.state

    def emitted(self, path: FlowPath[int], emission: _Emission, order: int, flags: int) -> int:
        return path.state

    def branch(self, guard: bool, entry: Sequence[FlowPath[int]], arms: Sequence[Sequence[FlowPath[int]]]) -> list[FlowPath[int]] | None:
        ends = {arm[0].state for arm in arms if arm}
        if len(ends) <= 1:
            return [path for arm in arms for path in arm]
        if guard and max(ends) > entry[0].state:
            low = min(ends)
            return [path for arm in arms for path in arm if path.state == low]
        return None

    def settle(self, paths: list[FlowPath[int]]) -> list[FlowPath[int]] | None:
        step, self._step = (self._step, [])
        if len({path.state for path in paths}) > 1:
            return None
        real = [finding for finding in step if finding not in (None, _ITERATED_OPEN)]
        if real:
            if None in step:
                return None
            if self.violator is None:
                self.violator = real[0]
        elif _ITERATED_OPEN in step:
            self.undecided = True
        return paths

    def statement(self, node: nodes.Node, paths: list[FlowPath[int]]) -> list[FlowPath[int]] | None:
        if isinstance(node, nodes.Assign | nodes.AssignBlock):
            return None if _binds_deferred_marker(node, self.deferred) else paths
        if isinstance(node, _CROSS_TEMPLATE):
            return None
        if isinstance(node, nodes.ExprStmt | nodes.EvalContextModifier):
            return paths
        return None if self._carries_marker(node) else paths

    def container(self, node: nodes.Node, paths: list[FlowPath[int]]) -> list[FlowPath[int]] | None:
        return None if self._joins_marker(node) else paths

    def loop_pass(self, entry: Sequence[FlowPath[int]], exits: Sequence[FlowPath[int]]) -> bool:
        return all((path.state == entry[0].state for path in exits))

    def later_pass_failed(self, entry: Sequence[FlowPath[int]]) -> None:
        if self.budget >= 0 and self.stopped is None:
            self.stopped = entry[0].state

    def overflow(self) -> None:
        pass

    def _joins_marker(self, node: nodes.Node) -> bool:
        text = _region_text(node)
        return bool(_open_count(text, self.pack) or _close_count(text, self.pack))

    def _carries_marker(self, node: nodes.Node) -> bool:
        if id(node) not in self._marked:
            turn = {*self.pack.open_markers, self.pack.eot_marker}
            inside = Presence(self.model, ())
            inside.budget = self.budget
            for body in pchat_flow.statement_lists(node):
                inside.read(body)
            self.budget = inside.budget
            self._marked[id(node)] = inside.overflowed or self._joins_marker(node) or any((occurrence.pattern in turn for occurrence in inside.found.values()))
        return self._marked[id(node)]

@dataclass(frozen=True, slots=True)
class _Depth:
    depth: int = 0
    violator: str | None = None
    speculative: bool = False
    uncertain_tail: bool = False
    pending: str | None = None

class _SemanticWalk:
    iterates = True
    exact = True

    def __init__(self, pack: ChatPack, model: Model) -> None:
        self.pack = pack
        self.budget = min(model.work_left, pchat_flow.MAX_STEPS) if model.work_left is not None else pchat_flow.MAX_STEPS
        self.resource_refused = False

    def literal(self, state: _Depth, found: Sequence[Occurrence]) -> _Depth:
        depth, violator, speculative = (state.depth, state.violator, state.speculative)
        pending = state.pending
        for occurrence in found:
            if occurrence.pattern in self.pack.open_markers:
                depth += 1
                if depth >= 2:
                    if occurrence.flags & ITERATED:
                        speculative = True
                    elif violator is None:
                        if state.uncertain_tail:
                            pending = pending or occurrence.pattern
                        else:
                            violator = occurrence.pattern
            elif occurrence.pattern == self.pack.eot_marker:
                depth = max(0, depth - 1)
        return _Depth(depth, violator, speculative, state.uncertain_tail, pending)

    def loop_exit(self, paths: list[FlowPath[_Depth]]) -> list[FlowPath[_Depth]]:
        return [dataclasses.replace(path, state=dataclasses.replace(path.state, uncertain_tail=True)) for path in paths]

    def completed(self, paths: list[FlowPath[_Depth]]) -> list[FlowPath[_Depth]]:
        if not any((path.state.pending for path in paths)):
            return paths
        out = []
        for path in paths:
            if not path.state.pending:
                out.append(path)
                continue
            justified = True
            for other in paths:
                cost = 20 * (len(path.facts) + 1) * (len(other.facts) + 1)
                if self.budget < cost:
                    self.budget = -1
                    self.overflow()
                    return paths
                self.budget -= cost
                facts = path.facts
                compatible = True
                for key, wanted in other.facts:
                    if (key, not wanted) in facts or not pchat_flow._compatible_facts(facts, key, wanted):
                        compatible = False
                        break
                    facts = facts | {(key, wanted)}
                if compatible and (not (other.state.violator or other.state.pending or other.state.speculative)):
                    justified = False
                    break
            out.append(dataclasses.replace(path, state=dataclasses.replace(path.state, violator=path.state.violator or (path.state.pending if justified else None), pending=None), stopped=path.stopped or (None if justified else 'iteration-dependent-depth')))
        return out

    def value(self, path: FlowPath[_Depth], emission: _Emission) -> _Depth:
        if isinstance(emission.node, nodes.Name) and (not emission.escaped) and any((hint in emission.node.name.lower() for hint in _EOS_VAR_HINTS)):
            return dataclasses.replace(path.state, depth=max(0, path.state.depth - 1))
        return path.state

    def emitted(self, path: FlowPath[_Depth], emission: _Emission, order: int, flags: int) -> _Depth:
        return path.state

    def branch(self, guard: bool, entry: Sequence[FlowPath[_Depth]], arms: Sequence[Sequence[FlowPath[_Depth]]]) -> list[FlowPath[_Depth]]:
        paths = [path for arm in arms for path in arm]
        if guard and paths and entry:
            low = min(entry[0].state.depth, min((path.state.depth for path in paths)))
            if max((path.state.depth for path in paths)) > entry[0].state.depth:
                paths = [dataclasses.replace(path, state=dataclasses.replace(path.state, depth=low)) for path in paths]
        return paths

    def settle(self, paths: list[FlowPath[_Depth]]) -> list[FlowPath[_Depth]]:
        return paths

    def statement(self, node: nodes.Node, paths: list[FlowPath[_Depth]]) -> list[FlowPath[_Depth]]:
        return paths

    def container(self, node: nodes.Node, paths: list[FlowPath[_Depth]]) -> list[FlowPath[_Depth]]:
        return paths

    def loop_pass(self, entry: Sequence[FlowPath[_Depth]], exits: Sequence[FlowPath[_Depth]]) -> bool:
        return all((path.state.depth == entry[0].state.depth for path in exits))

    def later_pass_failed(self, entry: Sequence[FlowPath[_Depth]]) -> None:
        return None

    def overflow(self) -> None:
        self.resource_refused = True

def _walk(ast: nodes.Template, pack: ChatPack, deferred: frozenset[str], model: Model | None=None) -> _BalanceResult:
    model = model or _model(ast)
    if not model.complete:
        return None
    if model.semantic:
        semantic = _SemanticWalk(pack, model)
        reached = Flow(model, semantic).run(ast.body, [FlowPath(pchat_flow.EMPTY, _Depth())])
        if reached is None or semantic.budget < 0 or semantic.resource_refused:
            return None
        for path in reached:
            if path.state.violator:
                return (path.state.depth, path.state.violator)
        if any((path.stopped or path.state.speculative for path in reached)):
            return None
        depths = {path.state.depth for path in reached}
        return (next(iter(depths)), None) if len(depths) == 1 else None
    walk = _Walk(pack, deferred, model)
    paths = Flow(model, walk).run(ast.body, [FlowPath(pchat_flow.EMPTY, 0)])
    if not paths:
        if walk.stopped is None or walk.violator is None:
            return None
        return (walk.stopped, walk.violator)
    if walk.violator is None and walk.undecided:
        return None
    return (paths[0].state, walk.violator)

class PchatRule:
    id: RuleId = RuleId.PCHAT

    def check(self, ctx: TemplateContext, config: LintConfig) -> list[Diagnostic]:
        ctx = _read_includes(ctx, config)
        model = _model(ctx.ast)
        presence = _presence(ctx.ast, model)
        found = presence.occurrences()
        texts = _marker_texts(found)
        resolved = _resolve_pack(texts, config.chat_format_packs)
        if resolved is None:
            return []
        pack, matches = resolved
        diagnostics: list[Diagnostic] = []
        if len(matches) > 1:
            diagnostics.append(self._ambiguous(ctx, pack, matches))
        if not _holds_unread_unit(ctx.ast):
            settled = not presence.overflowed
            eot_present = _chunks_contain(texts, pack.eot_marker) or presence.eos_present
            if not eot_present:
                if settled:
                    diagnostics.append(self._missing_eot(ctx, found, pack))
            else:
                diagnostics.extend(self._unbalanced(ctx, found, pack, model))
            if settled:
                diagnostics.extend(self._missing_generation_prompt(ctx, found, pack, model, presence))
                diagnostics.extend(self._role_literal(ctx.file, _first_line(found, pack.open_markers), pack, presence.role_evidence(pack.role_prefix)))
        diagnostics.extend(self._unknown_role(ctx.file, _first_line(found, pack.open_markers), pack, presence.roles))
        diagnostics.extend(self._bos_misuse(ctx, found, pack, model))
        return diagnostics

    def _missing_eot(self, ctx: TemplateContext, found: list[Occurrence], pack: ChatPack) -> Diagnostic:
        message, extra = render(RuleId.PCHAT, 'missing-eot', pack=pack.name, eot_token=pack.eot_marker)
        return Diagnostic(rule=RuleId.PCHAT, sub_code='missing-eot', severity=severity_for(RuleId.PCHAT, 'missing-eot'), message=message, file=ctx.file, line=_first_line(found, pack.open_markers), m2_anchor=anchor_for(RuleId.PCHAT, 'missing-eot'), extra=extra)

    def _unbalanced(self, ctx: TemplateContext, found: list[Occurrence], pack: ChatPack, model: Model) -> list[Diagnostic]:
        result = _walk(ctx.ast, pack, _deferred_marker_names(ctx.ast, pack), model)
        if result is None or result[1] is None:
            return []
        message, extra = render(RuleId.PCHAT, 'unbalanced-markers', pack=pack.name, open_marker=result[1], close_marker=pack.eot_marker)
        return [Diagnostic(rule=RuleId.PCHAT, sub_code='unbalanced-markers', severity=severity_for(RuleId.PCHAT, 'unbalanced-markers'), message=message, file=ctx.file, line=_first_line(found, pack.open_markers), m2_anchor=anchor_for(RuleId.PCHAT, 'unbalanced-markers'), extra=extra)]

    def _ambiguous(self, ctx: TemplateContext, pack: ChatPack, matches: list[ChatPack]) -> Diagnostic:
        names = ', '.join(sorted((match.name for match in matches)))
        message, extra = render(RuleId.PCHAT, 'ambiguous-format', names=names, pack=pack.name)
        return Diagnostic(rule=RuleId.PCHAT, sub_code='ambiguous-format', severity=severity_for(RuleId.PCHAT, 'ambiguous-format'), message=message, file=ctx.file, line=1, m2_anchor=anchor_for(RuleId.PCHAT, 'ambiguous-format'), extra=extra)

    def _missing_generation_prompt(self, ctx: TemplateContext, found: list[Occurrence], pack: ChatPack, model: Model, presence: Presence) -> list[Diagnostic]:
        if _has_gen_prompt_guard(ctx.ast, pack, model, presence):
            return []
        message, _asserted = render(RuleId.PCHAT, 'missing-generation-prompt')
        return [Diagnostic(rule=RuleId.PCHAT, sub_code='missing-generation-prompt', severity=severity_for(RuleId.PCHAT, 'missing-generation-prompt'), message=message, file=ctx.file, line=_first_line(found, pack.open_markers), m2_anchor=anchor_for(RuleId.PCHAT, 'missing-generation-prompt'), extra={'pack': pack.name})]

    def _role_literal(self, file: str, line: int, pack: ChatPack, evidence: RoleEvidence) -> list[Diagnostic]:
        if _has_role_access(evidence) or not evidence.available:
            return []
        message, _asserted = render(RuleId.PCHAT, 'role-literal')
        return [Diagnostic(rule=RuleId.PCHAT, sub_code='role-literal', severity=severity_for(RuleId.PCHAT, 'role-literal'), message=message, file=file, line=line, m2_anchor=anchor_for(RuleId.PCHAT, 'role-literal'), extra={'pack': pack.name})]

    def _unknown_role(self, file: str, line: int, pack: ChatPack, evidence: tuple[EmittedRole, ...]) -> list[Diagnostic]:
        if pack.role_prefix is None or not pack.allowed_roles:
            return []
        diagnostics: list[Diagnostic] = []
        for observed in evidence:
            if observed.prefix != pack.role_prefix:
                continue
            role = observed.role
            if not role.isalpha() or role in pack.allowed_roles:
                continue
            message, extra = render(RuleId.PCHAT, 'unknown-role', role=role, pack=pack.name)
            diagnostics.append(Diagnostic(rule=RuleId.PCHAT, sub_code='unknown-role', severity=severity_for(RuleId.PCHAT, 'unknown-role'), message=message, file=file, line=line, m2_anchor=anchor_for(RuleId.PCHAT, 'unknown-role'), extra=extra))
        return diagnostics

    def _bos_misuse(self, ctx: TemplateContext, found: list[Occurrence], pack: ChatPack, model: Model) -> list[Diagnostic]:
        bos = pack.bos_marker
        if bos is None or _bos_emissions(ctx.ast, bos, model) <= 1:
            return []
        message, extra = render(RuleId.PCHAT, 'bos-misuse', pack=pack.name, bos_token=bos)
        return [Diagnostic(rule=RuleId.PCHAT, sub_code='bos-misuse', severity=severity_for(RuleId.PCHAT, 'bos-misuse'), message=message, file=ctx.file, line=_first_line(found, (bos,)), m2_anchor=anchor_for(RuleId.PCHAT, 'bos-misuse'), extra=extra)]
