from __future__ import annotations
import re
from dataclasses import dataclass, field
import jinja2
from j2prompt_lint.core.model import RuleId
PREFIX = 'j2pl:'
_CALL = re.compile('^([A-Za-z_][\\w-]*)\\s*\\((.*)\\)$', re.DOTALL)
_ASSIGN = re.compile('^([A-Za-z_][\\w-]*)\\s*=\\s*(.+)$', re.DOTALL)
_LIST_ARG = re.compile('([A-Za-z_]\\w*)\\s*=\\s*\\[([^\\]]*)\\]')

@dataclass(frozen=True, slots=True)
class UnknownDirective:
    line: int
    text: str

@dataclass(frozen=True, slots=True)
class Directives:
    required: frozenset[str] | None = None
    optional: frozenset[str] | None = None
    trusted: frozenset[str] = frozenset()
    untrusted: frozenset[str] = frozenset()
    disabled: frozenset[RuleId] = frozenset()
    unknown: tuple[UnknownDirective, ...] = ()
NO_DIRECTIVES = Directives()

@dataclass
class _Accumulator:
    required: set[str] | None = None
    optional: set[str] | None = None
    trusted: set[str] = field(default_factory=set)
    untrusted: set[str] = field(default_factory=set)
    disabled: set[RuleId] = field(default_factory=set)
    unknown: list[UnknownDirective] = field(default_factory=list)

    def freeze(self) -> Directives:
        return Directives(required=None if self.required is None else frozenset(self.required), optional=None if self.optional is None else frozenset(self.optional), trusted=frozenset(self.trusted), untrusted=frozenset(self.untrusted), disabled=frozenset(self.disabled), unknown=tuple(self.unknown))

def _names(body: str) -> list[str]:
    return [name.strip() for name in body.split(',') if name.strip()]

def _apply_vars(acc: _Accumulator, body: str) -> bool:
    staged: dict[str, set[str]] = {}
    for match in _LIST_ARG.finditer(body):
        key, values = (match.group(1), _names(match.group(2)))
        if key not in ('required', 'optional'):
            return False
        staged.setdefault(key, set()).update(values)
    if not staged:
        return False
    if 'required' in staged:
        acc.required = (acc.required or set()) | staged['required']
    if 'optional' in staged:
        acc.optional = (acc.optional or set()) | staged['optional']
    return True

def _apply(acc: _Accumulator, line: int, text: str) -> None:
    call = _CALL.match(text)
    if call is not None:
        head, body = (call.group(1), call.group(2))
        if head == 'trusted':
            acc.trusted.update(_names(body))
            return
        if head == 'untrusted':
            acc.untrusted.update(_names(body))
            return
        if head == 'vars' and _apply_vars(acc, body):
            return
        acc.unknown.append(UnknownDirective(line, text))
        return
    assign = _ASSIGN.match(text)
    if assign is not None and assign.group(1) == 'disable':
        names = _names(assign.group(2))
        known = {rule.value for rule in RuleId}
        if names and all((name in known for name in names)):
            acc.disabled.update((RuleId(name) for name in names))
            return
    acc.unknown.append(UnknownDirective(line, text))

def parse_directives(source: str) -> Directives:
    if PREFIX not in source:
        return NO_DIRECTIVES
    accumulator = _Accumulator()
    try:
        tokens = list(jinja2.Environment().lex(source))
    except jinja2.TemplateSyntaxError:
        return accumulator.freeze()
    for lineno, kind, value in tokens:
        if kind != 'comment':
            continue
        text = value.strip()
        if not text.startswith(PREFIX):
            continue
        _apply(accumulator, lineno, text[len(PREFIX):].strip())
    return accumulator.freeze()
