from __future__ import annotations
from dataclasses import dataclass
from enum import StrEnum

class Severity(StrEnum):
    ERROR = 'error'
    WARNING = 'warning'
    INFO = 'info'

class RuleId(StrEnum):
    PVAR = 'PVAR'
    PCHAT = 'PCHAT'
    PINJ = 'PINJ'
    PTOK = 'PTOK'
    PFMT = 'PFMT'

class PinjCheckState(StrEnum):
    ENABLED = 'enabled'
    NO_SOURCES = 'no-sources'
    DISABLED = 'disabled'
    NOT_SELECTED = 'not-selected'
    PARSE_ERROR = 'parse-error'
    UNKNOWN = 'unknown'
_SEVERITY_RANK: dict[Severity, int] = {Severity.ERROR: 3, Severity.WARNING: 2, Severity.INFO: 1}

def severity_rank(severity: Severity) -> int:
    return _SEVERITY_RANK[severity]

@dataclass(frozen=True, slots=True)
class Edit:
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    replacement: str

@dataclass(frozen=True, slots=True)
class Diagnostic:
    rule: RuleId
    sub_code: str
    severity: Severity
    message: str
    file: str
    line: int
    col: int = 1
    m2_anchor: str = ''
    end_line: int | None = None
    end_col: int | None = None
    scope_ref: str | None = None
    fixable: bool = False
    edits: tuple[Edit, ...] = ()
    extra: dict[str, object] | None = None

    @property
    def code(self) -> str:
        return f'{self.rule.value}/{self.sub_code}'

    @property
    def sort_key(self) -> tuple[str, int, int, str, str, str]:
        return (self.file, self.line, self.col, self.rule.value, self.sub_code, self.message)
