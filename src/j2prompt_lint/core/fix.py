from __future__ import annotations
import itertools
from collections.abc import Iterable
from j2prompt_lint.core.model import Diagnostic, Edit

class OverlappingEditsError(ValueError):
    pass

def _line_starts(source: str) -> list[int]:
    starts = [0]
    for index, char in enumerate(source):
        if char == '\n':
            starts.append(index + 1)
    return starts

def _spans(source: str, edits: Iterable[Edit]) -> list[tuple[int, int, str]]:
    starts = _line_starts(source)

    def offset(line: int, col: int) -> int:
        return starts[line - 1] + (col - 1)
    unique = {(offset(e.start_line, e.start_col), offset(e.end_line, e.end_col), e.replacement) for e in edits}
    return sorted(unique)

def apply_edits(source: str, edits: Iterable[Edit]) -> str:
    spans = _spans(source, edits)
    for (a_start, a_end, a_text), (b_start, b_end, b_text) in itertools.pairwise(spans):
        if a_end > b_start:
            raise OverlappingEditsError(f"overlapping auto-fix edits: [{a_start}, {a_end}) -> {a_text!r} and [{b_start}, {b_end}) -> {b_text!r}; this is a defect in the linter's rules, not in the template")
    result = source
    for start, end, replacement in reversed(spans):
        result = result[:start] + replacement + result[end:]
    return result

def apply_fixes(source: str, diagnostics: Iterable[Diagnostic]) -> str:
    edits = [edit for diag in diagnostics if diag.fixable for edit in diag.edits]
    return apply_edits(source, edits)
