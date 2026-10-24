from __future__ import annotations
import bisect
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
import jinja2
from j2prompt_lint.core.config import PFMT_BLOCK_STYLES, LintConfig
from j2prompt_lint.core.context import TemplateContext
from j2prompt_lint.core.model import Diagnostic, Edit, RuleId
from j2prompt_lint.core.subcodes import anchor_for, render, severity_for
_TAB_WIDTH = 4
_TRAILING_WHITESPACE = ''.join((chr(code) for code in (9, 32, 160, 5760, *range(8192, 8203), 8239, 8287, 12288)))
_MIXED_INDENTATION_MSG, _ = render(RuleId.PFMT, 'mixed-indentation')
_DELIMITER_SPACING_MSG, _ = render(RuleId.PFMT, 'delimiter-spacing')
_JINJA_BLOCK_WHITESPACE_MSG = {style: render(RuleId.PFMT, 'jinja-block-whitespace', style)[0] for style in PFMT_BLOCK_STYLES}
_STYLE_PAD = {'spaced': ' ', 'tight': ''}

class _Pos:

    def __init__(self, source: str) -> None:
        starts = [0]
        for index, char in enumerate(source):
            if char == '\n':
                starts.append(index + 1)
        self._starts = starts

    def at(self, offset: int) -> tuple[int, int]:
        line = bisect.bisect_right(self._starts, offset)
        return (line, offset - self._starts[line - 1] + 1)

    def offset(self, line: int, col: int) -> int:
        return self._starts[line - 1] + (col - 1)

def _terminators(source: str, start: int=0) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    index, length = (start, len(source))
    while index < length:
        char = source[index]
        if char == '\r':
            stop = index + 2 if source[index + 1:index + 2] == '\n' else index + 1
            out.append((index, stop))
            index = stop
        elif char == '\n':
            out.append((index, index + 1))
            index += 1
        else:
            index += 1
    return out

def _trailing_whitespace(file: str, source: str) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    pos = _Pos(source)
    for start, stop, _term_stop in _physical_lines(source):
        content = source[start:stop]
        stripped = content.rstrip(_TRAILING_WHITESPACE)
        if stripped == content:
            continue
        cut = start + len(stripped)
        l1, c1 = pos.at(cut)
        l2, c2 = pos.at(stop)
        message, _asserted = render(RuleId.PFMT, 'trailing-whitespace')
        diagnostics.append(Diagnostic(rule=RuleId.PFMT, sub_code='trailing-whitespace', severity=severity_for(RuleId.PFMT, 'trailing-whitespace'), message=message, file=file, line=l1, col=c1, m2_anchor=anchor_for(RuleId.PFMT, 'trailing-whitespace'), fixable=True, edits=(Edit(l1, c1, l2, c2, ''),)))
    return diagnostics

def _line_ending_styles(source: str) -> list[str]:
    kinds = {source[start:stop] for start, stop in _terminators(source)}
    styles: list[str] = []
    if '\r\n' in kinds:
        styles.append('CRLF')
    if '\n' in kinds:
        styles.append('LF')
    if '\r' in kinds:
        styles.append('CR')
    return styles

def _line_endings(file: str, source: str, target: str, claimed: frozenset[int]=frozenset()) -> list[Diagnostic]:
    target = 'crlf' if target == 'crlf' else 'lf'
    target_nl = _target_newline(target)
    pos = _Pos(source)
    edits: list[Edit] = []
    for start, stop in _terminators(source):
        text = source[start:stop]
        if start in claimed or text == target_nl:
            continue
        l1, c1 = pos.at(start)
        if target_nl == '\n' and text == '\r\n':
            edits.append(Edit(l1, c1, l1, c1 + 1, ''))
        elif target_nl == '\r\n' and text == '\n':
            edits.append(Edit(l1, c1, l1, c1, '\r'))
        else:
            l2, c2 = pos.at(stop)
            edits.append(Edit(l1, c1, l2, c2, target_nl))
    if not edits:
        return []
    display = 'CRLF' if target == 'crlf' else 'LF'
    styles = _line_ending_styles(source)
    if len(styles) > 1:
        message, extra = render(RuleId.PFMT, 'line-endings', 'mixed', styles=', '.join(styles), target=display)
    else:
        found = styles[0] if styles else display
        message, extra = render(RuleId.PFMT, 'line-endings', 'uniform', found=found, target=display)
    return [Diagnostic(rule=RuleId.PFMT, sub_code='line-endings', severity=severity_for(RuleId.PFMT, 'line-endings'), message=message, file=file, line=1, m2_anchor=anchor_for(RuleId.PFMT, 'line-endings'), fixable=True, edits=tuple(edits), extra=extra)]

def _target_newline(target: str) -> str:
    return '\r\n' if target == 'crlf' else '\n'

def _final_newline(file: str, source: str, target: str, pos: _Pos) -> list[Diagnostic]:
    end = len(source)
    while end > 0 and source[end - 1] in ' \t\r\n':
        end -= 1
    if end == 0 and (not _terminators(source)):
        return []
    terms = _terminators(source, end)
    target_nl = _target_newline(target)
    edits: list[Edit] = []
    anchor: int
    if not terms:
        line, col = pos.at(len(source))
        edits.append(Edit(line, col, line, col, target_nl))
        anchor = len(source)
    elif len(terms) >= 2:
        for tstart, tstop in terms[1:]:
            l1, c1 = pos.at(tstart)
            l2, c2 = pos.at(tstop)
            edits.append(Edit(l1, c1, l2, c2, ''))
        anchor = terms[0][1]
    else:
        return []
    aline, acol = pos.at(anchor)
    message, _asserted = render(RuleId.PFMT, 'final-newline')
    return [Diagnostic(rule=RuleId.PFMT, sub_code='final-newline', severity=severity_for(RuleId.PFMT, 'final-newline'), message=message, file=file, line=aline, col=acol, m2_anchor=anchor_for(RuleId.PFMT, 'final-newline'), fixable=True, edits=tuple(edits))]

def _physical_lines(source: str) -> list[tuple[int, int, int]]:
    lines: list[tuple[int, int, int]] = []
    start = 0
    for tstart, tstop in _terminators(source):
        lines.append((start, tstart, tstop))
        start = tstop
    lines.append((start, len(source), len(source)))
    return lines

def _blank_lines(file: str, source: str, max_blank: int, pos: _Pos) -> list[Diagnostic]:
    lines = _physical_lines(source)

    def is_blank(item: tuple[int, int, int]) -> bool:
        start, stop, _term_stop = item
        return source[start:stop].strip(' \t') == ''
    diagnostics: list[Diagnostic] = []
    count = len(lines)
    index = 0
    while index < count:
        if not is_blank(lines[index]):
            index += 1
            continue
        run_end = index
        while run_end < count and is_blank(lines[run_end]):
            run_end += 1
        run = lines[index:run_end]
        if run_end < count and len(run) > max_blank:
            edits: list[Edit] = []
            for _start, stop, term_stop in run[max_blank:]:
                if term_stop == stop:
                    continue
                l1, c1 = pos.at(stop)
                l2, c2 = pos.at(term_stop)
                edits.append(Edit(l1, c1, l2, c2, ''))
            if edits:
                aline, acol = pos.at(run[max_blank][0])
                message, extra = render(RuleId.PFMT, 'blank-lines', max_blank=max_blank)
                diagnostics.append(Diagnostic(rule=RuleId.PFMT, sub_code='blank-lines', severity=severity_for(RuleId.PFMT, 'blank-lines'), message=message, file=file, line=aline, col=acol, m2_anchor=anchor_for(RuleId.PFMT, 'blank-lines'), fixable=True, edits=tuple(edits), extra=extra))
        index = run_end
    return diagnostics

def _expand_leading(indent: str) -> str:
    out: list[str] = []
    col = 0
    for char in indent:
        if char == '\t':
            spaces = _TAB_WIDTH - col % _TAB_WIDTH
            out.append(' ' * spaces)
            col += spaces
        else:
            out.append(' ')
            col += 1
    return ''.join(out)

def _mixed_indentation(file: str, source: str, pos: _Pos) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for start, stop, _term_stop in _physical_lines(source):
        content = source[start:stop]
        stripped = content.lstrip(' \t')
        indent = content[:len(content) - len(stripped)]
        if stripped and '\t' in indent and (' ' in indent):
            l1, c1 = pos.at(start)
            l2, c2 = pos.at(start + len(indent))
            diagnostics.append(Diagnostic(rule=RuleId.PFMT, sub_code='mixed-indentation', severity=severity_for(RuleId.PFMT, 'mixed-indentation'), message=_MIXED_INDENTATION_MSG, file=file, line=l1, col=c1, m2_anchor=anchor_for(RuleId.PFMT, 'mixed-indentation'), fixable=True, edits=(Edit(l1, c1, l2, c2, _expand_leading(indent)),)))
    return diagnostics
_BEGIN_TOKENS = frozenset({'variable_begin', 'block_begin', 'comment_begin'})
_END_TOKENS = frozenset({'variable_end', 'block_end', 'comment_end'})
_RAW_TOKENS = frozenset({'raw_begin', 'raw_end'})

def _end_marker(value: str) -> str | None:
    cut = value.rfind('}')
    return None if cut == -1 else value[:cut + 1]

@dataclass(frozen=True, slots=True)
class JinjaSpans:
    delimiters: list[tuple[int, int]] = field(default_factory=list)
    strings: list[tuple[int, int]] = field(default_factory=list)
    lexed: bool = True
_VALUE_TOKEN = 'string'

def _normalise_newlines(source: str) -> tuple[str, list[int]]:
    out: list[str] = []
    origin: list[int] = []
    index, length = (0, len(source))
    while index < length:
        char = source[index]
        if char == '\r':
            out.append('\n')
            origin.append(index)
            index += 2 if index + 1 < length and source[index + 1] == '\n' else 1
            continue
        out.append(char)
        origin.append(index)
        index += 1
    origin.append(length)
    return (''.join(out), origin)

def _locate_delimiters(source: str, env: jinja2.Environment) -> JinjaSpans:
    spans = JinjaSpans()
    cursor = 0
    open_marker: str | None = None
    interior: list[tuple[str, str]] = []
    text, origin = _normalise_newlines(source)
    try:
        tokens = list(env.lexer.tokeniter(source, 'pfmt'))
    except jinja2.TemplateSyntaxError:
        return JinjaSpans(lexed=False)
    for _lineno, token, value in tokens:
        if token in _RAW_TOKENS:
            marker = _end_marker(value)
            if marker is not None:
                idx = text.find(marker, cursor)
                if idx != -1:
                    spans.delimiters.append((origin[idx], origin[idx + len(marker)]))
                    cursor = idx + len(marker)
            open_marker = None
        elif token in _BEGIN_TOKENS:
            open_marker = value
            interior = []
        elif token in _END_TOKENS and open_marker is not None:
            close_marker = _end_marker(value)
            if close_marker is not None:
                body = ''.join((value for _kind, value in interior))
                full = open_marker + body + close_marker
                idx = text.find(full, cursor)
                if idx != -1:
                    spans.delimiters.append((origin[idx], origin[idx + len(full)]))
                    _add_string_spans(spans, interior, idx + len(open_marker), origin)
                    cursor = idx + len(full)
            open_marker = None
        elif open_marker is not None:
            interior.append((token, value))
    return spans

def _add_string_spans(spans: JinjaSpans, interior: list[tuple[str, str]], start: int, origin: list[int]) -> None:
    at = start
    for kind, value in interior:
        if kind == _VALUE_TOKEN:
            spans.strings.append((origin[at], origin[at + len(value)]))
        at += len(value)

def _open_marker_len(source: str, start: int) -> int:
    nxt = source[start + 2:start + 3]
    return 3 if nxt in '-+' else 2

def _close_marker_len(source: str, end: int) -> int:
    prev = source[end - 3:end - 2]
    return 3 if prev in '-+' else 2

def _multiline_padding_edits(source: str, start: int, end: int, open_len: int, close_len: int, pos: _Pos, pad: str) -> list[Edit]:
    interior = source[start + open_len:end - close_len]
    if not interior.strip():
        return []
    edits: list[Edit] = []
    lead = interior[:len(interior) - len(interior.lstrip(' \t'))]
    if interior[len(lead):len(lead) + 1] not in ('\n', '\r') and lead != pad:
        at = start + open_len
        l1, c1 = pos.at(at)
        l2, c2 = pos.at(at + len(lead))
        edits.append(Edit(l1, c1, l2, c2, pad))
    trail = interior[len(interior.rstrip(' \t')):]
    body_end = len(interior) - len(trail)
    if interior[body_end - 1:body_end] not in ('\n', '\r') and trail != pad:
        at = start + open_len + body_end
        l1, c1 = pos.at(at)
        l2, c2 = pos.at(at + len(trail))
        edits.append(Edit(l1, c1, l2, c2, pad))
    return edits

def _jinja_block_whitespace(spans: list[tuple[int, int]], source: str, file: str, pos: _Pos, style: str) -> list[Diagnostic]:
    pad = _STYLE_PAD[style]
    diagnostics: list[Diagnostic] = []
    for start, end in spans:
        open_len = _open_marker_len(source, start)
        close_len = _close_marker_len(source, end)
        open_marker = source[start:start + open_len]
        close_marker = source[end - close_len:end]
        interior = source[start + open_len:end - close_len]
        l1, c1 = pos.at(start)
        if '\n' in interior or '\r' in interior:
            edits = _multiline_padding_edits(source, start, end, open_len, close_len, pos, pad)
            if not edits:
                continue
        else:
            content = interior.strip(' \t')
            desired = f'{pad}{content}{pad}' if content else ' '
            if desired == interior:
                continue
            l2, c2 = pos.at(end)
            edits = [Edit(l1, c1, l2, c2, open_marker + desired + close_marker)]
        diagnostics.append(Diagnostic(rule=RuleId.PFMT, sub_code='jinja-block-whitespace', severity=severity_for(RuleId.PFMT, 'jinja-block-whitespace'), message=_JINJA_BLOCK_WHITESPACE_MSG[style], file=file, line=l1, col=c1, m2_anchor=anchor_for(RuleId.PFMT, 'jinja-block-whitespace'), fixable=True, edits=tuple(edits)))
    return diagnostics
_DATA_TAG = re.compile('<([A-Za-z][\\w-]*)>')

def _wrapping_tags(source: str, spans: list[tuple[int, int]]) -> frozenset[str]:
    found: set[str] = set()
    for tag in set(_DATA_TAG.findall(source)):
        open_pat, close_pat = (f'<{tag}>', f'</{tag}>')
        at = 0
        while (start := source.find(open_pat, at)) != -1:
            at = start + len(open_pat)
            stop = source.find(close_pat, at)
            if stop == -1:
                continue
            if '\n' not in source[at:stop] and any((at <= s and e <= stop for s, e in spans)):
                found.add(tag)
                break
    return frozenset(found)

def _delimiter_spacing(source: str, file: str, tags: frozenset[str] | None, spans: list[tuple[int, int]], pos: _Pos) -> list[Diagnostic]:
    if tags is None:
        tags = _wrapping_tags(source, spans)
    if not tags:
        return []

    def inside_jinja(offset: int) -> bool:
        return any((start <= offset < end for start, end in spans))
    diagnostics: list[Diagnostic] = []
    for tag in sorted(tags):
        open_pat, close_pat = (f'<{tag}>', f'</{tag}>')
        if close_pat not in source or open_pat not in source:
            continue
        diagnostics.extend(_open_padding(source, file, open_pat, inside_jinja, pos))
        diagnostics.extend(_close_padding(source, file, close_pat, inside_jinja, pos))
    return _one_finding_per_span(diagnostics)

def _one_finding_per_span(diagnostics: list[Diagnostic]) -> list[Diagnostic]:
    seen: set[tuple[int, int, int, int]] = set()
    unique: list[Diagnostic] = []
    for diag in diagnostics:
        key = tuple(((edit.start_line, edit.start_col, edit.end_line, edit.end_col) for edit in diag.edits))
        span = key[0] if len(key) == 1 else None
        if span is not None:
            if span in seen:
                continue
            seen.add(span)
        unique.append(diag)
    return unique

def _spacing_diagnostic(file: str, l1: int, c1: int, l2: int, c2: int) -> Diagnostic:
    return Diagnostic(rule=RuleId.PFMT, sub_code='delimiter-spacing', severity=severity_for(RuleId.PFMT, 'delimiter-spacing'), message=_DELIMITER_SPACING_MSG, file=file, line=l1, col=c1, m2_anchor=anchor_for(RuleId.PFMT, 'delimiter-spacing'), fixable=True, edits=(Edit(l1, c1, l2, c2, ''),))

def _open_padding(source: str, file: str, open_pat: str, inside_jinja: Callable[[int], bool], pos: _Pos) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    at = 0
    while (found := source.find(open_pat, at)) != -1:
        after = found + len(open_pat)
        at = after
        if inside_jinja(found):
            continue
        stop = after
        while stop < len(source) and source[stop] in ' \t':
            stop += 1
        if stop > after and stop < len(source) and (source[stop] not in '\r\n'):
            l1, c1 = pos.at(after)
            l2, c2 = pos.at(stop)
            diagnostics.append(_spacing_diagnostic(file, l1, c1, l2, c2))
    return diagnostics

def _close_padding(source: str, file: str, close_pat: str, inside_jinja: Callable[[int], bool], pos: _Pos) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    at = 0
    while (found := source.find(close_pat, at)) != -1:
        at = found + len(close_pat)
        if inside_jinja(found):
            continue
        start = found
        while start > 0 and source[start - 1] in ' \t':
            start -= 1
        if start < found and start > 0 and (source[start - 1] not in '\r\n'):
            l1, c1 = pos.at(start)
            l2, c2 = pos.at(found)
            diagnostics.append(_spacing_diagnostic(file, l1, c1, l2, c2))
    return diagnostics

def jinja_spans(source: str) -> JinjaSpans:
    return _locate_delimiters(source, jinja2.Environment())

def _jinja_aware(file: str, source: str, config: LintConfig, pos: _Pos, spans: JinjaSpans) -> list[Diagnostic]:
    return _jinja_block_whitespace(spans.delimiters, source, file, pos, config.jinja_block_style) + _delimiter_spacing(source, file, config.delimiter_tags, spans.delimiters, pos)

def _intersects(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    for span_start, span_end in spans:
        if start == end:
            if span_start < start < span_end:
                return True
        elif start < span_end and span_start < end:
            return True
    return False

def guard_text_edits(diagnostics: list[Diagnostic], spans: list[tuple[int, int]], pos: _Pos) -> list[Diagnostic]:
    if not spans:
        return diagnostics
    guarded: list[Diagnostic] = []
    for diag in diagnostics:
        kept = tuple((edit for edit in diag.edits if not _intersects(pos.offset(edit.start_line, edit.start_col), pos.offset(edit.end_line, edit.end_col), spans)))
        if len(kept) == len(diag.edits):
            guarded.append(diag)
        elif kept:
            guarded.append(replace(diag, edits=kept))
        else:
            guarded.append(replace(diag, fixable=False, edits=()))
    return guarded

def text_level_diagnostics(file: str, source: str, config: LintConfig, spans: JinjaSpans) -> list[Diagnostic]:
    pos = _Pos(source)
    target = config.line_ending_target
    final = _final_newline(file, source, target, pos)
    blank = _blank_lines(file, source, config.max_blank_lines, pos)
    claimed = frozenset((pos.offset(edit.start_line, edit.start_col) for diag in (*final, *blank) for edit in diag.edits if edit.replacement == ''))
    found = _trailing_whitespace(file, source) + _line_endings(file, source, target, claimed) + final + blank + _mixed_indentation(file, source, pos)
    if not spans.lexed:
        return [replace(diag, fixable=False, edits=()) if diag.edits else diag for diag in found]
    return guard_text_edits(found, spans.strings, pos)

class PfmtRule:
    id: RuleId = RuleId.PFMT

    def check(self, ctx: TemplateContext, config: LintConfig) -> list[Diagnostic]:
        pos = _Pos(ctx.source)
        spans = jinja_spans(ctx.source)
        return text_level_diagnostics(ctx.file, ctx.source, config, spans) + _jinja_aware(ctx.file, ctx.source, config, pos, spans)

class PfmtTextRule:
    id: RuleId = RuleId.PFMT

    def check(self, ctx: TemplateContext, config: LintConfig) -> list[Diagnostic]:
        return text_level_diagnostics(ctx.file, ctx.source, config, JinjaSpans())
