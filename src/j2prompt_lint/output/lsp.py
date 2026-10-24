from __future__ import annotations
from typing import Any
from j2prompt_lint.__about__ import docs_url
from j2prompt_lint.core.engine import FileResult
from j2prompt_lint.core.model import Diagnostic, Severity
from j2prompt_lint.output.render import pinj_no_sources_notice
from j2prompt_lint.rules.pinj import PINJ_SCOPE
_LSP_SEVERITY: dict[Severity, int] = {Severity.ERROR: 1, Severity.WARNING: 2, Severity.INFO: 3}
_SOURCE = 'j2prompt-lint'

def to_lsp_pinj_notice(result: FileResult) -> dict[str, Any] | None:
    notice = pinj_no_sources_notice([result])
    if notice is None:
        return None
    return {'type': 3, 'message': f'{notice}\nPINJ scope: {PINJ_SCOPE}'}

def _lsp_data(diag: Diagnostic) -> dict[str, Any]:
    data: dict[str, Any] = {}
    if diag.m2_anchor:
        data['m2_anchor'] = diag.m2_anchor
    if diag.scope_ref is not None:
        data['scope_ref'] = diag.scope_ref
    if diag.extra is not None:
        data['extra'] = diag.extra
    if diag.fixable:
        data['fixable'] = True
    if diag.edits:
        data['fix'] = {'edits': [{'start': [edit.start_line, edit.start_col], 'end': [edit.end_line, edit.end_col], 'replacement': edit.replacement} for edit in diag.edits]}
    return data

def to_lsp_diagnostic(diag: Diagnostic) -> dict[str, Any]:
    start_line = diag.line - 1
    start_char = diag.col - 1
    end_line = diag.end_line - 1 if diag.end_line is not None else start_line
    end_char = diag.end_col - 1 if diag.end_col is not None else start_char
    lsp: dict[str, Any] = {'range': {'start': {'line': start_line, 'character': start_char}, 'end': {'line': end_line, 'character': end_char}}, 'severity': _LSP_SEVERITY[diag.severity], 'code': diag.code, 'source': _SOURCE, 'message': diag.message}
    data = _lsp_data(diag)
    if data:
        lsp['data'] = data
    lsp['codeDescription'] = {'href': docs_url(diag.rule.value)}
    return lsp

def to_lsp_publish(result: FileResult, uri: str | None=None) -> dict[str, Any]:
    return {'uri': result.file if uri is None else uri, 'diagnostics': [to_lsp_diagnostic(diag) for diag in result.diagnostics]}

def to_code_action(diag: Diagnostic, uri: str) -> dict[str, Any] | None:
    if not diag.edits:
        return None
    return {'title': f'j2prompt-lint: fix {diag.code}', 'kind': 'quickfix', 'diagnostics': [to_lsp_diagnostic(diag)], 'isPreferred': True, 'edit': {'changes': {uri: [{'range': {'start': {'line': edit.start_line - 1, 'character': edit.start_col - 1}, 'end': {'line': edit.end_line - 1, 'character': edit.end_col - 1}}, 'newText': edit.replacement} for edit in diag.edits]}}}
