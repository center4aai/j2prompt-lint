from __future__ import annotations
import hashlib
import json
from dataclasses import fields
from j2prompt_lint.__about__ import PROJECT_URL, docs_url
from j2prompt_lint.core.config import LintConfig
from j2prompt_lint.core.engine import FileResult
from j2prompt_lint.core.model import Diagnostic, PinjCheckState, RuleId, Severity
from j2prompt_lint.core.subcodes import spec_for
from j2prompt_lint.rules.pinj import PINJ_SCOPE
PINJ_CONFIG_HINT = 'Configure [pinj] untrusted or j2pl: untrusted(...), or use --profile pinj-evaluation for conservative source analysis.'

def pinj_analysis(results: list[FileResult]) -> dict[str, object]:
    counts = {state.value: 0 for state in PinjCheckState}
    for result in results:
        counts[result.pinj_check_state.value] += 1
    return {'files': [{'file': result.file, 'state': result.pinj_check_state.value} for result in results], 'state_counts': counts, 'no_sources': counts[PinjCheckState.NO_SOURCES.value], 'hint': PINJ_CONFIG_HINT, 'scope': PINJ_SCOPE}

def pinj_no_sources_notice(results: list[FileResult]) -> str | None:
    count = sum((result.pinj_check_state is PinjCheckState.NO_SOURCES for result in results))
    if not count:
        return None
    return f'PINJ: no untrusted sources to trace in {count} file(s); no untrusted flow was checked for those files. {PINJ_CONFIG_HINT}'

def _summary(results: list[FileResult]) -> dict[str, object]:
    by_severity = {sev.value: 0 for sev in Severity}
    by_rule = {rule.value: 0 for rule in RuleId}
    syntax = 0
    for result in results:
        if result.parse_error is not None:
            syntax += 1
        for diag in result.diagnostics:
            by_severity[diag.severity.value] += 1
            by_rule[diag.rule.value] += 1
    return {**by_severity, 'syntax': syntax, 'by_rule': by_rule}

def _any_pinj(results: list[FileResult]) -> bool:
    return any((diag.rule is RuleId.PINJ for result in results for diag in result.diagnostics))

def render_text(results: list[FileResult]) -> str:
    lines: list[str] = []
    for result in results:
        if result.parse_error is not None:
            err = result.parse_error
            lines.append(f'{err.file}:{err.line}: syntax error: {err.message}')
        for diag in result.diagnostics:
            lines.append(_text_line(diag))
    notice = pinj_no_sources_notice(results)
    if notice is not None:
        lines.append(f'\n{notice}')
    if notice is not None or _any_pinj(results):
        lines.append(f'\nPINJ scope: {PINJ_SCOPE}')
    counts = _summary(results)
    lines.append(f"\n{counts['error']} error(s), {counts['warning']} warning(s), {counts['info']} info, {counts['syntax']} syntax error(s)")
    return '\n'.join(lines)

def _unasserted_extra(diag: Diagnostic) -> dict[str, object]:
    if not diag.extra:
        return {}
    asserted = spec_for(diag.rule, diag.sub_code).asserted_in(diag.message)
    return {key: value for key, value in diag.extra.items() if key not in asserted}

def _text_line(diag: Diagnostic) -> str:
    line = f'{diag.file}:{diag.line}:{diag.col}: {diag.severity.value} {diag.code} {diag.message}'
    if diag.fixable:
        line += ' [fixable]'
    if diag.rule is RuleId.PINJ:
        line += ' (scope: --explain PINJ)'
    if diag.m2_anchor:
        line += f' ({diag.m2_anchor})'
    silent = _unasserted_extra(diag)
    if silent:
        joined = ' '.join((f'{key}={silent[key]}' for key in sorted(silent)))
        line += f' [extra: {joined}]'
    return line

def _digest_value(value: object) -> object:
    if isinstance(value, frozenset | set):
        return sorted((item.value if isinstance(item, RuleId) else item for item in value))
    if isinstance(value, dict):
        return {key: item.value if isinstance(item, Severity) else item for key, item in sorted(value.items())}
    return value

def config_digest_payload(config: LintConfig) -> dict[str, object]:
    return {field.name: _digest_value(getattr(config, field.name)) for field in fields(config)}

def _config_digest(config: LintConfig) -> str:
    blob = json.dumps(config_digest_payload(config), sort_keys=True)
    return hashlib.sha256(blob.encode('utf-8')).hexdigest()

def _diag_to_dict(diag: Diagnostic) -> dict[str, object]:
    payload: dict[str, object] = {'rule': diag.rule.value, 'sub_code': diag.sub_code, 'severity': diag.severity.value, 'message': diag.message, 'file': diag.file, 'line': diag.line, 'col': diag.col}
    if diag.end_line is not None:
        payload['end_line'] = diag.end_line
    if diag.end_col is not None:
        payload['end_col'] = diag.end_col
    if diag.m2_anchor:
        payload['m2_anchor'] = diag.m2_anchor
    if diag.scope_ref is not None:
        payload['scope_ref'] = diag.scope_ref
    if diag.fixable:
        payload['fixable'] = True
    if diag.edits:
        payload['fix'] = {'edits': [{'start': [edit.start_line, edit.start_col], 'end': [edit.end_line, edit.end_col], 'replacement': edit.replacement} for edit in diag.edits]}
    if diag.extra is not None:
        payload['extra'] = diag.extra
    return payload

def render_json(results: list[FileResult], version: str, config: LintConfig) -> str:
    diagnostics = [_diag_to_dict(diag) for result in results for diag in result.diagnostics]
    syntax_errors = [{'file': r.parse_error.file, 'line': r.parse_error.line, 'message': r.parse_error.message} for r in results if r.parse_error is not None]
    envelope = {'version': f'j2prompt-lint {version}', 'config_digest': _config_digest(config), 'rules': {'PINJ': {'scope': PINJ_SCOPE, 'docs_url': docs_url('PINJ')}}, 'analysis': {'PINJ': pinj_analysis(results)}, 'diagnostics': diagnostics, 'syntax_errors': syntax_errors, 'summary': _summary(results)}
    return json.dumps(envelope, indent=2, sort_keys=True, ensure_ascii=False)
_SARIF_LEVEL = {Severity.ERROR: 'error', Severity.WARNING: 'warning', Severity.INFO: 'note'}

def _sarif_rule(diag: Diagnostic) -> dict[str, object]:
    spec = spec_for(diag.rule, diag.sub_code)
    rule: dict[str, object] = {'id': diag.code, 'name': diag.sub_code, 'shortDescription': {'text': f'{diag.rule.value} {diag.sub_code}'}, 'fullDescription': {'text': spec.description}}
    if diag.m2_anchor:
        rule['properties'] = {'m2_anchor': diag.m2_anchor}
    if diag.rule is RuleId.PINJ:
        rule['fullDescription'] = {'text': f'{PINJ_SCOPE} {spec.description}'}
        rule['help'] = {'text': PINJ_SCOPE}
    return rule
_INFORMATION_URI = PROJECT_URL

def _sarif_result(diag: Diagnostic) -> dict[str, object]:
    region: dict[str, object] = {'startLine': diag.line, 'startColumn': diag.col}
    if diag.end_line is not None:
        region['endLine'] = diag.end_line
    if diag.end_col is not None:
        region['endColumn'] = diag.end_col
    result: dict[str, object] = {'ruleId': diag.code, 'level': _SARIF_LEVEL[diag.severity], 'message': {'text': diag.message}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': diag.file}, 'region': region}}]}
    if diag.extra is not None:
        result['properties'] = diag.extra
    if diag.edits:
        result['fixes'] = [{'artifactChanges': [{'artifactLocation': {'uri': diag.file}, 'replacements': [{'deletedRegion': {'startLine': edit.start_line, 'startColumn': edit.start_col, 'endLine': edit.end_line, 'endColumn': edit.end_col}, 'insertedContent': {'text': edit.replacement}} for edit in diag.edits]}]}]
    return result

def render_sarif(results: list[FileResult], version: str) -> str:
    rules: dict[str, dict[str, object]] = {}
    sarif_results: list[dict[str, object]] = []
    for result in results:
        for diag in result.diagnostics:
            rules.setdefault(diag.code, _sarif_rule(diag))
            sarif_results.append(_sarif_result(diag))
    document = {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'runs': [{'tool': {'driver': {'name': 'j2prompt-lint', 'version': version, 'informationUri': _INFORMATION_URI, 'rules': list(rules.values())}}, 'results': sarif_results, 'properties': {'analysis': {'PINJ': pinj_analysis(results)}}}]}
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)
