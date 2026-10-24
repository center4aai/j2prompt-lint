from __future__ import annotations
import os
from dataclasses import dataclass, replace
from pathlib import Path
from j2prompt_lint.core.config import LintConfig
from j2prompt_lint.core.context import MARKDOWN_SUFFIXES, ParseError, build_context, is_markdown, text_only_context
from j2prompt_lint.core.model import Diagnostic, PinjCheckState, RuleId, Severity
from j2prompt_lint.core.rule import Rule

class TemplateReadError(ValueError):
    pass

class PathNotFoundError(ValueError):
    pass

def _apply_severity_overrides(diag: Diagnostic, overrides: dict[str, Severity]) -> Diagnostic:
    new_severity = overrides.get(diag.code) or overrides.get(diag.rule.value)
    if new_severity is None:
        return diag
    return replace(diag, severity=new_severity)

def _withhold_fix(diag: Diagnostic, no_fix: frozenset[str]) -> Diagnostic:
    if diag.code not in no_fix:
        return diag
    return replace(diag, fixable=False, edits=())
TEMPLATE_SUFFIXES: tuple[str, ...] = ('.j2', '.jinja', '.jinja2')

def is_template_suffix(path: Path) -> bool:
    return path.suffix.lower() in TEMPLATE_SUFFIXES
__all__ = ['MARKDOWN_SUFFIXES', 'SIDECAR_SUFFIX', 'TEMPLATE_SUFFIXES', 'FileResult', 'PathNotFoundError', 'TemplateReadError', 'discover_templates', 'is_markdown', 'lint_path', 'lint_text', 'read_template', 'refuse_sidecars', 'rules_for', 'sidecars_of']

def rules_for(path: Path) -> list[Rule]:
    from j2prompt_lint.rules import default_rules, markdown_rules
    return markdown_rules() if is_markdown(path) else default_rules()

@dataclass(frozen=True, slots=True)
class FileResult:
    file: str
    diagnostics: list[Diagnostic]
    parse_error: ParseError | None
    pinj_check_state: PinjCheckState = PinjCheckState.UNKNOWN

def lint_text(file: str, source: str, config: LintConfig, rules: list[Rule] | None=None) -> FileResult:
    if rules is None:
        from j2prompt_lint.rules import default_rules
        rules = default_rules()
    ctx = build_context(file, source)
    diagnostics: list[Diagnostic] = []
    parse_error: ParseError | None = None
    pinj_selected = any((rule.id is RuleId.PINJ for rule in rules))
    pinj_state = PinjCheckState.NOT_SELECTED if not pinj_selected else PinjCheckState.DISABLED if RuleId.PINJ not in config.enabled_rules else PinjCheckState.UNKNOWN
    if isinstance(ctx, ParseError):
        parse_error = ctx
        if pinj_state is PinjCheckState.UNKNOWN:
            pinj_state = PinjCheckState.PARSE_ERROR
        pfmt_selected = any((rule.id is RuleId.PFMT for rule in rules))
        if pfmt_selected and RuleId.PFMT in config.enabled_rules:
            from j2prompt_lint.rules.pfmt import jinja_spans, text_level_diagnostics
            diagnostics.extend(text_level_diagnostics(file, source, config, jinja_spans(source)))
        ptok_selected = any((rule.id is RuleId.PTOK for rule in rules))
        if ptok_selected and RuleId.PTOK in config.enabled_rules and is_markdown(Path(file)):
            from j2prompt_lint.rules.ptok import PtokRule
            diagnostics.extend(PtokRule().check(text_only_context(file, source), config))
    else:
        from j2prompt_lint.rules.pinj import _BUILTIN_CHECK, PinjRule
        enabled = config.enabled_rules - ctx.directives.disabled
        if pinj_selected and RuleId.PINJ not in enabled:
            pinj_state = PinjCheckState.DISABLED
        pinj_states: list[PinjCheckState] = []
        for rule in rules:
            if rule.id in enabled:
                if type(rule) is PinjRule and getattr(rule.check, '__func__', None) is _BUILTIN_CHECK:
                    found, state = rule.check_with_state(ctx, config)
                    diagnostics.extend(found)
                    pinj_states.append(state)
                else:
                    diagnostics.extend(rule.check(ctx, config))
                    if rule.id is RuleId.PINJ:
                        pinj_states.append(PinjCheckState.UNKNOWN)
        if pinj_states:
            pinj_state = PinjCheckState.UNKNOWN if PinjCheckState.UNKNOWN in pinj_states else PinjCheckState.ENABLED if PinjCheckState.ENABLED in pinj_states else PinjCheckState.NO_SOURCES
    if config.severity_overrides:
        diagnostics = [_apply_severity_overrides(diag, config.severity_overrides) for diag in diagnostics]
    if config.no_fix:
        diagnostics = [_withhold_fix(diag, config.no_fix) for diag in diagnostics]
    diagnostics.sort(key=lambda diag: diag.sort_key)
    return FileResult(file=file, diagnostics=diagnostics, parse_error=parse_error, pinj_check_state=pinj_state)

def discover_templates(paths: list[Path]) -> list[Path]:
    resolved: list[Path] = []
    missing: list[Path] = []
    for path in paths:
        if path.is_dir() or path.is_file():
            resolved.append(path)
            continue
        matched = _expand_glob(path)
        if matched:
            resolved.extend(matched)
        else:
            missing.append(path)
    if missing:
        named = ', '.join(sorted((path.as_posix() for path in missing)))
        raise PathNotFoundError(f'path does not exist: {named}')
    found: set[Path] = set()
    for path in resolved:
        if path.is_dir():
            found.update((p for p in path.rglob('*') if p.is_file() and is_template_suffix(p)))
        else:
            found.add(path)
    templates = sorted(found)
    refuse_sidecars(templates)
    return templates
SIDECAR_SUFFIX = '.j2pl.toml'

def sidecars_of(template: Path) -> list[Path]:
    found: dict[Path, Path] = {}
    for base in (template.absolute(), template.resolve()):
        parts = base.name.split('.')
        for end in range(1, len(parts) + 1):
            reading = '.'.join(parts[:end])
            if reading.strip('.'):
                candidate = base.with_name(reading + SIDECAR_SUFFIX)
                if candidate.is_file():
                    found.setdefault(candidate.resolve(), candidate)
    found.pop(template.resolve(), None)
    return list(found.values())

def refuse_sidecars(templates: list[Path]) -> None:
    from j2prompt_lint.config.schema import ConfigError
    found = [f'{_relative_posix(sidecar)} (beside {_relative_posix(template)})' for template in templates for sidecar in sidecars_of(template)]
    if not found:
        return
    raise ConfigError(f"per-template sidecar contract(s) found: {'; '.join(found)}. This tool does not read a sidecar (pvar_spec.md §5.2), so its contract would be silently ignored and the template linted as if it declared none. Declare the contract in the template instead — `{{# j2pl: vars(required=[...], optional=[...]) #}}`, with `trusted(...)` / `untrusted(...)` for provenance — or project-wide in the configuration file, and remove the sidecar. Track: D-04-131.")
_GLOB_CHARS = ('*', '?', '[')

def _expand_glob(pattern: Path) -> list[Path]:
    text = pattern.as_posix()
    if not any((char in text for char in _GLOB_CHARS)):
        return []
    anchor = Path(pattern.anchor) if pattern.anchor else Path()
    relative = text[len(pattern.anchor):] if pattern.anchor else text
    try:
        matched = anchor.glob(relative) if pattern.anchor else Path().glob(relative)
        return sorted((item for item in matched if item.is_file()))
    except (NotImplementedError, ValueError):
        return []

def read_template(path: Path) -> str:
    raw = path.read_bytes()
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError as error:
        raise TemplateReadError(f'{_relative_posix(path)}: not valid UTF-8 (byte {error.start}: {error.reason}); j2prompt-lint reads templates as UTF-8 text') from error

def _relative_posix(path: Path) -> str:
    resolved = path.resolve()
    cwd = Path.cwd()
    try:
        return resolved.relative_to(cwd).as_posix()
    except ValueError:
        pass
    try:
        return Path(os.path.relpath(resolved, cwd)).as_posix()
    except ValueError:
        return resolved.as_posix()

def lint_path(paths: list[Path], config: LintConfig, rules: list[Rule] | None=None) -> list[FileResult]:
    results: list[FileResult] = []
    for template in discover_templates(paths):
        source = read_template(template)
        selected = rules if rules is not None else rules_for(template)
        results.append(lint_text(_relative_posix(template), source, config, selected))
    return results
