from __future__ import annotations
import argparse
import difflib
import importlib.metadata
import json
import sys
from dataclasses import replace
from pathlib import Path
from j2prompt_lint.config import ConfigError, config_from_table, find_config_table, table_from_file
from j2prompt_lint.config.profiles import pinj_evaluation_config
from j2prompt_lint.core.config import PINJ_SOURCE_MODELS, LintConfig
from j2prompt_lint.core.engine import FileResult, PathNotFoundError, TemplateReadError, _relative_posix, discover_templates, lint_path, lint_text, read_template, rules_for
from j2prompt_lint.core.fix import OverlappingEditsError, apply_fixes
from j2prompt_lint.core.model import RuleId, Severity, severity_rank
from j2prompt_lint.output.render import config_digest_payload, render_json, render_sarif, render_text
from j2prompt_lint.rules.pinj import PINJ_SCOPE

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='j2prompt-lint', description='Static, model-free linter for Jinja2 LLM prompt templates.')
    parser.add_argument('paths', nargs='*', type=Path, help='Template files or directories.')
    parser.add_argument('--format', choices=('text', 'json', 'sarif'), default='text', help='Output format.')
    parser.add_argument('--fail-on', choices=('error', 'warning', 'info'), default='error', help='Minimum severity that makes the run fail (default: error).')
    parser.add_argument('--declare', default=None, help='Comma-separated PVAR variable contract (e.g. user_name,system_role).')
    parser.add_argument('--untrusted', default=None, help='Comma-separated PINJ untrusted variables (e.g. user_input,doc).')
    parser.add_argument('--pinj-dynamic-role-loops', action=argparse.BooleanOptionalAction, default=None, help='PINJ Q1 opt-in: recognise dynamically-built role turns as a sink (off by default; --no-... forces it off for one run).')
    parser.add_argument('--pinj-source-model', choices=PINJ_SOURCE_MODELS, default=None, help="How PINJ seeds untrusted sources: 'configured' (the --untrusted lexicon only, the default) or 'undeclared' (every undeclared variable, the conservative model pinj_spec.md §4 step 2 specifies).")
    parser.add_argument('--budget', type=int, default=None, help='PTOK static token budget; templates over it are flagged.')
    parser.add_argument('--explain', choices=[rule.value for rule in RuleId], default=None, help="Print a rule's scope statement and exit.")
    parser.add_argument('--config', type=Path, default=None, help='Config TOML path (default: discover .j2prompt-lint.toml/pyproject.toml).')
    parser.add_argument('--profile', choices=('pinj-evaluation',), default=None, help='Named PINJ evaluation settings with B-derived-8192. Applied after project settings and before explicit CLI overrides; see --show-config.')
    parser.add_argument('--show-config', action='store_true', help='Print the resolved configuration as JSON and exit without linting.')
    write_mode = parser.add_mutually_exclusive_group()
    write_mode.add_argument('--fix', action='store_true', help='Apply safe auto-fixes in place (PFMT).')
    write_mode.add_argument('--diff', action='store_true', help='Preview auto-fixes as a unified diff.')
    return parser

def _split_names(value: str | None) -> frozenset[str]:
    if value is None:
        return frozenset()
    return frozenset((name.strip() for name in value.split(',') if name.strip()))

def _resolve_config(args: argparse.Namespace) -> LintConfig:
    if args.config is not None:
        try:
            table = table_from_file(args.config)
        except OSError as error:
            raise OSError(f'cannot read --config {args.config}: {error}') from error
    else:
        table = find_config_table(Path.cwd())
    config = config_from_table(table)
    if args.profile == 'pinj-evaluation':
        config = pinj_evaluation_config(config)
    if args.declare is not None:
        config = replace(config, declared_vars=_split_names(args.declare))
    if args.untrusted is not None:
        config = replace(config, untrusted_vars=_split_names(args.untrusted))
    if args.pinj_dynamic_role_loops is not None:
        config = replace(config, dynamic_role_loops=args.pinj_dynamic_role_loops)
    if args.pinj_source_model is not None:
        config = replace(config, pinj_source_model=args.pinj_source_model)
    if args.budget is not None:
        config = replace(config, token_budget=args.budget)
    return config

def _should_fail(results: list[FileResult], threshold: Severity) -> bool:
    limit = severity_rank(threshold)
    for result in results:
        if result.parse_error is not None:
            return True
        if any((severity_rank(diag.severity) >= limit for diag in result.diagnostics)):
            return True
    return False

def _force_utf8_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, 'reconfigure', None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding='utf-8')
        except (OSError, ValueError):
            continue

def main() -> int:
    _force_utf8_streams()
    parser = _build_parser()
    args = parser.parse_args()
    if args.explain is not None:
        print(_explain(args.explain))
        return 0
    if not args.paths and (not args.show_config):
        parser.error('at least one path is required (or use --explain RULE/--show-config)')
    try:
        config = _resolve_config(args)
    except (ValueError, OSError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 2
    if args.show_config:
        print(json.dumps(config_digest_payload(config), indent=2, sort_keys=True))
        return 0
    try:
        if args.diff:
            _preview_fixes(list(args.paths), config)
            return 0
        if args.fix:
            return _run_fixes(list(args.paths), config, Severity(args.fail_on))
        results = lint_path(list(args.paths), config)
    except (PathNotFoundError, ConfigError, TemplateReadError, OverlappingEditsError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 2
    except OSError as error:
        print(f'error: {error}', file=sys.stderr)
        return 2
    version = importlib.metadata.version('j2prompt-lint')
    if args.format == 'json':
        print(render_json(results, version, config))
    elif args.format == 'sarif':
        print(render_sarif(results, version))
    else:
        print(render_text(results))
    return 1 if _should_fail(results, Severity(args.fail_on)) else 0

def _explain(rule: str) -> str:
    if rule == RuleId.PINJ.value:
        return f'PINJ scope: {PINJ_SCOPE}'
    return f'{rule}: see README rule matrix for scope.'

def _run_fixes(paths: list[Path], config: LintConfig, fail_on: Severity) -> int:
    changed = 0
    for path in discover_templates(paths):
        source = read_template(path)
        name = _relative_posix(path)
        diagnostics = lint_text(name, source, config, rules_for(path)).diagnostics
        fixed = apply_fixes(source, diagnostics)
        if fixed == source:
            continue
        changed += 1
        path.write_text(fixed, encoding='utf-8', newline='')
        print(f'fixed {name}')
    print(f'\n{changed} file(s) fixed')
    post_fix = lint_path(paths, config)
    return 1 if _should_fail(post_fix, fail_on) else 0

def _preview_fixes(paths: list[Path], config: LintConfig) -> None:
    changed = 0
    for path in discover_templates(paths):
        source = read_template(path)
        name = _relative_posix(path)
        diagnostics = lint_text(name, source, config, rules_for(path)).diagnostics
        fixed = apply_fixes(source, diagnostics)
        if fixed == source:
            continue
        changed += 1
        diff = difflib.unified_diff(source.splitlines(keepends=True), fixed.splitlines(keepends=True), fromfile=name, tofile=f'{name} (fixed)')
        sys.stdout.writelines(diff)
    print(f'\n{changed} file(s) would change')
if __name__ == '__main__':
    sys.exit(main())
