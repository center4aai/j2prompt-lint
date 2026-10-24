from __future__ import annotations
import tomllib
from pathlib import Path
from typing import Any
from j2prompt_lint.config.schema import PCHAT_KEYS, PINJ_TOP_LEVEL_KEYS, PTOK_KEYS, ConfigError, validate
from j2prompt_lint.core.config import DEFAULT_GLOBALS, DEFAULT_INSTRUCTION_NAMES, DEFAULT_SANITIZERS, DEFAULT_TYPO_CUTOFF, LintConfig
from j2prompt_lint.core.model import RuleId, Severity
from j2prompt_lint.rules.pchat import PACK_NAMES
__all__ = ['ConfigError', 'config_from_table', 'find_config_table', 'load_config', 'table_from_file']
_DEDICATED = '.j2prompt-lint.toml'
_IMPLEMENTED_TOKENIZERS: frozenset[str] = frozenset({'auto', 'cl100k_base'})
_PTOK_KEYS: tuple[str, ...] = tuple(PTOK_KEYS)
_PINJ_KEYS: tuple[str, ...] = PINJ_TOP_LEVEL_KEYS
_PCHAT_KEYS: tuple[str, ...] = tuple(PCHAT_KEYS)

def _merged(nested: dict[str, Any], top: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    merged = dict(nested)
    for key in keys:
        if key not in merged and key in top:
            merged[key] = top[key]
    return merged

def _subtable(table: dict[str, Any], name: str) -> dict[str, Any]:
    nested = table.get(name)
    return nested if isinstance(nested, dict) else {}

def _read_toml(path: Path) -> dict[str, Any]:
    with path.open('rb') as handle:
        try:
            return tomllib.load(handle)
        except tomllib.TOMLDecodeError as error:
            raise ConfigError(f'{path}: invalid TOML: {error}') from error

def find_config_table(start: Path) -> dict[str, Any]:
    for directory in [start.resolve(), *start.resolve().parents]:
        dedicated = directory / _DEDICATED
        if dedicated.is_file():
            data = _read_toml(dedicated)
            nested = data.get('tool', {}).get('j2prompt-lint')
            return nested if isinstance(nested, dict) else data
        pyproject = directory / 'pyproject.toml'
        if pyproject.is_file():
            table = _read_toml(pyproject).get('tool', {}).get('j2prompt-lint')
            return table if isinstance(table, dict) else {}
    return {}

def _reject_unimplemented_tokenizer(ptok: dict[str, Any]) -> None:
    tokenizer = ptok.get('tokenizer')
    if tokenizer is None or tokenizer in _IMPLEMENTED_TOKENIZERS:
        return
    supported = ', '.join((repr(name) for name in sorted(_IMPLEMENTED_TOKENIZERS)))
    raise ConfigError(f"PTOK tokenizer {tokenizer!r} is not implemented, so it would be silently ignored and the count taken with the wrong tokenizer. Supported values are {supported}; a named '<hf-id>' tokenizer (ptok_spec.md §5) is not yet wired.")

def _reject_unknown_packs(pchat: dict[str, Any]) -> None:
    names = pchat.get('chat_format_packs')
    if names is None:
        return
    unknown = sorted(set(names) - PACK_NAMES)
    if unknown:
        raise ConfigError(f"[tool.j2prompt-lint.pchat] chat_format_packs names unknown pack(s) {unknown}; the shipped packs are {', '.join(sorted(PACK_NAMES))}. An unrecognised name would filter PCHAT's auto-detection down to nothing and silence the rule.")

def config_from_table(table: dict[str, Any]) -> LintConfig:
    validate(table)
    ptok = _merged(_subtable(table, 'ptok'), table, _PTOK_KEYS)
    _reject_unimplemented_tokenizer(ptok)
    pinj = _merged(_subtable(table, 'pinj'), table, _PINJ_KEYS)
    pfmt = _subtable(table, 'pfmt')
    pvar = _subtable(table, 'pvar')
    pchat = _merged(_subtable(table, 'pchat'), table, _PCHAT_KEYS)
    _reject_unknown_packs(pchat)
    packs = pchat.get('chat_format_packs')
    declared = table.get('declared')
    required = pvar.get('required', table.get('required'))
    optional = pvar.get('optional', table.get('optional'))
    contract = None if declared is None and required is None and (optional is None) else frozenset(declared or []) | frozenset(required or []) | frozenset(optional or [])
    disabled = {RuleId(name) for name in table.get('disable', [])}
    overrides = {code: Severity(value) for code, value in table.get('severity', {}).items()}
    delimiter_tags = pinj.get('delimiter_tags')
    return LintConfig(globals_allowlist=DEFAULT_GLOBALS | frozenset(table.get('globals', [])), declared_vars=contract, required_vars=frozenset(required) if required is not None else None, infer_contract=bool(pvar.get('infer_contract', False)), likely_typo=bool(pvar.get('likely_typo', False)), typo_cutoff=pvar.get('typo_cutoff', DEFAULT_TYPO_CUTOFF), untrusted_vars=frozenset(pinj.get('untrusted', [])), sanitizer_filters=DEFAULT_SANITIZERS | frozenset(pinj.get('sanitizer_filters', [])), token_budget=ptok.get('token_budget', ptok.get('budget')), target_model=ptok.get('target_model'), tokenizer=ptok.get('tokenizer', 'auto'), context_window=ptok.get('context_window'), generation_reserve=ptok.get('generation_reserve', 512), var_token_estimate=ptok.get('var_token_estimate', 0), near_budget_ratio=ptok.get('near_budget_ratio', 0.9), instruction_names=DEFAULT_INSTRUCTION_NAMES | frozenset(pinj.get('instruction_names', [])), delimiter_tags=frozenset(delimiter_tags) if delimiter_tags is not None else None, pinj_source_model=pinj.get('source_model', 'configured'), dynamic_role_loops=bool(pinj.get('dynamic_role_loops', False)), cross_template=pinj.get('cross_template', 'bounded'), cross_template_depth=pinj.get('cross_template_depth', 1), template_search_path=tuple(pinj.get('template_search_path', ())), line_ending_target=pfmt.get('line_ending_target', 'lf'), max_blank_lines=pfmt.get('max_blank_lines', 2), jinja_block_style=pfmt.get('jinja_block_style', 'spaced'), no_fix=frozenset(pfmt.get('no_fix', [])), chat_format_packs=frozenset(packs) if packs is not None else None, enabled_rules=frozenset(RuleId) - disabled, severity_overrides=overrides)

def table_from_file(path: Path) -> dict[str, Any]:
    data = _read_toml(path)
    nested = data.get('tool', {}).get('j2prompt-lint')
    return nested if isinstance(nested, dict) else data

def load_config(start: Path) -> LintConfig:
    return config_from_table(find_config_table(start))
