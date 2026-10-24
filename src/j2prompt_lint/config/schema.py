from __future__ import annotations
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from j2prompt_lint.core.config import PFMT_BLOCK_STYLES, PINJ_SOURCE_MODELS
from j2prompt_lint.core.model import RuleId, Severity
from j2prompt_lint.core.subcodes import SUB_CODES

class ConfigError(ValueError):
    pass

@dataclass(frozen=True, slots=True)
class KeySpec:
    accepts: Callable[[object], bool]
    domain: str

def _is_bool(value: object) -> bool:
    return isinstance(value, bool)

def _is_str(value: object) -> bool:
    return isinstance(value, str)

def _is_str_list(value: object) -> bool:
    return isinstance(value, list) and all((isinstance(item, str) for item in value))

def _is_int_at_least(minimum: int) -> Callable[[object], bool]:

    def check(value: object) -> bool:
        if isinstance(value, bool) or not isinstance(value, int):
            return False
        return value >= minimum
    return check

def _is_ratio(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    return 0.0 < float(value) <= 1.0

def _is_one_of(*allowed: str) -> Callable[[object], bool]:

    def check(value: object) -> bool:
        return value in allowed
    return check

def _is_table(value: object) -> bool:
    return isinstance(value, dict)
_STR_LIST = 'a list of strings'
_TABLE = 'a table'
PTOK_KEYS: Mapping[str, KeySpec] = {'target_model': KeySpec(_is_str, 'a model id string'), 'tokenizer': KeySpec(_is_str, 'a tokenizer id string'), 'token_budget': KeySpec(_is_int_at_least(0), 'a non-negative integer'), 'budget': KeySpec(_is_int_at_least(0), 'a non-negative integer'), 'context_window': KeySpec(_is_int_at_least(1), 'a positive integer'), 'generation_reserve': KeySpec(_is_int_at_least(0), 'a non-negative integer'), 'var_token_estimate': KeySpec(_is_int_at_least(0), 'a non-negative integer'), 'near_budget_ratio': KeySpec(_is_ratio, 'a ratio in (0, 1]')}
PINJ_KEYS: Mapping[str, KeySpec] = {'untrusted': KeySpec(_is_str_list, _STR_LIST), 'sanitizer_filters': KeySpec(_is_str_list, _STR_LIST), 'delimiter_tags': KeySpec(_is_str_list, _STR_LIST), 'instruction_names': KeySpec(_is_str_list, _STR_LIST), 'dynamic_role_loops': KeySpec(_is_bool, 'a boolean'), 'cross_template': KeySpec(_is_one_of('bounded', 'off'), '"bounded" or "off"'), 'cross_template_depth': KeySpec(_is_int_at_least(1), 'a positive integer'), 'template_search_path': KeySpec(_is_str_list, _STR_LIST), 'source_model': KeySpec(_is_one_of(*PINJ_SOURCE_MODELS), '"configured" or "undeclared"')}
PCHAT_KEYS: Mapping[str, KeySpec] = {'chat_format_packs': KeySpec(_is_str_list, _STR_LIST)}
PINJ_TOP_LEVEL_KEYS: tuple[str, ...] = ('untrusted', 'sanitizer_filters', 'delimiter_tags')
TOP_LEVEL_FALLBACK: frozenset[str] = frozenset(PTOK_KEYS) | frozenset(PINJ_TOP_LEVEL_KEYS) | frozenset(PCHAT_KEYS)
SECTIONS: Mapping[str, Mapping[str, KeySpec]] = {'': {'globals': KeySpec(_is_str_list, _STR_LIST), 'declared': KeySpec(_is_str_list, _STR_LIST), 'required': KeySpec(_is_str_list, _STR_LIST), 'optional': KeySpec(_is_str_list, _STR_LIST), 'disable': KeySpec(_is_str_list, _STR_LIST), 'severity': KeySpec(_is_table, _TABLE), 'pvar': KeySpec(_is_table, _TABLE), 'pchat': KeySpec(_is_table, _TABLE), 'pinj': KeySpec(_is_table, _TABLE), 'ptok': KeySpec(_is_table, _TABLE), 'pfmt': KeySpec(_is_table, _TABLE), **dict(PTOK_KEYS), **{key: PINJ_KEYS[key] for key in PINJ_TOP_LEVEL_KEYS}, **dict(PCHAT_KEYS)}, 'pvar': {'required': KeySpec(_is_str_list, _STR_LIST), 'optional': KeySpec(_is_str_list, _STR_LIST), 'infer_contract': KeySpec(_is_bool, 'a boolean'), 'likely_typo': KeySpec(_is_bool, 'a boolean'), 'typo_cutoff': KeySpec(_is_ratio, 'a ratio in (0, 1]')}, 'pchat': PCHAT_KEYS, 'pinj': PINJ_KEYS, 'ptok': PTOK_KEYS, 'pfmt': {'line_ending_target': KeySpec(_is_one_of('lf', 'crlf'), '"lf" or "crlf"'), 'max_blank_lines': KeySpec(_is_int_at_least(0), 'a non-negative integer'), 'jinja_block_style': KeySpec(_is_one_of(*PFMT_BLOCK_STYLES), '"spaced" or "tight"'), 'no_fix': KeySpec(_is_str_list, _STR_LIST)}}
UNHONOURED: Mapping[tuple[str, str], str] = {**{(section, key): 'pinning ONE pack onto a template is not implemented, so this key would be ignored. PCHAT resolves the chat-format pack by auto-detection, restricted to the packs `chat_format_packs` allows (pchat_spec.md §4 step 2 (b)); the per-template pin of step 2 (a) needs the `j2pl: chat_format(...)` directive, which PCHAT does not read. Use `chat_format_packs` if an allowlist is what you want. Track: D-06-06.' for section in ('', 'pchat') for key in ('pack', 'packs', 'chat_format')}, **{(section, 'delimiter_lexicon'): 'a PAIR-valued data-delimiter lexicon is not implemented. The Z1 / PFMT lexicon the engine reads is keyed by TAG NAME: write `[tool.j2prompt-lint.pinj] delimiter_tags = ["user_input"]`. The pair form would be needed only for a delimiter that is not `<tag>`-shaped (`[INST]`…`[/INST]`, `<|im_start|>`…`<|im_end|>`, a ``` fence, `<<SYS>>`), and measured over the 446 published corpus bodies those occur in 23 / 121 / 46 / 3 of them but wrap an interpolation on one line as literal template text — the only shape either PINJ Z1 or PFMT `delimiter-spacing` can act on — in **0**. Track: PFMT-4.' for section in ('', 'pinj', 'pfmt')}}
ELSEWHERE: Mapping[tuple[str, str], str] = {('pfmt', 'delimiter_tags'): 'pinj'}

def _table_name(section: str) -> str:
    return 'tool.j2prompt-lint' if not section else f'tool.j2prompt-lint.{section}'

def _where(section: str, key: str) -> str:
    return f'[{_table_name(section)}] {key!r}'

def _refuse_unhonoured(section: str, table: Mapping[str, object]) -> None:
    by_reason: dict[str, list[str]] = {}
    for key in table:
        reason = UNHONOURED.get((section, key))
        if reason is not None:
            by_reason.setdefault(reason, []).append(key)
    for reason, keys in by_reason.items():
        named = ', '.join((repr(key) for key in sorted(keys)))
        raise ConfigError(f'[{_table_name(section)}] {named}: {reason}')

def _check_section(section: str, table: Mapping[str, object]) -> None:
    _refuse_unhonoured(section, table)
    honoured = SECTIONS[section]
    for key, value in table.items():
        spec = honoured.get(key)
        if spec is None:
            other = ELSEWHERE.get((section, key))
            if other is not None:
                raise ConfigError(f'{_where(section, key)} is read from [{_table_name(other)}], not from here — PFMT and PINJ share one data-delimiter lexicon (pfmt_spec.md §7). Move the key rather than removing it.')
            known = ', '.join(sorted(honoured)) or '(none — this table honours no keys)'
            raise ConfigError(f'{_where(section, key)} is not a setting this tool reads, so it would be silently ignored. Honoured keys here: {known}.')
        if not spec.accepts(value):
            raise ConfigError(f'{_where(section, key)} must be {spec.domain}; got {value!r}.')

def _check_severity_overrides(table: Mapping[str, object]) -> None:
    codes = {f'{rule.value}/{sub_code}' for rule, sub_code in SUB_CODES}
    rules = {rule.value for rule in RuleId}
    for key, value in table.items():
        if key not in codes and key not in rules:
            raise ConfigError(f"[tool.j2prompt-lint.severity] {key!r} names no rule or sub-code, so the override would be loaded and never applied. Use a rule ({', '.join(sorted(rules))}) or a '{{rule}}/{{sub_code}}' code.")
        if not isinstance(value, str) or value not in {sev.value for sev in Severity}:
            levels = ', '.join((sev.value for sev in Severity))
            raise ConfigError(f'[tool.j2prompt-lint.severity] {key!r} must be one of {levels}; got {value!r}.')

def _check_no_fix(names: list[str]) -> None:
    codes = {f'{rule.value}/{sub_code}' for rule, sub_code in SUB_CODES if rule is RuleId.PFMT}
    unknown = sorted((name for name in names if name not in codes))
    if unknown:
        raise ConfigError(f"[tool.j2prompt-lint.pfmt] no_fix names {unknown}, which are not auto-fixable sub-codes, so the entry would be loaded and never matched. Valid: {', '.join(sorted(codes))}.")

def _check_disabled_rules(names: list[str]) -> None:
    known = {rule.value for rule in RuleId}
    unknown = sorted((name for name in names if name not in known))
    if unknown:
        raise ConfigError(f"[tool.j2prompt-lint] disable names unknown rule(s) {unknown}; valid rules are {', '.join(sorted(known))}.")

def validate(table: Mapping[str, object]) -> None:
    _check_section('', table)
    for section in SECTIONS:
        if not section:
            continue
        nested = table.get(section)
        if isinstance(nested, dict):
            _check_section(section, nested)
    severity = table.get('severity')
    if isinstance(severity, dict):
        _check_severity_overrides(severity)
    pfmt = table.get('pfmt')
    if isinstance(pfmt, dict) and isinstance(pfmt.get('no_fix'), list):
        _check_no_fix(pfmt['no_fix'])
    disable = table.get('disable')
    if isinstance(disable, list):
        _check_disabled_rules(disable)
