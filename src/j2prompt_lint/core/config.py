from __future__ import annotations
from dataclasses import dataclass, field
from j2prompt_lint.core.model import RuleId, Severity
DEFAULT_GLOBALS: frozenset[str] = frozenset({'range', 'dict', 'list', 'lipsum', 'namespace', 'cycler', 'joiner'})
DEFAULT_SANITIZERS: frozenset[str] = frozenset()
DEFAULT_INSTRUCTION_NAMES: frozenset[str] = frozenset({'system', 'prompt', 'instruction'})
PINJ_SOURCE_MODELS: tuple[str, ...] = ('configured', 'undeclared')
PFMT_BLOCK_STYLES: tuple[str, ...] = ('spaced', 'tight')
DEFAULT_TYPO_CUTOFF: float = 0.8

@dataclass(frozen=True, slots=True)
class LintConfig:
    globals_allowlist: frozenset[str] = DEFAULT_GLOBALS
    declared_vars: frozenset[str] | None = None
    required_vars: frozenset[str] | None = None
    infer_contract: bool = False
    likely_typo: bool = False
    typo_cutoff: float = DEFAULT_TYPO_CUTOFF
    untrusted_vars: frozenset[str] = frozenset()
    sanitizer_filters: frozenset[str] = DEFAULT_SANITIZERS
    pinj_source_model: str = 'configured'
    token_budget: int | None = None
    target_model: str | None = None
    tokenizer: str = 'auto'
    context_window: int | None = None
    generation_reserve: int = 512
    var_token_estimate: int = 0
    near_budget_ratio: float = 0.9
    instruction_names: frozenset[str] = DEFAULT_INSTRUCTION_NAMES
    delimiter_tags: frozenset[str] | None = None
    dynamic_role_loops: bool = False
    cross_template: str = 'bounded'
    cross_template_depth: int = 1
    template_search_path: tuple[str, ...] = ()
    line_ending_target: str = 'lf'
    max_blank_lines: int = 2
    jinja_block_style: str = 'spaced'
    no_fix: frozenset[str] = frozenset()
    chat_format_packs: frozenset[str] | None = None
    enabled_rules: frozenset[RuleId] = field(default_factory=lambda: frozenset(RuleId))
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
