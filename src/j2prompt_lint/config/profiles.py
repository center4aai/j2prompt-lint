from __future__ import annotations
from dataclasses import replace
from j2prompt_lint.core.config import DEFAULT_SANITIZERS, LintConfig

def pinj_evaluation_config(project: LintConfig) -> LintConfig:
    return replace(project, pinj_source_model='undeclared', dynamic_role_loops=True, untrusted_vars=frozenset(), sanitizer_filters=DEFAULT_SANITIZERS, token_budget=None, target_model=None, tokenizer='auto', context_window=8192, generation_reserve=512, var_token_estimate=25)
