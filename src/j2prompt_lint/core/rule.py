from __future__ import annotations
from typing import Protocol, runtime_checkable
from j2prompt_lint.core.config import LintConfig
from j2prompt_lint.core.context import TemplateContext
from j2prompt_lint.core.model import Diagnostic, RuleId

@runtime_checkable
class Rule(Protocol):
    id: RuleId

    def check(self, ctx: TemplateContext, config: LintConfig) -> list[Diagnostic]:
        ...
