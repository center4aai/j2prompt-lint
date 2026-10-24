from __future__ import annotations
from jinja2 import nodes
from j2prompt_lint.core.config import LintConfig
from j2prompt_lint.core.context import TemplateContext
from j2prompt_lint.core.model import Diagnostic, RuleId
from j2prompt_lint.core.subcodes import anchor_for, render, severity_for
from j2prompt_lint.rules.ptok_tokenizer import CL100K_TOKENIZER_ID, TokenCount, count_tokens, resolve_budget
_NO_VOCABULARY = 'tokenizer-unavailable'
_NO_BUDGET = 'no-budget-resolved'

def _is_engaged(config: LintConfig) -> bool:
    return config.token_budget is not None or config.target_model is not None or config.context_window is not None

def _approx_message(count: TokenCount, config: LintConfig) -> tuple[str, dict[str, object]]:
    tid = count.tokenizer_id
    target = config.target_model
    if tid == CL100K_TOKENIZER_ID:
        if target is not None:
            return render(RuleId.PTOK, 'approx-tokenizer', 'explicit-overrides-target', tokenizer=tid, target_model=target)
        return render(RuleId.PTOK, 'approx-tokenizer', 'explicit-no-target', tokenizer=tid)
    if target is not None:
        return render(RuleId.PTOK, 'approx-tokenizer', 'reference-target-unavailable', tokenizer=tid, target_model=target)
    return render(RuleId.PTOK, 'approx-tokenizer', 'reference-no-target', tokenizer=tid)

def _static_text(ast: nodes.Template) -> str:
    parts: list[str] = []
    for output in ast.find_all(nodes.Output):
        for child in output.nodes:
            if isinstance(child, nodes.TemplateData):
                parts.append(child.data)
            elif isinstance(child, nodes.Const) and isinstance(child.value, str):
                parts.append(child.value)
    return ''.join(parts)

class PtokRule:
    id: RuleId = RuleId.PTOK

    def check(self, ctx: TemplateContext, config: LintConfig) -> list[Diagnostic]:
        if not _is_engaged(config):
            return []
        static_text = ctx.source if ctx.markdown else _static_text(ctx.ast)
        count = count_tokens(static_text, config)
        diagnostics: list[Diagnostic] = []
        if count.is_approx:
            diagnostics.append(self._approx_diag(ctx, count, config))
        if count.count is None:
            diagnostics.append(self._budget_unknown_diag(ctx, count.tokenizer_id, _NO_VOCABULARY))
            return diagnostics
        budget = resolve_budget(config)
        if budget is None:
            diagnostics.append(self._budget_unknown_diag(ctx, count.tokenizer_id, _NO_BUDGET, static_tokens=count.count))
            return diagnostics
        diagnostics.extend(self._budget_diags(ctx, count, budget, config))
        return diagnostics

    def _budget_diags(self, ctx: TemplateContext, count: TokenCount, budget: int, config: LintConfig) -> list[Diagnostic]:
        tid = count.tokenizer_id
        static_tokens = count.count or 0
        if static_tokens >= budget:
            return [self._over_budget_diag(ctx, tid, budget, static_tokens)]
        diagnostics: list[Diagnostic] = []
        n_unbound = len(ctx.undeclared)
        estimated = static_tokens + config.var_token_estimate * n_unbound
        if estimated >= budget:
            diagnostics.append(self._estimated_over_diag(ctx, tid, budget, static_tokens, estimate=config.var_token_estimate, unbound=n_unbound))
        if static_tokens >= config.near_budget_ratio * budget:
            diagnostics.append(self._near_budget_diag(ctx, tid, budget, static_tokens, config.near_budget_ratio))
        return diagnostics

    def _approx_diag(self, ctx: TemplateContext, count: TokenCount, config: LintConfig) -> Diagnostic:
        message, extra = _approx_message(count, config)
        return Diagnostic(rule=RuleId.PTOK, sub_code='approx-tokenizer', severity=severity_for(RuleId.PTOK, 'approx-tokenizer'), message=message, file=ctx.file, line=1, m2_anchor=anchor_for(RuleId.PTOK, 'approx-tokenizer'), extra=extra)

    def _budget_unknown_diag(self, ctx: TemplateContext, tokenizer_id: str, reason: str, static_tokens: int | None=None) -> Diagnostic:
        message, _asserted = render(RuleId.PTOK, 'budget-unknown', reason)
        extra: dict[str, object] = {'tokenizer': tokenizer_id}
        if static_tokens is not None:
            extra['static_tokens'] = static_tokens
        return Diagnostic(rule=RuleId.PTOK, sub_code='budget-unknown', severity=severity_for(RuleId.PTOK, 'budget-unknown'), message=message, file=ctx.file, line=1, m2_anchor=anchor_for(RuleId.PTOK, 'budget-unknown'), extra=extra)

    def _over_budget_diag(self, ctx: TemplateContext, tokenizer_id: str, budget: int, count: int) -> Diagnostic:
        message, extra = render(RuleId.PTOK, 'static-over-budget', static_tokens=count, budget=budget, tokenizer=tokenizer_id)
        return Diagnostic(rule=RuleId.PTOK, sub_code='static-over-budget', severity=severity_for(RuleId.PTOK, 'static-over-budget'), message=message, file=ctx.file, line=1, m2_anchor=anchor_for(RuleId.PTOK, 'static-over-budget'), extra=extra)

    def _estimated_over_diag(self, ctx: TemplateContext, tokenizer_id: str, budget: int, count: int, estimate: int, unbound: int) -> Diagnostic:
        message, asserted = render(RuleId.PTOK, 'estimated-over-budget', static_tokens=count, budget=budget)
        return Diagnostic(rule=RuleId.PTOK, sub_code='estimated-over-budget', severity=severity_for(RuleId.PTOK, 'estimated-over-budget'), message=message, file=ctx.file, line=1, m2_anchor=anchor_for(RuleId.PTOK, 'estimated-over-budget'), extra={'tokenizer': tokenizer_id, 'var_token_estimate': estimate, 'unbound_vars': unbound, **asserted})

    def _near_budget_diag(self, ctx: TemplateContext, tokenizer_id: str, budget: int, count: int, ratio: float) -> Diagnostic:
        message, asserted = render(RuleId.PTOK, 'near-budget', static_tokens=count, ratio=ratio, budget=budget)
        return Diagnostic(rule=RuleId.PTOK, sub_code='near-budget', severity=severity_for(RuleId.PTOK, 'near-budget'), message=message, file=ctx.file, line=1, m2_anchor=anchor_for(RuleId.PTOK, 'near-budget'), extra={'tokenizer': tokenizer_id, **asserted})
