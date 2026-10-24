from __future__ import annotations
import difflib
from jinja2 import nodes
from j2prompt_lint.core import dataflow
from j2prompt_lint.core.config import LintConfig
from j2prompt_lint.core.context import TemplateContext, first_load_line
from j2prompt_lint.core.model import Diagnostic, RuleId
from j2prompt_lint.core.subcodes import anchor_for, render, severity_for

def _assign_targets(ast: nodes.Template) -> list[tuple[str, int, bool]]:
    under_if_ids: set[int] = set()
    for if_node in ast.find_all(nodes.If):
        for assign in if_node.find_all(nodes.Assign):
            under_if_ids.add(id(assign))
        for block in if_node.find_all(nodes.AssignBlock):
            under_if_ids.add(id(block))
    targets: list[tuple[str, int, bool]] = []
    for assign in ast.find_all(nodes.Assign):
        if isinstance(assign.target, nodes.Name):
            targets.append((assign.target.name, assign.lineno, id(assign) in under_if_ids))
    for block in ast.find_all(nodes.AssignBlock):
        if isinstance(block.target, nodes.Name):
            targets.append((block.target.name, block.lineno, id(block) in under_if_ids))
    return targets

def _names_set_only_under_if(ast: nodes.Template) -> set[str]:
    all_under: dict[str, bool] = {}
    for name, _lineno, under_if in _assign_targets(ast):
        if name in all_under:
            all_under[name] = all_under[name] and under_if
        else:
            all_under[name] = under_if
    return {name for name, only in all_under.items() if only}

def _branch_only_reads(conditional_only: set[str], analysis: tuple[dataflow.Read, ...]) -> dict[str, dataflow.Read]:
    offending: dict[str, dataflow.Read] = {}
    for read in analysis:
        if read.name not in conditional_only or read.binder is not dataflow.Binder.SET:
            continue
        if read.macro is not None or read.guarded or read.assigned:
            continue
        current = offending.get(read.name)
        if current is None or read.lineno < current.lineno:
            offending[read.name] = read
    return offending

def _is_typo_side(ast: nodes.Template, name: str, candidate: str) -> bool:
    name_line = first_load_line(ast, name)
    candidate_line = first_load_line(ast, candidate)
    if name_line != candidate_line:
        return name_line > candidate_line
    return name > candidate

def _declared(ctx: TemplateContext, config: LintConfig) -> frozenset[str] | None:
    directives = ctx.directives
    if directives.required is None and directives.optional is None:
        return config.declared_vars
    return frozenset(directives.required or ()) | frozenset(directives.optional or ())

def _required(ctx: TemplateContext, config: LintConfig) -> frozenset[str] | None:
    directives = ctx.directives
    if directives.required is None and directives.optional is None:
        return config.required_vars
    return directives.required

class PvarRule:
    id: RuleId = RuleId.PVAR

    def check(self, ctx: TemplateContext, config: LintConfig) -> list[Diagnostic]:
        ast = ctx.ast
        used = ctx.undeclared - config.globals_allowlist
        declared = _declared(ctx, config)
        diagnostics: list[Diagnostic] = []
        if declared is not None:
            for name in sorted(used - declared):
                message, extra = render(RuleId.PVAR, 'used-undeclared', name=name)
                diagnostics.append(Diagnostic(rule=RuleId.PVAR, sub_code='used-undeclared', severity=severity_for(RuleId.PVAR, 'used-undeclared'), message=message, file=ctx.file, line=ctx.undeclared_lines[name], m2_anchor=anchor_for(RuleId.PVAR, 'used-undeclared'), extra=extra))
            required = _required(ctx, config)
            if required is not None:
                for name in sorted(required - used):
                    message, extra = render(RuleId.PVAR, 'unused-required', name=name)
                    diagnostics.append(Diagnostic(rule=RuleId.PVAR, sub_code='unused-required', severity=severity_for(RuleId.PVAR, 'unused-required'), message=message, file=ctx.file, line=1, m2_anchor=anchor_for(RuleId.PVAR, 'unused-required'), extra=extra))
        elif config.infer_contract and used:
            message, extra = render(RuleId.PVAR, 'inferred-contract', names=sorted(used))
            diagnostics.append(Diagnostic(rule=RuleId.PVAR, sub_code='inferred-contract', severity=severity_for(RuleId.PVAR, 'inferred-contract'), message=message, file=ctx.file, line=1, m2_anchor=anchor_for(RuleId.PVAR, 'inferred-contract'), extra=extra))
        targets = frozenset((name for name, _line, _under in _assign_targets(ast)))
        analysis = dataflow.reads(ast, targets)
        conditional_only = _names_set_only_under_if(ast)
        branch_only = _branch_only_reads(conditional_only, analysis)
        for name in sorted(branch_only):
            message, extra = render(RuleId.PVAR, 'branch-only-def', name=name)
            diagnostics.append(Diagnostic(rule=RuleId.PVAR, sub_code='branch-only-def', severity=severity_for(RuleId.PVAR, 'branch-only-def'), message=message, file=ctx.file, line=branch_only[name].lineno, m2_anchor=anchor_for(RuleId.PVAR, 'branch-only-def'), extra=extra))
        for name in sorted(targets - conditional_only):
            read = dataflow.first_unbound_read(analysis, name)
            if read is not None:
                message, extra = render(RuleId.PVAR, 'use-before-set', name=name)
                diagnostics.append(Diagnostic(rule=RuleId.PVAR, sub_code='use-before-set', severity=severity_for(RuleId.PVAR, 'use-before-set'), message=message, file=ctx.file, line=read.lineno, m2_anchor=anchor_for(RuleId.PVAR, 'use-before-set'), extra=extra))
        if config.likely_typo:
            base = declared or frozenset()
            candidates = sorted(base | used)
            nearest: dict[str, str] = {}
            for name in sorted(used - base):
                others = [c for c in candidates if c != name]
                match = difflib.get_close_matches(name, others, n=1, cutoff=config.typo_cutoff)
                if match:
                    nearest[name] = match[0]
            for name, candidate in nearest.items():
                if nearest.get(candidate) == name and (not _is_typo_side(ast, name, candidate)):
                    continue
                message, extra = render(RuleId.PVAR, 'likely-typo', name=name, candidate=candidate)
                diagnostics.append(Diagnostic(rule=RuleId.PVAR, sub_code='likely-typo', severity=severity_for(RuleId.PVAR, 'likely-typo'), message=message, file=ctx.file, line=first_load_line(ast, name), m2_anchor=anchor_for(RuleId.PVAR, 'likely-typo'), extra=extra))
        for directive in ctx.directives.unknown:
            message, extra = render(RuleId.PVAR, 'unknown-directive', directive=directive.text)
            diagnostics.append(Diagnostic(rule=RuleId.PVAR, sub_code='unknown-directive', severity=severity_for(RuleId.PVAR, 'unknown-directive'), message=message, file=ctx.file, line=directive.line, m2_anchor=anchor_for(RuleId.PVAR, 'unknown-directive'), extra=extra))
        return diagnostics
