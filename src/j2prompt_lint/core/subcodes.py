from __future__ import annotations
import re
import string
from collections.abc import Mapping
from dataclasses import dataclass
from j2prompt_lint.core.model import RuleId, Severity
ONLY = ''
_PVAR_UNDECLARED = 'mypy undefined-name / ESLint no-undef'
_PVAR_UNUSED = 'ESLint no-unused-vars / ruff F841'
_PVAR_USE_BEFORE = 'ESLint no-use-before-define'
_PVAR_TYPO = 'mypy / pyright did-you-mean identifier suggestion'
_PVAR_POSSIBLY_UNBOUND = 'mypy possibly-undefined / pyright reportPossiblyUnbound'
_PVAR_INFERRED_INTERFACE = 'mypy reveal_type / stubgen inferred-interface surfacing'
_PVAR_UNKNOWN_DIRECTIVE = 'mypy unused-ignore / ruff RUF100 unknown-pragma'
_PCHAT_CLASS = 'ESLint Possible Problems (adapted)'
_PINJ_CLASS = 'bandit / eslint-plugin-security'
_PTOK_CLASS = 'performance/budget'
_PFMT_CLASS = 'ruff/SQLFluff layout / Prettier/black'
_NO_ANTECEDENT = 'no direct antecedent (tool-state disclosure)'

def placeholders(template: str) -> frozenset[str]:
    return frozenset((name for _text, name, _spec, _conv in string.Formatter().parse(template) if name))

def _renders_to(template: str, message: str) -> bool:
    pattern = ''.join((re.escape(text) + ('(?s:.*?)' if name is not None else '') for text, name, _spec, _conv in string.Formatter().parse(template)))
    return re.fullmatch(pattern, message) is not None

@dataclass(frozen=True, slots=True)
class SubCodeSpec:
    rule: RuleId
    sub_code: str
    m2_anchor: str
    severity: Severity
    description: str
    messages: Mapping[str, str]
    extra_keys: frozenset[str] = frozenset()

    @property
    def code(self) -> str:
        return f'{self.rule.value}/{self.sub_code}'

    def placeholders(self) -> frozenset[str]:
        found: frozenset[str] = frozenset()
        for template in self.messages.values():
            found |= placeholders(template)
        return found

    def asserted_in(self, message: str) -> frozenset[str]:
        matched = [placeholders(template) for template in self.messages.values() if _renders_to(template, message)]
        if not matched:
            return self.placeholders()
        return frozenset.intersection(*matched)

def _spec(rule: RuleId, sub_code: str, m2_anchor: str, severity: Severity, message: str, *, description: str, extra_keys: frozenset[str]=frozenset()) -> SubCodeSpec:
    return SubCodeSpec(rule, sub_code, m2_anchor, severity, description, {ONLY: message}, extra_keys)

def _variants(rule: RuleId, sub_code: str, m2_anchor: str, severity: Severity, messages: Mapping[str, str], *, description: str, extra_keys: frozenset[str]=frozenset()) -> SubCodeSpec:
    return SubCodeSpec(rule, sub_code, m2_anchor, severity, description, dict(messages), extra_keys)
_PVAR: tuple[SubCodeSpec, ...] = (_spec(RuleId.PVAR, 'used-undeclared', _PVAR_UNDECLARED, Severity.ERROR, "variable '{name}' is used but not in the declared variable contract", description='A variable is used in the template but is not in the declared variable contract.', extra_keys=frozenset({'name'})), _spec(RuleId.PVAR, 'unused-required', _PVAR_UNUSED, Severity.WARNING, "required variable '{name}' is declared but never used", description='A variable is declared required but is never referenced in the template.', extra_keys=frozenset({'name'})), _spec(RuleId.PVAR, 'branch-only-def', _PVAR_POSSIBLY_UNBOUND, Severity.WARNING, "variable '{name}' is defined only inside a conditional branch but used unconditionally", description='A variable is defined only inside one conditional branch but is used unconditionally afterwards.', extra_keys=frozenset({'name'})), _spec(RuleId.PVAR, 'use-before-set', _PVAR_USE_BEFORE, Severity.WARNING, "variable '{name}' is used before it is set", description='A variable is used in output before its own set statement on all statically-determinable paths.', extra_keys=frozenset({'name'})), _spec(RuleId.PVAR, 'inferred-contract', _PVAR_INFERRED_INTERFACE, Severity.INFO, 'inferred required variables: {names}', description="The template's inferred required-variable interface, surfaced rather than checked because no contract was declared to compare it against.", extra_keys=frozenset({'names'})), _spec(RuleId.PVAR, 'likely-typo', _PVAR_TYPO, Severity.INFO, "variable '{name}' may be a typo of '{candidate}'", description='A used variable is a near-duplicate of another declared or used name — a ranked, opt-in suggestion, at most one per similar pair.', extra_keys=frozenset({'name', 'candidate'})), _spec(RuleId.PVAR, 'unknown-directive', _PVAR_UNKNOWN_DIRECTIVE, Severity.INFO, "unknown j2pl: directive '{directive}' — ignored", description='An in-source j2pl: directive the parser does not recognise, reported rather than obeyed or silently dropped.', extra_keys=frozenset({'directive'})))
_PCHAT: tuple[SubCodeSpec, ...] = (_spec(RuleId.PCHAT, 'missing-eot', _PCHAT_CLASS, Severity.ERROR, "{pack} chat template has no end-of-turn token '{eot_token}' anywhere", description="The resolved chat pack's end-of-turn token is absent from the template entirely — a whole-template presence check, not a per- turn one.", extra_keys=frozenset({'pack', 'eot_token'})), _spec(RuleId.PCHAT, 'unbalanced-markers', _PCHAT_CLASS, Severity.ERROR, "unbalanced {pack} turn markers: '{open_marker}' without matching '{close_marker}'", description="The resolved pack's turn markers open a turn while another is still open, proved structurally on the AST rather than by counting text.", extra_keys=frozenset({'pack', 'open_marker', 'close_marker'})), _spec(RuleId.PCHAT, 'ambiguous-format', _NO_ANTECEDENT, Severity.INFO, "multiple chat-format signatures matched ({names}); analysing as '{pack}'", description="More than one chat-format pack signature matched, and the analyser reports which pack it then analysed against — a statement about the tool's own mode selection, not about the template.", extra_keys=frozenset({'pack', 'names'})), _spec(RuleId.PCHAT, 'missing-generation-prompt', _PCHAT_CLASS, Severity.WARNING, 'no add_generation_prompt handling; template may be incompatible with apply_chat_template', description='The template has no add_generation_prompt-conditional opening of the assistant turn, so it may be incompatible with apply_chat_template.', extra_keys=frozenset({'pack'})), _spec(RuleId.PCHAT, 'role-literal', _PCHAT_CLASS, Severity.WARNING, 'roles are hardcoded as string literals; template cannot render multi-turn messages', description='Turn roles are hardcoded as string literals with no messages- loop role variable, so the template cannot render a multi-turn conversation.', extra_keys=frozenset({'pack'})), _spec(RuleId.PCHAT, 'unknown-role', _PCHAT_CLASS, Severity.WARNING, "role '{role}' is not in the {pack} allowed-role set", description="A role value used by the template is not in the resolved pack's allowed-role set.", extra_keys=frozenset({'pack', 'role'})), _spec(RuleId.PCHAT, 'bos-misuse', _PCHAT_CLASS, Severity.WARNING, "{pack} begin-of-sequence token '{bos_token}' is emitted more than once; it should appear once", description="The pack's beginning-of-sequence token appears more than once in the template's literal text — emitted per turn instead of once.", extra_keys=frozenset({'pack', 'bos_token'})))
_PINJ_BASE = frozenset({'tier', 'sink_kind'})
_PINJ_VAR_BEARING = _PINJ_BASE | {'untrusted_var', 'untrusted_basis'}
_PINJ: tuple[SubCodeSpec, ...] = (_spec(RuleId.PINJ, 'taint-surface', _PINJ_CLASS, Severity.WARNING, "taint surface: untrusted variable '{untrusted_var}' reaches an instruction context ({sink_kind})", description='An untrusted variable reaches a Tier-1 recognised instruction region: a chat system region, or an assignment to an instruction-named target.', extra_keys=_PINJ_VAR_BEARING), _spec(RuleId.PINJ, 'taint-surface-whole-prompt', _PINJ_CLASS, Severity.WARNING, "taint surface: untrusted variable '{untrusted_var}' interpolated into a single-string prompt without a data delimiter", description='An untrusted variable is interpolated into a single-string prompt with no chat structure and no enclosing data delimiter, so the whole rendered output is the instruction context (Tier-2, conservative).', extra_keys=_PINJ_VAR_BEARING), _spec(RuleId.PINJ, 'cross-template-surface', _PINJ_CLASS, Severity.WARNING, 'taint surface: untrusted content crosses {include_path} into an instruction context', description='Untrusted content crosses a locally-resolvable include, import or extends into a recognised instruction context.', extra_keys=_PINJ_BASE | {'include_path'}), _spec(RuleId.PINJ, 'dynamic-role-surface', _PINJ_CLASS, Severity.INFO, "taint surface: untrusted variable '{untrusted_var}' reaches a dynamically-built role turn", description='An untrusted variable reaches a dynamically-built role turn; opt-in, and reported separately from the Tier-1 denominator.', extra_keys=_PINJ_VAR_BEARING))
_PTOK: tuple[SubCodeSpec, ...] = (_variants(RuleId.PTOK, 'approx-tokenizer', _PTOK_CLASS, Severity.INFO, {'reference-no-target': 'token counts use the pinned {tokenizer} reference approximation; no target model configured', 'reference-target-unavailable': "token counts use the pinned {tokenizer} reference approximation; the tokenizer for target model '{target_model}' could not be loaded offline", 'explicit-no-target': 'token counts use the {tokenizer} approximation, selected explicitly by configuration', 'explicit-overrides-target': "token counts use the {tokenizer} approximation, selected explicitly by configuration instead of the tokenizer for target model '{target_model}'"}, description="Token counts use an approximate tokenizer instead of the target model's own — a disclosure about the measurement, not a defect in the template.", extra_keys=frozenset({'tokenizer', 'target_model'})), _variants(RuleId.PTOK, 'budget-unknown', _PTOK_CLASS, Severity.INFO, {'tokenizer-unavailable': 'token budget unknown: tokenizer vocabulary unavailable offline', 'no-budget-resolved': 'token budget unknown: no explicit budget and no known context window'}, description='No token budget could be resolved, or the tokenizer vocabulary was unavailable offline, so no budget check was performed.', extra_keys=frozenset({'tokenizer', 'static_tokens'})), _spec(RuleId.PTOK, 'static-over-budget', _PTOK_CLASS, Severity.WARNING, 'static prompt text is {static_tokens} tokens, at or above the {budget}-token budget ({tokenizer})', description='The static literal text alone meets or exceeds the resolved token budget; the variables can only add to it.', extra_keys=frozenset({'tokenizer', 'budget', 'static_tokens'})), _spec(RuleId.PTOK, 'estimated-over-budget', _PTOK_CLASS, Severity.WARNING, 'static text ({static_tokens}) plus estimated variable tokens is at or above the {budget}-token budget', description='The static text is under the budget but meets or exceeds it once the configured per-unbound-variable estimate is added.', extra_keys=frozenset({'tokenizer', 'budget', 'static_tokens', 'var_token_estimate', 'unbound_vars'})), _spec(RuleId.PTOK, 'near-budget', _PTOK_CLASS, Severity.INFO, 'static prompt text ({static_tokens}) is within {ratio} of the {budget}-token budget', description='The static literal text is within the configured ratio of the resolved token budget.', extra_keys=frozenset({'tokenizer', 'budget', 'static_tokens', 'ratio'})))
_PFMT: tuple[SubCodeSpec, ...] = (_spec(RuleId.PFMT, 'trailing-whitespace', _PFMT_CLASS, Severity.WARNING, 'trailing whitespace', description='Trailing spaces or tabs at the end of a line.'), _variants(RuleId.PFMT, 'line-endings', _PFMT_CLASS, Severity.WARNING, {'uniform': '{found} line endings; expected {target}', 'mixed': 'mixed line endings ({styles}); expected {target}'}, description='Line endings that do not match the configured target; the actual endings found are reported.', extra_keys=frozenset({'found', 'styles', 'target'})), _spec(RuleId.PFMT, 'final-newline', _PFMT_CLASS, Severity.WARNING, 'file should end with a single newline', description='The file does not end with exactly one final newline.'), _spec(RuleId.PFMT, 'blank-lines', _PFMT_CLASS, Severity.INFO, 'more than {max_blank} consecutive blank lines', description='More consecutive blank lines than the configured maximum.', extra_keys=frozenset({'max_blank'})), _spec(RuleId.PFMT, 'mixed-indentation', _PFMT_CLASS, Severity.INFO, 'mixed tabs and spaces in indentation', description='Mixed tabs and spaces in leading indentation.'), _variants(RuleId.PFMT, 'jinja-block-whitespace', _PFMT_CLASS, Severity.INFO, {'spaced': "inconsistent whitespace inside Jinja delimiter; expected '{{{{ expr }}}}' style", 'tight': "inconsistent whitespace inside Jinja delimiter; expected '{{{{expr}}}}' style"}, description='Whitespace inside a Jinja delimiter that does not match the configured style.'), _spec(RuleId.PFMT, 'delimiter-spacing', _PFMT_CLASS, Severity.INFO, 'inconsistent spacing around data delimiter', description='Spacing around a recognised data delimiter that does not match the configured style.'))
SUB_CODES: Mapping[tuple[RuleId, str], SubCodeSpec] = {(spec.rule, spec.sub_code): spec for spec in (*_PVAR, *_PCHAT, *_PINJ, *_PTOK, *_PFMT)}

def spec_for(rule: RuleId, sub_code: str) -> SubCodeSpec:
    try:
        return SUB_CODES[rule, sub_code]
    except KeyError:
        raise KeyError(f'unregistered sub-code {rule.value}/{sub_code}') from None

def anchor_for(rule: RuleId, sub_code: str) -> str:
    return spec_for(rule, sub_code).m2_anchor

def severity_for(rule: RuleId, sub_code: str) -> Severity:
    return spec_for(rule, sub_code).severity

def render(rule: RuleId, sub_code: str, variant: str=ONLY, /, **values: object) -> tuple[str, dict[str, object]]:
    messages = spec_for(rule, sub_code).messages
    if variant not in messages:
        raise KeyError(f'{rule.value}/{sub_code}: no message variant {variant!r}')
    template = messages[variant]
    fields = placeholders(template)
    if set(values) != fields:
        raise KeyError(f'{rule.value}/{sub_code} variant {variant!r}: message asserts {sorted(fields)} but was given {sorted(values)}')
    return (template.format(**values), dict(values))
