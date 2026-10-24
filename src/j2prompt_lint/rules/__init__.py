from __future__ import annotations
from j2prompt_lint.core.rule import Rule
from j2prompt_lint.rules.pchat import PchatRule
from j2prompt_lint.rules.pfmt import PfmtRule, PfmtTextRule
from j2prompt_lint.rules.pinj import PinjRule
from j2prompt_lint.rules.ptok import PtokRule
from j2prompt_lint.rules.pvar import PvarRule

def default_rules() -> list[Rule]:
    return [PvarRule(), PchatRule(), PinjRule(), PtokRule(), PfmtRule()]

def markdown_rules() -> list[Rule]:
    return [PinjRule(), PtokRule(), PfmtTextRule()]
