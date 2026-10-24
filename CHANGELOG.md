# Changelog

## 0.1.0

- Static Jinja2 checks for variable contracts, chat-format conditions, instruction-context taint surfaces, token budgets, and formatting.
- CLI text, JSON and SARIF output, severity thresholds, resolved configuration display, and rule-class explanations.
- Explicit contracts and source annotations, TOML project settings, and the built-in PINJ profile.
- Reviewable formatting diffs and supported PFMT fixes.
- Python string/file APIs, stdio language server, VS Code client, pre-commit and SARIF integration examples.
- Bundled reference tokenizer with approximation and fallback disclosures.

## Tool scope and prior work

- Static prompt linting and spelling/whitespace passes predate this tool, including PromptSet on Python-extracted prompt strings.
- PromptDoctor and Microsoft Chat Customizations Evaluations use LLM judging; PromptDoctor also executes attacks and applies LLM repair. Static analysis complements those capabilities.
- PINJ follows information-flow and taint-analysis practice. It is a bounded taint-surface linter, not an inference-time attack detector or prompt-injection defense.
- The five operational classes align with Tian and colleagues' taxonomy; they are not a comprehensive new taxonomy of prompt defects.
- Structural checks do not establish semantic quality, resolve contradiction, ambiguity, persona consistency or intent coverage, or guarantee model behavior.
- Static Jinja2 variable contracts and framework message-tag/list validation are prior art, including Jinja2 meta, LangChain, Haystack, banks, promptflow and promptkit-core; existing tools also check declared-but-unused variables.
- glyphhound, c4nary and chatpin perform render-free audits on the Jinja2 AST. c4nary propagates template taint and detects planted instructions. These auditors address malicious templates; PINJ examines untrusted values under a trusted template.
- CodeQL provides region-aware prompt-injection taint analysis in host code. TaintP2X and agentic-guard also analyze host code. PINJ applies source, sink and sanitizer reasoning within the template.
- Chat-format conformance is prior art: ChatLint checks rendered conversations and gguf-template-doctor uses a static scanner. PCHAT checks declared conditions on the Jinja2 AST, without a claim of firstness.

PINJ flags template positions where untrusted variables reach instruction contexts — an over-approximation of prompt-injection enabling patterns — and certifies neither the presence nor the absence of an exploitable attack.
