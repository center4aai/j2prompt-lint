# j2prompt-lint

A static, model-free linter for Jinja2 LLM prompt templates. Inspect variable
contracts, chat-format markers, instruction-context taint surfaces, token budgets
and formatting through a command line, Python API or browser playground.

Repository: <https://github.com/center4aai/j2prompt-lint>.

## Browser playground

The ready-to-use application is in `docs/`, including its Python/WebAssembly
runtime and the same 0.1.0 wheel used by the command-line tool. Serve it locally:

```sh
python web/build_site.py serve --site docs --port 8000
```

Open <http://127.0.0.1:8000/>. Use HTTP rather than opening the HTML as a local
file. Templates are analysed in a browser Web Worker. The browser supports one
file at a time; its runtime reports an unavailable token count because it omits
the tokenizer dependency.

To host this application on GitHub Pages, select **Settings → Pages → Deploy
from a branch**, then choose **main** and **/docs**. The included `.nojekyll`
marker lets Pages serve the static assets directly.

## Install

The command-line package requires Python 3.11 or newer; Python 3.12 is a useful
choice. Install the wheel included in this repository into your chosen Python
environment:

```sh
python -m pip install ./dist/j2prompt_lint-0.1.0-py3-none-any.whl
j2prompt-lint --help
```

Alternatively, with uv:

```sh
uv tool install --python 3.12 ./dist/j2prompt_lint-0.1.0-py3-none-any.whl
```

Installation resolves Python dependencies. Ordinary analysis runs locally;
the base installation includes its reference tokenizer. The source distribution
is also included at `dist/j2prompt_lint-0.1.0.tar.gz`.

## Try the included examples

Run commands from the repository root:

```sh
j2prompt-lint examples/templates/clean.j2 --format json
j2prompt-lint examples/templates/pvar_contract.j2
j2prompt-lint examples/templates/pchat_missing_eot.j2
j2prompt-lint examples/templates/pinj_taint.j2 --untrusted customer_note --fail-on warning
j2prompt-lint examples/templates/ptok_budget.j2 --budget 24
j2prompt-lint examples/templates/pfmt_layout.j2 --diff
```

Review a formatting diff before applying it:

```sh
j2prompt-lint examples/templates/pfmt_layout.j2 --fix
```

`--diff` previews supported PFMT edits; `--fix` writes them. JSON and SARIF are
available with `--format json` and `--format sarif`. `--fail-on` selects the
minimum failing severity: `error`, `warning` or `info`. Exit status 0 passes that
configured gate, 1 reports a matching diagnostic or parse error, and 2 reports
an invocation, configuration or file-access error.

## Checks and configuration

| Class | Template concern |
|---|---|
| PVAR | Variable use against explicit contracts and supported definition flow. |
| PCHAT | Bounded chat-format conditions for supported marker families. |
| PINJ | Selected untrusted values reaching recognised instruction contexts. |
| PTOK | Static text and variable estimates against a configured token budget. |
| PFMT | Whitespace, blank lines, indentation, newlines and Jinja delimiter layout. |

Use `.j2prompt-lint.toml` or `[tool.j2prompt-lint]` in `pyproject.toml`:

```toml
declared = ["customer_name", "customer_note"]
untrusted = ["customer_note"]
token_budget = 4096
```

Inspect resolved settings with `j2prompt-lint --show-config`, or a rule's scope
with `j2prompt-lint --explain PINJ`. Template annotations can also declare
required variables and untrusted values.

## PINJ

PINJ flags template positions where untrusted variables reach instruction
contexts, an over-approximation of prompt-injection enabling patterns. It
certifies neither the presence nor the absence of an exploitable attack.

The configured source model combines explicit source names and template
annotations, such as `{# j2pl: untrusted(customer_note) #}`. Inspect the PINJ
check state alongside the findings. `--pinj-source-model undeclared` additionally
uses undeclared variables as sources. PINJ assumes a trusted template and
examines its handling of untrusted values.

## Python and editors

```python
from j2prompt_lint.core.config import LintConfig
from j2prompt_lint.core.engine import lint_text

config = LintConfig(declared_vars=frozenset({"customer_name"}))
result = lint_text("greeting.j2", "Hello {{ customer_name }}.\n", config)
for item in result.diagnostics:
    print(item.line, item.col, item.code, item.message)
```

The installed `j2prompt-lint-lsp` command supplies a stdio language server.
The optional [VS Code client source](editors/vscode/) displays CLI diagnostics
on opening or saving a template. Its README explains configuration and local
packaging. The root `.pre-commit-hooks.yaml` defines hook ID `j2prompt-lint` for
repositories that use this package as a pre-commit hook provider.

## Scope and prior work

- [PromptSet](https://doi.org/10.1145/3643795.3648395) introduced static prompt
  linting and surface passes. The five classes follow
  [Tian et al.'s taxonomy](https://arxiv.org/abs/2509.14404).
- [PromptDoctor](https://doi.org/10.1109/ESEM64174.2025.00067) and
  [Microsoft Chat Customizations Evaluations](https://marketplace.visualstudio.com/items?itemName=ms-vscode.vscode-chat-customizations-evaluations)
  use model judging; PromptDoctor adds attack execution and model-based repair.
  Semantic assessment concerns consistency, contradiction, ambiguity, persona
  consistency, intent coverage and intended model behavior. AST rules analyse
  source structure and contracts.
- Variable contracts and framework message validation are established checks,
  including [promptkit-core](https://github.com/ochotzas/promptkit-core) and
  [promptflow](https://github.com/microsoft/promptflow).
- PINJ applies information-flow and taint analysis within Jinja2 templates.
  Render-free Jinja2-AST auditors include
  [glyphhound](https://github.com/ydarwish1/glyphhound) and
  [chatpin](https://github.com/cloudpayload/chatpin) audit template ASTs;
  [c4nary](https://github.com/paraxaQQ/canary) propagates taint to identify
  template-planted instructions. [CodeQL](https://github.com/github/codeql)
  provides region-aware host-code taint analysis; TaintP2X and agentic-guard
  also analyse host code.
- [ChatLint](https://github.com/dimondevceo/ChatLint) checks rendered chat
  conformance and [gguf-template-doctor](https://github.com/N-Combinator/gguf-template-doctor)
  scans templates. PCHAT checks bounded conditions on the Jinja2 AST. Token
  counts depend on the selected tokenizer and supported static approximation.

Licensed under [Apache-2.0](LICENSE).
