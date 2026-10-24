# Browser playground

The playground runs the same `j2prompt-lint` wheel as the command-line tool
inside a Web Worker with Pyodide. Open or paste a template, select its variable,
taint-source and budget options, then inspect source-located diagnostics or
the CLI's text, JSON, SARIF and fix-preview output. Template bytes stay in the
browser's in-memory filesystem. The page fetches static runtime assets and
the pinned wheel, and uses no model or analysis server.

The browser handles one file at a time. Use the installed CLI for whole
projects and their local include trees. The pinned browser runtime omits the
tokenizer dependency, so PTOK discloses an unknown count and the interface
withholds a pass/fail verdict while a budget is set. Installing the same wheel
locally enables its pinned reference tokenizer. Exact model-native counts need
the appropriate optional tokenizer configuration and local cache.

PINJ displays whether its bounded analysis engaged, had no sources, was
disabled or was not applicable. An empty diagnostic list does not establish
that untrusted flow was checked. Its selected source model is shown separately
from finding counts.

## Build and serve

Use the universal release wheel named in `pins.json`. Set the wheel filename,
version and SHA256 to the published artifact before building. The builder
refuses a mismatched wheel. Run these commands from the repository root:

```text
python web/build_site.py fetch --assets web/.cache/assets
python web/build_site.py build --assets web/.cache/assets --wheel PATH_TO_RELEASE_WHEEL --out web/_site
python web/build_site.py serve --site web/_site --port 8000
```

Open `http://127.0.0.1:8000/`. The output is a static site and can be served by
an HTTPS static host. Keep every generated runtime, wheel, script and example
file together. The build manifest records file sizes and digests. No shell
escape, API key, account or backend service is required to use the playground.

## Scope and prior work

- Static prompt linting predates this tool in
  [PromptSet](https://arxiv.org/abs/2402.16932).
- LLM judging predates it in
  [PromptDoctor](https://doi.org/10.1109/ESEM64174.2025.00067) and
  [Microsoft Chat Customizations Evaluations](https://marketplace.visualstudio.com/items?itemName=ms-vscode.vscode-chat-customizations-evaluations).
  PromptDoctor additionally executes attacks and performs LLM-based repair.
- PINJ is a bounded taint-surface linter, not a prompt-injection defense.
- The five rule classes align with an
  [existing taxonomy](https://arxiv.org/abs/2509.14404). They do not define a
  comprehensive taxonomy of prompt defects.
- Structural checks do not establish semantic prompt quality, resolve
  contradictions or determine a model's intended behavior.
- Jinja2 variable-contract checking and framework message validation are
  established, including [promptkit-core](https://github.com/ochotzas/promptkit-core)
  and [promptflow](https://github.com/microsoft/promptflow).
- Render-free Jinja2-AST security auditing predates it, including
  [c4nary](https://github.com/paraxaQQ/canary),
  [glyphhound](https://github.com/ydarwish1/glyphhound) and
  [chatpin](https://github.com/cloudpayload/chatpin). c4nary also propagates
  taint to identify template-planted instructions. PINJ assumes a trusted
  template and asks about untrusted values.
- Region-aware host-code injection taint predates it in
  [CodeQL](https://github.com/github/codeql). TaintP2X and agentic-guard also
  analyze host code.
- Chat-format conformance checking predates it, including
  [ChatLint](https://github.com/dimondevceo/ChatLint) through rendering and
  [gguf-template-doctor](https://github.com/N-Combinator/gguf-template-doctor)
  through scanning. PCHAT checks bounded conditions on the Jinja2 AST.

PINJ flags template positions where untrusted variables reach instruction
contexts, an over-approximation of prompt-injection enabling patterns.
It certifies neither the presence nor the absence of an exploitable attack.
The source model decides which variables are untrusted. Marking no variable
untrusted leaves no untrusted flow to check. No performance, energy, precision,
recall or coverage-superiority claim follows from a quiet run.
