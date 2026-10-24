# j2prompt-lint for VS Code

This client displays Jinja2 prompt-template diagnostics in VS Code's Problems
panel. It runs the installed `j2prompt-lint` command with JSON output on opening
or saving `.j2`, `.jinja`, and `.jinja2` files. The current file on disk is the
input; unsaved changes are analysed by the separate stdio language server.

## Install and configure

Install the Python command from a released wheel or package version using the
[tool installation instructions](../../README.md#install). To install a packaged
VSIX client, use **Extensions: Install from VSIX** in VS Code, or:

```sh
code --install-extension j2prompt-lint-vscode-<client-version>.vsix
```

The client version and Python tool version are separate. This command describes
sideloading a VSIX; it does not require a Marketplace listing.

If `j2prompt-lint` is on the editor's PATH, the default executable setting works.
Otherwise set `j2promptLint.path` to its absolute path. On Windows this can be the
`j2prompt-lint.exe` inside the chosen Python environment's `Scripts` directory.
The executable must be installed on the same machine or remote environment in
which the VS Code extension host runs.

Open or save a template to populate Problems. Rule codes and severities come
from the CLI. Source positions are converted from 1-based CLI coordinates to
0-based editor coordinates. PINJ findings include the tool's complete scope
statement as related information.

When the tool reports no selected PINJ source, the status bar displays that state;
click it to show details in the j2prompt-lint output channel. An empty Problems
panel is not a security verdict. A missing executable produces a configuration
warning and a **Configure path…** action.

## Language-server clients

The Python package also provides `j2prompt-lint-lsp`, a JSON-RPC language server
over standard input/output. Configure it as a stdio server in an LSP-capable
editor for open-buffer diagnostics and supported quick fixes. This VS Code
client uses the CLI route rather than starting that server.

## Package or launch the client source

From this directory, `npx @vscode/vsce package` creates a VSIX containing the
client. To inspect it in an extension host, open this directory as the VS Code
workspace and run the included **Run Extension** launch configuration. The
Python linter must still be installed and configured. Example templates are
included at [examples/templates](../../examples/templates/).

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
