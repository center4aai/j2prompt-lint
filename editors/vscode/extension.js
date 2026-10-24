// VS Code client for Jinja2 prompt templates.
// Runs the installed CLI with JSON output on open/save and publishes diagnostics.
// PINJ related information carries the tool's complete scope statement.

"use strict";

const path = require("path");
const { execFile } = require("child_process");
const vscode = require("vscode");

const LINTABLE_EXTENSIONS = [".j2", ".jinja", ".jinja2"];

function isLintable(document) {
  return LINTABLE_EXTENSIONS.includes(
    path.extname(document.uri.fsPath).toLowerCase()
  );
}

function severityOf(severity) {
  if (severity === "error") return vscode.DiagnosticSeverity.Error;
  if (severity === "warning") return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

function runLinter(executable, file, cwd) {
  return new Promise((resolve, reject) => {
    execFile(
      executable,
      [file, "--format", "json"],
      { cwd, maxBuffer: 16 * 1024 * 1024 },
      (error, stdout) => {
        // A non-zero exit code still carries the envelope (gate semantics);
        // only an empty stdout is a real spawn/run failure.
        if (stdout && stdout.trim().length > 0) return resolve(stdout);
        reject(error || new Error("empty linter output"));
      }
    );
  });
}

function toDiagnostics(envelope, documentUri) {
  const pinjScope =
    envelope.rules && envelope.rules.PINJ ? envelope.rules.PINJ.scope : null;
  const diagnostics = [];
  for (const entry of envelope.diagnostics || []) {
    // CLI diagnostic positions are 1-based.
    const line = Math.max(0, (entry.line || 1) - 1);
    const col = Math.max(0, (entry.col || 1) - 1);
    const range = new vscode.Range(line, col, line, col);
    const diagnostic = new vscode.Diagnostic(
      range,
      entry.message,
      severityOf(entry.severity)
    );
    diagnostic.source = "j2prompt-lint";
    diagnostic.code = `${entry.rule}/${entry.sub_code}`;
    if (entry.rule === "PINJ" && pinjScope) {
      diagnostic.relatedInformation = [
        new vscode.DiagnosticRelatedInformation(
          new vscode.Location(documentUri, range),
          `PINJ scope: ${pinjScope}`
        ),
      ];
    }
    diagnostics.push(diagnostic);
  }
  for (const err of envelope.syntax_errors || []) {
    const line = Math.max(0, (err.line || 1) - 1);
    const range = new vscode.Range(line, 0, line, 0);
    const diagnostic = new vscode.Diagnostic(
      range,
      `syntax error: ${err.message}`,
      vscode.DiagnosticSeverity.Error
    );
    diagnostic.source = "j2prompt-lint";
    diagnostics.push(diagnostic);
  }
  return diagnostics;
}

// This is an execution fact from the linter, never a guess from an empty
// Problems panel. Status is shown when supplied by the JSON envelope.
function pinjSourceNotice(envelope) {
  const analysis = envelope.analysis && envelope.analysis.PINJ;
  if (
    !analysis ||
    !Array.isArray(analysis.files) ||
    analysis.files.length === 0 ||
    !Number.isInteger(analysis.no_sources) ||
    analysis.no_sources < 1 ||
    analysis.no_sources > analysis.files.length
  ) {
    return null;
  }
  const total = analysis.files.length;
  const count = analysis.no_sources;
  const text =
    count === total
      ? "$(info) PINJ: no sources traced"
      : `$(info) PINJ: no sources in ${count}/${total} files`;
  const hint = typeof analysis.hint === "string" ? analysis.hint : "";
  const scope = typeof analysis.scope === "string" ? analysis.scope : "";
  const details = [
    `PINJ traced no untrusted sources in ${count} of ${total} file(s).`,
    hint,
    scope,
  ]
    .filter(Boolean)
    .join("\n");
  return { text, details };
}

// Node's spawn raises ENOENT when the executable cannot be located on PATH.
// That is a configuration fault (linter not installed, or a wrong
// j2promptLint.path) — categorically different from a linter that ran and
// produced output — so it warrants a user-facing hint, not just a silent line
// in the output channel where a first-time user would never look.
function isExecutableNotFound(error) {
  return Boolean(error) && error.code === "ENOENT";
}

const CONFIGURE_PATH_ACTION = "Configure path…";

function warnExecutableNotFound(executable) {
  vscode.window
    .showWarningMessage(
      `j2prompt-lint: linter executable "${executable}" was not found. ` +
        `Install it (pip install j2prompt-lint) so it is on PATH, or set ` +
        `"j2promptLint.path" to the executable's absolute location.`,
      CONFIGURE_PATH_ACTION
    )
    .then((choice) => {
      if (choice === CONFIGURE_PATH_ACTION) {
        vscode.commands.executeCommand(
          "workbench.action.openSettings",
          "j2promptLint.path"
        );
      }
    });
}

function activate(context) {
  const collection =
    vscode.languages.createDiagnosticCollection("j2prompt-lint");
  const output = vscode.window.createOutputChannel("j2prompt-lint");
  const pinjStatus = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100
  );
  pinjStatus.name = "j2prompt-lint PINJ source analysis";
  pinjStatus.command = "j2promptLint.showPinjStatus";
  context.subscriptions.push(collection, output, pinjStatus);

  // Status follows the active document. Saving other open templates cannot
  // overwrite it; mixed run states name exactly the no-source subset.
  const sourceNotices = new Map();
  const lintRequests = new Map();
  const activeNotice = () => {
    const editor = vscode.window.activeTextEditor;
    return editor ? sourceNotices.get(editor.document.uri.toString()) : null;
  };
  const showSourceStatus = () => {
    const notice = activeNotice();
    if (!notice) {
      pinjStatus.hide();
      return;
    }
    pinjStatus.text = notice.text;
    pinjStatus.tooltip = `${notice.details}\nClick for details.`;
    pinjStatus.show();
  };
  context.subscriptions.push(
    vscode.commands.registerCommand("j2promptLint.showPinjStatus", () => {
      const notice = activeNotice();
      if (!notice) return;
      output.appendLine(notice.details);
      output.show(true);
    }),
    vscode.window.onDidChangeActiveTextEditor(showSourceStatus)
  );

  // The missing-executable warning fires once per broken episode: shown on the
  // first ENOENT, then re-armed only after a successful run. Fixing the path
  // (or reintroducing the fault) surfaces at most one dialog each time, so
  // open/save churn never spams the user.
  let executableMissingNotified = false;

  const lintDocument = async (document) => {
    if (!isLintable(document)) return;
    const key = document.uri.toString();
    // A unique token also distinguishes a reopened URI from a closed request.
    // Only the latest outstanding run may update diagnostics or disclosures.
    const request = {};
    lintRequests.set(key, request);
    const executable = vscode.workspace
      .getConfiguration("j2promptLint")
      .get("path", "j2prompt-lint");
    const folder = vscode.workspace.getWorkspaceFolder(document.uri);
    const cwd = folder
      ? folder.uri.fsPath
      : path.dirname(document.uri.fsPath);
    try {
      const stdout = await runLinter(executable, document.uri.fsPath, cwd);
      if (lintRequests.get(key) !== request) return;
      const envelope = JSON.parse(stdout);
      collection.set(document.uri, toDiagnostics(envelope, document.uri));
      const notice = pinjSourceNotice(envelope);
      if (notice) sourceNotices.set(key, notice);
      else sourceNotices.delete(key);
      showSourceStatus();
      executableMissingNotified = false;
    } catch (error) {
      if (lintRequests.get(key) !== request) return;
      sourceNotices.delete(key);
      showSourceStatus();
      output.appendLine(`${document.uri.fsPath}: ${error.message}`);
      if (isExecutableNotFound(error) && !executableMissingNotified) {
        executableMissingNotified = true;
        warnExecutableNotFound(executable);
      }
    }
  };

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(lintDocument),
    vscode.workspace.onDidSaveTextDocument(lintDocument),
    vscode.workspace.onDidCloseTextDocument((document) => {
      lintRequests.delete(document.uri.toString());
      collection.delete(document.uri);
      sourceNotices.delete(document.uri.toString());
      showSourceStatus();
    })
  );
  // Lint templates that are already open when the extension activates.
  vscode.workspace.textDocuments.forEach(lintDocument);
  showSourceStatus();
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
  toDiagnostics,
  isExecutableNotFound,
  pinjSourceNotice,
};
