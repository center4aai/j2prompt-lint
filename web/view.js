// j2prompt-lint playground: rendering one lint's results.
//
// Everything shown comes from the CLI: the diagnostics list and the summary
// from its JSON envelope, the Text, SARIF and Fix-preview panels from its own
// output for those flags. Template content only ever reaches the page as text
// nodes, never as markup.

import { $, jumpTo, renderGutter } from "./editor.js";

const LOCATION_PREFIX = /^(.+?):(\d+):(\d+):/;
const SYNTAX_PREFIX = /^(.+?):(\d+): syntax error:/;
const NO_CHANGE = /^\n?0 file\(s\) would change\s*$/;

export function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
}

export function showSummary(counts, gate, timing) {
  $("summary-counts").textContent = counts;
  $("summary-gate").textContent = gate;
  $("summary-gate").dataset.gate = "";
  $("summary-timing").textContent = timing;
  $("pinj-analysis").textContent = "";
}

const PINJ_STATES = Object.freeze({
  enabled: "bounded untrusted-flow analysis engaged; no safety verdict",
  "no-sources": "no untrusted sources to trace; no untrusted flow was checked",
  disabled: "disabled",
  "not-selected": "not selected",
  "parse-error": "not checked because the template did not parse",
  unknown: "execution state unknown",
});

export function pinjStatus(envelope, argv) {
  const analysis = envelope.analysis?.PINJ;
  const files = analysis?.files;
  if (!Array.isArray(files) || files.length === 0) {
    return "PINJ execution state unavailable; a quiet result establishes no coverage or safety.";
  }
  const option = argv.indexOf("--pinj-source-model");
  const model = option >= 0 ? argv[option + 1] : "configured";
  const states = files.map(({ file, state }) => `${file}: ${PINJ_STATES[state] ?? PINJ_STATES.unknown}`);
  const hint = files.some(({ state }) => state === "no-sources") ? ` ${analysis.hint ?? ""}` : "";
  return `PINJ (${model} source model): ${states.join("; ")}.${hint}`;
}

function plural(count, noun) {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function locationButton(file, line, col) {
  const button = element("button", "location", col ? `${file}:${line}:${col}` : `${file}:${line}`);
  button.type = "button";
  button.setAttribute("aria-label", `Go to line ${line}${col ? `, column ${col}` : ""} in the editor`);
  button.addEventListener("click", () => jumpTo(line, col || 1));
  return button;
}

function diagnosticDetails(diag) {
  const details = [];
  if (diag.m2_anchor) {
    details.push(`PL-tooling analogue: ${diag.m2_anchor}`);
  }
  if (diag.extra) {
    const pairs = Object.keys(diag.extra)
      .sort()
      .map((key) => `${key}=${JSON.stringify(diag.extra[key])}`);
    if (pairs.length) {
      details.push(`extra: ${pairs.join(" ")}`);
    }
  }
  if (diag.scope_ref) {
    details.push("scope: see the PINJ scope statement");
  }
  return details;
}

function diagnosticItem(severity, label, code, location, message, details) {
  const item = element("li", "diagnostic");
  item.dataset.severity = severity;
  const head = element("div", "diagnostic-head");
  head.append(element("span", `severity severity-${severity}`, label));
  if (code) {
    head.append(element("span", "code", code));
  }
  head.append(location);
  item.append(head, element("p", "message", message));
  if (details.length) {
    item.append(element("p", "detail", details.join(" · ")));
  }
  return item;
}

function renderDiagnostics(diagnostics, syntaxErrors) {
  const items = syntaxErrors.map((error) =>
    diagnosticItem("error", "syntax", "", locationButton(error.file, error.line, 0), error.message, []),
  );
  for (const diag of diagnostics) {
    const item = diagnosticItem(
      diag.severity,
      diag.severity,
      `${diag.rule}/${diag.sub_code}`,
      locationButton(diag.file, diag.line, diag.col),
      diag.message,
      diagnosticDetails(diag),
    );
    if (diag.fixable) {
      item.querySelector(".diagnostic-head").append(element("span", "tag", "fixable"));
    }
    items.push(item);
  }
  $("diagnostics").replaceChildren(...items);
  $("diagnostics-empty").hidden = items.length > 0;
}

function renderText(run) {
  const target = $("output-text");
  target.replaceChildren();
  if (!run) {
    return;
  }
  const lines = (run.stdout + run.stderr).split("\n");
  lines.forEach((line, index) => {
    const match = LOCATION_PREFIX.exec(line);
    const syntax = match ? null : SYNTAX_PREFIX.exec(line);
    if (match) {
      target.append(
        locationButton(match[1], Number(match[2]), Number(match[3])),
        document.createTextNode(line.slice(match[0].length - 1)),
      );
    } else if (syntax) {
      target.append(
        locationButton(syntax[1], Number(syntax[2]), 0),
        document.createTextNode(line.slice(`${syntax[1]}:${syntax[2]}`.length)),
      );
    } else {
      target.append(document.createTextNode(line));
    }
    if (index < lines.length - 1) {
      target.append(document.createTextNode("\n"));
    }
  });
}

function renderDiff(run) {
  const target = $("output-diff");
  target.replaceChildren();
  if (!run) {
    return;
  }
  const text = run.stdout + run.stderr;
  if (NO_CHANGE.test(text)) {
    target.textContent = `No auto-fix applies to this template.\n\n${text.trim()}`;
    return;
  }
  for (const line of text.split(/(?<=\n)/)) {
    let className = "";
    if (line.startsWith("@@")) {
      className = "diff-hunk";
    } else if (line.startsWith("+") && !line.startsWith("+++")) {
      className = "diff-add";
    } else if (line.startsWith("-") && !line.startsWith("---")) {
      className = "diff-del";
    }
    target.append(className ? element("span", className, line) : document.createTextNode(line));
  }
}

function gateLine(run, budgetSet, failOn) {
  if (budgetSet) {
    return ["No pass/fail verdict while a budget is set: PTOK cannot count tokens here.", ""];
  }
  if (run.code === 0) {
    return [`Passes --fail-on ${failOn} (exit 0).`, "pass"];
  }
  return [`Fails --fail-on ${failOn} (exit ${run.code}).`, "fail"];
}

function parseEnvelope(run) {
  if (run.code === 2 || !run.stdout) {
    return null;
  }
  try {
    return JSON.parse(run.stdout);
  } catch {
    return null;
  }
}

function renderEnvelope(envelope, run, timing, budgetSet, failOn, argv) {
  const counts = envelope.summary;
  const parts = [plural(counts.error, "error"), plural(counts.warning, "warning"), `${counts.info} info`];
  if (counts.syntax) {
    parts.push(plural(counts.syntax, "syntax error"));
  }
  const [gate, gateKind] = gateLine(run, budgetSet, failOn);
  showSummary(`${plural(envelope.diagnostics.length, "diagnostic")}: ${parts.join(", ")}`, gate, timing);
  $("pinj-analysis").textContent = pinjStatus(envelope, argv);
  $("summary-gate").dataset.gate = gateKind;
  renderDiagnostics(envelope.diagnostics, envelope.syntax_errors);
  renderGutter(envelope.diagnostics.concat(envelope.syntax_errors));
  const pinj = envelope.analysis?.PINJ || envelope.diagnostics.some((diag) => diag.rule === "PINJ");
  $("scope-reminder").hidden = !pinj;
  $("scope-reminder-text").textContent = pinj ? envelope.analysis?.PINJ?.scope ?? envelope.rules.PINJ.scope : "";
}

// Render one lint. `argv` is what the lint ran with, `failOn` its gate.
export function renderResult(runs, ms, roundTrip, argv, failOn) {
  const run = runs.json;
  const budgetSet = argv.includes("--budget");
  $("ptok-notice").hidden = !budgetSet;
  const envelope = parseEnvelope(run);
  const timing = `Linted in ${ms.json.toFixed(0)} ms (the CLI call) · ${roundTrip.toFixed(0)} ms end to end.`;
  if (envelope === null) {
    showSummary(`The CLI refused this run (exit ${run.code}).`, run.stderr.trim() || "It printed no JSON.", "");
    $("summary-gate").dataset.gate = "fail";
    renderDiagnostics([], []);
    renderGutter([]);
    $("scope-reminder").hidden = true;
  } else {
    renderEnvelope(envelope, run, timing, budgetSet, failOn, argv);
  }
  $("output-json").textContent = run.stdout || run.stderr;
  renderText(runs.text);
  $("output-sarif").textContent = runs.sarif ? runs.sarif.stdout + runs.sarif.stderr : "";
  renderDiff(runs.diff);
  return envelope === null ? [] : envelope.diagnostics.concat(envelope.syntax_errors);
}
