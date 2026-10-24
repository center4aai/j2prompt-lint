// j2prompt-lint playground: the page's main thread.
//
// The page paints without waiting for Python. The analysis runs in a Web
// Worker (worker.js) that loads Pyodide, checks the pinned wheel's sha256 and
// installs it; this module owns the options, the requests and the wiring.
// Rendering is view.js's, the editor pane editor.js's.

import { $, lineCount, renderGutter, templateFromJson } from "./editor.js";
import { renderResult, showSummary } from "./view.js";

const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const LINT_DELAY_MS = 350;
const MAX_TEMPLATE_BYTES = 2 * 1024 * 1024;
const FILE_NAME_HELP =
  "The name the CLI sees. Its suffix matters: .md selects the plain-markdown rule subset.";
const encoder = new TextEncoder();

const pinMeta = document.querySelector('meta[name="j2pl-wheel"]');
const pin = {
  file: pinMeta.content,
  sha256: pinMeta.dataset.sha256,
  version: pinMeta.dataset.version,
};

const state = {
  worker: null,
  ready: false,
  inFlight: false,
  pending: null,
  sentAt: 0,
  seq: 0,
  view: "diagnostics",
  lastLint: null,
  marks: [],
  opened: null,
  examples: [],
  lintTimer: 0,
};

// ---------------------------------------------------------------- worker

async function startWorker() {
  const base = new URL(".", window.location.href).href;
  performance.mark("j2pl-worker-start");
  let source;
  try {
    const response = await fetch(new URL("worker.js", base));
    if (!response.ok) {
      throw new Error(`worker.js answered HTTP ${response.status}`);
    }
    source = await response.text();
  } catch (error) {
    fail(`The analysis worker could not be fetched: ${error.message}`);
    return;
  }
  // A blob: worker inherits this page's Content-Security-Policy, so the
  // policy's connect-src binds the analysis too (see worker.js).
  const url = URL.createObjectURL(new Blob([source], { type: "text/javascript" }));
  let worker;
  try {
    worker = new Worker(url, { type: "module", name: "j2prompt-lint" });
  } catch (error) {
    URL.revokeObjectURL(url);
    fail(
      `This browser could not start the analysis worker (${error.message}). ` +
        "The playground needs module Web Workers and WebAssembly.",
    );
    return;
  }
  state.worker = worker;
  worker.addEventListener("message", (event) => {
    URL.revokeObjectURL(url);
    onWorkerMessage(event.data);
  });
  worker.addEventListener("error", (event) => {
    event.preventDefault();
    fail(`The analysis worker stopped: ${event.message || "unknown error"}`);
  });
  worker.postMessage({ type: "init", base, wheel: { file: pin.file, sha256: pin.sha256 } });
}

function onWorkerMessage(message) {
  if (message.type === "progress") {
    setRuntime("loading", `${message.label}… (step ${message.step} of ${message.total})`);
    $("runtime-progress").max = message.total;
    $("runtime-progress").value = message.step - 1;
  } else if (message.type === "ready") {
    onReady(message);
  } else if (message.type === "result") {
    onResult(message);
  } else if (message.type === "failed") {
    if (message.stage === "init") {
      fail(`The linter could not be loaded: ${message.message}`);
    } else {
      state.inFlight = false;
      showSummary(`The lint did not complete: ${message.message}`, "", "");
      flushPending();
    }
  }
}

function onReady(message) {
  state.ready = true;
  const seconds = (message.timings.total_ms / 1000).toFixed(1);
  performance.mark("j2pl-ready", {
    detail: {
      timings: message.timings,
      wasmBytes: message.wasmBytes,
      version: message.version,
      python: message.python,
      pyodide: message.pyodide,
    },
  });
  setRuntime(
    "ready",
    `Ready: j2prompt-lint ${message.version} on Python ${message.python} (loaded in ${seconds} s)`,
  );
  $("lint-button").disabled = false;
  requestLint();
}

function fail(text) {
  setRuntime("error", "The linter is unavailable.");
  $("fatal").textContent = text;
  $("fatal").hidden = false;
  $("lint-button").disabled = true;
}

function setRuntime(kind, text) {
  $("runtime").dataset.state = kind;
  $("runtime-status").textContent = text;
}

// ------------------------------------------------------------- requests

function fileName() {
  return $("file-name").value.trim();
}

function fileNameProblem(name) {
  if (!SAFE_NAME.test(name)) {
    return "Use letters, digits, '.', '_' or '-' (at most 100 characters), starting with a letter or digit.";
  }
  if (name.toLowerCase().endsWith(".toml")) {
    return "A .toml name could be read as the CLI's own configuration; choose another suffix.";
  }
  return "";
}

function splitNames(value) {
  return value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .join(",");
}

function optionArgs() {
  const args = [];
  const declare = splitNames($("opt-declare").value);
  if (declare) {
    args.push("--declare", declare);
  }
  const untrusted = splitNames($("opt-untrusted").value);
  if (untrusted) {
    args.push("--untrusted", untrusted);
  }
  const model = $("opt-source-model").value;
  if (model) {
    args.push("--pinj-source-model", model);
  }
  const budget = $("opt-budget").value.trim();
  if (budget) {
    args.push("--budget", budget);
  }
  const failOn = $("opt-fail-on").value;
  if (failOn !== "error") {
    args.push("--fail-on", failOn);
  }
  return args;
}

const VIEW_FLAGS = { json: ["--format", "json"], sarif: ["--format", "sarif"], diff: ["--diff"] };
// The views the worker runs besides the JSON every lint renders from.
const WORKER_VIEWS = new Set(["text", "sarif", "diff"]);

function templateBytes() {
  const text = $("source").value;
  // An opened file keeps its exact bytes (CRLF line endings, say) until it is
  // edited: a textarea normalises line endings, and PFMT reads them.
  if (state.opened && state.opened.text === text) {
    return state.opened.bytes;
  }
  return encoder.encode(text);
}

function scheduleLint() {
  window.clearTimeout(state.lintTimer);
  state.lintTimer = window.setTimeout(requestLint, LINT_DELAY_MS);
}

function requestLint() {
  window.clearTimeout(state.lintTimer);
  updateCommand();
  const name = fileName();
  const problem = fileNameProblem(name);
  $("file-name").setAttribute("aria-invalid", problem ? "true" : "false");
  $("file-name-help").textContent = problem || FILE_NAME_HELP;
  if (problem || !state.ready) {
    return;
  }
  const bytes = templateBytes();
  if (bytes.byteLength > MAX_TEMPLATE_BYTES) {
    showSummary("This template is larger than the playground's 2 MB limit; use the CLI.", "", "");
    return;
  }
  const request = {
    type: "lint",
    file: name,
    bytes,
    argv: optionArgs(),
    failOn: $("opt-fail-on").value,
    view: WORKER_VIEWS.has(state.view) ? state.view : "json",
  };
  if (state.inFlight) {
    state.pending = request;
    return;
  }
  send(request);
}

function send(request) {
  state.seq += 1;
  state.inFlight = true;
  state.sentAt = performance.now();
  state.request = request;
  state.worker.postMessage({ ...request, id: state.seq });
}

function flushPending() {
  if (state.pending) {
    const next = state.pending;
    state.pending = null;
    send(next);
  }
}

function onResult(message) {
  state.inFlight = false;
  const roundTrip = performance.now() - state.sentAt;
  const { argv, failOn } = state.request;
  state.lastLint = { id: message.id, runs: message.runs };
  state.marks = renderResult(message.runs, message.ms, roundTrip, argv, failOn);
  performance.mark("j2pl-lint", {
    detail: {
      id: message.id,
      cli_ms: message.ms.json,
      total_ms: message.ms.total,
      round_trip_ms: roundTrip,
      wasmBytes: message.wasmBytes,
    },
  });
  $("results").dataset.lintId = String(message.id);
  flushPending();
}

// --------------------------------------------------------------- source

function updateSourceStats() {
  const text = $("source").value;
  const lines = lineCount(text);
  const bytes = encoder.encode(text).byteLength;
  $("source-stats").textContent = `${lines} line${lines === 1 ? "" : "s"} · ${bytes} bytes`;
  const keptCr = state.opened && state.opened.text === text && state.opened.hasCr;
  $("source-bytes-note").textContent = keptCr ? " · CR line endings kept from the opened file" : "";
  $("json-notice").hidden = templateFromJson(text) === null;
}

function onSourceInput() {
  const selected = state.examples.find((item) => item.id === $("example-select").value);
  if (selected && selected.text !== $("source").value) {
    $("example-select").value = "";
    $("example-summary").textContent = "";
  }
  if ($("gutter").childElementCount !== lineCount($("source").value)) {
    renderGutter(state.marks);
  }
  updateSourceStats();
  scheduleLint();
}

function setSource(text, name, summary) {
  $("source").value = text;
  $("source").scrollTop = 0;
  $("file-name").value = name;
  $("example-summary").textContent = summary;
  state.marks = [];
  renderGutter([]);
  updateSourceStats();
  requestLint();
}

function decodePastedJson() {
  const template = templateFromJson($("source").value);
  if (template !== null) {
    state.opened = null;
    $("example-select").value = "";
    setSource(template, "chat_template.jinja", "Decoded from the JSON string you pasted.");
  }
}

// ------------------------------------------------------------- examples

async function loadExamples() {
  let manifest;
  try {
    const response = await fetch("examples/index.json");
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    manifest = await response.json();
  } catch (error) {
    $("example-summary").textContent = `The examples could not be loaded (${error.message}).`;
    return;
  }
  for (const example of manifest.examples) {
    const option = document.createElement("option");
    option.value = example.id;
    option.textContent = example.title;
    $("example-select").append(option);
  }
  state.examples = manifest.examples.map((example) => ({ ...example, text: null }));
  await selectExample(manifest.default);
}

async function selectExample(id) {
  const example = state.examples.find((item) => item.id === id);
  if (!example) {
    $("example-summary").textContent = "";
    return;
  }
  if (example.text === null) {
    const response = await fetch(`examples/${example.file}`);
    example.text = await response.text();
  }
  $("example-select").value = id;
  $("opt-declare").value = example.options.declare ?? "";
  $("opt-untrusted").value = example.options.untrusted ?? "";
  $("opt-source-model").value = example.options.pinj_source_model ?? "";
  $("opt-budget").value = example.options.budget === undefined ? "" : String(example.options.budget);
  $("opt-fail-on").value = example.options.fail_on ?? "error";
  state.opened = null;
  setSource(example.text, example.file, example.summary);
}

// ---------------------------------------------------------------- files

function safeNameFrom(name) {
  const cleaned = name.replace(/[^A-Za-z0-9._-]/g, "_").replace(/^[^A-Za-z0-9]+/, "");
  return cleaned.slice(0, 100) || "template.j2";
}

async function openFile(file) {
  if (file.size > MAX_TEMPLATE_BYTES) {
    showSummary(`${file.name} is larger than the playground's 2 MB limit; use the CLI.`, "", "");
    return;
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  const decoded = new TextDecoder("utf-8").decode(bytes);
  $("source").value = decoded;
  // Keep what the textarea really holds (it normalises line endings), so an
  // unedited file is recognised and linted from its own bytes.
  state.opened = { bytes, text: $("source").value, hasCr: decoded.includes("\r") };
  $("example-select").value = "";
  setSource(
    $("source").value,
    safeNameFrom(file.name),
    `Opened ${file.name} (${bytes.byteLength} bytes). It stays in this browser.`,
  );
}

// ---------------------------------------------------------------- tabs

function selectView(view, focus) {
  state.view = view;
  for (const tab of document.querySelectorAll('[role="tab"]')) {
    const selected = tab.dataset.view === view;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    $(tab.getAttribute("aria-controls")).hidden = !selected;
    if (selected && focus) {
      tab.focus();
    }
  }
  updateCommand();
  if (WORKER_VIEWS.has(view) && (!state.lastLint || !state.lastLint.runs[view])) {
    requestLint();
  }
}

const TAB_KEYS = {
  ArrowRight: (index, count) => (index + 1) % count,
  ArrowLeft: (index, count) => (index - 1 + count) % count,
  Home: () => 0,
  End: (_index, count) => count - 1,
};

function onTabKey(event) {
  const move = TAB_KEYS[event.key];
  if (!move) {
    return;
  }
  const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
  const next = move(tabs.indexOf(event.currentTarget), tabs.length);
  event.preventDefault();
  selectView(tabs[next].dataset.view, true);
}

// -------------------------------------------------------------- command

function shellQuote(value) {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(value)) {
    return value;
  }
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function updateCommand() {
  const name = fileName() || "template.j2";
  const args = [...optionArgs(), ...(VIEW_FLAGS[state.view] ?? []), name];
  $("command").textContent = ["j2prompt-lint", ...args.map(shellQuote)].join(" ");
}

async function copyCommand() {
  const button = $("copy-command");
  try {
    await navigator.clipboard.writeText($("command").textContent);
    button.textContent = "Copied";
  } catch {
    const range = document.createRange();
    range.selectNodeContents($("command"));
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(range);
    button.textContent = "Selected: press Ctrl+C";
  }
  window.setTimeout(() => {
    button.textContent = "Copy";
  }, 2000);
}

// ---------------------------------------------------------------- wiring

function wireEditor() {
  const source = $("source");
  source.addEventListener("input", onSourceInput);
  source.addEventListener("scroll", () => {
    $("gutter").scrollTop = source.scrollTop;
  });
  source.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      requestLint();
    }
  });
  source.addEventListener("dragover", (event) => {
    if (event.dataTransfer && Array.from(event.dataTransfer.types).includes("Files")) {
      event.preventDefault();
    }
  });
  source.addEventListener("drop", (event) => {
    const file = event.dataTransfer?.files?.[0];
    if (file) {
      event.preventDefault();
      openFile(file);
    }
  });
  $("json-decode").addEventListener("click", decodePastedJson);
}

function wireControls() {
  $("lint-button").addEventListener("click", requestLint);
  $("open-file").addEventListener("click", () => $("file-input").click());
  $("file-input").addEventListener("change", (event) => {
    const file = event.target.files?.[0];
    if (file) {
      openFile(file);
    }
    event.target.value = "";
  });
  $("example-select").addEventListener("change", (event) => {
    if (event.target.value) {
      selectExample(event.target.value);
    } else {
      $("example-summary").textContent = "";
    }
  });
  for (const id of ["opt-declare", "opt-untrusted", "opt-budget", "file-name"]) {
    $(id).addEventListener("input", scheduleLint);
  }
  for (const id of ["opt-source-model", "opt-fail-on"]) {
    $(id).addEventListener("change", requestLint);
  }
  for (const tab of document.querySelectorAll('[role="tab"]')) {
    tab.addEventListener("click", () => selectView(tab.dataset.view, false));
    tab.addEventListener("keydown", onTabKey);
  }
  $("copy-command").addEventListener("click", copyCommand);
}

wireEditor();
wireControls();
renderGutter([]);
updateSourceStats();
updateCommand();
startWorker();
loadExamples();
