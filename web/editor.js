// j2prompt-lint playground: the editor pane (gutter, jumps, pasted JSON).
//
// The editor is a plain textarea, kept dependable for keyboards and screen
// readers, with a line-number gutter that marks the lines diagnostics name.

export const $ = (id) => document.getElementById(id);

const SEVERITY_RANK = { error: 3, warning: 2, info: 1 };
const FLASH_MS = 1200;

export function lineCount(text) {
  let count = 1;
  for (let index = text.indexOf("\n"); index !== -1; index = text.indexOf("\n", index + 1)) {
    count += 1;
  }
  return count;
}

export function renderGutter(diagnostics) {
  const gutter = $("gutter");
  const count = lineCount($("source").value);
  const marks = new Map();
  for (const diag of diagnostics) {
    const severity = diag.severity || "error";
    const current = marks.get(diag.line);
    if (!current || SEVERITY_RANK[severity] > SEVERITY_RANK[current]) {
      marks.set(diag.line, severity);
    }
  }
  const fragment = document.createDocumentFragment();
  for (let line = 1; line <= count; line += 1) {
    const span = document.createElement("span");
    span.textContent = String(line);
    const severity = marks.get(line);
    if (severity) {
      span.className = `has-${severity}`;
    }
    fragment.append(span);
  }
  gutter.replaceChildren(fragment);
  gutter.scrollTop = $("source").scrollTop;
}

export function jumpTo(line, col) {
  const editor = $("source");
  const text = editor.value;
  let start = 0;
  for (let current = 1; current < line; current += 1) {
    const next = text.indexOf("\n", start);
    if (next === -1) {
      break;
    }
    start = next + 1;
  }
  const lineEnd = text.indexOf("\n", start);
  const end = lineEnd === -1 ? text.length : lineEnd;
  const caret = Math.min(start + Math.max(col - 1, 0), end);
  editor.focus({ preventScroll: true });
  editor.setSelectionRange(caret, end > caret ? end : caret);
  const lineHeight = parseFloat(getComputedStyle(editor).lineHeight) || 20;
  editor.scrollTop = Math.max(0, (line - 1) * lineHeight - editor.clientHeight / 3);
  const marker = $("gutter").children[line - 1];
  if (marker) {
    marker.classList.add("flash");
    window.setTimeout(() => marker.classList.remove("flash"), FLASH_MS);
  }
}

// Hugging Face publishes chat templates inside tokenizer_config.json, as a
// JSON string, so what a reader copies is often escaped ("\n" for newlines).
// Linting that as a template would report on the escaping, not the template.
// This recognises the shapes a copy takes and returns the template inside, or
// null; the page offers the decoding and never applies it unasked.
const CHAT_TEMPLATE_FIELD = /^"chat_template"\s*:\s*("(?:[^"\\]|\\.)*")\s*,?$/s;

function looksLikeJinja(text) {
  return text.includes("{%") || text.includes("{{");
}

function fromConfig(value) {
  const template = value?.chat_template;
  if (typeof template === "string") {
    return template;
  }
  if (Array.isArray(template)) {
    const named = template.find((entry) => entry?.name === "default") ?? template[0];
    return typeof named?.template === "string" ? named.template : null;
  }
  return null;
}

export function templateFromJson(text) {
  const trimmed = text.trim();
  if (!trimmed.startsWith('"') && !trimmed.startsWith("{")) {
    return null;
  }
  let value;
  try {
    value = JSON.parse(trimmed);
  } catch {
    const field = CHAT_TEMPLATE_FIELD.exec(trimmed);
    if (!field) {
      return null;
    }
    try {
      value = JSON.parse(field[1]);
    } catch {
      return null;
    }
  }
  const template = typeof value === "string" ? value : fromConfig(value);
  return template !== null && looksLikeJinja(template) ? template : null;
}
