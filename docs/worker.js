// j2prompt-lint playground: the analysis worker.
//
// The page starts this file as a *module* worker from a blob: URL (see
// app.js). A blob: worker inherits the page's Content-Security-Policy, so the
// `connect-src 'self'` the page declares also binds every request made here,
// where the analysis runs. A worker loaded from its own https URL would take
// its policy from that response's headers instead, and a static host cannot
// set them. This loader uses a module worker.
//
// Messages in:  {type: "init", base, wheel: {file, sha256}}
//               {type: "lint", id, file, bytes, argv, view}
// Messages out: {type: "progress", step, total, label}
//               {type: "ready", version, python, pyodide, timings, wasmBytes}
//               {type: "result", id, runs, ms, wasmBytes}
//               {type: "failed", id, message}
//
// Every lint is the CLI's own `main()` over a file in Pyodide's in-memory
// filesystem, driven by runner.py; nothing here interprets the template.

const WORK_DIR = "/work";
const RUNNER_MODULE = "j2pl_playground_runner";
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const TOTAL_STEPS = 5;

let pyodide = null;
let runCli = null;
let currentFile = null;

function post(message) {
  self.postMessage(message);
}

function progress(step, label) {
  post({ type: "progress", step, total: TOTAL_STEPS, label });
}

function wasmBytes() {
  // The WebAssembly linear memory backing CPython: the dominant part of the
  // worker's footprint, and the part a page can measure without cross-origin
  // isolation. `_module` is Pyodide's handle on the Emscripten module.
  return pyodide?._module?.HEAPU8?.byteLength ?? null;
}

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

async function sha256Hex(bytes) {
  if (self.crypto?.subtle) {
    return toHex(await self.crypto.subtle.digest("SHA-256", bytes));
  }
  // SubtleCrypto exists only in secure contexts (https, or localhost). A copy
  // of the site served over plain http from another host still verifies the
  // wheel, with CPython's own hashlib.
  const hashlib = pyodide.pyimport("hashlib");
  const data = pyodide.toPy(bytes);
  try {
    return hashlib.sha256(data).hexdigest();
  } finally {
    data.destroy();
    hashlib.destroy();
  }
}

async function fetchBytes(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url} answered HTTP ${response.status}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

async function fetchText(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url} answered HTTP ${response.status}`);
  }
  return response.text();
}

function callCli(args) {
  const pyArgs = pyodide.toPy(args);
  let run = null;
  try {
    run = runCli(pyArgs);
    const [code, stdout, stderr] = run.toJs();
    return { code, stdout, stderr };
  } finally {
    run?.destroy();
    pyArgs.destroy();
  }
}

async function init({ base, wheel }) {
  const t0 = performance.now();
  progress(1, "Loading the Python runtime (Pyodide)");
  const indexURL = new URL("pyodide/", base).href;
  const { loadPyodide } = await import(new URL("pyodide.mjs", indexURL).href);
  // packageBaseUrl is passed explicitly: left unset, Pyodide's fallback for
  // packages it cannot find locally is a third-party CDN. The page's CSP would
  // refuse that request anyway; naming our own directory means none is tried.
  pyodide = await loadPyodide({
    indexURL,
    packageBaseUrl: indexURL,
    stdout: () => {},
    stderr: () => {},
  });
  const t1 = performance.now();

  progress(2, "Loading jinja2 and MarkupSafe");
  await pyodide.loadPackage(["jinja2", "markupsafe"], {
    messageCallback: () => {},
    errorCallback: () => {},
    checkIntegrity: true,
  });
  const t2 = performance.now();

  progress(3, "Verifying the j2prompt-lint wheel (sha256)");
  const bytes = await fetchBytes(new URL(`wheels/${wheel.file}`, base).href);
  const digest = await sha256Hex(bytes);
  if (digest !== wheel.sha256) {
    throw new Error(
      `the wheel's sha256 is ${digest}, but this page is pinned to ` +
        `${wheel.sha256}; refusing to run an unpinned wheel`,
    );
  }

  progress(4, "Installing the wheel and importing the linter");
  const sitePackages = pyodide.runPython(
    "import sysconfig; sysconfig.get_paths()['purelib']",
  );
  pyodide.unpackArchive(bytes, "wheel", { extractDir: sitePackages });
  const runnerSource = await fetchText(new URL("runner.py", base).href);
  pyodide.FS.writeFile(`${sitePackages}/${RUNNER_MODULE}.py`, runnerSource);
  pyodide.runPython("import importlib; importlib.invalidate_caches()");
  runCli = pyodide.pyimport(RUNNER_MODULE).run_cli;
  pyodide.FS.mkdirTree(WORK_DIR);
  pyodide.FS.chdir(WORK_DIR);
  const version = pyodide.runPython(
    "import importlib.metadata; importlib.metadata.version('j2prompt-lint')",
  );
  const python = pyodide.runPython("import platform; platform.python_version()");
  const t3 = performance.now();

  // One throwaway lint imports the engine's modules now, so the reader's first
  // lint is not the one that pays for them.
  progress(5, "Warming up the linter");
  pyodide.FS.writeFile(`${WORK_DIR}/warmup.j2`, "{{ greeting }}\n");
  callCli(["--format", "json", "warmup.j2"]);
  pyodide.FS.unlink(`${WORK_DIR}/warmup.j2`);
  const t4 = performance.now();

  post({
    type: "ready",
    version,
    python,
    pyodide: pyodide.version,
    wasmBytes: wasmBytes(),
    timings: {
      runtime_ms: t1 - t0,
      packages_ms: t2 - t1,
      wheel_ms: t3 - t2,
      warmup_ms: t4 - t3,
      total_ms: t4 - t0,
    },
  });
}

function lint({ id, file, bytes, argv, view }) {
  if (!SAFE_NAME.test(file) || file.toLowerCase().endsWith(".toml")) {
    // The page refuses these names before sending; this is the second lock.
    // A `.toml` name could be read as the CLI's own configuration file.
    throw new Error(`refusing the file name ${JSON.stringify(file)}`);
  }
  if (currentFile !== null && currentFile !== file) {
    pyodide.FS.unlink(`${WORK_DIR}/${currentFile}`);
    currentFile = null;
  }
  pyodide.FS.writeFile(`${WORK_DIR}/${file}`, bytes);
  currentFile = file;

  const started = performance.now();
  const runs = { json: callCli([...argv, "--format", "json", file]) };
  const jsonDone = performance.now();
  if (view === "text") {
    runs.text = callCli([...argv, file]);
  } else if (view === "sarif") {
    runs.sarif = callCli([...argv, "--format", "sarif", file]);
  } else if (view === "diff") {
    runs.diff = callCli([...argv, "--diff", file]);
  }
  const finished = performance.now();
  post({
    type: "result",
    id,
    runs,
    ms: { json: jsonDone - started, total: finished - started },
    wasmBytes: wasmBytes(),
  });
}

self.addEventListener("message", async (event) => {
  const message = event.data;
  try {
    if (message.type === "init") {
      await init(message);
    } else if (message.type === "lint") {
      if (runCli === null) {
        throw new Error("the linter is not loaded yet");
      }
      lint(message);
    }
  } catch (error) {
    post({
      type: "failed",
      id: message.id ?? null,
      stage: message.type,
      message: String(error?.message ?? error),
    });
  }
});
