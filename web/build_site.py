"""Build the j2prompt-lint web playground from pinned inputs, and serve it locally.

Usage::

    python web/build_site.py fetch --assets DIR
    python web/build_site.py wheel --out DIR
    python web/build_site.py build --assets DIR [--wheel FILE] --out DIR
    python web/build_site.py serve --site DIR [--port 8000]

``fetch`` downloads the Pyodide runtime and the two packages the linter needs
(``jinja2``, ``markupsafe``) and keeps a file only if its sha256 is the one
``pins.json`` records. ``wheel`` rebuilds the pinned ``j2prompt-lint`` wheel
from the checkout's ``HEAD`` using the pinned backend and timestamp. ``build``
re-verifies
every input, copies the page and its examples, stamps the wheel's pin into
``index.html`` and writes ``build-manifest.json``. ``serve`` is a static server
with the media types module scripts and WebAssembly need; it sets no
Content-Security-Policy header, so the page's own ``<meta>`` policy is the one
in force, as on a static host that cannot set headers.

Nothing fetched is committed: the default locations are git-ignored. The script
uses the standard library only.
"""

from __future__ import annotations

import argparse
import base64
import functools
import gzip
import hashlib
import http.server
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

WEB_DIR = Path(__file__).resolve().parent
REPO_ROOT = WEB_DIR.parent
PINS_PATH = WEB_DIR / "pins.json"
DEFAULT_ASSETS = WEB_DIR / ".cache" / "assets"
DEFAULT_SITE = WEB_DIR / "_site"
DEFAULT_WHEELS = WEB_DIR / ".cache" / "wheels"

#: The page's own files, copied verbatim except for `index.html`, which is
#: stamped. An allowlist, so a stray file in `web/` never reaches the site.
PAGE_FILES = (
    "index.html",
    "app.js",
    "editor.js",
    "view.js",
    "worker.js",
    "style.css",
    "runner.py",
    "favicon.svg",
)
EXAMPLES = "examples"
EXAMPLES_INDEX = "index.json"
RUNTIME_DIR = "pyodide"
WHEEL_DIR = "wheels"
MANIFEST = "build-manifest.json"

#: The package and metadata paths exported to build the pinned wheel.
WHEEL_SOURCES = (
    "src/j2prompt_lint",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "uv.lock",
)

#: A stamp token in `index.html`, e.g. `%WHEEL_SHA256%`.
TOKEN = re.compile(r"%[A-Z][A-Z0-9_]*%")
SHA256_HEX = re.compile(r"[0-9a-f]{64}")

#: Explicit media types. A module script is refused unless served as
#: JavaScript, and `WebAssembly.instantiateStreaming` needs `application/wasm`;
#: `mimetypes` on Windows reads the registry, which may say otherwise.
MEDIA_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json",
    ".wasm": "application/wasm",
    ".zip": "application/zip",
    ".whl": "application/zip",
    ".py": "text/plain; charset=utf-8",
    ".j2": "text/plain; charset=utf-8",
    ".svg": "image/svg+xml",
    "": "application/octet-stream",
}

USER_AGENT = "j2prompt-lint-playground-build"
DOWNLOAD_TIMEOUT_S = 120


class BuildError(Exception):
    """A pinned input is missing, altered, or inconsistent."""


@dataclass(frozen=True)
class Download:
    """A file fetched from the network and accepted by its sha256 alone."""

    name: str
    url: str
    sha256: str


@dataclass(frozen=True)
class Pins:
    """The parsed `pins.json`: every external byte the site may contain."""

    pyodide_version: str
    pyodide_python: str
    tarball: Download
    tarball_integrity: str
    core: Mapping[str, str]
    packages: tuple[Download, ...]
    wheel_file: str
    wheel_version: str
    wheel_sha256: str
    source_date_epoch: int
    build_backend: str

    def runtime_files(self) -> dict[str, str]:
        """Return every runtime file the site serves, mapped to its sha256."""
        files = dict(self.core)
        files.update({package.name: package.sha256 for package in self.packages})
        return files


def _require(table: Mapping[str, Any], key: str, kind: type) -> Any:  # noqa: ANN401
    """Return ``table[key]`` if it has the expected type, else refuse."""
    value = table.get(key)
    if not isinstance(value, kind) or isinstance(value, bool):
        raise BuildError(f"pins.json: {key!r} must be a {kind.__name__}")
    return value


def _sha(value: object, where: str) -> str:
    """Return `value` if it is a lowercase sha256 hex digest, else refuse."""
    if not isinstance(value, str) or not SHA256_HEX.fullmatch(value):
        raise BuildError(f"pins.json: {where} is not a sha256 hex digest")
    return value


def _plain_name(name: str, where: str) -> str:
    """Return `name` if it is a bare file name (no directory part), else refuse."""
    if not name or name != Path(name).name or name.startswith("."):
        raise BuildError(f"pins.json: {where} must be a bare file name, got {name!r}")
    return name


def load_pins(path: Path = PINS_PATH) -> Pins:
    """Parse and validate `pins.json`.

    Args:
        path: The pins file.

    Returns:
        The validated pins.

    Raises:
        BuildError: If a key is missing, mistyped, or not a digest.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    pyodide = _require(data, "pyodide", dict)
    tarball = _require(pyodide, "tarball", dict)
    core = _require(pyodide, "core", dict)
    packages = _require(pyodide, "packages", dict)
    wheel = _require(data, "wheel", dict)
    return Pins(
        pyodide_version=_require(pyodide, "version", str),
        pyodide_python=_require(pyodide, "python", str),
        tarball=Download(
            name=Path(_require(tarball, "url", str)).name,
            url=_require(tarball, "url", str),
            sha256=_sha(tarball.get("sha256"), "pyodide.tarball.sha256"),
        ),
        tarball_integrity=_require(tarball, "integrity", str),
        core={
            _plain_name(name, "a core file"): _sha(digest, f"core {name}")
            for name, digest in core.items()
        },
        packages=tuple(
            Download(
                name=_plain_name(name, "a package file"),
                url=_require(entry, "url", str),
                sha256=_sha(entry.get("sha256"), f"package {name}"),
            )
            for name, entry in packages.items()
        ),
        wheel_file=_plain_name(_require(wheel, "file", str), "wheel.file"),
        wheel_version=_require(wheel, "version", str),
        wheel_sha256=_sha(wheel.get("sha256"), "wheel.sha256"),
        source_date_epoch=_require(wheel, "source_date_epoch", int),
        build_backend=_require(wheel, "build_backend", str),
    )


def sha256_of(path: Path) -> str:
    """Return the sha256 hex digest of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(functools.partial(stream.read, 1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _download(url: str) -> bytes:
    """Return the body of an https URL, refusing any other scheme."""
    if not url.startswith("https://"):
        raise BuildError(f"refusing a non-https download: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT_S) as response:
        body: bytes = response.read()
    return body


def _check_digest(data: bytes, expected: str, what: str) -> None:
    """Refuse `data` unless its sha256 is `expected`."""
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise BuildError(f"{what}: sha256 {actual} is not the pinned {expected}")


def _write_atomically(path: Path, data: bytes) -> None:
    """Write `data` to `path` through a temporary sibling, then rename it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".part")
    temporary.write_bytes(data)
    temporary.replace(path)


def _is_current(path: Path, expected: str) -> bool:
    """Return True if `path` exists and has the pinned sha256."""
    return path.is_file() and sha256_of(path) == expected


def _extract_core(pins: Pins, archive: bytes, runtime: Path) -> None:
    """Write the pinned core files out of the npm tarball, checking each one."""
    wanted = {f"package/{name}": name for name in pins.core}
    found: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar.getmembers():
            name = wanted.get(member.name)
            if name is None:
                continue
            if not member.isfile():
                raise BuildError(f"{member.name} in the tarball is not a regular file")
            stream = tar.extractfile(member)
            if stream is None:
                raise BuildError(f"{member.name} could not be read from the tarball")
            data = stream.read()
            _check_digest(data, pins.core[name], f"{pins.tarball.name}:{member.name}")
            _write_atomically(runtime / name, data)
            found.add(name)
    missing = sorted(set(pins.core) - found)
    if missing:
        raise BuildError(f"the tarball lacks pinned files: {', '.join(missing)}")


def fetch_assets(pins: Pins, assets: Path) -> Path:
    """Download the pinned runtime into ``assets/pyodide``, verifying each file.

    Files already present with the pinned sha256 are kept, so a second run
    downloads nothing.

    Args:
        pins: The pins.
        assets: The directory to fill (created if needed).

    Returns:
        The runtime directory.

    Raises:
        BuildError: If any download does not match its pin.
    """
    runtime = assets / RUNTIME_DIR
    if not all(
        _is_current(runtime / name, digest) for name, digest in pins.core.items()
    ):
        archive = _download(pins.tarball.url)
        _check_digest(archive, pins.tarball.sha256, pins.tarball.name)
        integrity = (
            "sha512-" + base64.b64encode(hashlib.sha512(archive).digest()).decode()
        )
        if integrity != pins.tarball_integrity:
            raise BuildError(
                f"{pins.tarball.name}: npm integrity {integrity} is not pinned"
            )
        _extract_core(pins, archive, runtime)
    for package in pins.packages:
        target = runtime / package.name
        if not _is_current(target, package.sha256):
            data = _download(package.url)
            _check_digest(data, package.sha256, package.name)
            _write_atomically(target, data)
    verify_runtime(pins, runtime)
    return runtime


def verify_runtime(pins: Pins, runtime: Path) -> None:
    """Re-hash every runtime file against its pin.

    A downloaded file can change after the fact (a cleaner deleting temporary
    files, a partial copy), so every use re-verifies instead of trusting an
    earlier check.

    Raises:
        BuildError: Naming every missing or altered file.
    """
    problems = []
    for name, digest in sorted(pins.runtime_files().items()):
        path = runtime / name
        if not path.is_file():
            problems.append(f"{name}: missing")
        elif sha256_of(path) != digest:
            problems.append(f"{name}: sha256 differs from the pin")
    if problems:
        raise BuildError(
            f"runtime at {runtime} is not the pinned one: " + "; ".join(problems)
        )


def verify_wheel(pins: Pins, wheel: Path) -> None:
    """Refuse a wheel whose file name or sha256 is not the pinned one."""
    if wheel.name != pins.wheel_file:
        raise BuildError(f"wheel {wheel.name} is not the pinned {pins.wheel_file}")
    actual = sha256_of(wheel)
    if actual != pins.wheel_sha256:
        raise BuildError(
            f"wheel {wheel.name}: sha256 {actual} is not the pinned {pins.wheel_sha256}"
        )


def build_wheel(pins: Pins, out_dir: Path, repo: Path = REPO_ROOT) -> Path:
    """Build the ``j2prompt-lint`` wheel from ``HEAD`` with the pinned settings.

    The export comes from ``git archive`` with ``core.autocrlf=false``, so the
    wheel holds the committed bytes rather than a Windows working copy's CRLF
    ones; ``SOURCE_DATE_EPOCH`` and the pinned backend version make the build
    repeatable. The caller compares the result with the pin.

    Args:
        pins: The pins (build backend and timestamp).
        out_dir: Where the wheel is written.
        repo: The repository to export.

    Returns:
        The built wheel's path.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="j2pl-wheel-") as scratch:
        export = Path(scratch) / "export"
        archive = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "core.autocrlf=false",
                "archive",
                "--format=tar",
                "HEAD",
                "--",
                *WHEEL_SOURCES,
            ],
            check=True,
            capture_output=True,
        ).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(export, filter="data")
        constraints = Path(scratch) / "build-constraints.txt"
        constraints.write_text(pins.build_backend + "\n", encoding="utf-8")
        environment = {**os.environ, "SOURCE_DATE_EPOCH": str(pins.source_date_epoch)}
        subprocess.run(
            [
                "uv",
                "build",
                "--wheel",
                "--out-dir",
                str(out_dir),
                "--build-constraint",
                str(constraints),
                str(export),
            ],
            check=True,
            env=environment,
        )
    return out_dir / pins.wheel_file


def stamp(html: str, pins: Pins) -> str:
    """Replace the pin tokens in `index.html`, refusing any unknown token."""
    values = {
        "%J2PL_VERSION%": pins.wheel_version,
        "%WHEEL_FILE%": pins.wheel_file,
        "%WHEEL_SHA256%": pins.wheel_sha256,
        "%PYODIDE_VERSION%": pins.pyodide_version,
        "%PYODIDE_PYTHON%": pins.pyodide_python,
    }
    unknown = sorted(set(TOKEN.findall(html)) - set(values))
    if unknown:
        raise BuildError(f"index.html has unknown tokens: {', '.join(unknown)}")
    return TOKEN.sub(lambda match: values[match.group(0)], html)


def example_files(web: Path = WEB_DIR) -> list[str]:
    """Return the example files `examples/index.json` names, index first."""
    index = json.loads((web / EXAMPLES / EXAMPLES_INDEX).read_text(encoding="utf-8"))
    names = [EXAMPLES_INDEX]
    for example in index["examples"]:
        names.append(_plain_name(example["file"], "an example file"))
    return names


def _prepare_out(out: Path) -> None:
    """Empty `out` if it holds an earlier build; refuse any other non-empty dir."""
    if out.exists() and any(out.iterdir()):
        if not (out / MANIFEST).is_file():
            raise BuildError(f"{out} is not empty and holds no earlier build; refusing")
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)


def _file_record(path: Path) -> dict[str, int | str]:
    """Return a file's sha256, size, and gzip-9 size (a compressing host's cost)."""
    data = path.read_bytes()
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "gzip_bytes": len(gzip.compress(data, compresslevel=9, mtime=0)),
    }


def build_site(pins: Pins, runtime: Path, wheel: Path, out: Path) -> dict[str, Any]:
    """Assemble the static site in `out` and return its manifest.

    Args:
        pins: The pins.
        runtime: The fetched runtime directory (``fetch`` output).
        wheel: The pinned ``j2prompt-lint`` wheel.
        out: The site directory to (re)create.

    Returns:
        The manifest written to ``build-manifest.json``.
    """
    verify_runtime(pins, runtime)
    verify_wheel(pins, wheel)
    _prepare_out(out)
    for name in PAGE_FILES:
        source = WEB_DIR / name
        if name == "index.html":
            html = stamp(source.read_text(encoding="utf-8"), pins)
            (out / name).write_text(html, encoding="utf-8", newline="\n")
        else:
            shutil.copyfile(source, out / name)
    (out / EXAMPLES).mkdir()
    for name in example_files():
        shutil.copyfile(WEB_DIR / EXAMPLES / name, out / EXAMPLES / name)
    (out / RUNTIME_DIR).mkdir()
    for name in sorted(pins.runtime_files()):
        shutil.copyfile(runtime / name, out / RUNTIME_DIR / name)
    (out / WHEEL_DIR).mkdir()
    shutil.copyfile(wheel, out / WHEEL_DIR / wheel.name)
    verify_runtime(pins, out / RUNTIME_DIR)
    verify_wheel(pins, out / WHEEL_DIR / wheel.name)
    files = {
        path.relative_to(out).as_posix(): _file_record(path)
        for path in sorted(out.rglob("*"))
        if path.is_file()
    }
    manifest = {
        "j2prompt_lint": {
            "version": pins.wheel_version,
            "wheel": pins.wheel_file,
            "sha256": pins.wheel_sha256,
        },
        "pyodide": {"version": pins.pyodide_version, "python": pins.pyodide_python},
        "files": files,
        "total_bytes": sum(int(record["bytes"]) for record in files.values()),
        "total_gzip_bytes": sum(int(record["gzip_bytes"]) for record in files.values()),
    }
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


class SiteHandler(http.server.SimpleHTTPRequestHandler):
    """Static handler with explicit media types and no caching."""

    extensions_map = MEDIA_TYPES

    def end_headers(self) -> None:
        """Disable caching while serving the local playground."""
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: ANN401
        """Keep the console quiet; the tests read what they need elsewhere."""


def make_server(
    site: Path, host: str = "127.0.0.1", port: int = 0
) -> http.server.ThreadingHTTPServer:
    """Return a server for `site` (port 0 picks a free port)."""
    handler = functools.partial(SiteHandler, directory=str(site))
    return http.server.ThreadingHTTPServer((host, port), handler)


def _parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    fetch = commands.add_parser("fetch", help="download and verify the pinned runtime")
    fetch.add_argument("--assets", type=Path, default=DEFAULT_ASSETS)
    wheel = commands.add_parser("wheel", help="rebuild the pinned wheel from HEAD")
    wheel.add_argument("--out", type=Path, default=DEFAULT_WHEELS)
    build = commands.add_parser("build", help="assemble the site")
    build.add_argument("--assets", type=Path, default=DEFAULT_ASSETS)
    build.add_argument(
        "--wheel",
        type=Path,
        default=None,
        help="default: the pinned file in wheel's --out",
    )
    build.add_argument("--out", type=Path, default=DEFAULT_SITE)
    serve = commands.add_parser("serve", help="serve a built site locally")
    serve.add_argument("--site", type=Path, default=DEFAULT_SITE)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one subcommand; return the process exit status."""
    args = _parser().parse_args(argv)
    try:
        pins = load_pins()
        if args.command == "fetch":
            runtime = fetch_assets(pins, args.assets)
            print(f"runtime verified in {runtime}")
        elif args.command == "wheel":
            built = build_wheel(pins, args.out)
            verify_wheel(pins, built)
            print(f"{built} matches the pin ({pins.wheel_sha256})")
        elif args.command == "build":
            wheel_path = args.wheel or DEFAULT_WHEELS / pins.wheel_file
            manifest = build_site(pins, args.assets / RUNTIME_DIR, wheel_path, args.out)
            count = len(manifest["files"])
            raw, packed = manifest["total_bytes"], manifest["total_gzip_bytes"]
            print(
                f"site in {args.out}: {count} files, {raw} bytes ({packed} at gzip -9)"
            )
        else:
            server = make_server(args.site, args.host, args.port)
            where = f"http://{args.host}:{server.server_port}/"
            print(f"serving {args.site} at {where} (Ctrl+C stops)")
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
    except (BuildError, OSError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
