from __future__ import annotations
import os
import re
import sys
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any, TypeAlias
from j2prompt_lint.__about__ import __version__
from j2prompt_lint.config import ConfigError, config_from_table, find_config_table
from j2prompt_lint.core.config import LintConfig
from j2prompt_lint.core.engine import FileResult, _relative_posix, lint_text, refuse_sidecars, rules_for
from j2prompt_lint.lsp.jsonrpc import ProtocolError, read_message, write_message
from j2prompt_lint.output.lsp import to_code_action, to_lsp_pinj_notice, to_lsp_publish
_METHOD_NOT_FOUND = -32601
_INTERNAL_ERROR = -32603
_MESSAGE_ERROR = 1
_DRIVE = re.compile('^/[A-Za-z][:|](?:[/\\\\]|$)')
_RequestId: TypeAlias = 'int | str | None'
_Handler: TypeAlias = Callable[[dict[str, Any]], Any]

def _path_of(uri: str) -> Path | None:
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != 'file':
        return None
    path = urllib.parse.unquote(parsed.path)
    host = parsed.netloc
    if host and host.lower() != 'localhost':
        return Path(f'//{host}{path}')
    if os.name == 'nt' and _DRIVE.match(path):
        return Path(path[1] + ':' + path[3:])
    return Path(path)

def _document_name(uri: str) -> str:
    path = _path_of(uri)
    return uri if path is None else _relative_posix(path)

def _overlaps(diagnostic_line: int, start_line: int, end_line: int) -> bool:
    return start_line <= diagnostic_line - 1 <= end_line

class Server:

    def __init__(self, config: LintConfig, stdin: IO[bytes], stdout: IO[bytes]) -> None:
        self._config = config
        self._stdin = stdin
        self._stdout = stdout
        self._cache: dict[str, FileResult] = {}
        self._shutdown_requested = False
        self._pinj_no_sources_notified = False

    def initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        del params
        return {'capabilities': {'textDocumentSync': {'openClose': True, 'change': 1, 'save': True}, 'codeActionProvider': {'codeActionKinds': ['quickfix']}}, 'serverInfo': {'name': 'j2prompt-lint', 'version': __version__}}

    def shutdown(self, params: dict[str, Any]) -> None:
        del params
        self._shutdown_requested = True
        return None

    def did_open(self, params: dict[str, Any]) -> None:
        document = params['textDocument']
        self._publish(document['uri'], document['text'])

    def did_change(self, params: dict[str, Any]) -> None:
        changes = params['contentChanges']
        if changes:
            self._publish(params['textDocument']['uri'], changes[-1]['text'])

    def did_save(self, params: dict[str, Any]) -> None:
        text = params.get('text')
        if text is not None:
            self._publish(params['textDocument']['uri'], text)

    def did_close(self, params: dict[str, Any]) -> None:
        uri = params['textDocument']['uri']
        self._cache.pop(uri, None)
        self._notify('textDocument/publishDiagnostics', {'uri': uri, 'diagnostics': []})

    def code_action(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        uri = params['textDocument']['uri']
        result = self._cache.get(uri)
        if result is None:
            return []
        start = params['range']['start']['line']
        end = params['range']['end']['line']
        actions: list[dict[str, Any]] = []
        for diag in result.diagnostics:
            if not _overlaps(diag.line, start, end):
                continue
            action = to_code_action(diag, uri)
            if action is not None:
                actions.append(action)
        return actions

    def _publish(self, uri: str, text: str) -> None:
        name = _document_name(uri)
        path = _path_of(uri)
        if path is not None:
            try:
                refuse_sidecars([path])
            except ConfigError as error:
                self._cache.pop(uri, None)
                self._notify('window/showMessage', {'type': _MESSAGE_ERROR, 'message': f'j2prompt-lint: {error}'})
                self._notify('textDocument/publishDiagnostics', {'uri': uri, 'diagnostics': []})
                return
        result = lint_text(name, text, self._config, rules_for(Path(name)))
        self._cache[uri] = result
        self._notify('textDocument/publishDiagnostics', to_lsp_publish(result, uri=uri))
        if not self._pinj_no_sources_notified:
            notice = to_lsp_pinj_notice(result)
            if notice is not None:
                self._notify('window/showMessage', notice)
                self._pinj_no_sources_notified = True
    _REQUESTS = ('initialize', 'shutdown', 'textDocument/codeAction')
    _NOTIFICATIONS = ('initialized', 'textDocument/didOpen', 'textDocument/didChange', 'textDocument/didSave', 'textDocument/didClose', 'exit')

    def _handler(self, method: str) -> _Handler | None:
        table: dict[str, _Handler] = {'initialize': self.initialize, 'shutdown': self.shutdown, 'textDocument/codeAction': self.code_action, 'textDocument/didOpen': self.did_open, 'textDocument/didChange': self.did_change, 'textDocument/didSave': self.did_save, 'textDocument/didClose': self.did_close, 'initialized': lambda params: None}
        return table.get(method)

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        write_message(self._stdout, {'jsonrpc': '2.0', 'method': method, 'params': params})

    def _respond(self, request_id: _RequestId, result: object) -> None:
        write_message(self._stdout, {'jsonrpc': '2.0', 'id': request_id, 'result': result})

    def _respond_error(self, request_id: _RequestId, code: int, message: str) -> None:
        write_message(self._stdout, {'jsonrpc': '2.0', 'id': request_id, 'error': {'code': code, 'message': message}})

    def handle(self, message: dict[str, Any]) -> bool:
        method = message.get('method', '')
        request_id = message.get('id')
        if method == 'exit':
            return False
        handler = self._handler(method)
        if handler is None:
            if request_id is not None:
                self._respond_error(request_id, _METHOD_NOT_FOUND, f'unsupported method: {method}')
            return True
        try:
            result = handler(message.get('params') or {})
        except Exception as error:
            if request_id is not None:
                self._respond_error(request_id, _INTERNAL_ERROR, str(error))
            print(f'j2prompt-lint-lsp: {method}: {error}', file=sys.stderr)
            return True
        if request_id is not None:
            self._respond(request_id, result)
        return True

    def run(self) -> int:
        while True:
            message = read_message(self._stdin)
            if message is None or not self.handle(message):
                break
        return 0 if self._shutdown_requested else 1

def _root_of(params: dict[str, Any]) -> Path:
    folders = params.get('workspaceFolders')
    if folders:
        path = _path_of(folders[0]['uri'])
        if path is not None:
            return path
    root_uri = params.get('rootUri')
    if root_uri:
        path = _path_of(root_uri)
        if path is not None:
            return path
    return Path.cwd()

def main() -> int:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    try:
        first = read_message(stdin)
    except ProtocolError as error:
        print(f'error: {error}', file=sys.stderr)
        return 2
    if first is None:
        return 1
    if first.get('method') != 'initialize':
        print('error: first message must be `initialize`', file=sys.stderr)
        return 2
    params = first.get('params') or {}
    try:
        config = config_from_table(find_config_table(_root_of(params)))
    except (ValueError, OSError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 2
    server = Server(config, stdin, stdout)
    server.handle(first)
    try:
        return server.run()
    except ProtocolError as error:
        print(f'error: {error}', file=sys.stderr)
        return 2
if __name__ == '__main__':
    sys.exit(main())
