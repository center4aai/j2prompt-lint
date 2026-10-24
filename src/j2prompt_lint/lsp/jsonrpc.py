from __future__ import annotations
import json
from typing import IO, Any
_HEADER_SEPARATOR = b'\r\n'
_CONTENT_LENGTH = b'content-length:'

class ProtocolError(ValueError):
    pass

def read_message(stream: IO[bytes]) -> dict[str, Any] | None:
    length: int | None = None
    while True:
        line = stream.readline()
        if not line:
            if length is None:
                return None
            raise ProtocolError('stream ended inside a message header')
        if line in (_HEADER_SEPARATOR, b'\n'):
            break
        name, _, value = line.partition(b':')
        if name.strip().lower() + b':' == _CONTENT_LENGTH:
            try:
                length = int(value.strip())
            except ValueError as error:
                raise ProtocolError(f'bad Content-Length: {value!r}') from error
    if length is None:
        raise ProtocolError('message header carries no Content-Length')
    body = stream.read(length)
    if len(body) != length:
        raise ProtocolError(f'stream ended inside a message body: {len(body)} of {length} bytes')
    payload = json.loads(body.decode('utf-8'))
    if not isinstance(payload, dict):
        raise ProtocolError(f'message body is not a JSON object: {type(payload)}')
    return payload

def write_message(stream: IO[bytes], payload: dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    stream.write(b'Content-Length: %d\r\n\r\n' % len(body))
    stream.write(body)
    stream.flush()
