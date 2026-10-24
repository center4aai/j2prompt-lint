from __future__ import annotations
import hashlib
import os
import tempfile
from dataclasses import dataclass
from functools import cache
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Protocol
from j2prompt_lint.core.config import LintConfig
if TYPE_CHECKING:
    from tokenizers import Tokenizer

class _Encoder(Protocol):

    def encode(self, text: str) -> list[int]:
        ...
REFERENCE_TOKENIZER_ID = 'gpt-neox-20b'
_REFERENCE_SHA256 = 'c24618a1b3e6a38167beff1c72cffd126c3a66254347304b50547d12c5f25624'
_REFERENCE_RESOURCE = 'data/reference_tokenizer/tokenizer.json'
CL100K_TOKENIZER_ID = 'cl100k_base'
_CL100K_BLOBPATH = 'https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken'
_DOWNLOAD_FLAG = 'J2PL_ALLOW_TOKENIZER_DOWNLOAD'
_CL100K_SHA256 = '223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7'
_VENDORED_CACHE = Path(__file__).resolve().parents[1] / 'data' / 'tiktoken_cache'
_CONTEXT_WINDOWS: dict[str, int] = {'gpt-4o': 128000, 'gpt-4-turbo': 128000, 'gpt-4': 8192, 'gpt-3.5-turbo': 16385, 'llama-3': 8192, 'llama3': 8192, 'mistral-7b': 32768, 'mixtral': 32768}

@dataclass(frozen=True, slots=True)
class TokenCount:
    count: int | None
    tokenizer_id: str
    is_approx: bool

class _FastTokenizerEncoder:

    def __init__(self, tokenizer: Tokenizer) -> None:
        self._tokenizer = tokenizer

    def encode(self, text: str) -> list[int]:
        ids: list[int] = self._tokenizer.encode(text, add_special_tokens=False).ids
        return ids

def _reference_bytes() -> bytes | None:
    try:
        data = resources.files('j2prompt_lint').joinpath(_REFERENCE_RESOURCE).read_bytes()
    except OSError:
        return None
    if hashlib.sha256(data).hexdigest() != _REFERENCE_SHA256:
        return None
    return data

@cache
def _load_reference() -> _Encoder | None:
    data = _reference_bytes()
    if data is None:
        return None
    try:
        from tokenizers import Tokenizer
    except ImportError:
        return None
    try:
        return _FastTokenizerEncoder(Tokenizer.from_str(data.decode('utf-8')))
    except Exception:
        return None

def _cache_key(blobpath: str) -> str:
    return hashlib.sha1(blobpath.encode(), usedforsecurity=False).hexdigest()

def _candidate_cache_dirs() -> list[Path]:
    dirs: list[Path] = []
    if _VENDORED_CACHE.is_dir():
        dirs.append(_VENDORED_CACHE)
    env = os.environ.get('TIKTOKEN_CACHE_DIR')
    if env:
        dirs.append(Path(env))
    dirs.append(Path(tempfile.gettempdir()) / 'data-gym-cache')
    return dirs

def _intact_cache_dir(blobpath: str, expected_sha256: str) -> Path | None:
    key = _cache_key(blobpath)
    for directory in _candidate_cache_dirs():
        try:
            data = (directory / key).read_bytes()
        except OSError:
            continue
        if hashlib.sha256(data).hexdigest() == expected_sha256:
            return directory
    return None

def _load_cl100k() -> _Encoder | None:
    try:
        import tiktoken
    except ImportError:
        return None
    allow_download = os.environ.get(_DOWNLOAD_FLAG) == '1'
    cache_dir = _intact_cache_dir(_CL100K_BLOBPATH, _CL100K_SHA256)
    if cache_dir is None and (not allow_download):
        return None
    if cache_dir is not None:
        os.environ['TIKTOKEN_CACHE_DIR'] = str(cache_dir)
    try:
        encoding: _Encoder = tiktoken.get_encoding(CL100K_TOKENIZER_ID)
        return encoding
    except Exception:
        return None

def _model_native_count(text: str, target_model: str) -> int | None:
    try:
        from transformers import AutoTokenizer
    except ImportError:
        return None
    try:
        tokenizer = AutoTokenizer.from_pretrained(target_model, local_files_only=True)
        return len(tokenizer.encode(text))
    except Exception:
        return None
_WINDOW_FIELDS: tuple[str, ...] = ('max_position_embeddings', 'n_positions', 'max_sequence_length')

def _model_config_window(target_model: str | None) -> int | None:
    if target_model is None:
        return None
    try:
        from transformers import AutoConfig
    except ImportError:
        return None
    try:
        model_config = AutoConfig.from_pretrained(target_model, local_files_only=True)
    except Exception:
        return None
    for field in _WINDOW_FIELDS:
        value = getattr(model_config, field, None)
        if isinstance(value, int) and (not isinstance(value, bool)) and (value > 0):
            return value
    return None

def count_tokens(text: str, config: LintConfig) -> TokenCount:
    target = config.target_model
    if target is not None and config.tokenizer == 'auto':
        exact = _model_native_count(text, target)
        if exact is not None:
            return TokenCount(exact, target, False)
    if config.tokenizer == CL100K_TOKENIZER_ID:
        encoding = _load_cl100k()
        count = None if encoding is None else len(encoding.encode(text))
        return TokenCount(count, CL100K_TOKENIZER_ID, True)
    reference = _load_reference()
    count = None if reference is None else len(reference.encode(text))
    return TokenCount(count, REFERENCE_TOKENIZER_ID, True)

def _lookup_context_window(target_model: str | None) -> int | None:
    if target_model is None:
        return None
    lowered = target_model.lower()
    for key in sorted(_CONTEXT_WINDOWS, key=len, reverse=True):
        if key in lowered:
            return _CONTEXT_WINDOWS[key]
    return None

def resolve_budget(config: LintConfig) -> int | None:
    if config.token_budget:
        return config.token_budget
    window = config.context_window or _model_config_window(config.target_model) or _lookup_context_window(config.target_model)
    if window is None:
        return None
    derived = window - config.generation_reserve
    return derived if derived > 0 else None
