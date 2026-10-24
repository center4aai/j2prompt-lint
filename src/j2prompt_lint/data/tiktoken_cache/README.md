# Optional cl100k_base tokenizer cache

The default PTOK tokenizer is packaged under ../reference_tokenizer/ and loads
offline. This directory is an optional local-cache location for cl100k_base.
The cl100k_base vocabulary file is not included in this package.

To select the optional route, install the cl100k extra and configure:

```toml
[tool.j2prompt-lint.ptok]
tokenizer = "cl100k_base"
```

On a connected machine, populate a cache once with tiktoken:

```bash
TIKTOKEN_CACHE_DIR="src/j2prompt_lint/data/tiktoken_cache" \
J2PL_ALLOW_TOKENIZER_DOWNLOAD=1 \
python -c "import tiktoken; tiktoken.get_encoding('cl100k_base')"
```

Without a valid cached vocabulary this route reports PTOK/budget-unknown.
The linter checks the vocabulary checksum before use, leaves corrupt cache
files in place and does not repair them by downloading replacement data.
The packaged reference tokenizer remains the default option.
