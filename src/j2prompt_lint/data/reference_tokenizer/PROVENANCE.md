# Reference tokenizer

PTOK uses this packaged BPE tokenizer for its default, disclosed approximate
counts. Loading is offline. These counts estimate template token use and are
not an exact count for an arbitrary target model or a rendered conversation.

- File: tokenizer.json, 2,113,710 bytes.
- Tokenizer identifier: gpt-neox-20b.
- SHA256: c24618a1b3e6a38167beff1c72cffd126c3a66254347304b50547d12c5f25624.
- Vocabulary: 50,254 base entries.
- Source: https://huggingface.co/EleutherAI/gpt-neox-20b .
- Source revision: c292233c833e336628618a88a648727eb3dff0a7 .
- Pinned download: https://huggingface.co/EleutherAI/gpt-neox-20b/resolve/c292233c833e336628618a88a648727eb3dff0a7/tokenizer.json .
- Rights holder: EleutherAI. License: Apache-2.0, as declared by the upstream
  model repository. License text: https://www.apache.org/licenses/LICENSE-2.0 .
- Loader: Hugging Face tokenizers, licensed under Apache-2.0.

The loader verifies the file checksum before use. A missing or changed file
produces PTOK/budget-unknown rather than a trustworthy budget result. Preserve
these bytes when copying the package between platforms.
