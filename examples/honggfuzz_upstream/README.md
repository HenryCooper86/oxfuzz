# Upstream honggfuzz examples (vendored)

Unmodified copies of the self-contained parts of the honggfuzz `examples/`
and `socketfuzzer/` directories. The showcase targets one level up are
clean-room rewrites. This directory holds the upstream code itself, so the
AI harness pipeline is tested against real signatures that were not written
for oxfuzz.

- Source: <https://github.com/google/honggfuzz>
- Commit: `940b958dfeb6f9131fd846cae31fcc0fe996ae98` (2026-09-25)
- License: Apache-2.0, copyright Google Inc. The full text is in `LICENSE`
  (upstream `COPYING`). No file here has been modified.

## Targets

These targets build with libc alone.

| Path | Upstream path | Entry point(s) | Bug | Harness challenge |
| --- | --- | --- | --- | --- |
| `badcode/badcode1.c` | `examples/badcode/targets/badcode1.c` | `output(char *filename)` | stack-buffer-overflow: `fgets(str, 128, fp)` into `char str[64]` | Takes a file path, not bytes. A correct harness writes `data` to a temporary file and passes its path. |
| `badcode/badcode2.c` | `examples/badcode/targets/badcode2.c` | none (no input) | stack-buffer-overflow in `crash()`, reached by two different call stacks | No input surface. Useful for crash triage and stack deduplication, not for harness drafting. |
| `vulnserver/vulnserver_cov.c` | `socketfuzzer/vulnserver_cov.c` | `handleData1(char *, int)`, `handleData2(char *, int)` | stack overflow (`handleData1`) and heap overflow (`handleData2`) from `memcpy` of an unbounded length | Socket server. The harness must call the handlers directly or drive `doprocessing` through a socket pair. Linux only (`crypt.h`). |

`badcode/inputfiles/badcode1.txt` is the upstream seed input. Each of its
two lines is longer than 64 bytes, so the seed alone triggers the
`badcode1` overflow.

```bash
oxfuzz discover examples/honggfuzz_upstream/badcode --lang c
oxfuzz harness examples/honggfuzz_upstream/badcode --target badcode1.c::output \
  --engine honggfuzz --draft-only --ai require
oxfuzz discover examples/honggfuzz_upstream/vulnserver --lang c
oxfuzz harness examples/honggfuzz_upstream/vulnserver \
  --target vulnserver_cov.c::handleData2 --engine honggfuzz --draft-only --ai require
```

## Reference harnesses

`reference_harnesses/` holds the human-written honggfuzz persistent-mode
harnesses that upstream ships for real libraries. Each one defines
`LLVMFuzzerTestOneInput` (and sometimes `LLVMFuzzerInitialize`) and includes
`libhfuzz/libhfuzz.h`. They do not build here, because the library sources
are not vendored. Use them as baselines when you compare an LLM-drafted
harness for the same library entry point.

| Path | Library | API exercised |
| --- | --- | --- |
| `libxml2/persistent-xml2.c` | libxml2 | `xmlReadMemory`, `xmlDocFormatDump` |
| `libpng/persistent-png.c` | libpng | `png_read_png` with a custom read callback |
| `libjpeg/persistent-jpeg.c` | libjpeg | `jpeg_read_header`, `jpeg_start_decompress` |
| `libjpeg/persistent-jpegturbo.c` | libjpeg-turbo | `tjDecompressHeader3`, `tjDecompress2` |
| `file/persistent-file.c` | libmagic (file) | `magic_buffer` |
| `openssl/x509.c` | OpenSSL | `d2i_X509`, `X509_print_ex` |
| `openssl/privkey.c` | OpenSSL | `d2i_AutoPrivateKey` |
| `openssl/hf_ssl_lib.h` | OpenSSL | shared setup for the two harnesses above |

### Comparing an AI draft against a reference harness

`fetch-libs.sh` downloads the library sources at pinned commits into the
git-ignored `third_party/` directory. It builds and runs nothing.

| Library | Tag | Commit |
| --- | --- | --- |
| libxml2 | `v2.13.5` | `de918d45e1b2276a28a4cd32bcf556bef65284e4` |
| libpng | `v1.6.44` | `f5e92d76973a7a53f517579bc95d61483bf108c0` |
| libjpeg-turbo | `3.0.4` | `f29eda648547b36aa594c4116c7764a6c8a079b9` |
| file (libmagic) | `FILE5_45` | `4cbd5c8f0851201d203755b76cb66ba991ffd8be` |

```bash
examples/honggfuzz_upstream/fetch-libs.sh libxml2
oxfuzz discover examples/honggfuzz_upstream/third_party/libxml2 --lang c
oxfuzz harness examples/honggfuzz_upstream/third_party/libxml2 \
  --target parser.c::xmlReadMemory --engine honggfuzz --draft-only --ai require
# then compare the draft with reference_harnesses/libxml2/persistent-xml2.c
```

A draft only needs the source. Compiling it needs the library's own build
configuration (`config.h` and a compile database), which these projects
generate with their configure step. Set that up with `oxfuzz build diagnose`,
`oxfuzz build profile` and `oxfuzz build run` before you compile or
smoke-test a draft.

## Not vendored

These upstream directories were left out because they are build recipes or
patches for large external projects, or binary corpora:

- `apache`, `apache-httpd`, `bind`, `glibc`, `linux_kernel_ip`
- `terminal-emulators`, `externalfuzzers`
- the OpenSSL `client.c` and `server.c` TLS harnesses
- every `corpus*` directory

## Tests

`crates/hf-discovery/tests/honggfuzz_upstream_examples.rs` checks three things
without a toolchain:

- `LICENSE` is present.
- Discovery finds `output`, `handleData1`, and `handleData2`.
- Every reference harness exposes `LLVMFuzzerTestOneInput`.
