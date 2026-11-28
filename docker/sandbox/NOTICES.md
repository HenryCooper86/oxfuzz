# oxfuzz sandbox image: third-party notices

This file accompanies the container image `oxfuzz/fuzz-sandbox:0.2.4`
(published as `ghcr.io/<owner>/oxfuzz-fuzz-sandbox:0.2.4`). In the image it is
`/usr/share/doc/oxfuzz-sandbox/NOTICES.md`, beside `packages.tsv` (the Ubuntu
packages this build installed, with binary and source package versions),
`ubuntu-snapshot.txt` (see below) and `licenses/` (the GPL-2, GPL-3, LGPL-2.1
and LGPL-3 texts). The image is a
collection of independent programs built or installed by
`docker/sandbox/Dockerfile`. Each program keeps its own licence; the oxfuzz
source code is MIT licensed (`LICENSE` in the repository) and is not part of
the programs listed here, apart from the small oxfuzz-authored files named in
the last section.

This file records what the Dockerfile installs and where the corresponding
source is. It does not interpret how any licence applies to your use.

Provenance: the pinned versions below are the ones in `docker/sandbox/Dockerfile`
at the release that built the image. The Dockerfile in the repository at the
matching release tag is the authoritative record of how each program was
built, including every patch applied (`docker/sandbox/*.patch`).

## Source for GPL and LGPL components

For every component below marked GPL or LGPL, the corresponding source is
obtained as follows.

- Components built from source in the image (SymCC, the AFL++ QEMU mode, and
  honggfuzz): clone the upstream repository named in the table and check out
  the pinned commit. Patches applied to honggfuzz are in this repository under
  `docker/sandbox/` at the release tag.
- Semgrep Community Edition (LGPL-2.1-or-later): the pinned release is tag
  `v1.169.0` (commit `09c90f40de48bac000f6d49f978a65ee8a09a3f4`) of
  https://github.com/semgrep/semgrep. The licence text is in
  `third_party/semgrep/LICENSE` in this repository.
- Ubuntu packages (QEMU, GDB, GNU binutils including libbfd and libopcodes,
  GNU libc, libgcc, libstdc++, OpenSSH, Z3 and the rest): the Ubuntu source
  packages for the exact versions in `/usr/share/doc/oxfuzz-sandbox/packages.tsv`
  are available from the Ubuntu snapshot service, at the timestamp in
  `/usr/share/doc/oxfuzz-sandbox/ubuntu-snapshot.txt` (`<timestamp>` below).
  On Ubuntu 24.04 add these source entries and run
  `apt-get update && apt-get source <source-package>=<source-version>`:

  ```
  Types: deb-src
  URIs: https://snapshot.ubuntu.com/ubuntu/<timestamp>/
  Suites: noble noble-updates noble-security
  Components: main universe restricted multiverse
  Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
  ```

  Source packages are architecture-independent, so the same entries serve the
  amd64 and arm64 images. Launchpad is the fallback:
  `https://launchpad.net/ubuntu/+source/<source-package>`.

Ubuntu binary packages are not version-pinned: the Dockerfile installs them from
the live `noble` archive, so two builds of the same Dockerfile can contain
different versions. `packages.tsv` lists what each published image contains
(binary package, version, source package, source version). `ubuntu-snapshot.txt`
is the UTC time of the build's first `apt-get update`, rounded up to the next
whole hour (format `YYYYMMDDTHHMMSSZ`). Packages installed by later layers of a
cached rebuild can be newer than that time. Packages that come with the
pinned base image (for example glibc, systemd, coreutils and perl) keep the
version of the base image's build and can already be superseded in the snapshot;
for any version the snapshot does not list, use Launchpad, which keeps every
published version (`https://launchpad.net/ubuntu/+source/<source-package>/<source-version>`). Each package's licence text is in
`/usr/share/doc/<package>/copyright`; the image keeps these files (the Ubuntu
base image excludes other documentation but explicitly keeps `copyright`).

## Written offer

For at least three years from the publication of each image, the corresponding
source for the GPL and LGPL components in that image is provided on request
through the issue tracker of https://github.com/HenryCooper86/oxfuzz, for a
charge no greater than the cost of distributing it. The request should name the
image tag and the component.

## Components built from source or downloaded

| Component | Pinned version | Licence | Source |
|---|---|---|---|
| SymCC (compiler pass and wrapper) | commit `3b8acabf06c83b92facccde7f6dfb191b1a163b3` | GPL-3.0-or-later | https://github.com/eurecom-s3/symcc |
| SymCC runtime (`symcc-rt`, built with the `qsym` backend) | commit `892f817f38f5abfa083dd0c1caa7ced821566bf5` (submodule of the SymCC commit) | LGPL-3.0-or-later | https://github.com/eurecom-s3/symcc-rt |
| QSYM (SymCC fork), inside the SymCC runtime | submodule of `symcc-rt` at the commit it pins | BSD-style (UC Regents; text in its `LICENSE`) | https://github.com/eurecom-s3/qsym (branch `symcc`) |
| AFL++ QEMU mode (`afl-qemu-trace`, built from QEMUAFL) | AFL++ commit `108fb0b29ad1586e668ba23e23a0eb1a13c45c49`; QEMUAFL revision `a1321713c7` (QEMU 5.2.50 base), taken from `qemu_mode/QEMUAFL_VERSION` | GPL-2.0-or-later (QEMU); AFL++ glue Apache-2.0 | https://github.com/AFLplusplus/AFLplusplus and https://github.com/AFLplusplus/qemuafl |
| honggfuzz (with `docker/sandbox/honggfuzz-*.patch`) | commit `83a8415a372d84dcc69ac1e2c2f152190bcf76d1` (release 2.6) | Apache-2.0; the binary links GNU libbfd and libopcodes (GPL-3.0-or-later), see the note below | https://github.com/google/honggfuzz |
| syzkaller | commit `27a8bd60fa3a186e2b15eb9c4706689e3d2be6f2` | Apache-2.0 | https://github.com/google/syzkaller |
| Go toolchain | 1.26.5 | BSD-3-Clause | https://github.com/golang/go (tag `go1.26.5`) |
| Rust nightly toolchain | `nightly-2026-06-10` | MIT OR Apache-2.0 | https://github.com/rust-lang/rust |
| cargo-fuzz | 0.13.2 | MIT OR Apache-2.0 | https://github.com/rust-fuzz/cargo-fuzz |
| Vendored crates for Rust harness builds (`/opt/rust/vendor`): libfuzzer-sys 0.4.13, arbitrary, cc, cfg-if, find-msvc-tools, getrandom, jobserver, libc, r-efi, shlex | resolved at build time, recorded in each crate's `Cargo.toml` | libfuzzer-sys: (MIT OR Apache-2.0) AND NCSA (it bundles LLVM libFuzzer); the others MIT OR Apache-2.0 | https://crates.io and each crate's repository |
| CASR | 2.13.1 | Apache-2.0 | https://github.com/ispras/casr |
| gdb-command (patched, statically linked into CASR) | 0.7.8 (`docker/sandbox/gdb-command-output.patch`) | MIT | https://crates.io/crates/gdb-command |
| Crates statically linked into the CASR binaries | resolved from CASR 2.13.1's `Cargo.lock` (`--locked`) | not individually audited here; see each crate's licence in the CASR lockfile | https://crates.io |
| Semgrep Community Edition | 1.169.0 | LGPL-2.1-or-later | https://github.com/semgrep/semgrep (tag `v1.169.0`) |
| Semgrep C rules (0xdea) | commit `4d66ecf30bfb1809a984085f2c86a8c3915bfc71` | MIT | https://github.com/0xdea/semgrep-rules (copy in `/opt/oxfuzz/semgrep-rules`, licence in `LICENSE` beside it) |
| LLVM libc++, libc++abi and libFuzzer, built with MemorySanitizer | `llvmorg-18.1.3`, commit `c13b7485b87909fcf739f62cfa382b55407433c0` | Apache-2.0 WITH LLVM-exception | https://github.com/llvm/llvm-project |
| Jazzer standalone launcher | 0.30.0 | Apache-2.0 | https://github.com/CodeIntelligenceTesting/jazzer |
| Jazzer.js and its npm dependency tree (`/opt/jazzerjs`) | `@jazzer.js/core` 4.0.0, installed from `docker/sandbox/jazzerjs/package-lock.json` | Apache-2.0 for Jazzer.js; each npm package carries its own licence file under `node_modules` | https://github.com/CodeIntelligenceTesting/jazzer.js and https://www.npmjs.com |
| Node.js | 24.22.3 | MIT, with bundled components under their own licences (full text in the Node.js `LICENSE`) | https://github.com/nodejs/node (tag `v24.22.3`) |
| Bazel | 8.9.0 and 9.3.3 | Apache-2.0 | https://github.com/bazelbuild/bazel |
| Atheris | 3.0.0, built from the PyPI sdist | Apache-2.0 | https://github.com/google/atheris |
| MarkItDown and its Python dependencies (installed with pip into the system Python) | markitdown 0.1.6 | MIT for MarkItDown; dependencies mostly MIT, BSD, Apache-2.0, PSF; certifi is MPL-2.0 | https://github.com/microsoft/markitdown and https://pypi.org |
| Semgrep's Python dependencies | resolved by pip at build time | the licence recorded in each package's `*.dist-info` directory | https://pypi.org |
| `oxfuzz-clang-analyze` | built from `tools/clang-analysis` in this repository | MIT; dynamically links the Ubuntu LLVM and Clang 18 libraries (Apache-2.0 WITH LLVM-exception) | this repository |

Licence determination: the licences in the table were read from the pinned
upstream trees (`LICENSE` or `COPYING` at the pinned commit or tag, or the
package metadata of the pinned release) and compared with the files present
in a built image. Where an upstream states a licence per directory (SymCC and
its runtime, Node.js, libfuzzer-sys), the table lists the top-level licence
and names the exceptions it found.

### honggfuzz and libbfd

honggfuzz is Apache-2.0, but the Dockerfile builds it against
`libbfd-dev` (binutils 2.42), and the installed `honggfuzz` binary links
`libbfd-2.42-system.so` and `libopcodes-2.42-system.so`, which are
GPL-3.0-or-later. The honggfuzz binary in this image is therefore
distributed under the terms of the GPL-3.0-or-later as well as Apache-2.0.
Its source and build recipe are the pinned commit and patches above, plus the
Ubuntu `binutils` source package.

### SymCC

SymCC is GPL-3.0-or-later. Its runtime library, which is linked into programs
compiled with the `symcc` wrapper, is LGPL-3.0-or-later and includes QSYM
(BSD-style licence). The full GPL-3.0 and LGPL-3.0 texts are in
`/usr/share/common-licenses/GPL-3` and `/usr/share/common-licenses/LGPL-3`
in the image, and under `/usr/share/doc/oxfuzz-sandbox/licenses/`.

## Ubuntu packages

The base image is `ubuntu:24.04` pinned by digest
`sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90`.
Everything else installed with `apt-get` is from the Ubuntu 24.04 (noble)
archives. Notable packages and their licences, taken from each package's
`/usr/share/doc/<package>/copyright`:

- GPL or LGPL (per each package's copyright file): GNU libc and libstdc++
  (LGPL with, for libstdc++, the GCC runtime library exception), GDB
  (GPL-2.0-or-later and GPL-3.0-or-later files), GNU binutils, libbfd and
  libopcodes (GPL-3.0-or-later), QEMU system emulators and utilities
  (GPL-2.0-or-later with LGPL and other licences for some files), GNU make
  (GPL-3.0-or-later), Bison, Flex, Libtool, Bear (GPL-3.0-or-later), GNU gettext
  and autopoint (GPL-3.0-or-later), OpenJDK 21
  (GPL-2.0 with the Classpath exception, with LGPL-2.1, MIT and BSD files).
- Apache-2.0 WITH LLVM-exception: Clang, LLVM, LLD, libFuzzer and the
  compiler runtime libraries, versions 17 and 18 (some files MIT or BSD-3-Clause).
- Other: AFL++ 4.09c from Ubuntu (Apache-2.0 with BSD, MIT, MPL-2.0 and GPL-3
  files, see its copyright file), CMake (BSD and MIT), Meson (Apache-2.0),
  Ninja (Apache-2.0), Z3 (MIT, with one GPL-2.0-or-later file), OpenSSH (BSD
  and public-domain licences).

The package copyright files are authoritative; this summary is not.

## oxfuzz-authored files in the image

`/usr/local/bin/oxfuzz-semgrep-scan`, `/opt/oxfuzz/semgrep-tree-digest.py`,
`/usr/local/bin/bazel` (launcher), `/usr/local/bin/oxfuzz-bazel-compdb` and
`/usr/local/bin/oxfuzz-clang-analyze` are part of oxfuzz and are MIT licensed.
