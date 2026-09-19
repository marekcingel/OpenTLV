# Contributing to OpenTLV

Report bugs and propose features through
[GitHub issues](https://github.com/marekcingel/OpenTLV/issues), using the
Bug Report, Feature Request, or Documentation issue form. For bugs, include a
small reproducer, expected and actual behavior, compiler, build options, and
the version or commit used. Report suspected security vulnerabilities
privately instead, following [SECURITY.md](SECURITY.md).

All project spaces, including issues, pull requests, and reviews, are
governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

Before opening a pull request:

- Keep changes focused and preserve documented memory ownership and API boundaries.
- Update relevant documentation and add meaningful tests for behavior changes;
  document new or changed public API as described in
  [Public API documentation](#public-api-documentation).
- Build and run the applicable tests using the [getting-started guide](docs/getting-started/README.md#build-and-run-tests).
- Format C and C++ changes with clang-format, ideally via the pre-commit hooks
  (see below); CI rejects a pull request that isn't formatted.
- Record meaningful user-facing changes at the top of the appropriate `Unreleased`
  category in [CHANGELOG.md](CHANGELOG.md), including the issue reference.
- Describe the problem, resulting behavior, and verification in the pull request.

For substantial API or architecture changes, discuss the proposed scope in an
issue first. Repository-specific instructions are in [AGENTS.md](AGENTS.md).

## Public API documentation

The public headers ([tlv/include/tlv](tlv/include/tlv) and
[tlv++/include/tlv++](tlv++/include/tlv++)) are the authoritative source for
API contracts and are written as Doxygen comments, so a generated API
reference can be built from them. Every new or changed public declaration
follows the conventions below. Doxygen generation itself is not part of the
build yet; the comments are checked by review and, for the C headers, by the
compiler (see the end of this section).

**Format.** Use `/** ... */` blocks with a leading `@brief` line, a blank line,
then the details. Put the block directly above the declaration. Use
`/** ... */` above a member or enumerator (or `/**< ... */` after it) for
structure members, enum values and constants. Plain `/* ... */` and `//`
comments stay for implementation notes and are never used for public
contracts. Start each header with an `@file` block giving a one-line `@brief`,
and put any module-wide rules there.

**Tags**, in this order:

| Tag | Use |
| --- | --- |
| `@brief` | One sentence, imperative or descriptive, ending in a period. |
| `@param[in]`, `@param[out]`, `@param[in,out]` | Every parameter that is not obvious from its name and type. State the direction, whether `NULL` is allowed and when, valid ranges, and units (bytes, not elements). |
| `@return` | One line per distinct result code, naming the enumerator (`@return #TLV_ERR_NULL_ARG if ...`); use one line for success. |
| `@note` | Guarantees and clarifications, such as output preservation on failure. |
| `@warning` | Hazards the caller must act on, such as lifetime requirements, or callbacks that may leave a buffer modified on error. |
| `@see` | Related functions or types. |
| `@deprecated` | Deprecated APIs, with the replacement. |

**Describe the public contract, not the implementation.** Where they apply,
state each of the following explicitly:

- ownership and lifetime: who owns each buffer, and what must outlive a
  returned view, reader, writer or descriptor;
- allocation behavior, including that a function never allocates;
- zero-copy behavior: which outputs borrow input bytes;
- valid and invalid arguments, including `NULL` handling and overlap rules;
- error conditions, using the result-code names;
- output preservation on failure, such as `*written` left unchanged, a
  destination left unspecified, or a callback that may have modified it;
- reader and writer state changes, such as the position advancing only on
  success;
- native-size limitations, such as a 64-bit `tlv_length_t` narrowed to
  `size_t`;
- format- or profile-specific restrictions.

**Conventions.**

- Refer to code entities by name: `#TLV_OK` for constants, types and enumerators
  in the same header set, `function()` for functions (Doxygen links them), and
  backticks for parameters and other code. Cross-reference documentation files
  by path.
- Do not restate the signature. Skip `@param` only for parameters whose name and
  type make them obvious.
- A family of overloads that differ only by type (for example `_u8`, `_u16`,
  `_u32`, `_u64`) documents the first in full and uses `@copydetails` on the
  rest, each with its own `@brief`.
- Generated code, such as constants produced from
  [emv_tags.def](tlv/include/tlv/profiles/emv_tags.def), is documented once on the
  generating macro or in the header that expands it.
- Preserve existing useful documentation when converting a comment; move its
  content into the structure above rather than rewriting it.
- Public C headers stay C99 and must not need Doxygen to compile.

To catch malformed comments (for example a `@param` that names a nonexistent
parameter), build the C headers with Clang's `-Wdocumentation`.

## Pre-commit hooks

[.pre-commit-config.yaml](.pre-commit-config.yaml) runs clang-format plus a
few whitespace/YAML/Markdown checks before each commit. Install
[pre-commit](https://pre-commit.com/) once per clone:

```sh
pip install pre-commit
pre-commit install
```

`git commit` then runs the hooks automatically and reformats or fixes what it
can; re-stage and commit again if it changed anything. Run them on the whole
tree (e.g. after changing `.clang-format`) with:

```sh
pre-commit run --all-files
```

[static-analysis.yml](.github/workflows/static-analysis.yml) runs the same
config in CI, so a clone with the hooks installed won't be surprised by CI.

## Code formatting

The `tlv` (C) and `tlv++` (C++) code, along with `tools/`, `tests/`,
`benchmarks/` and `examples/`, follows the style defined in
[.clang-format](.clang-format) (the root file, for tlv++ and everything built
on it) and [tlv/.clang-format](tlv/.clang-format) (an override for the pure C
layer). clang-format applies whichever of the two is nearest to a given file,
so both apply automatically; there's no `Language:`-based split in one shared
file because clang-format versions disagree on how to classify an ambiguous
`.h` file as C or C++, and clang-format 18 (still common) can't even parse a
`Language: C` section. Install the exact version pinned in
[.pre-commit-config.yaml](.pre-commit-config.yaml) (`rev:` under
`mirrors-clang-format`, currently 23.1.1 - `pip install clang-format==23.1.1`
also gets that same build) to avoid version-to-version formatting
differences, and, from a configured build directory, run:

```sh
cmake --build <build-dir> --target format        # reformat in place
cmake --build <build-dir> --target format-check   # check only, like CI
```

Both targets are opt-in and are skipped with a warning if clang-format isn't
found, so their absence never breaks a regular build.

## Static analysis (cppcheck)

[static-analysis.yml](.github/workflows/static-analysis.yml) also runs
[cppcheck](https://cppcheck.sourceforge.io/) over `tlv` (C) and `tlv++`
(C++) with `--enable=warning,style,performance,portability`. Reproduce it
locally by installing cppcheck, configuring a build directory, and building
the opt-in `cppcheck` target:

```sh
cmake -S . -B <build-dir> -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build <build-dir> --target cppcheck
```

Like `format`/`format-check`, the target is skipped with a warning (never
breaking a regular build) if cppcheck isn't found. Justified exceptions
(for example a limitation of cppcheck's own preprocessor, or intentional
API behavior a check flags) live in
[.cppcheck-suppressions](.cppcheck-suppressions), with a comment explaining
each one; prefer fixing a finding over suppressing it.

## Static analysis (clang-tidy)

[static-analysis.yml](.github/workflows/static-analysis.yml) also runs
[clang-tidy](https://clang.llvm.org/extra/clang-tidy/) 18 over `tlv` (C) and
`tlv++` (C++). Check selection lives in [.clang-tidy](.clang-tidy) at the
repository root (the shared baseline for both languages) plus
[tlv/.clang-tidy](tlv/.clang-tidy) and [tlv++/.clang-tidy](tlv++/.clang-tidy),
which layer C- and C++-specific checks on top of it; clang-tidy resolves the
config for a given file by merging every `.clang-tidy` it finds walking up
from that file's own directory, so both apply automatically. Reproduce it
locally by installing clang-tidy, configuring a build directory with
`CMAKE_EXPORT_COMPILE_COMMANDS` enabled (clang-tidy needs the resulting
`compile_commands.json` to know each file's include paths and language
standard), and building the opt-in `clang-tidy` target:

```sh
cmake -S . -B <build-dir> -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build <build-dir> --target clang-tidy
```

Like `format`/`format-check`/`cppcheck`, the target is skipped with a
warning (never breaking a regular build) if clang-tidy isn't found or
`CMAKE_EXPORT_COMPILE_COMMANDS` wasn't enabled (also requires
`OPENTLV_BUILD_CXX`/`OPENTLV_BUILD_TESTS`/`OPENTLV_BUILD_UNIT_TESTS`, all ON
by default). tlv++ is header-only, so there's no translation unit of its
own for clang-tidy to attach to; instead the target points clang-tidy at
`tests/unit/tlv++/src/test_tlvpp.cpp`, which already includes and exercises
every tlv++ header with real instantiations (a synthetic TU that just
`#include`s the headers would compile but never instantiate their
templates, so clang-tidy would have nothing to analyze inside them).
Findings are still reported for that test file itself, so it has to stay
clang-tidy-clean too. Justified exceptions (for example a Clang Static
Analyzer false positive through an indirect function-pointer call it can't
resolve) are fixed with a
`NOLINT`/`NOLINTNEXTLINE`/`NOLINTBEGIN`-`NOLINTEND` comment explaining why,
right at the finding; prefer fixing a finding over suppressing it.

## Documentation site

The [docs/](docs) directory is also built into a [MkDocs](https://www.mkdocs.org/)
site with the [Material](https://squidfunk.github.io/mkdocs-material/) theme,
configured in [mkdocs.yml](mkdocs.yml). The Markdown files stay the single
source and remain readable on GitHub. Build and preview it locally:

```sh
pip install -r requirements-docs.txt
mkdocs serve   # live preview at http://127.0.0.1:8000
mkdocs build   # writes the static site to site/ (git-ignored)
```

Documentation is grouped by purpose (`getting-started/`, `concepts/`, `guides/`,
`formats/`, `profiles/`, `cli/`, `reference/`, `development/`); see
[where documentation belongs](docs/development/documentation-layout.md) before
adding a page.

For a documentation move, follow the repository-wide link checks and content
preservation rules in that guide. The [migration table and URL policy](docs/development/documentation-layout.md#migration-for-issue-186)
record the paths changed by the documentation reorganization.

The build is strict: broken links between documentation pages fail it. Add a
new page to the `nav` section of `mkdocs.yml` so it appears in the site
navigation. Relative links that leave `docs/` (to source files, `README.md`,
`CHANGELOG.md` and so on) are rewritten to GitHub URLs by
[tools/docs/hooks.py](tools/docs/hooks.py). The site landing page is
[docs/index.md](docs/index.md); [docs/README.md](docs/README.md) remains the
index shown on GitHub.

### Publishing

The [Documentation workflow](.github/workflows/docs.yml) builds the site with
`mkdocs build` and deploys it to GitHub Pages at
<https://marekcingel.github.io/OpenTLV/>:

- Pull requests to `main` or `develop` only verify that the site builds.
- A push to `main`, the publication branch, builds and deploys the site. A
  failed build stops the workflow before deployment, so the published site is
  never replaced by a broken one.
- The generated site is uploaded as a workflow artifact; nothing is committed
  to a `gh-pages` branch.

No manual upload is needed. One-time repository setup: under **Settings ->
Pages**, set **Source** to **GitHub Actions**. To publish from another branch,
change `on.push.branches` and the `github.ref` check in the workflow, and allow
that branch in the `github-pages` environment's deployment branch rules.
A run can also be started manually from the Actions tab (`main` only deploys).
