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
- Update relevant documentation and add meaningful tests for behavior changes.
- Build and run the applicable tests using the [getting-started guide](docs/getting-started.md#build-and-run-tests).
- Format C and C++ changes with clang-format, ideally via the pre-commit hooks
  (see below); CI rejects a pull request that isn't formatted.
- Record meaningful user-facing changes at the top of the appropriate `Unreleased`
  category in [CHANGELOG.md](CHANGELOG.md), including the issue reference.
- Describe the problem, resulting behavior, and verification in the pull request.

For substantial API or architecture changes, discuss the proposed scope in an
issue first. Repository-specific instructions are in [AGENTS.md](AGENTS.md).

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
