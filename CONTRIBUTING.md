# Contributing to OpenTLV

Report bugs and propose features through
[GitHub issues](https://github.com/marekcingel/OpenTLV/issues).
For bugs, include a small reproducer, expected and actual behavior, compiler,
build options, and the version or commit used.

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
