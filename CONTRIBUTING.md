# Contributing to OpenTLV

Report bugs and propose features through
[GitHub issues](https://github.com/marekcingel/OpenTLV/issues).
For bugs, include a small reproducer, expected and actual behavior, compiler,
build options, and the version or commit used.

Before opening a pull request:

- Keep changes focused and preserve documented memory ownership and API boundaries.
- Update relevant documentation and add meaningful tests for behavior changes.
- Build and run the applicable tests using the [getting-started guide](docs/getting-started.md#build-and-run-tests).
- Record meaningful user-facing changes at the top of the appropriate `Unreleased`
  category in [CHANGELOG.md](CHANGELOG.md), including the issue reference.
- Describe the problem, resulting behavior, and verification in the pull request.

For substantial API or architecture changes, discuss the proposed scope in an
issue first. Repository-specific instructions are in [AGENTS.md](AGENTS.md).
