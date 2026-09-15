# Conan recipe

[Back to documentation](../docs/README.md)

This directory is the source of truth for OpenTLV's [ConanCenter](https://conan.io/center)
recipe, following [Conan 2](https://docs.conan.io/2/) conventions. It mirrors
the layout `conan-center-index` expects under `recipes/opentlv/`:

```text
conan/
  config.yml           # version -> recipe folder mapping
  all/
    conanfile.py        # the recipe itself
    conandata.yml        # version -> source archive URL and sha256
    test_package/         # consumption smoke test (C and C++)
```

`config.yml` and `conandata.yml` start empty and are populated automatically,
one version at a time, by [`conan-publish.yml`](../.github/workflows/conan-publish.yml)
when a version tag is pushed. That workflow opens a pull request against
[`conan-io/conan-center-index`](https://github.com/conan-io/conan-center-index)
adding the new version; it does not resubmit versions tagged before the
workflow existed. Running it requires a `CONAN_CENTER_PAT` repository secret:
a GitHub personal access token, for an account with a fork of
`conan-center-index`, with permission to push branches and open pull requests.
Without that secret the workflow is skipped.

## Recipe options

| Option | Default | Effect |
| --- | --- | --- |
| `shared` | `False` | Builds `tlv` as a shared instead of static library. |
| `fPIC` | `True` | Position-independent code for static builds (ignored on Windows and when `shared=True`). |
| `with_cxx` | `True` | Installs the header-only `tlv++` wrapper and exposes the `OpenTLV::tlvpp` target. |

Consumers get both the C API (`OpenTLV::tlv`) and, by default, the C++ API
(`OpenTLV::tlvpp`) through `find_package(OpenTLV CONFIG REQUIRED)`, the same
CMake package OpenTLV installs from a source build. See
[getting started](../docs/getting-started.md#install-and-generate-distribution-archives)
for that CMake package's target names and layout.

## Local validation

```sh
pip install "conan>=2.0,<3.0"
conan profile detect --force
conan create conan/all --name opentlv --version 0.3.0 \
    -o "opentlv/*:shared=False" -o "opentlv/*:with_cxx=True" --build=missing
```

This requires a `sources` entry for the chosen version in
`conan/all/conandata.yml`; add a temporary local entry (source archive URL and
sha256, for example from an existing GitHub release tag) to validate the
recipe against a version that has not gone through `conan-publish.yml` yet,
and revert it afterward.

## Project stability

OpenTLV is in a late-alpha / pre-beta stage; see the
[project status note](../README.md#project-status) before depending on API
stability across versions consumed through Conan.
