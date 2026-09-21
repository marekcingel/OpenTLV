# C ABI compatibility

The `tlv` C shared library exports a public ABI: the functions and data marked
`TLV_API`, and the layout of the public types in `tlv/include/`. The **ABI
Compatibility** CI job compares the library built from a pull request with a
stored ABI baseline using [libabigail](https://sourceware.org/libabigail/)
(`abidw` and `abidiff`).

Out of scope: private and internal symbols (hidden by
`-fvisibility=hidden`), static libraries, the header-only C++ layer (`tlv++`),
source and behavioral compatibility, and Windows/MSVC.

## Baseline

The baseline is the file `scripts/abi/baseline.abi`, an `abidw` dump of the
public ABI that is committed to the repository. CI builds the library from the
pull request as a Debug shared library, dumps its ABI in the same way and
compares the two dumps. Nothing is built for the baseline.

| Version | What the baseline holds |
| --- | --- |
| Before 1.0.0 | The ABI accepted on `main`; updated in the pull request that changes the ABI on purpose |
| 1.0.0 and later | The ABI of the latest stable release of the current major version, for example the newest `1.x.y`; updated only when a release is cut |

Because the file is part of the pull request, an ABI change is visible in the
diff and reviewed like any other change.

The dump depends on the compiler and on the libabigail version, so generate it
on Linux with the same toolchain as CI (Ubuntu 24.04, GCC, `abigail-tools`).

## What breaks the ABI

These changes are incompatible:

- removing or renaming an exported function or variable, or making it hidden;
- changing a parameter or return type of an exported function;
- changing the order, type or offset of a member of a public structure;
- changing the size or alignment of a public type, which includes adding a
  member to a public structure;
- changing an enumeration so that its representation changes.

Adding a new exported function is compatible.

## CI behavior

- The job runs for pull requests that touch `tlv/`, `cmake/`, a
  `CMakeLists.txt` or the ABI scripts. Documentation-only changes skip it.
- The log shows a summary and the affected symbols and types. The full report
  is stored as the `abi-report` artifact.
- Before 1.0.0 an incompatible change is reported as a warning and does not
  fail the job, because the API is still allowed to change. From 1.0.0 it
  fails the job.

## Intentional breaking changes

A breaking change must be described in the pull request (tick "ABI changed"
and "Breaking change"), have a `CHANGELOG.md` entry and, from 1.0.0, target a
new major version. Before 1.0.0, regenerate the baseline in the same pull
request (see below). From 1.0.0, update it only as part of the major-version
transition or when a release is cut.

Suppressions live in `scripts/abi/suppressions.abignore`. Add one only for a
confirmed implementation detail that is not part of the public ABI, with a
comment saying why.

## Running the check locally

Install libabigail (`abigail-tools` on Debian and Ubuntu) and run:

```sh
python scripts/abi/check.py --mode enforce   # compare with the stored baseline
python scripts/abi/check.py --update         # regenerate scripts/abi/baseline.abi
python scripts/abi/test_check.py             # mutation tests of the check itself
```

The report is written to `build/abi/report/`.
