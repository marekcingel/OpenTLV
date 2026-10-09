# Deterministic property suite

This suite verifies invariants over generated valid wire streams. Unit tests
cover component contracts; integration tests cover explicit wire vectors and
layer interactions; fuzz tests explore arbitrary or malformed inputs. A
minimized discovered regression belongs in unit or integration tests according
to its root cause, rather than becoming a permanent property corpus.

## Build and run

```sh
cmake -S . -B build -DOPENTLV_BUILD_PROPERTY_TESTS=ON
cmake --build build --target otlv property-roundtrip
ctest --test-dir build -L property --output-on-failure --no-tests=error
```

For Visual Studio, add `--config Release` to the build and `-C Release` to CTest.
The option defaults to OFF and is gated by `OPENTLV_BUILD_TESTS`, just like the
unit and integration group options. Enabling it requires the CLI/C++ layer and
Python 3.8 or newer. Property-only builds can disable unit and integration
tests and do not fetch GoogleTest. No libFuzzer dependency is introduced.

`OPENTLV_PROPERTY_COUNT` defaults to 128 cases per configuration.
`OPENTLV_PROPERTY_SEED` accepts an explicit decimal uint64 seed, including zero;
an empty value derives it from `OPENTLV_PROPERTY_COMMIT`. The latter defaults
to Git HEAD at configure time, or `source-archive` without Git metadata.
Reconfigure after changing HEAD to refresh the commit-derived seed.

## Corpus contract

Each configuration owns a directory under
`build/property-data/<configuration>/<format-configuration>/`. Each `.bin`
contains one complete, nonempty, independently parseable and round-trippable
stream. Names are zero-based decimal indices padded to at least six digits.
The enumerator rejects missing, extra or empty cases. Runs replace their own
binary cases and metadata; generated data stays in the build directory.

`metadata.json` records the contract version, commit, Format/configuration,
decimal seed as a string (avoiding JSON number precision loss), SplitMix64
algorithm and native `TLV_GENERATOR_VERSION`, CLI candidate-domain version,
generation limits and exact generation command. Commit identity also pins the
CLI domain implementation. The stable seed mapping is:

```python
seed = int.from_bytes(hashlib.sha256(commit.lower().encode("ascii")).digest()[:8], "big")
```

This uses the actual checked-out commit, including a PR merge commit. The same
commit, generator version, candidate domain, Format and limits reproduce the
same corpus. The mapping itself has a versioned name in metadata.
Generator version 2 changes seed/case-index mixing. Rebuild the CLI and rerun
the suite to regenerate both binary cases and `metadata.json`; version 1 corpus
bytes must not be relabeled as version 2. The metadata contract and CLI candidate
domain version are unchanged.

## Wire property and coverage

The native verifier consumes public Tree Reader BEGIN/ELEMENT/END events and
feeds them to public Tree Writer. It verifies complete Reader exhaustion,
Writer completion and byte-for-byte equality. Constructed Values are rebuilt
from their children; source preservation and raw copying are not used.
Python independently compares the files and stores failure evidence.

Enabled CLI generator domains are tested: Fixed (narrow, wide big/little
endian and empty Values), BER, DER, EMV, Bluetooth LTV and NFC Type 2.
The native generator samples empty Values, 127/128 and 255/256 length
boundaries, multiple roots and nested/empty constructed elements, subject to
the configured bounds. Bluetooth exercises LTV and tag-plus-value Length
scope. NFC tests extended lengths and a separate configuration adds a NULL
prefix and Terminator suffix; metadata identifies this deterministic
transformation. Its recorded generator limits reserve two bytes/elements for
the controls. Apply the transformation after replaying the generation command.

BER corpora use minimal definite encodings that Writer reconstructs exactly.
Arbitrary Reader-valid nonminimal or indefinite BER is outside this property,
as it may be normalized. DER/EMV/AD/NDEF semantic validation is also outside
scope: this is a wire invariant. CER, DHCP and LLDP do not yet have CLI
generator domains and therefore have no generated property registrations.

## Failure evidence and reproduction

Failures live under
`build/property-failures/<configuration>/<format-configuration>/<case-index>/`:

- `input.bin`: exact failing complete input;
- `output.bin`: actual Writer output, including a partial prefix on errors;
- `metadata.json`: corpus identity, filename/index and checker error/offset.

Generation failures retain metadata and any completed cases. The verifier
continues after a failed case to collect other failures. Each rerun clears old
failure evidence for its configuration. CTest logs include the Format,
filename, seed and failure count.

To regenerate, check out the recorded commit, build its CLI, and run the
recorded `generation_command` with a new output directory. To inspect one
saved input directly, run `property-roundtrip FORMAT input.bin output.bin
MAX_DEPTH MAX_ELEMENTS TAG_WIDTH LENGTH_WIDTH BYTE_ORDER` with metadata's
configuration and traversal limits (restore the two reserved elements for the
NFC control variant). Defaults for non-Fixed widths/order are `1 1 big`.

The separate `property.yml` workflow runs default and minimal builds for
pushes, pull requests and manual dispatch. It generates 1000 cases per
configuration, derives seeds from the checked-out SHA, uploads only failure
evidence and the CTest log on failure, and discards successful corpora.
Generated corpora are never cached.
