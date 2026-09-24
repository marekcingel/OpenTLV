# Fuzzing the C API

The optional `OPENTLV_BUILD_FUZZING` build tests the C `tlv` API using
[libFuzzer](https://llvm.org/docs/LibFuzzer.html), AddressSanitizer (ASan), and
[UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
(UBSan). It defaults to `OFF`. The C++ wrappers are outside this suite.

The fuzz build requires Linux (including WSL), Clang 18 or newer, and its
libFuzzer and sanitizer runtimes. On Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install clang-18 libclang-rt-18-dev llvm-18 cmake ninja-build
cmake -S . -B build/fuzz -G Ninja \
  -DCMAKE_C_COMPILER=clang-18 -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DOPENTLV_BUILD_FUZZING=ON -DOPENTLV_BUILD_CXX=OFF \
  -DOPENTLV_BUILD_TESTS=OFF -DOPENTLV_BUILD_EXAMPLES=OFF
cmake --build build/fuzz --parallel
```

No GoogleTest or C++ compiler configuration is needed. The runtime itself may
depend on the toolchain's C++ runtime. A separate static `tlv_fuzz` library
reuses the enabled C sources with coverage and sanitizer instrumentation.
The ordinary `tlv` target, installed package, and consumers receive no fuzzing
flags. Contract checks remain active with `NDEBUG`; UBSan errors are fatal.

## Targets and contracts

| Target | Checks |
| --- | --- |
| `fuzz_read` | Sequential `tlv_read` calls, positive bounded consumption, borrowed value ranges, unchanged view and consumed count on failure. |
| `fuzz_walk_tree` | Nested `tlv_walk_tree` traversal, depth and element limits (including zero), view ranges, increasing offsets and parent bounds, STOP/ERROR handling, agreement with validation-only traversal. |
| `fuzz_der` | `tlv_der_read` and `tlv_der_walk`, canonical DER-TLV framing, all four profile limits, unchanged read outputs on failure, error offsets, callbacks and validation-only traversal. |
| `fuzz_der_schema` | `tlv_der_schema_read` against a fixed representative schema (IMPLICIT/EXPLICIT tagging, a DEFAULT component, SET, SET OF, SEQUENCE OF and CHOICE), all five schema limits, unchanged read outputs and bounded error offsets on failure. |
| `fuzz_roundtrip` | Generated tags and values, sizing, insufficient-capacity output preservation, successful write/read tag and value equality. |
| `fuzz_codec` | `tlv_codec_decode`/`tlv_codec_encode` for every EMV dictionary tag's codec (NUMBER, FLAGS, DIGITS, DATE, TIME, ACCOUNT, CRYPTOGRAM, BIOMETRIC, NUMBER_LIST), one-byte-short capacities, decode/encode/decode round-trip equality, and undersized-output rejection. |
| `fuzz_dol` | `tlv_dol_read` and `tlv_dol_write` (both a size query and a full write against a deterministic `resolve` callback exercising presence, padding and truncation), both DOL limits, and that `tlv_dol_write`'s output length depends only on the input DOL. |

The reader, walker, and round-trip targets run each input against every enabled
built-in format: default, fixed 1-byte, Bluetooth LTV, BER, and DER. Component switches still
apply; `fuzz_der` and `fuzz_der_schema` are omitted when `OPENTLV_FORMAT_DER=OFF`,
and `fuzz_codec` and `fuzz_dol` are omitted when `OPENTLV_PROFILE_EMV=OFF`. At
least one built-in format must be enabled. For the raw-byte formats, the
walker harness uses tag bit `0x20` as a test-only container convention. BER
and DER use their public nesting predicates. `fuzz_der` covers the existing
DER-TLV contract, not ASN.1 value semantics or SET/SET OF ordering;
`fuzz_der_schema` covers the schema-aware layer that does (SET/SET OF
ordering, tagging, CHOICE, DEFAULT omission) against one fixed schema.
`fuzz_codec` covers value-codec semantics (BCD/binary numeric ranges,
date/time calendar checks, enum validation) independently of TLV framing.
`fuzz_dol` covers the dedicated DOL value component (tag/one-byte-length
parsing, resolve-driven construction, and EMV padding/truncation), which is
not ordinary TLV structure and so is not exercised by any other target.

`error_offset` may change on failure; on success it must stay unchanged.
Earlier visitor effects are not rolled back. The suite checks these documented
exceptions rather than requiring every output to remain unchanged on error.

## Seed corpus

Each harness's checked-in seed corpus lives next to it, under a `corpus/`
folder in the same subsystem or built-in directory of `tests/fuzz/`, which
mirrors `tlv/src`'s own layout: `tests/fuzz/reader/corpus/read` and
`tests/fuzz/reader/corpus/walk_tree` for the generic reader/walker targets,
`tests/fuzz/corpus/roundtrip` for the cross-cutting round-trip target, and
`tests/fuzz/builtins/asn1/corpus/{der,der_schema}` /
`tests/fuzz/builtins/emv/corpus/{codec,dol}` for the built-in-specific ones.
Checked-in seed files use the `.bin` extension to identify binary test inputs.
Only seed inputs belong in these corpus directories; mutation discoveries and
crash artifacts go under the build directory instead.

`corpus/read`, `corpus/walk_tree`, and `builtins/asn1/corpus/der` contain raw
TLV bytes, with no selector prefix. Every enabled format receives the same
input. A seed may be valid for one format and invalid for another. Walker and
DER limits are also derived from input bytes without removing them from the
parsed input.

Seed names describe framing cases: empty input/value, primitive values,
concatenated elements, truncated tag/length/value, invalid/overflowing lengths,
high-number tags, nested containers, BER indefinite framing and EOC errors,
noncanonical DER framing, and depth-limit boundaries. `bluetooth-ltv-*` seeds
cover the length-first layout: valid advertising data, zero-length padding,
truncated and overrunning lengths, the maximum length byte, and type-only
elements. The raw formats use `0x20` as a test-only constructed bit in the walker.

`corpus/roundtrip` uses a different layout: byte 0 modulo
`17` gives the candidate tag size, clamped to the remaining
input size; subsequent bytes hold that tag, followed by its value. Empty input
produces an empty candidate tag/value. Every input is also tested as a value
with the valid primitive tag `04`, ensuring successful writes are exercised.
Long-value seeds cover 127/128 and 255/256 length transitions, including the
Bluetooth LTV 254/255-byte value limit.

`builtins/emv/corpus/codec` also contains raw bytes with no selector prefix:
every input is tried as the raw value of every EMV dictionary tag's codec, so
a seed only needs to be interesting for one value kind (BCD/binary numbers,
dates, times, account/biometric enums, cryptogram info, digit strings) to be
useful. Names describe the targeted kind and boundary: valid/invalid BCD,
calendar and clock range violations, undefined enum values, and digit strings
with mid-string or leading padding nibbles.

## Run locally

Run from the repository root. Keep discoveries in a writable build directory;
the checked-in seed corpus (see [above](#seed-corpus)) is the second corpus path.
For one target:

```sh
export ASAN_OPTIONS=abort_on_error=1:detect_leaks=1
export UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1
mkdir -p build/fuzz/corpus/read build/fuzz/findings/read
build/fuzz/tests/fuzz/fuzz_read \
  build/fuzz/corpus/read tests/fuzz/reader/corpus/read \
  -max_total_time=60 -max_len=4096 -timeout=10 -rss_limit_mb=2048 \
  -artifact_prefix=build/fuzz/findings/read/
```

For all enabled targets (Bash):

```bash
set -o pipefail
status=0
declare -A corpus_dir=(
  [read]=tests/fuzz/reader/corpus/read
  [walk_tree]=tests/fuzz/reader/corpus/walk_tree
  [roundtrip]=tests/fuzz/corpus/roundtrip
  [der]=tests/fuzz/builtins/asn1/corpus/der
  [der_schema]=tests/fuzz/builtins/asn1/corpus/der_schema
  [codec]=tests/fuzz/builtins/emv/corpus/codec
  [dol]=tests/fuzz/builtins/emv/corpus/dol
)
for target in read walk_tree der der_schema roundtrip codec dol; do
  executable="build/fuzz/tests/fuzz/fuzz_$target"
  [ -x "$executable" ] || continue
  mkdir -p "build/fuzz/corpus/$target" "build/fuzz/findings/$target"
  "$executable" "build/fuzz/corpus/$target" "${corpus_dir[$target]}" \
    -max_total_time=60 -max_len=4096 -timeout=10 -rss_limit_mb=2048 \
    -artifact_prefix="build/fuzz/findings/$target/" \
    2>&1 | tee "build/fuzz/findings/$target/run.log" || status=1
done
test "$status" -eq 0
```

Increase `-max_total_time` for longer sessions, or use `-runs=N` for a bounded
number of executions. `-max_len` limits generated inputs, not the API's supported
input size. `-timeout` bounds one execution and the RSS option limits memory.
With `-runs=0`, libFuzzer replays the seed corpus without a mutation campaign.

## Reproduce and minimize a finding

The [C API Fuzzing](../../.github/workflows/fuzz.yml) workflow runs on pushes to
`main` (including merged pull requests), every Monday at 03:17 UTC even without
new commits, and manually through `workflow_dispatch`. Scheduled runs use the
latest commit on the default branch; the workflow must be merged there first.
Fuzzing runs separately from pull-request builds. It builds the C fuzz targets
in Debug mode, runs each configured CI target for approximately 60 seconds, fails on any
target failure, and uploads per-target logs and reproducing inputs even when
the run fails. A 15-minute step timeout bounds fuzz execution. This short
campaign is a smoke check, not exhaustive validation. CI caches `build/fuzz/corpus`
across runs (`actions/cache`, restored before the fuzz build and saved after
it), so each run's 60 seconds builds on inputs the previous run discovered
instead of starting over from just the checked-in seed corpus every time.

Download the `c-fuzz-findings-<run>-<attempt>` artifact, check out the failing
commit, and build with the same component options and Clang version. Pass the
saved input as a file instead of a corpus directory:

```sh
build/fuzz/tests/fuzz/fuzz_read path/to/read/crash-<hash>
```

Use the corresponding target for `walk_tree`, `der`, `der_schema`, `roundtrip`,
`codec`, or `dol`. Findings
may also use names such as `timeout-<hash>` or `oom-<hash>`; retain the original
timeout/RSS settings when reproducing those. Keep the sanitizer environment
variables from the local-run example and ensure `llvm-symbolizer-18` is on
PATH (or set `ASAN_SYMBOLIZER_PATH` to its absolute path).

To minimize a crashing input:

```sh
build/fuzz/tests/fuzz/fuzz_read -minimize_crash=1 -max_total_time=60 \
  -exact_artifact_path=build/fuzz/minimized-input path/to/read/crash-<hash>
```

Retain the original artifact and log. Once understood and fixed, add the small
reproducer to the appropriate seed corpus and a focused regression test for
the violated library contract.
