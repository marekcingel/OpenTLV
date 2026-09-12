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
  -DOPENTLV_BUILD_TESTS=OFF -DOPENTLV_BUILD_EXAMPLES=OFF \
  -DOPENTLV_PROFILE_EMV=OFF
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
| `fuzz_roundtrip` | Generated tags and values, sizing, insufficient-capacity output preservation, successful write/read tag and value equality. |

The reader, walker, and round-trip targets run each input against every enabled
built-in format: default, fixed 1-byte, BER, and DER. Component switches still
apply; `fuzz_der` is omitted when `OPENTLV_FORMAT_DER=OFF`. At least one built-in
format must be enabled. For the raw-byte formats, the walker harness uses tag
bit `0x20` as a test-only container convention. BER and DER use their public
nesting predicates. DER profile validation covers the existing DER-TLV
contract, not ASN.1 value semantics or SET/SET OF ordering.

`error_offset` may change on failure; on success it must stay unchanged.
Earlier visitor effects are not rolled back. The suite checks these documented
exceptions rather than requiring every output to remain unchanged on error.

## Run locally

Run from the repository root. Keep discoveries in a writable build directory;
the checked-in [seed corpus](../tests/fuzz/README.md) is the second corpus path.
For one target:

```sh
export ASAN_OPTIONS=abort_on_error=1:detect_leaks=1
export UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1
mkdir -p build/fuzz/corpus/read build/fuzz/findings/read
build/fuzz/tests/fuzz/fuzz_read \
  build/fuzz/corpus/read tests/fuzz/corpus/read \
  -max_total_time=60 -max_len=4096 -timeout=10 -rss_limit_mb=2048 \
  -artifact_prefix=build/fuzz/findings/read/
```

For all enabled targets (Bash):

```bash
set -o pipefail
status=0
for target in read walk_tree der roundtrip; do
  executable="build/fuzz/tests/fuzz/fuzz_$target"
  [ -x "$executable" ] || continue
  mkdir -p "build/fuzz/corpus/$target" "build/fuzz/findings/$target"
  "$executable" "build/fuzz/corpus/$target" "tests/fuzz/corpus/$target" \
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

The Debug/C++23 job in [Clang Build](../.github/workflows/build-clang.yml) builds
the C fuzz targets separately in Debug mode after coverage collection. It runs
each target for approximately 60 seconds, fails on any
target failure, and uploads per-target logs and reproducing inputs even when
the run fails. A 15-minute step timeout bounds fuzz execution. This short
campaign is a smoke check, not exhaustive validation.

Download the `c-fuzz-findings-<run>-<attempt>` artifact, check out the failing
commit, and build with the same component options and Clang version. Pass the
saved input as a file instead of a corpus directory:

```sh
build/fuzz/tests/fuzz/fuzz_read path/to/read/crash-<hash>
```

Use the corresponding target for `walk_tree`, `der`, or `roundtrip`. Findings
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
