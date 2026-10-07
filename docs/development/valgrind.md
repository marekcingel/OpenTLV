# Valgrind Memcheck

The C and C++ suites can run under Valgrind Memcheck on Linux, including WSL.
This checks invalid memory accesses, uses of uninitialized memory, and leaks in
a plain native build. It complements the [sanitized fuzz targets](fuzzing.md)
and Query sanitizer jobs.

## Run locally

On Ubuntu 24.04, install the tools and configure a separate build directory:

```sh
sudo apt-get update
sudo apt-get install gcc g++ cmake ninja-build valgrind python3
cmake -S . -B build/valgrind -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ \
  -DOPENTLV_BUILD_TESTS=ON -DOPENTLV_BUILD_MEMCHECK=ON \
  -DOPENTLV_BUILD_EXAMPLES=OFF -DOPENTLV_BUILD_CLI=OFF \
  -DOPENTLV_BUILD_CLI_TESTS=OFF
cmake --build build/valgrind --parallel 2
ctest --test-dir build/valgrind --output-on-failure --no-tests=error --parallel 2
ctest --test-dir build/valgrind -T memcheck -LE no-memcheck --output-on-failure --no-tests=error --parallel 2
```

`OPENTLV_BUILD_MEMCHECK` defaults to `OFF`, so ordinary builds do not require
Valgrind or the Memcheck launcher. Enabling it requires a native Linux build,
Python and Valgrind. Use a fresh build directory without ASan, UBSan or MSan
compiler/linker flags; Memcheck configuration rejects sanitizer, fuzzing and
WASM builds. Language binding jobs remain separate.

The Memcheck build registers each GoogleTest suite as a whole binary, executing
all its cases in one Valgrind process. Builds without this option retain
individual GoogleTest registrations. Other CTest commands and arguments stay
unchanged. This matters for Query conformance drivers, which require corpus arguments supplied by their
Python harness. The launcher wraps native executable arguments (`--native`,
`--cli`, and `--checker`) with Valgrind and runs the Python harness normally.
This keeps Python runtime allocations outside the C/C++ check. Other Python
harnesses need an explicit adapter or an exclusion. Each instrumented process
has a separate log, and every report is checked before returning to CTest.
A harness that expects a child to fail cannot hide a Memcheck error in that
child. Native tests also trace any further child processes they start.

The Memcheck configuration uses `--leak-check=full`,
`--errors-for-leak-kinds=definite,indirect,possible`, `--track-origins=yes`, and
a nonzero `--error-exitcode`. Still-reachable allocations are not errors.
Missing or incomplete reports also fail the check.

Select a smaller set while investigating a failure:

```sh
GTEST_FILTER='Unit_Tlv_QueryProgram.*:Unit_Tlv_Incremental.*' \
ctest --test-dir build/valgrind -T memcheck -LE no-memcheck \
  -R '^test-unit-tlv$' \
  --output-on-failure --no-tests=error
```

Memcheck extends test timeouts only after the instrumented launcher starts.
An ordinary `ctest` invocation retains the usual limits, including the
retained-input scaling regression. Grouping the GoogleTest cases avoids paying
Valgrind startup and debug-symbol loading costs for every case. Query corpus
harnesses still start individual native processes; measure the complete CTest
job when assessing CI duration.

## Read a report

CTest reports the failing test name. Inspect its
`Testing/Temporary/MemoryChecker.<number>.log` in the build directory for the
combined report and the retained process logs for individual child commands.
`Testing/` also contains CTest's dashboard XML and execution logs. The
`valgrind.yml` workflow uploads this directory even when a test fails.

For an uninitialized-value error, start with the first application stack frame
and the origin stack emitted by `--track-origins=yes`. The use site may be a
transactional test's `memcmp`, while the origin is an incompletely initialized
output copied by the library. For leaks, inspect the allocation stack and leak
kind. Fix the earliest underlying defect before interpreting later errors.

A test that requires an object to remain byte-for-byte unchanged must initialize
its complete representation and take the snapshot with `memcpy`. A structure
assignment need not preserve padding. Compare members when the contract only
requires semantic equality. Do not weaken output-preservation assertions to
silence a real library write of undefined bytes.

## Suppressions and exclusions

`tests/valgrind.supp` starts with no suppression rules. Every added suppression
must have a comment explaining its reason and the affected external component,
with a tracking reference where available. Keep its stack match narrow and
remove it when the dependency is fixed. OpenTLV memory defects and unsafe test
snapshots should be fixed directly.

Use the CTest `no-memcheck` label for a test that cannot run under Valgrind and
document the reason beside its registration. The `-LE no-memcheck` option in
the commands above excludes that label; such tests still run under ordinary
CTest. An exclusion must not hide a failing native memory check;
sanitized binaries, fuzz targets and WASM require their dedicated workflows.

See the [CTest MemCheck documentation](https://cmake.org/cmake/help/latest/manual/ctest.1.html#ctest-memcheck-step)
and [Valgrind manual](https://valgrind.org/docs/manual/manual-core.html) for
report and command-line details.
