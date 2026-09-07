# Supported compilers

OpenTLV supports GCC, MSVC, and upstream Clang 18 or newer. The Clang
minimum is checked by CMake; CI uses Clang 18 on Ubuntu 24.04 with libstdc++.
AppleClang and clang-cl are not part of the supported CI configuration.

The C API requires C99. The header-only C++ API supports C++11, C++14,
C++17, C++20, and C++23. A matching C++ standard library is required;
the wrapper uses its compatibility implementations when optional library
features such as `std::expected` are unavailable.

The dedicated Clang job builds the C API in strict C99 mode and the C++
example in every supported C++ standard, then runs both examples and all
unit tests. GoogleTest v1.18 requires C++17, so unit-test targets use at least
C++17 even in the C++11 and C++14 configurations. The C++ example does not
link GoogleTest and verifies those older language modes directly.
Existing GCC and MSVC jobs continue to run on Ubuntu and Windows.
Clang compilation and testing do not depend on clang-tidy or static analysis.

## Building with Clang

With Clang 18 or newer and CMake 3.20 or newer installed (CMake 3.16 is
sufficient for C++11 through C++20):

```sh
cmake -S . -B build-clang -G Ninja \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_STANDARD=99 -DCMAKE_C_STANDARD_REQUIRED=ON -DCMAKE_C_EXTENSIONS=OFF \
  -DCMAKE_CXX_STANDARD=23 -DCMAKE_CXX_STANDARD_REQUIRED=ON -DCMAKE_CXX_EXTENSIONS=OFF \
  -DOPENTLV_WARNINGS_AS_ERRORS=ON
cmake --build build-clang
ctest --test-dir build-clang --output-on-failure
```

Select `11`, `14`, `17`, `20`, or `23` with `CMAKE_CXX_STANDARD`.
For a C-only build without GoogleTest, also pass
`-DOPENTLV_BUILD_CXX=OFF -DOPENTLV_BUILD_TESTS=OFF -DOPENTLV_BUILD_BENCHMARKS=OFF`.

OpenTLV's own compiled targets enable `-Wall -Wextra -Wpedantic` with Clang,
plus `-Wstrict-prototypes` for C.

`OPENTLV_WARNINGS_AS_ERRORS` defaults to `ON` for all supported compilers:
it adds `-Werror` for GCC and Clang, and `/WX` for MSVC, for both C and C++.
Pass `-DOPENTLV_WARNINGS_AS_ERRORS=OFF` to disable this behavior.
These options are private to OpenTLV's compiled targets and do not propagate
to library consumers or third-party dependencies.
