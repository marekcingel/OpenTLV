# Getting started

[Back to documentation](README.md)

## Build from a checkout

Install Git, CMake 3.16+ and GCC, MSVC, or upstream Clang 18+.
Use CMake 3.20+ for C++23. On Windows, use a Visual Studio developer shell
when selecting Ninja with MSVC. See [compiler support](compilers.md).

```sh
git clone https://github.com/marekcingel/OpenTLV.git
cd OpenTLV
cmake -S . -B build -DOPENTLV_BUILD_TESTS=OFF
cmake --build build --config Release --parallel
```

The C core has no third-party dependencies. The C++ wrapper uses the C++ standard
library and links the C core. Tests fetch GoogleTest; optional benchmarks fetch
Google Benchmark. Disable those targets for a build without dependency downloads.
For single-configuration generators such as Ninja, also configure with
`-DCMAKE_BUILD_TYPE=Release`; `--config` selects the configuration for generators
such as Visual Studio.

## Integrate with CMake

Place the checkout at `external/OpenTLV` in your application. Save the complete
[C quick-start example](../README.md#quick-start) as `main.c` and use:

```cmake
cmake_minimum_required(VERSION 3.16)
project(tlv_demo LANGUAGES C)

set(OPENTLV_BUILD_CXX OFF CACHE BOOL "" FORCE)
set(OPENTLV_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(OPENTLV_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(OPENTLV_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
add_subdirectory(external/OpenTLV)

add_executable(tlv_demo main.c)
target_link_libraries(tlv_demo PRIVATE tlv)
```

Configure and build the application using the same CMake commands above.
Run `build/tlv_demo` (Ninja/Makefiles), or `build/Release/tlv_demo.exe`
(Visual Studio). Exit code zero indicates a successful round trip.

For a C++ application, enable `CXX` in `project`, set `OPENTLV_BUILD_CXX` to `ON`,
and link `tlv++` instead. This target propagates the C library and include paths.
See the [C++ example](../examples/tlv++/src/basic_usage.cpp).

## C-only build

```sh
cmake -S . -B build-c -DOPENTLV_BUILD_CXX=OFF -DOPENTLV_BUILD_TESTS=OFF -DOPENTLV_BUILD_BENCHMARKS=OFF
cmake --build build-c --config Release --parallel
```

The [component configuration](architecture.md#build-configuration) lists the
format and profile switches. Keep `OPENTLV_FORMAT_FIXED_1BYTE=ON` for the README
example. Built-in descriptors are direction-specific: use a `tlv_reader_format_t`
for reads and a `tlv_writer_format_t` for writes. See
[format contracts](formats/README.md#generic-interface) and [migration](architecture.md#migration).

## Build and run tests

Tests require a C++17-capable toolchain and access to the GoogleTest dependency.

```sh
cmake -S . -B build-tests -DOPENTLV_BUILD_TESTS=ON -DCMAKE_CXX_STANDARD=17
cmake --build build-tests --config Release --parallel
ctest --test-dir build-tests -C Release --output-on-failure --no-tests=error
```

See [compiler-specific settings](compilers.md) for strict builds. GitHub Actions
runs build and test jobs for GCC, Clang, and MSVC; the README badges follow `main`.
