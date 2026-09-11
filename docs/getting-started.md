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

## Install and generate distribution archives

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DOPENTLV_BUILD_TESTS=OFF -DOPENTLV_BUILD_EXAMPLES=OFF
cmake --build build --parallel
cmake --install build --prefix /path/to/install
cpack --config build/CPackConfig.cmake -C Release
```

With Visual Studio, omit `-G Ninja` and use `--config Release` when building
and installing. CPack defaults to ZIP on Windows and TGZ elsewhere. Archives
are written to `build/packages`, for example
`OpenTLV-0.1.0-Windows-AMD64-MSVC.zip`,
`OpenTLV-0.1.0-Linux-x86_64-GNU.tar.gz`, or
`OpenTLV-0.1.0-Linux-x86_64-Clang.tar.gz`.
The version comes from the project version, including any pre-release suffix.
Use `cpack --config build/CPackConfig.cmake -C Release -G TGZ` (or `-G ZIP`)
to select another archive format.

Each archive has one enclosing directory containing exactly the CMake install
layout: `include/tlv`, optional `include/tlv++`, library artifacts in `lib`
(Windows shared libraries in `bin`), CMake exports in `lib/cmake/OpenTLV`,
and license, README and changelog in `share/doc/OpenTLV`. GNUInstallDirs options
such as `CMAKE_INSTALL_LIBDIR` customize the shared installation layout.
Use relative install directories to keep packages relocatable.

After extracting, point `CMAKE_PREFIX_PATH` at that enclosing directory:

```cmake
find_package(OpenTLV CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE OpenTLV::tlv)
# For C++ applications, use OpenTLV::tlvpp instead.
```

```sh
cmake -S my-app -B my-app/build -DCMAKE_PREFIX_PATH=/path/to/extracted/OpenTLV-0.1.0-Linux-x86_64-GNU
cmake --build my-app/build --config Release
```

The source checkout is unnecessary. Use a compatible compiler, architecture
and runtime for the binary library. For shared builds, make the installed
runtime library discoverable by the platform loader (for example, Windows `PATH`).
`OPENTLV_BUILD_CXX=OFF` omits C++ headers and the `OpenTLV::tlvpp` target.
CPack only packages `install()` output; it requires neither Conan nor vcpkg.
On version-tag pushes (for example `0.1.0` or `0.2.0-rc.1`), the standard
GCC, Clang and MSVC Release jobs each package their tested builds. GCC and Clang
produce TGZ archives; MSVC produces ZIP archives. Archive and CI artifact names
include the compiler identifier to distinguish the packages.
They compare each archive with `cmake --install`, build standalone C and C++
consumers, and upload the archives as both Actions artifacts and GitHub Release
assets for the tag. Each compiler job attaches its archive after its checks pass.
If the release does not exist, it is created with generated release notes;
tags with a pre-release suffix create a pre-release. Existing release notes are
preserved, and reruns replace assets with matching names.
Branch pushes and pull requests skip packaging and release uploads.
The CI helper `python scripts/check_package.py build --cxx ON` runs CPack in a
fresh directory and copies verified archives to `build/packages`. It reports
missing, unexpected and changed files, respects the configured installation
directories, and checks consumers with the original compiler and the extracted
CMake package. Use `--cxx OFF` for a C-only build. Checks also run under `python -O`.
Native OS installers are not generated.

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
