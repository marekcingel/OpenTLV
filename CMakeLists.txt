cmake_minimum_required(VERSION 3.16)

include(cmake/version.cmake)

project(OpenTLV VERSION ${OPENTLV_VERSION} LANGUAGES C)

opentlv_generate_version_files()

# Build and language bindings
option(OPENTLV_BUILD_SHARED_LIBS "Build tlv as a shared library instead of static" ON)
option(OPENTLV_BUILD_CXX "Build the tlv++ header-only C++ layer and its tests" ON)
option(OPENTLV_BUILD_WASM "Build the experimental WebAssembly module (requires Emscripten)" OFF)
option(OPENTLV_BUILD_PYTHON "Build the experimental Python native extension" OFF)
option(OPENTLV_BUILD_LUA "Build the experimental Lua native extension" OFF)

# Core capabilities
option(OPENTLV_READER "Include wire readers and traversal" ON)
option(OPENTLV_WRITER "Include wire writers and generation" ON)
option(OPENTLV_DOCUMENT "Include the allocating mutable document API" ON)
option(OPENTLV_QUERY "Include Query execution" ON)
option(OPENTLV_SCHEMA "Include Schema validation" ON)
option(OPENTLV_CODEC "Include semantic value codecs" ON)

# Query features
option(OPENTLV_QUERY_FRONTEND "Include Query text parsing and compilation" ON)
option(OPENTLV_QUERY_SET_OPERATIONS "Include Query union, intersection and difference operations" ON)

# Builtin protocols and formats
option(OPENTLV_FORMAT_ASN1 "Include ASN.1-related wire formats (BER, DER)" ON)
option(OPENTLV_FORMAT_BER "Include the BER wire format" ON)
option(OPENTLV_FORMAT_DER "Include the DER wire format and validation" ON)
option(OPENTLV_FORMAT_CER "Include the CER wire format and validation" ON)
option(OPENTLV_EMV "Include EMV framing, dictionary, schemas and codecs" ON)
option(OPENTLV_BLUETOOTH "Include Bluetooth format, containers, definitions, schemas and codecs" ON)
option(OPENTLV_NFC "Include NFC Type 2 Tag TLV framing" ON)
option(OPENTLV_DHCP "Include DHCPv4 option framing, definitions and value codecs" ON)
option(OPENTLV_LLDP "Include LLDP framing, definitions, structural validation and value codecs" ON)

# Tools and documentation
option(OPENTLV_BUILD_CLI "Build the otlv command-line tool" ON)
option(OPENTLV_BUILD_EXAMPLES "Build examples" ON)
option(OPENTLV_BUILD_DOCS "Enable the Doxygen C and C++ API reference targets" OFF)

# Tests and quality checks
option(OPENTLV_BUILD_TESTS "Build tests" ON)
option(OPENTLV_BUILD_UNIT_TESTS "Build component contract tests" ON)
option(OPENTLV_BUILD_INTEGRATION_TESTS "Build format and layer integration tests" ON)
option(OPENTLV_BUILD_QUERY_TESTS "Build independent C Query conformance tests (no C++ or GoogleTest required)" ON)
option(OPENTLV_BUILD_PROPERTY_TESTS "Build deterministic generated-corpus property tests (requires CLI and Python)" OFF)
option(OPENTLV_BUILD_CLI_TESTS "Build dependency-free CLI integration tests" ${OPENTLV_BUILD_TESTS})
option(OPENTLV_BUILD_BENCHMARKS "Build Google Benchmark performance suites" OFF)
option(OPENTLV_BUILD_FUZZING "Build C API fuzz targets with libFuzzer, ASan and UBSan" OFF)
option(OPENTLV_BUILD_MEMCHECK "Enable native Linux CTest Valgrind Memcheck runs" OFF)
option(OPENTLV_WARNINGS_AS_ERRORS "Treat OpenTLV compiler warnings as errors" ON)

include(cmake/format_options.cmake)
include(cmake/capability_options.cmake)
opentlv_generate_config_files()

if(OPENTLV_BUILD_CLI AND NOT OPENTLV_BUILD_CXX)
    # The CLI is built on tlv++; a C-only build (OPENTLV_BUILD_CXX=OFF) simply
    # skips it instead of failing, since OPENTLV_BUILD_CLI defaults to ON.
    set(OPENTLV_BUILD_CLI OFF)
    message(STATUS "OPENTLV_BUILD_CLI requires OPENTLV_BUILD_CXX=ON (tlv++); disabling the CLI for this C-only build.")
endif()
if(OPENTLV_BUILD_TESTS AND OPENTLV_BUILD_PROPERTY_TESTS AND NOT OPENTLV_BUILD_CLI)
    message(FATAL_ERROR "OPENTLV_BUILD_PROPERTY_TESTS requires OPENTLV_BUILD_CLI and OPENTLV_BUILD_CXX.")
endif()
# Enable CXX at the top level (rather than relying solely on tlv++'s own
# project(LANGUAGES CXX)) so multi-config generators such as Visual Studio
# know about the CXX compiler before generating every subdirectory's project
# files; without this, target_compile_features() in tools/cli fails to find
# CXX compile features under that generator.
if(OPENTLV_BUILD_CXX)
    enable_language(CXX)
endif()

if(OPENTLV_BUILD_WASM)
    if(NOT EMSCRIPTEN)
        message(FATAL_ERROR "OPENTLV_BUILD_WASM requires Emscripten; configure with emcmake cmake.")
    endif()
    # The module links the core statically; Emscripten shared libraries are not supported.
    set(OPENTLV_BUILD_SHARED_LIBS OFF)
endif()

if(OPENTLV_BUILD_PYTHON)
    # The extension module links the core statically, so the wheel carries no
    # separate shared tlv library to locate at import time.
    set(OPENTLV_BUILD_SHARED_LIBS OFF)
endif()

if(OPENTLV_BUILD_LUA)
    # The extension module links the core statically, so require("opentlv")
    # carries no separate shared tlv library to locate at load time.
    set(OPENTLV_BUILD_SHARED_LIBS OFF)
endif()


include(cmake/compiler.cmake)
include(cmake/memcheck.cmake)
include(GNUInstallDirs)

include(cmake/clang_format.cmake)
opentlv_add_clang_format_targets()

include(cmake/cppcheck.cmake)
opentlv_add_cppcheck_targets()

add_subdirectory(tlv)

if(OPENTLV_BUILD_WASM)
    # ctest reads the top-level test file, so testing is enabled here, not in bindings/wasm.
    enable_testing()
    add_subdirectory(bindings/wasm)
endif()

if(OPENTLV_BUILD_PYTHON)
    add_subdirectory(bindings/python/opentlv-core)
endif()

if(OPENTLV_BUILD_LUA)
    # ctest reads the top-level test file, so testing is enabled here, not in bindings/lua.
    enable_testing()
    add_subdirectory(bindings/lua)
endif()

if(OPENTLV_BUILD_DOCS)
    include(cmake/doxygen.cmake)
endif()

if(OPENTLV_BUILD_FUZZING)
    add_subdirectory(tests/fuzz)
endif()

if(OPENTLV_BUILD_CXX)
    add_subdirectory(tlv++)
endif()

include(cmake/clang_tidy.cmake)
opentlv_add_clang_tidy_targets()

if(OPENTLV_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(OPENTLV_BUILD_EXAMPLES)
    # Runnable examples are acceptance tests even without GoogleTest targets.
    enable_testing()
    add_subdirectory(examples)
endif()

if(OPENTLV_BUILD_CLI)
    if(OPENTLV_BUILD_CLI_TESTS)
        enable_testing()
    endif()
    add_subdirectory(tools/cli)
endif()

if(OPENTLV_BUILD_BENCHMARKS AND OPENTLV_FORMAT_BER)
    add_subdirectory(benchmarks)
endif()

include(cmake/install.cmake)
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    include(cmake/packaging.cmake)
endif()
