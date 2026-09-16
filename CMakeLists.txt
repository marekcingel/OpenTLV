cmake_minimum_required(VERSION 3.16)

include(cmake/version.cmake)

project(OpenTLV VERSION ${OPENTLV_VERSION} LANGUAGES C)

opentlv_generate_version_files()

option(OPENTLV_BUILD_CXX "Build the tlv++ header-only C++ layer and its tests" ON)
option(OPENTLV_BUILD_SHARED_LIBS "Build tlv as a shared library instead of static" ON)
option(OPENTLV_BUILD_TESTS "Build tests" ON)
option(OPENTLV_BUILD_UNIT_TESTS "Build component contract tests" ON)
option(OPENTLV_BUILD_INTEGRATION_TESTS "Build format and layer integration tests" ON)
option(OPENTLV_BUILD_EXAMPLES "Build examples" ON)
option(OPENTLV_BUILD_CLI "Build the opentlv command-line tool" ON)
option(OPENTLV_BUILD_CLI_TESTS "Build dependency-free CLI integration tests" ${OPENTLV_BUILD_TESTS})
if(OPENTLV_BUILD_CLI AND NOT OPENTLV_BUILD_CXX)
    # The CLI is built on tlv++; a C-only build (OPENTLV_BUILD_CXX=OFF) simply
    # skips it instead of failing, since OPENTLV_BUILD_CLI defaults to ON.
    set(OPENTLV_BUILD_CLI OFF)
    message(STATUS "OPENTLV_BUILD_CLI requires OPENTLV_BUILD_CXX=ON (tlv++); disabling the CLI for this C-only build.")
endif()
# Enable CXX at the top level (rather than relying solely on tlv++'s own
# project(LANGUAGES CXX)) so multi-config generators such as Visual Studio
# know about the CXX compiler before generating every subdirectory's project
# files; without this, target_compile_features() in tools/cli fails to find
# CXX compile features under that generator.
if(OPENTLV_BUILD_CXX)
    enable_language(CXX)
endif()
option(OPENTLV_BUILD_BENCHMARKS "Build Google Benchmark performance suites" OFF)
option(OPENTLV_BUILD_FUZZING "Build C API fuzz targets with libFuzzer, ASan and UBSan" OFF)
option(OPENTLV_WARNINGS_AS_ERRORS "Treat OpenTLV compiler warnings as errors" ON)

option(OPENTLV_FORMAT_DEFAULT "Include the default wire format" ON)
option(OPENTLV_FORMAT_FIXED_1BYTE "Include the fixed one-byte wire format" ON)
option(OPENTLV_FORMAT_ASN1 "Include ASN.1-related wire formats (BER, DER)" ON)
option(OPENTLV_FORMAT_BER "Include the BER wire format" ON)
option(OPENTLV_FORMAT_DER "Include the DER wire format and validation profile" ON)
option(OPENTLV_FORMAT_CER "Include the CER wire format and validation profile" ON)
option(OPENTLV_PROFILE_EMV "Include the EMV dictionary, schemas and codecs" ON)

include(cmake/format_options.cmake)
opentlv_generate_config_files()

include(cmake/compiler.cmake)
include(GNUInstallDirs)

include(cmake/clang_format.cmake)
opentlv_add_clang_format_targets()

include(cmake/cppcheck.cmake)
opentlv_add_cppcheck_targets()

add_subdirectory(tlv)

if(OPENTLV_BUILD_FUZZING)
    add_subdirectory(tests/fuzz)
endif()

if(OPENTLV_BUILD_CXX)
    add_subdirectory(tlv++)
endif()

if(OPENTLV_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(OPENTLV_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(OPENTLV_BUILD_CLI)
    if(OPENTLV_BUILD_CLI_TESTS)
        enable_testing()
    endif()
    add_subdirectory(tools/cli)
endif()

if(OPENTLV_BUILD_BENCHMARKS AND OPENTLV_FORMAT_DEFAULT)
    add_subdirectory(benchmarks)
endif()

include(cmake/install.cmake)
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    include(cmake/packaging.cmake)
endif()
