cmake_minimum_required(VERSION 3.16)

include(cmake/version.cmake)

project(OpenTLV VERSION ${OPENTLV_VERSION} LANGUAGES C)

opentlv_generate_version_files()

option(OPENTLV_BUILD_CXX "Build the tlv++ header-only C++ layer and its tests" ON)
option(OPENTLV_BUILD_TESTS "Build tests" ON)
option(OPENTLV_BUILD_EXAMPLES "Build examples" ON)
option(OPENTLV_BUILD_BENCHMARKS "Build Google Benchmark performance suites" OFF)
option(OPENTLV_WARNINGS_AS_ERRORS "Treat OpenTLV compiler warnings as errors" ON)

option(OPENTLV_FORMAT_DEFAULT "Include the default wire format" ON)
option(OPENTLV_FORMAT_FIXED_1BYTE "Include the fixed one-byte wire format" ON)
option(OPENTLV_FORMAT_BER "Include the BER wire format" ON)
option(OPENTLV_FORMAT_DER "Include the DER wire format and validation profile" ON)
option(OPENTLV_PROFILE_EMV "Include the EMV dictionary, schemas and codecs" ON)

include(cmake/compiler.cmake)
include(GNUInstallDirs)

add_subdirectory(tlv)

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

if(OPENTLV_BUILD_BENCHMARKS AND OPENTLV_FORMAT_DEFAULT)
    add_subdirectory(benchmarks)
endif()

include(cmake/install.cmake)
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    include(cmake/packaging.cmake)
endif()
