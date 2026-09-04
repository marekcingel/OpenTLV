cmake_minimum_required(VERSION 3.16)

include(cmake/version.cmake)

project(OpenTLV VERSION ${OPENTLV_VERSION} LANGUAGES NONE)

opentlv_generate_version_files()

option(OPENTLV_BUILD_CXX "Build the tlv++ header-only C++ layer and its tests" ON)
option(OPENTLV_BUILD_TESTS "Build tests" ON)
option(OPENTLV_BUILD_EXAMPLES "Build examples" ON)
option(OPENTLV_BUILD_BENCHMARKS "Build Google Benchmark performance suites" OFF)

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

if(OPENTLV_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()
