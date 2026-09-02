cmake_minimum_required(VERSION 3.16)

project(OpenTLV)

option(OPENTLV_BUILD_CXX "Build the tlv++ header-only C++ layer and its tests" ON)
option(OPENTLV_BUILD_TESTS "Build tests" ON)
option(OPENTLV_BUILD_EXAMPLES "Build examples" ON)

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