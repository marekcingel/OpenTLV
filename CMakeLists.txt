cmake_minimum_required(VERSION 3.16)
project(OpenTLV LANGUAGES C)

option(OPENTLV_BUILD_CXX "Build the tlv++ header-only C++ layer and its tests" ON)
option(OPENTLV_BUILD_TESTS "Build tests" ON)

enable_testing()

add_subdirectory(tlv)

if(OPENTLV_BUILD_CXX)
    add_subdirectory(tlv++)
endif()
