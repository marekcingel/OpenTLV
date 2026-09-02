cmake_minimum_required(VERSION 3.16)

project(tests)

add_subdirectory(tlv)

if(OPENTLV_BUILD_CXX)
    add_subdirectory(tlv++)
endif()
