cmake_minimum_required(VERSION 3.16)

project(tests)

include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.18.0
)

FetchContent_MakeAvailable(googletest)

add_subdirectory(tlv)

if(OPENTLV_BUILD_CXX)
    add_subdirectory(tlv++)
endif()
