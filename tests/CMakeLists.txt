cmake_minimum_required(VERSION 3.16)

project(tests)

include(format_type_checks.cmake)

include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.18.0
)

set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

foreach(test_group IN ITEMS unit integration)
    string(TOUPPER "${test_group}" group_option)
    if(OPENTLV_BUILD_${group_option}_TESTS)
        add_subdirectory(${test_group}/tlv)
        if(OPENTLV_BUILD_CXX AND (test_group STREQUAL "unit" OR OPENTLV_FORMAT_DEFAULT))
            add_subdirectory(${test_group}/tlv++)
        endif()
    endif()
endforeach()
