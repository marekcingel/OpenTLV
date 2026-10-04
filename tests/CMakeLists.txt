cmake_minimum_required(VERSION 3.16)

project(tests)

if(OPENTLV_BUILD_UNIT_TESTS OR OPENTLV_BUILD_INTEGRATION_TESTS)
    include(tag_layout_checks.cmake)
    include(fixed_format_checks.cmake)
    include(custom_format_checks.cmake)
    include(typed_field_checks.cmake)
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
            add_subdirectory(${test_group})
        endif()
    endforeach()
endif()

if(OPENTLV_BUILD_INTEGRATION_TESTS)
    add_subdirectory(query)
    add_test(NAME architecture-pipeline
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/pipeline_checks.cmake)
    set_tests_properties(architecture-pipeline PROPERTIES LABELS "integration;architecture")
endif()

if(OPENTLV_BUILD_PROPERTY_TESTS)
    add_subdirectory(property)
endif()
