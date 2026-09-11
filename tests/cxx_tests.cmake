cmake_minimum_required(VERSION 3.16)

set(test_target test-${test_group}-tlvpp)

set(HEADERS
)

set(SOURCES
    src/test_tlvpp.cpp
)

if(test_group STREQUAL "integration")
    list(APPEND SOURCES src/layers_test.cpp)
endif()

add_executable(${test_target}
    ${HEADERS}
    ${SOURCES}
)

target_include_directories(${test_target}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${OpenTLV_SOURCE_DIR}/tests/unit/tlv/src
)

target_link_libraries(${test_target} PRIVATE
    tlv++
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(${test_target} PROPERTIES LABELS ${test_group})

opentlv_configure_compiler(${test_target})
