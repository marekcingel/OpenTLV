cmake_minimum_required(VERSION 3.16)

project(test-tlv LANGUAGES CXX)

set(HEADERS
)

set(SOURCES
    src/dhcp_option_tests.cpp
    src/test_tlv.cpp
)

add_executable(${PROJECT_NAME}
    ${HEADERS}
    ${SOURCES}
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    tlv
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME})
