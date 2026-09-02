cmake_minimum_required(VERSION 3.16)

project(test-tlv LANGUAGES C)

set(HEADERS
    include/dhcp_option_tests.h
    include/test_framework.h
)

set(SOURCES

    src/test_tlv.c
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
)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
