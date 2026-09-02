cmake_minimum_required(VERSION 3.16)

project(example-tlv)

set(HEADERS
)

set(SOURCES
    src/basic_usage.c
)

add_executable(${PROJECT_NAME}
    ${HEADERS}
    ${SOURCES}
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    tlv
)