cmake_minimum_required(VERSION 3.16)

project(example-tlv++ LANGUAGES CXX)

set(HEADERS
)

set(SOURCES
    src/basic_usage.cpp
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
    tlv++
)

opentlv_configure_compiler(${PROJECT_NAME})
