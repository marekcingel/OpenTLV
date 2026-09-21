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
opentlv_copy_shared_runtime(${PROJECT_NAME})

# Backs the C++ example in Getting Started; scripts/check_doc_examples.py keeps the
# Markdown copy identical to this file. It is the C++ counterpart of the C quick start.
add_executable(example-tlv++-quick-start src/quick_start.cpp)
target_link_libraries(example-tlv++-quick-start PRIVATE tlv++)
opentlv_configure_compiler(example-tlv++-quick-start)
opentlv_copy_shared_runtime(example-tlv++-quick-start)

add_executable(example-tlv++-fixed-format src/fixed_format.cpp)
target_link_libraries(example-tlv++-fixed-format PRIVATE tlv++)
opentlv_configure_compiler(example-tlv++-fixed-format)
opentlv_copy_shared_runtime(example-tlv++-fixed-format)
