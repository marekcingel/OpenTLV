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

# Generic-format example: defines a fixed-width format at compile time.
add_executable(example-tlv++-formats-fixed-format src/formats/fixed_format.cpp)
target_link_libraries(example-tlv++-formats-fixed-format PRIVATE tlv++)
opentlv_configure_compiler(example-tlv++-formats-fixed-format)
opentlv_copy_shared_runtime(example-tlv++-formats-fixed-format)

# Same format, but tlv_fixed_format_t chosen at runtime through the raw C API
# (needs the C library built with the fixed format, unlike the compile-time
# template above).
if(OPENTLV_FORMAT_FIXED)
    add_executable(example-tlv++-formats-fixed-format-runtime src/formats/fixed_format_runtime.cpp)
    target_link_libraries(example-tlv++-formats-fixed-format-runtime PRIVATE tlv++)
    opentlv_configure_compiler(example-tlv++-formats-fixed-format-runtime)
    opentlv_copy_shared_runtime(example-tlv++-formats-fixed-format-runtime)
    add_test(NAME Integration_example_tlv++_formats_fixed_format_runtime
        COMMAND $<TARGET_FILE:example-tlv++-formats-fixed-format-runtime>)
    set_tests_properties(Integration_example_tlv++_formats_fixed_format_runtime PROPERTIES LABELS "integration;examples")
endif()

# Use-case examples shared across languages: the same document is parsed,
# written, queried and validated in examples/tlv, examples/tlv++ and
# bindings/rust/opentlv/examples.
if(OPENTLV_FORMAT_BER)
    foreach(use_case parse write query validate)
        add_executable(example-tlv++-${use_case} src/${use_case}.cpp)
        target_link_libraries(example-tlv++-${use_case} PRIVATE tlv++)
        opentlv_configure_compiler(example-tlv++-${use_case})
        opentlv_copy_shared_runtime(example-tlv++-${use_case})
        add_test(NAME Integration_example_tlv++_${use_case} COMMAND $<TARGET_FILE:example-tlv++-${use_case}>)
        set_tests_properties(Integration_example_tlv++_${use_case} PROPERTIES LABELS "integration;examples")
    endforeach()
endif()
