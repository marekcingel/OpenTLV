cmake_minimum_required(VERSION 3.16)

project(example-tlv++ LANGUAGES CXX)

add_executable(example-tlvpp-typed-fields src/typed_fields.cpp)
target_link_libraries(example-tlvpp-typed-fields PRIVATE tlv++)
set_target_properties(example-tlvpp-typed-fields PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
opentlv_configure_compiler(example-tlvpp-typed-fields)
opentlv_copy_shared_runtime(example-tlvpp-typed-fields)
add_test(NAME Integration_example_tlvpp_typed_fields COMMAND $<TARGET_FILE:example-tlvpp-typed-fields>)
set_tests_properties(Integration_example_tlvpp_typed_fields PROPERTIES LABELS "integration;examples")

if(OPENTLV_LLDP)
    add_executable(example-tlvpp-lldp src/lldp.cpp)
    target_link_libraries(example-tlvpp-lldp PRIVATE tlv++)
    opentlv_configure_compiler(example-tlvpp-lldp)
    opentlv_copy_shared_runtime(example-tlvpp-lldp)
    add_test(NAME Integration_example_tlvpp_lldp COMMAND $<TARGET_FILE:example-tlvpp-lldp>)
    set_tests_properties(Integration_example_tlvpp_lldp PROPERTIES LABELS "integration;examples")
endif()

# Backs the C++ example in Getting Started; scripts/check_doc_examples.py keeps the
# Markdown copy identical to this file. It is the C++ counterpart of the C quick start.
add_executable(example-tlv++-quick-start src/quick_start.cpp)
target_link_libraries(example-tlv++-quick-start PRIVATE tlv++)
opentlv_configure_compiler(example-tlv++-quick-start)
opentlv_copy_shared_runtime(example-tlv++-quick-start)
add_test(NAME Integration_example_tlvpp_quick_start COMMAND $<TARGET_FILE:example-tlv++-quick-start>)
set_tests_properties(Integration_example_tlvpp_quick_start PROPERTIES
    LABELS "integration;examples" PASS_REGULAR_EXPRESSION "Hello, world!")

if(OPENTLV_FORMAT_BER)
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
    add_test(NAME Integration_example_tlvpp_basic_usage COMMAND $<TARGET_FILE:${PROJECT_NAME}>)
    set_tests_properties(Integration_example_tlvpp_basic_usage PROPERTIES LABELS "integration;examples")


endif()

# Generic-format example: defines a fixed-width format at compile time.
# tlv::fixed_format<> delegates to tlv_fixed_format_init(), so it needs the C
# always-built C Fixed implementation, same as the runtime example below.
add_executable(example-tlv++-formats-fixed-format src/formats/fixed_format.cpp)
target_link_libraries(example-tlv++-formats-fixed-format PRIVATE tlv++)
opentlv_configure_compiler(example-tlv++-formats-fixed-format)
opentlv_copy_shared_runtime(example-tlv++-formats-fixed-format)
add_test(NAME Integration_example_tlvpp_fixed_format COMMAND $<TARGET_FILE:example-tlv++-formats-fixed-format>)
set_tests_properties(Integration_example_tlvpp_fixed_format PROPERTIES LABELS "integration;examples")
# Same format, but tlv_fixed_format_t chosen at runtime through the raw C API.
add_executable(example-tlv++-formats-fixed-format-runtime src/formats/fixed_format_runtime.cpp)
target_link_libraries(example-tlv++-formats-fixed-format-runtime PRIVATE tlv++)
opentlv_configure_compiler(example-tlv++-formats-fixed-format-runtime)
opentlv_copy_shared_runtime(example-tlv++-formats-fixed-format-runtime)
add_test(NAME Integration_example_tlv++_formats_fixed_format_runtime
    COMMAND $<TARGET_FILE:example-tlv++-formats-fixed-format-runtime>)
set_tests_properties(Integration_example_tlv++_formats_fixed_format_runtime PROPERTIES LABELS "integration;examples")

# Use-case examples shared across languages: the same document is parsed,
# written, queried and validated in examples/tlv, examples/tlv++ and
# bindings/rust/opentlv/examples.
if(OPENTLV_FORMAT_BER)
    # Explicit source registration also backs the synchronized Writer guide example.
    add_executable(example-tlv++-write src/write.cpp)
    target_link_libraries(example-tlv++-write PRIVATE tlv++)
    opentlv_configure_compiler(example-tlv++-write)
    opentlv_copy_shared_runtime(example-tlv++-write)
    add_test(NAME Integration_example_tlv++_write COMMAND $<TARGET_FILE:example-tlv++-write>)
    set_tests_properties(Integration_example_tlv++_write PROPERTIES LABELS "integration;examples")
    foreach(use_case parse query validate)
        add_executable(example-tlv++-${use_case} src/${use_case}.cpp)
        target_link_libraries(example-tlv++-${use_case} PRIVATE tlv++)
        opentlv_configure_compiler(example-tlv++-${use_case})
        opentlv_copy_shared_runtime(example-tlv++-${use_case})
        add_test(NAME Integration_example_tlv++_${use_case} COMMAND $<TARGET_FILE:example-tlv++-${use_case}>)
        set_tests_properties(Integration_example_tlv++_${use_case} PROPERTIES LABELS "integration;examples")
    endforeach()
endif()

# Application-defined C++ Format; independent of every optional built-in.
add_executable(example-tlvpp-custom-format src/formats/custom_format.cpp)
target_link_libraries(example-tlvpp-custom-format PRIVATE tlv++)
opentlv_configure_compiler(example-tlvpp-custom-format)
opentlv_copy_shared_runtime(example-tlvpp-custom-format)
add_test(NAME Integration_example_tlvpp_custom_format COMMAND $<TARGET_FILE:example-tlvpp-custom-format>)
set_tests_properties(Integration_example_tlvpp_custom_format PROPERTIES LABELS "integration;examples")

# Explicit incremental control and native interoperability require no optional built-in.
add_executable(example-tlvpp-advanced-control src/advanced_control.cpp)
target_link_libraries(example-tlvpp-advanced-control PRIVATE tlv++)
opentlv_configure_compiler(example-tlvpp-advanced-control)
opentlv_copy_shared_runtime(example-tlvpp-advanced-control)
add_test(NAME Integration_example_tlvpp_advanced_control COMMAND $<TARGET_FILE:example-tlvpp-advanced-control>)
set_tests_properties(Integration_example_tlvpp_advanced_control PROPERTIES LABELS "integration;examples")

if(OPENTLV_DOCUMENT AND OPENTLV_FORMAT_BER)
    add_executable(example-tlv++-document src/document.cpp)
    target_link_libraries(example-tlv++-document PRIVATE tlv++)
    opentlv_configure_compiler(example-tlv++-document)
    opentlv_copy_shared_runtime(example-tlv++-document)
    add_test(NAME Integration_example_tlv++_document COMMAND $<TARGET_FILE:example-tlv++-document>)
    set_tests_properties(Integration_example_tlv++_document PROPERTIES LABELS "integration;examples")
    add_executable(example-tlvpp-document-edit src/document_edit.cpp)
    target_link_libraries(example-tlvpp-document-edit PRIVATE tlv++)
    opentlv_configure_compiler(example-tlvpp-document-edit)
    opentlv_copy_shared_runtime(example-tlvpp-document-edit)
    add_test(NAME Integration_example_tlvpp_document_edit COMMAND $<TARGET_FILE:example-tlvpp-document-edit>)
    set_tests_properties(Integration_example_tlvpp_document_edit PROPERTIES LABELS "integration;examples")
endif()
