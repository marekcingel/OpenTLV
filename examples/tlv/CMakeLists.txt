cmake_minimum_required(VERSION 3.16)

project(example-tlv LANGUAGES C)

add_executable(example-tlv-incremental-reader src/incremental_reader.c)
target_link_libraries(example-tlv-incremental-reader PRIVATE tlv)
opentlv_configure_compiler(example-tlv-incremental-reader)
opentlv_copy_shared_runtime(example-tlv-incremental-reader)
add_test(NAME Integration_example_tlv_incremental_reader COMMAND $<TARGET_FILE:example-tlv-incremental-reader>)
set_tests_properties(Integration_example_tlv_incremental_reader PROPERTIES LABELS "integration;examples")

add_executable(example-tlv-tree-reader src/tree_reader.c)
target_link_libraries(example-tlv-tree-reader PRIVATE tlv)
opentlv_configure_compiler(example-tlv-tree-reader)
opentlv_copy_shared_runtime(example-tlv-tree-reader)
add_test(NAME Integration_example_tlv_tree_reader COMMAND $<TARGET_FILE:example-tlv-tree-reader>)
set_tests_properties(Integration_example_tlv_tree_reader PROPERTIES LABELS "integration;examples")

add_executable(example-tlv-visitor src/visitor.c)
target_link_libraries(example-tlv-visitor PRIVATE tlv)
opentlv_configure_compiler(example-tlv-visitor)
opentlv_copy_shared_runtime(example-tlv-visitor)
add_test(NAME Integration_example_tlv_visitor COMMAND $<TARGET_FILE:example-tlv-visitor>)
set_tests_properties(Integration_example_tlv_visitor PROPERTIES LABELS "integration;examples")

if(OPENTLV_DHCP)
    add_executable(example-tlv-dhcpv4 src/dhcpv4.c)
    target_link_libraries(example-tlv-dhcpv4 PRIVATE tlv)
    opentlv_configure_compiler(example-tlv-dhcpv4)
    opentlv_copy_shared_runtime(example-tlv-dhcpv4)
    add_test(NAME Integration_example_tlv_dhcpv4 COMMAND $<TARGET_FILE:example-tlv-dhcpv4>)
    set_tests_properties(Integration_example_tlv_dhcpv4 PROPERTIES LABELS "integration;examples")
endif()
if(OPENTLV_LLDP)
    add_executable(example-tlv-lldp src/lldp.c)
    target_link_libraries(example-tlv-lldp PRIVATE tlv)
    opentlv_configure_compiler(example-tlv-lldp)
    opentlv_copy_shared_runtime(example-tlv-lldp)
    add_test(NAME Integration_example_tlv_lldp COMMAND $<TARGET_FILE:example-tlv-lldp>)
    set_tests_properties(Integration_example_tlv_lldp PROPERTIES LABELS "integration;examples")
endif()

if(OPENTLV_FORMAT_BER)
    # Backs the C example in the README and Getting Started; scripts/check_doc_examples.py
    # keeps the Markdown copies identical to this file.
    add_executable(example-tlv-quick-start src/quick_start.c)
    target_link_libraries(example-tlv-quick-start PRIVATE tlv)
    opentlv_configure_compiler(example-tlv-quick-start)
    opentlv_copy_shared_runtime(example-tlv-quick-start)

    # Use-case examples shared across languages: the same document is parsed,
    # written, queried and validated in examples/tlv, examples/tlv++ and
    # bindings/rust/opentlv/examples.
    foreach(use_case parse write query validate)
        add_executable(example-tlv-${use_case} src/${use_case}.c)
        target_link_libraries(example-tlv-${use_case} PRIVATE tlv)
        opentlv_configure_compiler(example-tlv-${use_case})
        opentlv_copy_shared_runtime(example-tlv-${use_case})
        add_test(NAME Integration_example_tlv_${use_case} COMMAND $<TARGET_FILE:example-tlv-${use_case}>)
        set_tests_properties(Integration_example_tlv_${use_case} PROPERTIES LABELS "integration;examples")
    endforeach()

    # One topic per example, each its own small self-checking program.
    foreach(topic sequential_io copies schema_walk codecs_and_endian custom_format)
        string(REPLACE "_" "-" topic_dashed ${topic})
        add_executable(example-tlv-${topic_dashed} src/${topic}.c)
        target_link_libraries(example-tlv-${topic_dashed} PRIVATE tlv)
        opentlv_configure_compiler(example-tlv-${topic_dashed})
        opentlv_copy_shared_runtime(example-tlv-${topic_dashed})
        add_test(NAME Integration_example_tlv_${topic} COMMAND $<TARGET_FILE:example-tlv-${topic_dashed}>)
        set_tests_properties(Integration_example_tlv_${topic} PROPERTIES LABELS "integration;examples")
    endforeach()

    # Builtin-specific examples: one per wire format.
    add_executable(example-tlv-builtins-asn1-ber src/builtins/asn1/ber.c)
    target_link_libraries(example-tlv-builtins-asn1-ber PRIVATE tlv)
    opentlv_configure_compiler(example-tlv-builtins-asn1-ber)
    opentlv_copy_shared_runtime(example-tlv-builtins-asn1-ber)
    add_test(NAME Integration_example_tlv_builtins_asn1_ber COMMAND $<TARGET_FILE:example-tlv-builtins-asn1-ber>)
    set_tests_properties(Integration_example_tlv_builtins_asn1_ber PROPERTIES LABELS "integration;examples")

    if(OPENTLV_FORMAT_CER)
        add_executable(example-tlv-builtins-asn1-cer src/builtins/asn1/cer.c)
        target_link_libraries(example-tlv-builtins-asn1-cer PRIVATE tlv)
        opentlv_configure_compiler(example-tlv-builtins-asn1-cer)
        opentlv_copy_shared_runtime(example-tlv-builtins-asn1-cer)
        add_test(NAME Integration_example_tlv_builtins_asn1_cer COMMAND $<TARGET_FILE:example-tlv-builtins-asn1-cer>)
        set_tests_properties(Integration_example_tlv_builtins_asn1_cer PROPERTIES LABELS "integration;examples")
    endif()
endif()

# Generic-format example: a runtime-configurable fixed-width format.
# Fixed is always available as part of the generic core.
add_executable(example-tlv-formats-fixed-format src/formats/fixed_format.c)
target_link_libraries(example-tlv-formats-fixed-format PRIVATE tlv)
opentlv_configure_compiler(example-tlv-formats-fixed-format)
opentlv_copy_shared_runtime(example-tlv-formats-fixed-format)
add_test(NAME Integration_example_tlv_formats_fixed_format
    COMMAND $<TARGET_FILE:example-tlv-formats-fixed-format>)
set_tests_properties(Integration_example_tlv_formats_fixed_format PROPERTIES LABELS "integration;examples")

# Builtin-specific example: walks an EMV template with the EMV dictionary.
# Kept independent of the flags above; it only needs OPENTLV_EMV
# (which already implies OPENTLV_FORMAT_BER).
if(OPENTLV_EMV)
    add_executable(example-tlv-builtins-emv-tag-decoding src/builtins/emv/tag_decoding.c)
    target_include_directories(example-tlv-builtins-emv-tag-decoding PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/builtins/emv
    )
    target_link_libraries(example-tlv-builtins-emv-tag-decoding PRIVATE tlv)
    opentlv_configure_compiler(example-tlv-builtins-emv-tag-decoding)
    opentlv_copy_shared_runtime(example-tlv-builtins-emv-tag-decoding)

    add_test(NAME Integration_example_tlv_builtins_emv_tag_decoding
        COMMAND $<TARGET_FILE:example-tlv-builtins-emv-tag-decoding>)
    set_tests_properties(Integration_example_tlv_builtins_emv_tag_decoding PROPERTIES LABELS "integration;examples")
endif()
