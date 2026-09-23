cmake_minimum_required(VERSION 3.16)

project(example-tlv LANGUAGES C)

if(OPENTLV_FORMAT_DEFAULT AND OPENTLV_FORMAT_FIXED_1BYTE AND OPENTLV_FORMAT_BER)
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
    foreach(topic sequential_io copies schema_walk_and_scan codecs_and_endian custom_format)
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

# Builtin-specific example: walks an EMV template with the EMV dictionary.
# Kept independent of the flags above; it only needs OPENTLV_PROFILE_EMV
# (which already implies OPENTLV_FORMAT_BER).
if(OPENTLV_PROFILE_EMV)
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
