cmake_minimum_required(VERSION 3.16)

set(test_target test-${test_group}-tlv)

set(HEADERS
)

set(SOURCES
    architecture_test.cpp
    copy_test.cpp
    diagnostic_test.cpp
    endian_test.cpp
    endian_c_test.c
    length_test.cpp
    value_test.cpp
    tag_test.cpp
    view_test.cpp
    versiontest.cpp
    format_init_test.cpp
    format_test.cpp
    test_tlv.cpp
    reader/reader_test.cpp
    reader/scanner_test.cpp
    reader/walker_test.cpp
    writer/writer_test.cpp
    query/query_test.cpp
    schema/schema_test.cpp
    schema/schema_report_test.cpp
    schema/constraint_test.cpp
    document/document_test.cpp
    codec/codec_test.cpp
    builtins/asn1/format_ber_test.cpp
    builtins/asn1/asn1_codec_test.cpp
    builtins/asn1/der_test.cpp
    builtins/asn1/der_values_test.cpp
    builtins/asn1/der_schema_test.cpp
    builtins/asn1/cer_test.cpp
    builtins/asn1/cer_values_test.cpp
    builtins/emv/emv_test.cpp
    builtins/emv/emv_schema_test.cpp
    builtins/emv/dol_test.cpp
    builtins/emv/tag_c_test.c
    builtins/bluetooth/format_bluetooth_ltv_test.cpp
    builtins/bluetooth/format_bluetooth_ltv_conformance_test.cpp
    builtins/fixed/format_fixed_1byte_test.cpp
    builtins/fixed/dhcp_option_tests.cpp
)

# A split source exists only in the group containing relevant cases.
foreach(source IN LISTS SOURCES)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${source}")
        list(REMOVE_ITEM SOURCES "${source}")
    endif()
endforeach()

# Tests that name an optional component follow the same feature selection.
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_FIXED_1BYTE))
        list(REMOVE_ITEM SOURCES codec/codec_test.cpp)
    endif()
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_FIXED_1BYTE AND OPENTLV_FORMAT_BER))
        list(REMOVE_ITEM SOURCES copy_test.cpp)
    endif()
endif()
if(NOT OPENTLV_FORMAT_DER)
    list(REMOVE_ITEM SOURCES builtins/asn1/der_test.cpp builtins/asn1/der_values_test.cpp
                                 builtins/asn1/der_schema_test.cpp)
endif()
if(NOT OPENTLV_FORMAT_CER)
    list(REMOVE_ITEM SOURCES builtins/asn1/cer_test.cpp builtins/asn1/cer_values_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_DEFAULT))
    list(REMOVE_ITEM SOURCES builtins/fixed/dhcp_option_tests.cpp)
endif()
if(NOT (OPENTLV_FORMAT_BER AND OPENTLV_PROFILE_EMV))
    list(REMOVE_ITEM SOURCES builtins/emv/emv_test.cpp builtins/emv/emv_schema_test.cpp
                                 builtins/emv/dol_test.cpp builtins/emv/tag_c_test.c)
endif()
if(NOT (OPENTLV_FORMAT_BER))
    list(REMOVE_ITEM SOURCES builtins/asn1/format_ber_test.cpp builtins/asn1/asn1_codec_test.cpp
                                 schema/schema_report_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_FIXED_1BYTE))
    list(REMOVE_ITEM SOURCES builtins/fixed/format_fixed_1byte_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_BLUETOOTH_LTV))
    list(REMOVE_ITEM SOURCES builtins/bluetooth/format_bluetooth_ltv_test.cpp
                                 builtins/bluetooth/format_bluetooth_ltv_conformance_test.cpp)
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_DEFAULT AND OPENTLV_FORMAT_FIXED_1BYTE))
        list(REMOVE_ITEM SOURCES reader/reader_test.cpp)
    endif()
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_DEFAULT AND OPENTLV_FORMAT_FIXED_1BYTE))
        list(REMOVE_ITEM SOURCES reader/scanner_test.cpp)
    endif()
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_FIXED_1BYTE))
        list(REMOVE_ITEM SOURCES schema/schema_test.cpp)
    endif()
endif()
if(NOT (OPENTLV_FORMAT_DEFAULT))
    list(REMOVE_ITEM SOURCES test_tlv.cpp)
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_DEFAULT AND OPENTLV_FORMAT_FIXED_1BYTE))
        list(REMOVE_ITEM SOURCES reader/walker_test.cpp)
    endif()
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_DEFAULT AND OPENTLV_FORMAT_FIXED_1BYTE))
        list(REMOVE_ITEM SOURCES writer/writer_test.cpp)
    endif()
endif()

if(NOT OPENTLV_DOCUMENT)
    list(REMOVE_ITEM SOURCES document/document_test.cpp)
endif()

add_executable(${test_target}
    ${HEADERS}
    ${SOURCES}
)

target_include_directories(${test_target}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${test_target} PRIVATE
    tlv
    GTest::gtest_main
)

include(GoogleTest)
opentlv_configure_compiler(${test_target})
opentlv_copy_shared_runtime(${test_target})
gtest_discover_tests(${test_target} PROPERTIES LABELS ${test_group})
