cmake_minimum_required(VERSION 3.16)

set(test_target test-${test_group}-tlv)

set(HEADERS
)

set(SOURCES
    architecture_test.cpp
    attributes_c_test.c
    attributes_test.cpp
    builtins/asn1/asn1_codec_test.cpp
    builtins/asn1/ber_io_test.cpp
    builtins/asn1/cer_test.cpp
    builtins/asn1/cer_values_test.cpp
    builtins/asn1/der_schema_test.cpp
    builtins/asn1/der_test.cpp
    builtins/asn1/der_values_test.cpp
    builtins/asn1/format_ber_test.cpp
    builtins/bluetooth/ad_codec_test.cpp
    builtins/bluetooth/ad_data_test.cpp
    builtins/bluetooth/ad_schema_test.cpp
    builtins/bluetooth/ad_types_test.cpp
    builtins/bluetooth/company_ids_test.cpp
    builtins/bluetooth/format_bluetooth_ltv_conformance_test.cpp
    builtins/bluetooth/format_bluetooth_ltv_test.cpp
    builtins/bluetooth/manufacturer_data_test.cpp
    builtins/bluetooth/semantic_test.cpp
    builtins/bluetooth/service_data_test.cpp
    builtins/bluetooth/uuid_test.cpp
    builtins/dhcp/codec_test.cpp
    builtins/dhcp/container_test.cpp
    builtins/dhcp/dhcpv4_test.cpp
    builtins/dhcp/options_test.cpp
    builtins/emv/dol_test.cpp
    builtins/emv/emv_schema_test.cpp
    builtins/emv/emv_test.cpp
    builtins/emv/format_emv_test.cpp
    builtins/emv/tag_c_test.c
    builtins/lldp/codec_test.cpp
    builtins/lldp/lldp_test.cpp
    codec/codec_test.cpp
    codec/ipv4_test.cpp
    codec/values_test.cpp
    codec/digits_test.cpp
    codec/text_test.cpp
    compiler_c_test.c
    compiler_test.cpp
    copy_test.cpp
    definition_test.cpp
    diagnostic_test.cpp
    document/document_test.cpp
    element_test.cpp
    endian_c_test.c
    endian_test.cpp
    format_init_test.cpp
    format_test.cpp
    formats/fixed_dhcp_options_test.cpp
    formats/fixed_io_test.cpp
    formats/format_fixed_test.cpp
    formats/variable_test.cpp
    packed_field_test.cpp
    query/query_test.cpp
    reader/reader_test.cpp
    reader/incremental_test.cpp
    reader/walker_test.cpp
    schema/constraint_test.cpp
    schema/schema_report_test.cpp
    schema/schema_test.cpp
    size_test.cpp
    tag_test.cpp
    tagged_binary_test.cpp
    transformed_tag_test.cpp
    value_test.cpp
    versiontest.cpp
    writer/writer_test.cpp
)

# A split source exists only in the group containing relevant cases.
foreach(source IN LISTS SOURCES)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${source}")
        list(REMOVE_ITEM SOURCES "${source}")
    endif()
endforeach()

# Tests that name an optional component follow the same feature selection.
if(NOT OPENTLV_DHCP)
    list(FILTER SOURCES EXCLUDE REGEX "^builtins/dhcp/")
endif()
if(NOT OPENTLV_LLDP)
    list(FILTER SOURCES EXCLUDE REGEX "^builtins/lldp/")
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_BER))
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
if(NOT (OPENTLV_FORMAT_BER AND OPENTLV_EMV))
    list(REMOVE_ITEM SOURCES builtins/emv/emv_test.cpp builtins/emv/emv_schema_test.cpp
                                 builtins/emv/dol_test.cpp builtins/emv/tag_c_test.c
                                 builtins/emv/format_emv_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_BER))
    list(REMOVE_ITEM SOURCES builtins/asn1/format_ber_test.cpp builtins/asn1/asn1_codec_test.cpp
                                 schema/schema_report_test.cpp)
endif()
if(NOT (OPENTLV_BLUETOOTH))
    list(FILTER SOURCES EXCLUDE REGEX "^builtins/bluetooth/")
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_BER))
        list(REMOVE_ITEM SOURCES reader/reader_test.cpp)
    endif()
endif()
if(test_group STREQUAL "integration" AND NOT OPENTLV_FORMAT_BER)
    list(REMOVE_ITEM SOURCES builtins/asn1/ber_io_test.cpp)
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_BER))
        list(REMOVE_ITEM SOURCES reader/walker_test.cpp)
    endif()
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_BER))
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
    ${OpenTLV_SOURCE_DIR}/tests
)

target_link_libraries(${test_target} PRIVATE
    tlv
    GTest::gtest_main
)

include(GoogleTest)
opentlv_configure_compiler(${test_target})
opentlv_copy_shared_runtime(${test_target})
gtest_discover_tests(${test_target} PROPERTIES LABELS ${test_group})
