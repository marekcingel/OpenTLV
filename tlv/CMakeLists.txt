cmake_minimum_required(VERSION 3.16)

project(tlv LANGUAGES C)

set(_tlv_library_type STATIC)
if(OPENTLV_BUILD_SHARED_LIBS)
    set(_tlv_library_type SHARED)
endif()

add_library(${PROJECT_NAME} ${_tlv_library_type}
    src/definition.c
    src/codec/codec.c
    src/codec/values.c
    src/codec/number.c
    src/codec/digits.c
    src/codec/text.c
    src/codec/ipv4.c
    src/codec/structure.c
    src/generator.c
    src/format.c
    src/layout.c
    src/formats/fixed.c
    src/formats/variable.c
    src/formats/escaped.c
    src/copy.c
    src/diagnostic.c
    src/tag.c
    src/endian.c
    src/size.c
    src/value.c
    src/utf8_internal.c
    src/reader/reader.c
    src/reader/tree.c
    src/reader/visitor.c
    src/query/query.c
    src/query/compiler.c
    src/query/execute.c
    src/query/evaluation.c
    src/query/adapters.c
    src/schema/schema.c
    src/schema/query.c
    src/schema/number.c
    src/schema/structure.c
    src/schema/report.c
    src/schema/constraint.c
    src/writer/writer.c
    src/writer/tree.c
    src/error.c
    ${OpenTLV_BINARY_DIR}/generated/src/version.c
    ${OpenTLV_BINARY_DIR}/generated/src/config.c
)

if(OPENTLV_NFC)
    target_sources(${PROJECT_NAME} PRIVATE src/builtins/nfc/type2.c)
endif()

if(OPENTLV_DHCP)
    target_sources(${PROJECT_NAME} PRIVATE
        src/builtins/dhcp/dhcpv4.c
        src/builtins/dhcp/options.c
        src/builtins/dhcp/container.c)
endif()
if(OPENTLV_LLDP)
    target_sources(${PROJECT_NAME} PRIVATE
        src/builtins/lldp/lldp.c
        src/builtins/lldp/schema.c
        src/builtins/lldp/codec.c)
endif()
if(OPENTLV_BLUETOOTH)
    target_sources(${PROJECT_NAME} PRIVATE
        src/builtins/bluetooth/ad_types.c
        src/builtins/bluetooth/ad_schema.c
        src/builtins/bluetooth/ad_codec.c
        src/builtins/bluetooth/uuid.c
        src/builtins/bluetooth/service_data.c
        src/builtins/bluetooth/manufacturer_data.c
        src/builtins/bluetooth/company_ids.c
        src/builtins/bluetooth/bluetooth_ltv.c src/builtins/bluetooth/ad_data.c)
endif()
if(OPENTLV_FORMAT_BER)
    target_sources(${PROJECT_NAME} PRIVATE src/builtins/asn1/ber.c src/builtins/asn1/identifier.c src/builtins/asn1/asn1_codec.c src/builtins/asn1/query.c)
endif()
if(OPENTLV_FORMAT_DER)
    target_sources(${PROJECT_NAME} PRIVATE src/builtins/asn1/der.c)
endif()
if(OPENTLV_FORMAT_CER)
    target_sources(${PROJECT_NAME} PRIVATE src/builtins/asn1/cer.c)
endif()
if(OPENTLV_FORMAT_BER)
    # DER and CER (below) cascade off whenever BER is OFF, so this single
    # guard covers the shared private BER wire helpers used by both.
    target_sources(${PROJECT_NAME} PRIVATE src/builtins/asn1/ber_internal.c)
endif()
if(OPENTLV_FORMAT_BER OR OPENTLV_FORMAT_DER OR OPENTLV_FORMAT_CER)
    # Universal-value content validators, shared by the BER-layer codecs
    # above and by the DER/CER strict-mode validators below.
    target_sources(${PROJECT_NAME} PRIVATE src/builtins/asn1/asn1_values_internal.c)
endif()
if(OPENTLV_FORMAT_DER OR OPENTLV_FORMAT_CER)
    # Shared canonical identifier/length helpers, usable by either sibling
    # without requiring the other.
    target_sources(${PROJECT_NAME} PRIVATE src/builtins/asn1/asn1_internal.c)
endif()
if(OPENTLV_FORMAT_DER)
    target_sources(${PROJECT_NAME} PRIVATE
        src/builtins/asn1/der_validation.c src/builtins/asn1/der_schema.c)
endif()
if(OPENTLV_FORMAT_CER)
    target_sources(${PROJECT_NAME} PRIVATE
        src/builtins/asn1/cer_validation.c src/builtins/asn1/cer_values_internal.c)
endif()
if(OPENTLV_EMV)
    target_sources(${PROJECT_NAME} PRIVATE
        src/builtins/emv/format.c
        src/builtins/emv/emv.c src/builtins/emv/dictionary.c src/builtins/emv/query.c
        src/builtins/emv/emv_codec.c src/builtins/emv/presentation.c src/builtins/emv/dol.c src/builtins/emv/emv_schema.c)
endif()
if(OPENTLV_DOCUMENT)
    # Optional owning component and its allocation-free compiled Query adapter.
    target_sources(${PROJECT_NAME} PRIVATE src/document/document.c src/query/document_backend.c)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

include(GenerateExportHeader)
generate_export_header(${PROJECT_NAME}
    BASE_NAME TLV
    EXPORT_MACRO_NAME TLV_API
    EXPORT_FILE_NAME "${OpenTLV_BINARY_DIR}/generated/include/tlv/export.h"
)

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${OpenTLV_BINARY_DIR}/generated/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_compile_features(${PROJECT_NAME} PUBLIC
    c_std_99
)

opentlv_configure_compiler(${PROJECT_NAME})
