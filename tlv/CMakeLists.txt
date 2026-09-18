cmake_minimum_required(VERSION 3.16)

project(tlv LANGUAGES C)

set(_tlv_library_type STATIC)
if(OPENTLV_BUILD_SHARED_LIBS)
    set(_tlv_library_type SHARED)
endif()

add_library(${PROJECT_NAME} ${_tlv_library_type}
    src/codec/codec.c
    src/codec/structure.c
    src/formats/format.c
    src/copy.c
    src/tag.c
    src/endian.c
    src/length.c
    src/value.c
    src/reader/reader.c
    src/reader/scanner.c
    src/reader/walker.c
    src/schemas/schema.c
    src/schemas/structure.c
    src/writer/writer.c
    src/error.c
    ${OpenTLV_BINARY_DIR}/generated/src/version.c
    ${OpenTLV_BINARY_DIR}/generated/src/config.c
)

if(OPENTLV_FORMAT_DEFAULT)
    target_sources(${PROJECT_NAME} PRIVATE src/formats/default/default.c)
endif()
if(OPENTLV_FORMAT_FIXED_1BYTE)
    target_sources(${PROJECT_NAME} PRIVATE src/formats/fixed/fixed_1byte.c)
endif()
if(OPENTLV_FORMAT_BER)
    target_sources(${PROJECT_NAME} PRIVATE src/formats/asn1/ber.c)
endif()
if(OPENTLV_FORMAT_DER)
    target_sources(${PROJECT_NAME} PRIVATE src/formats/asn1/der.c)
endif()
if(OPENTLV_FORMAT_CER)
    target_sources(${PROJECT_NAME} PRIVATE src/formats/asn1/cer.c)
endif()
if(OPENTLV_FORMAT_BER)
    # DER and CER (below) cascade off whenever BER is OFF, so this single
    # guard covers the shared private BER wire helpers used by both.
    target_sources(${PROJECT_NAME} PRIVATE src/formats/asn1/ber_internal.c)
endif()
if(OPENTLV_FORMAT_DER OR OPENTLV_FORMAT_CER)
    # Shared canonical identifier/length helpers and universal-value content
    # validators, usable by either sibling without requiring the other.
    target_sources(${PROJECT_NAME} PRIVATE
        src/formats/asn1/asn1_internal.c
        src/profiles/asn1_values_internal.c)
endif()
if(OPENTLV_FORMAT_DER)
    target_sources(${PROJECT_NAME} PRIVATE
        src/profiles/der.c src/profiles/der_values.c src/profiles/der_schema.c)
endif()
if(OPENTLV_FORMAT_CER)
    target_sources(${PROJECT_NAME} PRIVATE
        src/profiles/cer.c src/profiles/cer_values_internal.c)
endif()
if(OPENTLV_PROFILE_EMV)
    target_sources(${PROJECT_NAME} PRIVATE
        src/profiles/emv.c src/codec/emv.c src/profiles/dol.c src/profiles/emv_schema.c)
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
