cmake_minimum_required(VERSION 3.16)

project(tlv LANGUAGES C)

add_library(${PROJECT_NAME}
    src/codec/codec.c
    src/codec/structure.c
    src/formats/format.c
    src/copy.c
    src/endian.c
    src/reader/reader.c
    src/reader/scanner.c
    src/reader/walker.c
    src/schemas/schema.c
    src/schemas/structure.c
    src/writer/writer.c
    src/error.c
    ${OpenTLV_BINARY_DIR}/generated/src/version.c
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
if(OPENTLV_FORMAT_BER OR OPENTLV_FORMAT_DER)
    target_sources(${PROJECT_NAME} PRIVATE src/formats/asn1/ber_internal.c)
endif()
if(OPENTLV_FORMAT_DER)
    target_sources(${PROJECT_NAME} PRIVATE src/profiles/der.c)
endif()
if(OPENTLV_PROFILE_EMV)
    target_sources(${PROJECT_NAME} PRIVATE src/profiles/emv.c src/codec/emv.c)
endif()
configure_file(include/tlv/config.h.in
    ${OpenTLV_BINARY_DIR}/generated/include/tlv/config.h)

set_target_properties(${PROJECT_NAME} PROPERTIES
    WINDOWS_EXPORT_ALL_SYMBOLS ON
)

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${OpenTLV_BINARY_DIR}/generated/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(${PROJECT_NAME} PUBLIC
    c_std_99
)

opentlv_configure_compiler(${PROJECT_NAME})
