cmake_minimum_required(VERSION 3.16)

project(tlv LANGUAGES C)

add_library(${PROJECT_NAME}
    src/codec/codec.c
    src/codec/structure.c
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

foreach(component IN ITEMS DEFAULT FIXED_1BYTE BER DER)
    if(OPENTLV_FORMAT_${component})
        string(TOLOWER "${component}" source_name)
        target_sources(${PROJECT_NAME} PRIVATE src/formats/${source_name}.c)
    endif()
endforeach()
if(OPENTLV_FORMAT_BER OR OPENTLV_FORMAT_DER)
    target_sources(${PROJECT_NAME} PRIVATE src/formats/ber_internal.c)
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
