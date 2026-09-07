cmake_minimum_required(VERSION 3.16)

project(tlv LANGUAGES C)

add_library(${PROJECT_NAME}
    src/profiles/emv.c
    src/profiles/emv_codec.c
    src/codec.c
    src/copy.c
    src/endian.c
    src/format_default.c
    src/format_ber.c
    src/format_fixed_1byte.c
    src/reader.c
    src/scanner.c
    src/schema.c
    src/walker.c
    src/writer.c
    src/error.c
    ${OpenTLV_BINARY_DIR}/generated/src/version.c
)

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
