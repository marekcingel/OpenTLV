cmake_minimum_required(VERSION 3.16)
project(opentlv_fixed_abi_probe C)

if(NOT OPENTLV_SOURCE_DIR)
    message(FATAL_ERROR "OPENTLV_SOURCE_DIR must point to the matching OpenTLV sources")
endif()

# Compile the real public types independently of the Rust FFI mirror. Only an
# export header is generated; visibility macros have no effect on struct layout.
include(GenerateExportHeader)
add_library(abi_values STATIC values.c)
set_target_properties(abi_values PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)
generate_export_header(abi_values
    EXPORT_FILE_NAME "${CMAKE_CURRENT_BINARY_DIR}/include/tlv/export.h"
    EXPORT_MACRO_NAME TLV_API
    STATIC_DEFINE TLV_STATIC_DEFINE)
target_compile_definitions(abi_values PRIVATE TLV_STATIC_DEFINE)
target_include_directories(abi_values PRIVATE
    "${OPENTLV_SOURCE_DIR}/tlv/include"
    "${CMAKE_CURRENT_BINARY_DIR}/include")
add_executable(abi_probe main.c)
target_link_libraries(abi_probe PRIVATE abi_values)
