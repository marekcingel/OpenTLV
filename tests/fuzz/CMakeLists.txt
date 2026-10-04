# Keep instrumentation private to a separate copy of the enabled C sources.
if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang" OR NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "OPENTLV_BUILD_FUZZING requires Clang 18+ on Linux (or WSL).")
endif()
opentlv_check_compiler()

include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer,address,undefined")
check_c_source_compiles("
    #include <stddef.h>
    #include <stdint.h>
    int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        (void)data; (void)size; return 0;
    }" OPENTLV_HAS_LIBFUZZER)
unset(CMAKE_REQUIRED_FLAGS)
if(NOT OPENTLV_HAS_LIBFUZZER)
    message(FATAL_ERROR "Clang must provide working libFuzzer, ASan and UBSan runtimes.")
endif()

get_target_property(tlv_sources tlv SOURCES)
get_target_property(tlv_source_dir tlv SOURCE_DIR)
get_target_property(tlv_includes tlv INCLUDE_DIRECTORIES)
set(fuzz_sources)
foreach(source IN LISTS tlv_sources)
    get_filename_component(source "${source}" ABSOLUTE BASE_DIR "${tlv_source_dir}")
    list(APPEND fuzz_sources "${source}")
endforeach()
add_library(tlv_fuzz STATIC ${fuzz_sources})
target_include_directories(tlv_fuzz PUBLIC ${tlv_includes})
# Compiles library sources directly rather than linking the tlv target;
# TLV_STATIC_DEFINE keeps TLV_API a no-op regardless of OPENTLV_BUILD_SHARED_LIBS.
target_compile_definitions(tlv_fuzz PUBLIC TLV_STATIC_DEFINE)
target_compile_features(tlv_fuzz PUBLIC c_std_99)
opentlv_configure_compiler(tlv_fuzz)
target_compile_options(tlv_fuzz PRIVATE
    -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all
    -fno-omit-frame-pointer -g)

set(fuzz_targets read visitor roundtrip)
list(APPEND fuzz_targets query_parse query_match query_program)
set(fuzz_source_query_parse query/parse.c)
set(fuzz_source_query_match query/match.c)
set(fuzz_source_query_program query/program.c)
set(fuzz_source_read reader/read.c)
set(fuzz_source_visitor reader/visitor.c)
set(fuzz_source_roundtrip roundtrip.c)
list(APPEND fuzz_targets fixed)
set(fuzz_source_fixed builtins/fixed/fixed.c)
if(OPENTLV_FORMAT_DER)
    list(APPEND fuzz_targets der der_schema)
    set(fuzz_source_der builtins/asn1/der.c)
    set(fuzz_source_der_schema builtins/asn1/der_schema.c)
endif()
if(OPENTLV_EMV)
    list(APPEND fuzz_targets codec dol)
    set(fuzz_source_codec builtins/emv/codec.c)
    set(fuzz_source_dol builtins/emv/dol.c)
endif()
foreach(name IN LISTS fuzz_targets)
    add_executable(fuzz_${name} ${fuzz_source_${name}})
    target_include_directories(fuzz_${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(fuzz_${name} PRIVATE tlv_fuzz)
    opentlv_configure_compiler(fuzz_${name})
    target_compile_options(fuzz_${name} PRIVATE
        -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all
        -fno-omit-frame-pointer -g)
    target_link_options(fuzz_${name} PRIVATE -fsanitize=fuzzer,address,undefined)
endforeach()
