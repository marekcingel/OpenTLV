# Keep instrumentation private to a separate copy of the enabled C sources.
if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang" OR NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "OPENTLV_BUILD_FUZZING requires Clang 18+ on Linux (or WSL).")
endif()
opentlv_check_compiler()
if(NOT (OPENTLV_FORMAT_DEFAULT OR OPENTLV_FORMAT_FIXED_1BYTE OR
        OPENTLV_FORMAT_BER OR OPENTLV_FORMAT_DER))
    message(FATAL_ERROR "OPENTLV_BUILD_FUZZING requires at least one built-in format.")
endif()

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
target_compile_features(tlv_fuzz PUBLIC c_std_99)
opentlv_configure_compiler(tlv_fuzz)
target_compile_options(tlv_fuzz PRIVATE
    -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all
    -fno-omit-frame-pointer -g)

set(fuzz_targets read walk_tree roundtrip)
if(OPENTLV_FORMAT_DER)
    list(APPEND fuzz_targets der)
endif()
foreach(name IN LISTS fuzz_targets)
    add_executable(fuzz_${name} ${name}.c)
    target_link_libraries(fuzz_${name} PRIVATE tlv_fuzz)
    opentlv_configure_compiler(fuzz_${name})
    target_compile_options(fuzz_${name} PRIVATE
        -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all
        -fno-omit-frame-pointer -g)
    target_link_options(fuzz_${name} PRIVATE -fsanitize=fuzzer,address,undefined)
endforeach()
