cmake_minimum_required(VERSION 3.16)

project(opentlv-perf-workloads LANGUAGES C)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_CROSSCOMPILING)
    message(FATAL_ERROR "The comparison workloads require a native Linux build.")
endif()

set(OPENTLV_SOURCE_DIR "" CACHE PATH "OpenTLV checkout to measure")
if(NOT EXISTS "${OPENTLV_SOURCE_DIR}/tlv/CMakeLists.txt")
    message(FATAL_ERROR "Set OPENTLV_SOURCE_DIR to the OpenTLV checkout to measure.")
endif()
option(OPENTLV_CALLGRIND_INSTRUMENTATION "Enable explicit Callgrind measurement regions" OFF)

# The same driver from the candidate checkout is built against both libraries.
# Keep dependencies, capabilities, linkage and instrumentation identical.
foreach(feature IN ITEMS TESTS UNIT_TESTS INTEGRATION_TESTS QUERY_TESTS PROPERTY_TESTS
        CLI_TESTS EXAMPLES CLI BENCHMARKS FUZZING MEMCHECK DOCS CXX WASM PYTHON LUA SHARED_LIBS)
    set(OPENTLV_BUILD_${feature} OFF CACHE BOOL "" FORCE)
endforeach()
foreach(feature IN ITEMS READER WRITER DOCUMENT QUERY QUERY_FRONTEND QUERY_SET_OPERATIONS
        SCHEMA CODEC FORMAT_ASN1 FORMAT_BER FORMAT_DER FORMAT_CER EMV BLUETOOTH NFC DHCP LLDP)
    set(OPENTLV_${feature} ON CACHE BOOL "" FORCE)
endforeach()
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)
add_subdirectory("${OPENTLV_SOURCE_DIR}" opentlv EXCLUDE_FROM_ALL)

add_executable(opentlv-perf-workload workloads.c)
target_compile_features(opentlv-perf-workload PRIVATE c_std_99)
set_target_properties(opentlv-perf-workload PROPERTIES C_EXTENSIONS OFF)
target_compile_definitions(opentlv-perf-workload PRIVATE _POSIX_C_SOURCE=200809L)
target_compile_options(opentlv-perf-workload PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(opentlv-perf-workload PRIVATE tlv)

if(OPENTLV_CALLGRIND_INSTRUMENTATION)
    find_path(OPENTLV_CALLGRIND_INCLUDE_DIR valgrind/callgrind.h)
    if(NOT OPENTLV_CALLGRIND_INCLUDE_DIR)
        message(FATAL_ERROR "Callgrind instrumentation requires valgrind/callgrind.h.")
    endif()
    target_include_directories(opentlv-perf-workload PRIVATE "${OPENTLV_CALLGRIND_INCLUDE_DIR}")
    target_compile_definitions(opentlv-perf-workload PRIVATE OPENTLV_CALLGRIND_INSTRUMENTATION=1)
endif()
