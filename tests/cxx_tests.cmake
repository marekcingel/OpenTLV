cmake_minimum_required(VERSION 3.16)

set(test_target test-${test_group}-tlvpp)

set(HEADERS
)

set(SOURCES
    test_tlvpp.cpp
)

if(test_group STREQUAL "unit")
    list(APPEND SOURCES public_api_test.cpp)
    list(APPEND SOURCES generator_test.cpp test_native_boundary.cpp test_semantic_views.cpp codec/test_typed_fields.cpp)
    list(APPEND SOURCES test_diagnostic.cpp builtins/test_convenience.cpp)
    add_executable(test-builtin-convenience-smoke builtins/convenience_smoke.cpp)
    target_link_libraries(test-builtin-convenience-smoke PRIVATE tlv++)
    set_target_properties(test-builtin-convenience-smoke PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
    target_compile_options(test-builtin-convenience-smoke PRIVATE
        "$<$<CXX_COMPILER_ID:GNU,Clang>:-fno-elide-constructors>")
    opentlv_configure_compiler(test-builtin-convenience-smoke)
    opentlv_copy_shared_runtime(test-builtin-convenience-smoke)
    add_test(NAME Unit_Tlvpp_BuiltinConvenience_AllocationAndNamespaces COMMAND test-builtin-convenience-smoke)
    set_tests_properties(Unit_Tlvpp_BuiltinConvenience_AllocationAndNamespaces PROPERTIES LABELS "unit")
    list(APPEND SOURCES reader/test_reader.cpp)
    list(APPEND SOURCES reader/test_iterable_reader.cpp)
    list(APPEND SOURCES query/test_query_ranges.cpp)
    add_executable(test-reader-iteration-smoke reader/iteration_smoke.cpp)
    target_include_directories(test-reader-iteration-smoke PRIVATE ${OpenTLV_SOURCE_DIR}/tests)
    target_link_libraries(test-reader-iteration-smoke PRIVATE tlv++)
    set_target_properties(test-reader-iteration-smoke PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
    target_compile_options(test-reader-iteration-smoke PRIVATE
        "$<$<CXX_COMPILER_ID:GNU,Clang>:-fno-elide-constructors>")
    opentlv_configure_compiler(test-reader-iteration-smoke)
    opentlv_copy_shared_runtime(test-reader-iteration-smoke)
    add_test(NAME Unit_Tlvpp_IterableReader_AllocationAndMoves COMMAND test-reader-iteration-smoke)
    set_tests_properties(Unit_Tlvpp_IterableReader_AllocationAndMoves PROPERTIES LABELS "unit")
    list(APPEND SOURCES writer/test_tree_writer.cpp writer/test_builder.cpp)
    add_executable(test-writer-builder-smoke writer/builder_smoke.cpp)
    target_include_directories(test-writer-builder-smoke PRIVATE ${OpenTLV_SOURCE_DIR}/tests)
    target_link_libraries(test-writer-builder-smoke PRIVATE tlv++)
    set_target_properties(test-writer-builder-smoke PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
    target_compile_options(test-writer-builder-smoke PRIVATE
        "$<$<CXX_COMPILER_ID:GNU,Clang>:-fno-elide-constructors>")
    opentlv_configure_compiler(test-writer-builder-smoke)
    opentlv_copy_shared_runtime(test-writer-builder-smoke)
    add_test(NAME Unit_Tlvpp_WriterBuilder_AllocationAndMoves COMMAND test-writer-builder-smoke)
    set_tests_properties(Unit_Tlvpp_WriterBuilder_AllocationAndMoves PROPERTIES LABELS "unit")
    # tlv::fixed_format<> now delegates to tlv_fixed_format_init(), so its
    # tests need the C fixed format compiled into tlv.
    list(APPEND SOURCES formats/test_fixed_format.cpp formats/test_custom_format.cpp)
    if(OPENTLV_DOCUMENT)
        list(APPEND SOURCES document/test_document.cpp)
        add_executable(test-document-handle-smoke document/handle_smoke.cpp)
        target_link_libraries(test-document-handle-smoke PRIVATE tlv++)
        set_target_properties(test-document-handle-smoke PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
        opentlv_configure_compiler(test-document-handle-smoke)
        opentlv_copy_shared_runtime(test-document-handle-smoke)
        add_test(NAME Unit_Tlvpp_Document_AllocationAndHandles COMMAND test-document-handle-smoke)
        set_tests_properties(Unit_Tlvpp_Document_AllocationAndHandles PROPERTIES LABELS "unit")
    endif()
endif()

if(test_group STREQUAL "integration")
    list(APPEND SOURCES layers_test.cpp)
    if(OPENTLV_NFC)
        list(APPEND SOURCES builtins/nfc/type2_cpp_test.cpp)
    endif()
    if(OPENTLV_DHCP)
        list(APPEND SOURCES builtins/dhcp/dhcpv4_cpp_test.cpp)
    endif()
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
    tlv++
    GTest::gtest_main
)

opentlv_configure_compiler(${test_target})
opentlv_copy_shared_runtime(${test_target})

include(GoogleTest)
if(OPENTLV_BUILD_MEMCHECK)
    # Run every GoogleTest case with one Valgrind startup per binary.
    add_test(NAME ${test_target} COMMAND ${test_target})
    set_tests_properties(${test_target} PROPERTIES LABELS ${test_group})
    opentlv_memcheck_timeout(${test_target} 3600)
else()
    gtest_discover_tests(${test_target} DISCOVERY_TIMEOUT 30 PROPERTIES LABELS ${test_group})
endif()
