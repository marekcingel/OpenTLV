cmake_minimum_required(VERSION 3.16)

set(test_target test-${test_group}-tlvpp)

set(HEADERS
)

set(SOURCES
    test_tlvpp.cpp
)

if(test_group STREQUAL "unit")
    list(APPEND SOURCES test_native_boundary.cpp)
    list(APPEND SOURCES test_diagnostic.cpp)
    list(APPEND SOURCES reader/test_reader.cpp)
    list(APPEND SOURCES writer/test_tree_writer.cpp)
    # tlv::fixed_format<> now delegates to tlv_fixed_format_init(), so its
    # tests need the C fixed format compiled into tlv.
    list(APPEND SOURCES formats/test_fixed_format.cpp)
    if(OPENTLV_DOCUMENT)
        list(APPEND SOURCES document/test_document.cpp)
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
gtest_discover_tests(${test_target} PROPERTIES LABELS ${test_group})
