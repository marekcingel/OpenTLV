cmake_minimum_required(VERSION 3.16)

set(test_target test-${test_group}-tlv)

set(HEADERS
)

set(SOURCES
    src/architecture_test.cpp
    src/emv_test.cpp
    src/emv_schema_test.cpp
    src/dol_test.cpp
    src/tag_c_test.c
    src/codec_test.cpp
    src/copy_test.cpp
    src/endian_test.cpp
    src/endian_c_test.c
    src/length_test.cpp
    src/value_test.cpp
    src/dhcp_option_tests.cpp
    src/test_tlv.cpp
    src/reader_test.cpp
    src/scanner_test.cpp
    src/schema_test.cpp
    src/schema_report_test.cpp
    src/walker_test.cpp
    src/query_test.cpp
    src/document_test.cpp
    src/writer_test.cpp
    src/format_init_test.cpp
    src/format_test.cpp
    src/format_ber_test.cpp
    src/der_test.cpp
    src/der_values_test.cpp
    src/der_schema_test.cpp
    src/cer_test.cpp
    src/cer_values_test.cpp
    src/format_fixed_1byte_test.cpp
    src/format_bluetooth_ltv_test.cpp
    src/format_bluetooth_ltv_conformance_test.cpp
    src/tag_test.cpp
    src/view_test.cpp
    src/versiontest.cpp
)

# A split source exists only in the group containing relevant cases.
foreach(source IN LISTS SOURCES)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${source}")
        list(REMOVE_ITEM SOURCES "${source}")
    endif()
endforeach()

# Tests that name an optional component follow the same feature selection.
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_FIXED_1BYTE))
        list(REMOVE_ITEM SOURCES src/codec_test.cpp)
    endif()
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_FIXED_1BYTE AND OPENTLV_FORMAT_BER))
        list(REMOVE_ITEM SOURCES src/copy_test.cpp)
    endif()
endif()
if(NOT OPENTLV_FORMAT_DER)
    list(REMOVE_ITEM SOURCES src/der_test.cpp src/der_values_test.cpp src/der_schema_test.cpp)
endif()
if(NOT OPENTLV_FORMAT_CER)
    list(REMOVE_ITEM SOURCES src/cer_test.cpp src/cer_values_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_DEFAULT))
    list(REMOVE_ITEM SOURCES src/dhcp_option_tests.cpp)
endif()
if(NOT (OPENTLV_FORMAT_BER AND OPENTLV_PROFILE_EMV))
    list(REMOVE_ITEM SOURCES src/emv_test.cpp src/emv_schema_test.cpp src/dol_test.cpp src/tag_c_test.c)
endif()
if(NOT (OPENTLV_FORMAT_BER))
    list(REMOVE_ITEM SOURCES src/format_ber_test.cpp src/schema_report_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_FIXED_1BYTE))
    list(REMOVE_ITEM SOURCES src/format_fixed_1byte_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_BLUETOOTH_LTV))
    list(REMOVE_ITEM SOURCES src/format_bluetooth_ltv_test.cpp
                                 src/format_bluetooth_ltv_conformance_test.cpp)
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_DEFAULT AND OPENTLV_FORMAT_FIXED_1BYTE))
        list(REMOVE_ITEM SOURCES src/reader_test.cpp)
    endif()
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_DEFAULT AND OPENTLV_FORMAT_FIXED_1BYTE))
        list(REMOVE_ITEM SOURCES src/scanner_test.cpp)
    endif()
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_FIXED_1BYTE))
        list(REMOVE_ITEM SOURCES src/schema_test.cpp)
    endif()
endif()
if(NOT (OPENTLV_FORMAT_DEFAULT))
    list(REMOVE_ITEM SOURCES src/test_tlv.cpp)
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_DEFAULT AND OPENTLV_FORMAT_FIXED_1BYTE))
        list(REMOVE_ITEM SOURCES src/walker_test.cpp)
    endif()
endif()
if(test_group STREQUAL "integration")
    if(NOT (OPENTLV_FORMAT_DEFAULT AND OPENTLV_FORMAT_FIXED_1BYTE))
        list(REMOVE_ITEM SOURCES src/writer_test.cpp)
    endif()
endif()

if(NOT OPENTLV_DOCUMENT)
    list(REMOVE_ITEM SOURCES src/document_test.cpp)
endif()

add_executable(${test_target}
    ${HEADERS}
    ${SOURCES}
)

target_include_directories(${test_target}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${test_target} PRIVATE
    tlv
    GTest::gtest_main
)

include(GoogleTest)
opentlv_configure_compiler(${test_target})
opentlv_copy_shared_runtime(${test_target})
gtest_discover_tests(${test_target} PROPERTIES LABELS ${test_group})
