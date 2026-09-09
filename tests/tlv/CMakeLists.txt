cmake_minimum_required(VERSION 3.16)

project(test-tlv LANGUAGES CXX)

set(HEADERS
)

set(SOURCES
    src/architecture_test.cpp
    src/emv_test.cpp
    src/codec_test.cpp
    src/copy_test.cpp
    src/endian_test.cpp
    src/dhcp_option_tests.cpp
    src/test_tlv.cpp
    src/reader_test.cpp
    src/scanner_test.cpp
    src/schema_test.cpp
    src/walker_test.cpp
    src/writer_test.cpp
    src/format_init_test.cpp
    src/format_test.cpp
    src/format_ber_test.cpp
    src/der_test.cpp
    src/format_fixed_1byte_test.cpp
    src/types_test.cpp
    src/versiontest.cpp
)

# Tests that name an optional component follow the same feature selection.
if(NOT (OPENTLV_FORMAT_FIXED_1BYTE))
    list(REMOVE_ITEM SOURCES src/codec_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_FIXED_1BYTE AND OPENTLV_FORMAT_BER))
    list(REMOVE_ITEM SOURCES src/copy_test.cpp)
endif()
if(NOT OPENTLV_FORMAT_DER)
    list(REMOVE_ITEM SOURCES src/der_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_DEFAULT))
    list(REMOVE_ITEM SOURCES src/dhcp_option_tests.cpp)
endif()
if(NOT (OPENTLV_FORMAT_BER AND OPENTLV_PROFILE_EMV))
    list(REMOVE_ITEM SOURCES src/emv_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_BER))
    list(REMOVE_ITEM SOURCES src/format_ber_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_FIXED_1BYTE))
    list(REMOVE_ITEM SOURCES src/format_fixed_1byte_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_DEFAULT AND OPENTLV_FORMAT_FIXED_1BYTE))
    list(REMOVE_ITEM SOURCES src/reader_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_DEFAULT AND OPENTLV_FORMAT_FIXED_1BYTE))
    list(REMOVE_ITEM SOURCES src/scanner_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_FIXED_1BYTE))
    list(REMOVE_ITEM SOURCES src/schema_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_DEFAULT))
    list(REMOVE_ITEM SOURCES src/test_tlv.cpp)
endif()
if(NOT (OPENTLV_FORMAT_DEFAULT AND OPENTLV_FORMAT_FIXED_1BYTE))
    list(REMOVE_ITEM SOURCES src/walker_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_DEFAULT AND OPENTLV_FORMAT_FIXED_1BYTE))
    list(REMOVE_ITEM SOURCES src/writer_test.cpp)
endif()

add_executable(${PROJECT_NAME}
    ${HEADERS}
    ${SOURCES}
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    tlv
    GTest::gtest_main
)

include(GoogleTest)
opentlv_configure_compiler(${PROJECT_NAME})
gtest_discover_tests(${PROJECT_NAME})

# Compile alternate capacities separately to keep type layouts consistent.
if(OPENTLV_PROFILE_EMV AND OPENTLV_FORMAT_BER)
    foreach(tag_capacity IN ITEMS 1 2 3)
        set(emv_target test-tlv-emv-${tag_capacity})
        add_executable(${emv_target}
            src/emv_test.cpp
            ${OpenTLV_SOURCE_DIR}/tlv/src/profiles/emv.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/codec/emv.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/codec/codec.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/schemas/schema.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/ber.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/ber_internal.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/reader/reader.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/writer/writer.c
        )
        target_include_directories(${emv_target} PRIVATE ${OpenTLV_SOURCE_DIR}/tlv/include)
        target_link_libraries(${emv_target} PRIVATE GTest::gtest_main)
        target_compile_features(${emv_target} PRIVATE c_std_99)
        target_compile_definitions(${emv_target} PRIVATE TLV_TAG_MAX_SIZE=${tag_capacity})
        opentlv_configure_compiler(${emv_target})
        gtest_discover_tests(${emv_target} TEST_PREFIX "TagCapacity${tag_capacity}.")
    endforeach()

endif()

# DER must preserve the configurable raw-tag capacity, including large tags.
if(OPENTLV_FORMAT_DER)
    foreach(tag_capacity IN ITEMS 1 16 255)
        set(der_target test-tlv-der-${tag_capacity})
        add_executable(${der_target}
            src/der_test.cpp
            ${OpenTLV_SOURCE_DIR}/tlv/src/profiles/der.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/der.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/ber_internal.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/reader/reader.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/writer/writer.c
        )
        target_include_directories(${der_target} PRIVATE ${OpenTLV_SOURCE_DIR}/tlv/include
            ${OpenTLV_BINARY_DIR}/generated/include)
        if(OPENTLV_FORMAT_BER)
            target_sources(${der_target} PRIVATE ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/ber.c)
        endif()
        target_link_libraries(${der_target} PRIVATE GTest::gtest_main)
        target_compile_features(${der_target} PRIVATE c_std_99)
        target_compile_definitions(${der_target} PRIVATE TLV_TAG_MAX_SIZE=${tag_capacity})
        opentlv_configure_compiler(${der_target})
        gtest_discover_tests(${der_target} TEST_PREFIX "TagCapacity${tag_capacity}.")
    endforeach()

endif()

foreach(tag_capacity IN ITEMS 1 16 255)
    set(types_target test-tlv-types-${tag_capacity})
    add_executable(${types_target} src/types_test.cpp)
    target_include_directories(${types_target} PRIVATE ${OpenTLV_SOURCE_DIR}/tlv/include)
    target_link_libraries(${types_target} PRIVATE GTest::gtest_main)
    target_compile_definitions(${types_target} PRIVATE TLV_TAG_MAX_SIZE=${tag_capacity})
    opentlv_configure_compiler(${types_target})
    gtest_discover_tests(${types_target} TEST_PREFIX "TagCapacity${tag_capacity}.")
endforeach()

# Build the BER implementation and generic I/O with matching alternate layouts.
if(OPENTLV_FORMAT_BER)
    foreach(tag_capacity IN ITEMS 1 16 255)
        set(ber_target test-tlv-ber-${tag_capacity})
        add_executable(${ber_target}
            src/format_ber_test.cpp
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/ber.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/ber_internal.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/reader/reader.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/writer/writer.c
        )
        target_include_directories(${ber_target} PRIVATE ${OpenTLV_SOURCE_DIR}/tlv/include)
        target_link_libraries(${ber_target} PRIVATE GTest::gtest_main)
        target_compile_features(${ber_target} PRIVATE c_std_99)
        target_compile_definitions(${ber_target} PRIVATE TLV_TAG_MAX_SIZE=${tag_capacity})
        opentlv_configure_compiler(${ber_target})
        gtest_discover_tests(${ber_target} TEST_PREFIX "TagCapacity${tag_capacity}.")
    endforeach()

endif()
