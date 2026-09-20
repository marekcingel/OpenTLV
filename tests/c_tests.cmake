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
    src/walker_test.cpp
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
    list(REMOVE_ITEM SOURCES src/format_ber_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_FIXED_1BYTE))
    list(REMOVE_ITEM SOURCES src/format_fixed_1byte_test.cpp)
endif()
if(NOT (OPENTLV_FORMAT_BLUETOOTH_LTV))
    list(REMOVE_ITEM SOURCES src/format_bluetooth_ltv_test.cpp)
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

# Compile alternate capacities separately to keep type layouts consistent.
if(OPENTLV_PROFILE_EMV AND OPENTLV_FORMAT_BER)
    foreach(tag_capacity IN ITEMS 1 2 3)
        set(emv_target test-${test_group}-tlv-emv-${tag_capacity})
        add_executable(${emv_target}
            src/emv_test.cpp
            ${OpenTLV_SOURCE_DIR}/tlv/src/tag.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/profiles/emv.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/codec/emv.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/codec/codec.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/schemas/schema.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/ber.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/endian.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/length.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/ber_internal.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/reader/reader.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/writer/writer.c
        )
        if(test_group STREQUAL "unit")
            target_sources(${emv_target} PRIVATE src/tag_c_test.c)
        endif()
        target_include_directories(${emv_target} PRIVATE ${OpenTLV_SOURCE_DIR}/tlv/include
            ${OpenTLV_BINARY_DIR}/generated/include)
        target_link_libraries(${emv_target} PRIVATE GTest::gtest_main)
        target_compile_features(${emv_target} PRIVATE c_std_99)
        # Compiles library sources directly rather than linking the tlv target;
        # TLV_STATIC_DEFINE keeps TLV_API a no-op regardless of OPENTLV_BUILD_SHARED_LIBS.
        target_compile_definitions(${emv_target} PRIVATE TLV_TAG_CAPACITY=${tag_capacity} TLV_STATIC_DEFINE)
        opentlv_configure_compiler(${emv_target})
        gtest_discover_tests(${emv_target} TEST_PREFIX "TagCapacity${tag_capacity}." PROPERTIES LABELS ${test_group})
    endforeach()

endif()

# DER must preserve the configurable raw-tag capacity, including large tags.
if(OPENTLV_FORMAT_DER)
    foreach(tag_capacity IN ITEMS 1 16 255)
        set(der_target test-${test_group}-tlv-der-${tag_capacity})
        set(der_target_sources
            src/der_test.cpp
            src/der_schema_test.cpp
            ${OpenTLV_SOURCE_DIR}/tlv/src/profiles/der.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/profiles/der_values.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/profiles/der_schema.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/profiles/asn1_values_internal.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/der.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/asn1_internal.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/endian.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/length.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/ber_internal.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/reader/reader.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/writer/writer.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/tag.c
        )
        # der_values_test.cpp only exists in the unit test sources.
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/der_values_test.cpp")
            list(APPEND der_target_sources src/der_values_test.cpp)
        endif()
        add_executable(${der_target} ${der_target_sources})
        target_include_directories(${der_target} PRIVATE ${OpenTLV_SOURCE_DIR}/tlv/include
            ${OpenTLV_BINARY_DIR}/generated/include)
        if(OPENTLV_FORMAT_BER)
            target_sources(${der_target} PRIVATE ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/ber.c)
        endif()
        target_link_libraries(${der_target} PRIVATE GTest::gtest_main)
        target_compile_features(${der_target} PRIVATE c_std_99)
        # Compiles library sources directly rather than linking the tlv target;
        # TLV_STATIC_DEFINE keeps TLV_API a no-op regardless of OPENTLV_BUILD_SHARED_LIBS.
        target_compile_definitions(${der_target} PRIVATE TLV_TAG_CAPACITY=${tag_capacity} TLV_STATIC_DEFINE)
        opentlv_configure_compiler(${der_target})
        gtest_discover_tests(${der_target} TEST_PREFIX "TagCapacity${tag_capacity}." PROPERTIES LABELS ${test_group})
    endforeach()

endif()

# CER must preserve the configurable raw-tag capacity, and must build and
# pass its tests with DER disabled: this block never lists a DER source.
if(OPENTLV_FORMAT_CER)
    foreach(tag_capacity IN ITEMS 1 16 255)
        set(cer_target test-${test_group}-tlv-cer-${tag_capacity})
        set(cer_target_sources
            src/cer_test.cpp
            ${OpenTLV_SOURCE_DIR}/tlv/src/profiles/cer.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/profiles/cer_values_internal.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/profiles/asn1_values_internal.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/cer.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/asn1_internal.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/endian.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/length.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/ber_internal.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/reader/reader.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/reader/walker.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/writer/writer.c
        )
        # cer_values_test.cpp only exists in the unit test sources.
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/cer_values_test.cpp")
            list(APPEND cer_target_sources src/cer_values_test.cpp)
        endif()
        add_executable(${cer_target} ${cer_target_sources})
        target_include_directories(${cer_target} PRIVATE ${OpenTLV_SOURCE_DIR}/tlv/include
            ${OpenTLV_BINARY_DIR}/generated/include)
        if(OPENTLV_FORMAT_BER)
            target_sources(${cer_target} PRIVATE ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/ber.c)
        endif()
        target_link_libraries(${cer_target} PRIVATE GTest::gtest_main)
        target_compile_features(${cer_target} PRIVATE c_std_99)
        # Compiles library sources directly rather than linking the tlv target;
        # TLV_STATIC_DEFINE keeps TLV_API a no-op regardless of OPENTLV_BUILD_SHARED_LIBS.
        target_compile_definitions(${cer_target} PRIVATE TLV_TAG_CAPACITY=${tag_capacity} TLV_STATIC_DEFINE)
        opentlv_configure_compiler(${cer_target})
        gtest_discover_tests(${cer_target} TEST_PREFIX "TagCapacity${tag_capacity}." PROPERTIES LABELS ${test_group})
    endforeach()

endif()

if(test_group STREQUAL "unit")
foreach(tag_capacity IN ITEMS 1 16 255)
    set(view_target test-${test_group}-tlv-view-${tag_capacity})
    add_executable(${view_target} src/view_test.cpp src/tag_test.cpp
        ${OpenTLV_SOURCE_DIR}/tlv/src/endian.c
        ${OpenTLV_SOURCE_DIR}/tlv/src/tag.c)
    target_include_directories(${view_target} PRIVATE ${OpenTLV_SOURCE_DIR}/tlv/include
        ${OpenTLV_BINARY_DIR}/generated/include)
    target_link_libraries(${view_target} PRIVATE GTest::gtest_main)
    # Compiles library sources directly rather than linking the tlv target;
    # TLV_STATIC_DEFINE keeps TLV_API a no-op regardless of OPENTLV_BUILD_SHARED_LIBS.
    target_compile_definitions(${view_target} PRIVATE TLV_TAG_CAPACITY=${tag_capacity} TLV_STATIC_DEFINE)
    opentlv_configure_compiler(${view_target})
    gtest_discover_tests(${view_target} TEST_PREFIX "TagCapacity${tag_capacity}." PROPERTIES LABELS ${test_group})
endforeach()

endif()

# Build the BER implementation and generic I/O with matching alternate layouts.
if(OPENTLV_FORMAT_BER)
    foreach(tag_capacity IN ITEMS 1 16 255)
        set(ber_target test-${test_group}-tlv-ber-${tag_capacity})
        add_executable(${ber_target}
            src/format_ber_test.cpp
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/ber.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/endian.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/length.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/formats/asn1/ber_internal.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/reader/reader.c
            ${OpenTLV_SOURCE_DIR}/tlv/src/writer/writer.c
        )
        target_include_directories(${ber_target} PRIVATE ${OpenTLV_SOURCE_DIR}/tlv/include
            ${OpenTLV_BINARY_DIR}/generated/include)
        target_link_libraries(${ber_target} PRIVATE GTest::gtest_main)
        target_compile_features(${ber_target} PRIVATE c_std_99)
        # Compiles library sources directly rather than linking the tlv target;
        # TLV_STATIC_DEFINE keeps TLV_API a no-op regardless of OPENTLV_BUILD_SHARED_LIBS.
        target_compile_definitions(${ber_target} PRIVATE TLV_TAG_CAPACITY=${tag_capacity} TLV_STATIC_DEFINE)
        opentlv_configure_compiler(${ber_target})
        gtest_discover_tests(${ber_target} TEST_PREFIX "TagCapacity${tag_capacity}." PROPERTIES LABELS ${test_group})
    endforeach()

endif()
