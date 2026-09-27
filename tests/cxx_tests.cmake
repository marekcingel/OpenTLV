cmake_minimum_required(VERSION 3.16)

set(test_target test-${test_group}-tlvpp)

set(HEADERS
)

set(SOURCES
    test_tlvpp.cpp
)

if(test_group STREQUAL "unit")
    list(APPEND SOURCES test_diagnostic.cpp)
    # tlv::fixed_format<> now delegates to tlv_fixed_format_init(), so its
    # tests need the C fixed format compiled into tlv.
    if(OPENTLV_FORMAT_FIXED)
        list(APPEND SOURCES formats/test_fixed_format.cpp)
    endif()
    if(OPENTLV_DOCUMENT)
        list(APPEND SOURCES document/test_document.cpp)
    endif()
endif()

if(test_group STREQUAL "integration")
    list(APPEND SOURCES layers_test.cpp)
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
