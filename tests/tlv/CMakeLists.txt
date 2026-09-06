cmake_minimum_required(VERSION 3.16)

project(test-tlv LANGUAGES CXX)

set(HEADERS
)

set(SOURCES
    src/dhcp_option_tests.cpp
    src/test_tlv.cpp
    src/types_test.cpp
    src/versiontest.cpp
)

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
gtest_discover_tests(${PROJECT_NAME})

# Compile alternate capacities separately to keep type layouts consistent.
foreach(tag_capacity IN ITEMS 1 16 255)
    set(types_target test-tlv-types-${tag_capacity})
    add_executable(${types_target} src/types_test.cpp)
    target_include_directories(${types_target} PRIVATE ${OpenTLV_SOURCE_DIR}/tlv/include)
    target_link_libraries(${types_target} PRIVATE GTest::gtest_main)
    target_compile_definitions(${types_target} PRIVATE TLV_TAG_MAX_SIZE=${tag_capacity})
    gtest_discover_tests(${types_target} TEST_PREFIX "TagCapacity${tag_capacity}.")
endforeach()
