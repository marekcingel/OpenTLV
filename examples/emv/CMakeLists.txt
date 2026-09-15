cmake_minimum_required(VERSION 3.16)

project(example-emv LANGUAGES C)

set(SOURCES
    src/tag_decoding.c
)

add_executable(${PROJECT_NAME}
    ${SOURCES}
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    tlv
)
opentlv_configure_compiler(${PROJECT_NAME})
opentlv_copy_shared_runtime(${PROJECT_NAME})

add_test(NAME Integration_example_emv COMMAND $<TARGET_FILE:${PROJECT_NAME}>)
set_tests_properties(Integration_example_emv PROPERTIES LABELS "integration;examples")
