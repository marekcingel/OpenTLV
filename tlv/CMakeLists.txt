add_library(tlv
    src/reader.c
    src/writer.c
    src/error.c
)

target_include_directories(tlv PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(tlv PUBLIC c_std_99)

if (OPENTLV_BUILD_TESTS)
    add_executable(tlv_tests ${CMAKE_SOURCE_DIR}/tests/tlv/test_tlv.c)
    target_link_libraries(tlv_tests PRIVATE tlv)
    add_test(NAME tlv_tests COMMAND tlv_tests)
endif()
