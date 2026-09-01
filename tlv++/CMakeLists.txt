add_library(tlv++ INTERFACE)

target_include_directories(tlv++ INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(tlv++ INTERFACE tlv)
target_compile_features(tlv++ INTERFACE cxx_std_23)

if (OPENTLV_BUILD_TESTS)
    add_executable(tlvpp_tests ${CMAKE_SOURCE_DIR}/tests/tlv++/test_tlvpp.cpp)
    target_link_libraries(tlvpp_tests PRIVATE tlv++)
    add_test(NAME tlvpp_tests COMMAND tlvpp_tests)
endif()
