include(${OpenTLV_SOURCE_DIR}/tests/c_tests.cmake)
if(OPENTLV_BUILD_CXX AND OPENTLV_FORMAT_BER)
    include(${OpenTLV_SOURCE_DIR}/tests/cxx_tests.cmake)
endif()
