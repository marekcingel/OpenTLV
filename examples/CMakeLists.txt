cmake_minimum_required(VERSION 3.16)

project(examples LANGUAGES C)

if(OPENTLV_FORMAT_DEFAULT AND OPENTLV_FORMAT_FIXED_1BYTE AND OPENTLV_FORMAT_BER)
    add_subdirectory(tlv)
endif()

if(OPENTLV_BUILD_CXX AND OPENTLV_FORMAT_DEFAULT)
    add_subdirectory(tlv++)
endif()
