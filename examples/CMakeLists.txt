cmake_minimum_required(VERSION 3.16)

project(examples LANGUAGES C)

# examples/tlv also hosts the EMV builtin example (src/builtins/emv), which
# only needs OPENTLV_PROFILE_EMV; the other flags gate the rest of the folder.
if(OPENTLV_FORMAT_FIXED OR (OPENTLV_FORMAT_DEFAULT AND OPENTLV_FORMAT_BER) OR OPENTLV_PROFILE_EMV)
    add_subdirectory(tlv)
endif()

if(OPENTLV_BUILD_CXX AND OPENTLV_FORMAT_DEFAULT)
    add_subdirectory(tlv++)
endif()
