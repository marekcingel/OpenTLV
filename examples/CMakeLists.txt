cmake_minimum_required(VERSION 3.16)

project(examples LANGUAGES C)

# examples/tlv also hosts the EMV builtin example (src/builtins/emv), which
# only needs OPENTLV_PROFILE_EMV; the other flags gate the rest of the folder.
add_subdirectory(tlv)

if(OPENTLV_BUILD_CXX)
    add_subdirectory(tlv++)
endif()
