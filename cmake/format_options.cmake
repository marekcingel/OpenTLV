# Centralizes the parent/child relationships between the
# OPENTLV_FORMAT_*/OPENTLV_PROFILE_* options declared in the root
# CMakeLists.txt, and generates tlv/config.h and tlv/config.c from
# tlv/resources/config.h.in / config.c.in (mirrors the version file setup in
# cmake/version.cmake).
#
# Format/profile tree (disabling a node forces every node below it OFF,
# regardless of how that node's own option was set):
#
#   OPENTLV_FORMAT_ASN1
#     `- OPENTLV_FORMAT_BER
#          |- OPENTLV_FORMAT_DER
#          |    `- OPENTLV_PROFILE_EMV
#          `- OPENTLV_FORMAT_CER
#
# OPENTLV_FORMAT_DER and OPENTLV_FORMAT_CER are independent siblings under
# OPENTLV_FORMAT_BER: CER never depends on DER (or vice versa), and
# OPENTLV_PROFILE_EMV cascades only from OPENTLV_FORMAT_DER, so it is
# unaffected by OPENTLV_FORMAT_CER either way.
#
# OPENTLV_FORMAT_DEFAULT, OPENTLV_FORMAT_FIXED_1BYTE and
# OPENTLV_FORMAT_BLUETOOTH_LTV are unrelated leaves
# and cascade to nothing.
set(_OPENTLV_FORMAT_OPTIONS_MODULE_DIR "${CMAKE_CURRENT_LIST_DIR}")

if(NOT OPENTLV_FORMAT_ASN1)
    set(OPENTLV_FORMAT_BER OFF CACHE BOOL "Include the BER wire format" FORCE)
    message(STATUS "OPENTLV_FORMAT_ASN1 is OFF: forcing OPENTLV_FORMAT_BER OFF")
endif()
if(NOT OPENTLV_FORMAT_BER)
    set(OPENTLV_FORMAT_DER OFF CACHE BOOL
        "Include the DER wire format and validation profile" FORCE)
    message(STATUS "OPENTLV_FORMAT_BER is OFF: forcing OPENTLV_FORMAT_DER OFF")
    set(OPENTLV_FORMAT_CER OFF CACHE BOOL
        "Include the CER wire format and validation profile" FORCE)
    message(STATUS "OPENTLV_FORMAT_BER is OFF: forcing OPENTLV_FORMAT_CER OFF")
endif()
if(NOT OPENTLV_FORMAT_DER)
    set(OPENTLV_PROFILE_EMV OFF CACHE BOOL
        "Include the EMV dictionary, schemas and codecs" FORCE)
    message(STATUS "OPENTLV_FORMAT_DER is OFF: forcing OPENTLV_PROFILE_EMV OFF")
endif()

function(opentlv_generate_config_files)
    configure_file(
        "${_OPENTLV_FORMAT_OPTIONS_MODULE_DIR}/../tlv/resources/config.h.in"
        "${PROJECT_BINARY_DIR}/generated/include/tlv/config.h"
    )
    configure_file(
        "${_OPENTLV_FORMAT_OPTIONS_MODULE_DIR}/../tlv/resources/config.c.in"
        "${PROJECT_BINARY_DIR}/generated/src/config.c"
    )
endfunction()
