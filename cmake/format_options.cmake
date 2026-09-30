# Centralizes the parent/child relationships between the
# OPENTLV_FORMAT_* and OPENTLV_EMV options declared in the root
# CMakeLists.txt, and generates tlv/config.h and tlv/config.c from
# tlv/resources/config.h.in / config.c.in (mirrors the version file setup in
# cmake/version.cmake).
#
# Builtin dependency tree (disabling a node forces every node below it OFF,
# regardless of how that node's own option was set):
#
#   OPENTLV_FORMAT_ASN1
#     `- OPENTLV_FORMAT_BER
#          |- OPENTLV_FORMAT_DER
#          |- OPENTLV_EMV (legacy DOL identifier helper)
#          `- OPENTLV_FORMAT_CER
#
# OPENTLV_FORMAT_DER and OPENTLV_FORMAT_CER are independent siblings under
# OPENTLV_FORMAT_BER: CER never depends on DER (or vice versa), and
# OPENTLV_EMV retains a BER dependency for the unchanged DOL helper.
# EMV element framing itself uses only generic primitives and needs no DER/CER.
#
# OPENTLV_NFC independently controls the NFC Type 2 preset; generic escaped
# length fields and identifier-selected framing are always built.
#
# OPENTLV_BLUETOOTH controls the entire Bluetooth extension independently
# of the always-built Fixed format. Both formats reuse the generic
# binary layout primitives.
#
set(_OPENTLV_FORMAT_OPTIONS_MODULE_DIR "${CMAKE_CURRENT_LIST_DIR}")

if(NOT OPENTLV_FORMAT_ASN1)
    set(OPENTLV_FORMAT_BER OFF CACHE BOOL "Include the BER wire format" FORCE)
    message(STATUS "OPENTLV_FORMAT_ASN1 is OFF: forcing OPENTLV_FORMAT_BER OFF")
endif()
if(NOT OPENTLV_FORMAT_BER)
    set(OPENTLV_FORMAT_DER OFF CACHE BOOL
        "Include the DER wire format and validation" FORCE)
    message(STATUS "OPENTLV_FORMAT_BER is OFF: forcing OPENTLV_FORMAT_DER OFF")
    set(OPENTLV_FORMAT_CER OFF CACHE BOOL
        "Include the CER wire format and validation" FORCE)
    message(STATUS "OPENTLV_FORMAT_BER is OFF: forcing OPENTLV_FORMAT_CER OFF")
endif()
if(NOT OPENTLV_FORMAT_BER)
    set(OPENTLV_EMV OFF CACHE BOOL
        "Include EMV framing, dictionary, schemas and codecs" FORCE)
    message(STATUS "OPENTLV_FORMAT_BER is OFF: forcing OPENTLV_EMV OFF")
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
