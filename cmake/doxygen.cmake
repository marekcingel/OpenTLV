find_package(Doxygen 1.9.1 REQUIRED COMPONENTS doxygen)

# Doxygen reads macro definitions from includes, but does not document the
# declarations produced by the twice-included EMV X-macro dictionary. Inline
# that dictionary in a documentation-only copy so both public constant forms
# are parsed using their actual definitions, without maintaining a second list.
set(_emv_header "${PROJECT_SOURCE_DIR}/tlv/include/tlv/profiles/emv.h")
set(_emv_dictionary "${PROJECT_SOURCE_DIR}/tlv/include/tlv/profiles/emv_tags.def")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${_emv_header}" "${_emv_dictionary}")
file(READ "${_emv_header}" _emv_contents)
file(READ "${_emv_dictionary}" _emv_entries)
string(REPLACE "#include \"tlv/profiles/emv_tags.def\"" "${_emv_entries}"
    _emv_contents "${_emv_contents}")
file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/docs-input/tlv/profiles")
file(WRITE "${PROJECT_BINARY_DIR}/docs-input/tlv/profiles/emv.h" "${_emv_contents}")

configure_file(
    "${PROJECT_SOURCE_DIR}/tools/docs/Doxyfile.in"
    "${PROJECT_BINARY_DIR}/Doxyfile"
    @ONLY
)

add_custom_target(c-api-docs
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${PROJECT_BINARY_DIR}/docs/c-api"
    COMMAND Doxygen::doxygen "${PROJECT_BINARY_DIR}/Doxyfile"
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    COMMENT "Generating the OpenTLV C API reference"
    VERBATIM
)
