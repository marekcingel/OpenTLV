find_package(Doxygen 1.9.1 REQUIRED COMPONENTS doxygen)

# Base URL of the published documentation site, used by the @docs alias to
# link generated API pages back to the guides and concepts.
set(OPENTLV_DOCS_URL "https://marekcingel.github.io/OpenTLV/")

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

configure_file(
    "${PROJECT_SOURCE_DIR}/tools/docs/Doxyfile.common.in"
    "${PROJECT_BINARY_DIR}/Doxyfile.common" @ONLY
)
configure_file(
    "${PROJECT_SOURCE_DIR}/tools/docs/Doxyfile.cxx.in"
    "${PROJECT_BINARY_DIR}/Doxyfile.cxx" @ONLY
)

add_custom_target(cxx-api-docs
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${PROJECT_BINARY_DIR}/docs/cxx-api"
    COMMAND Doxygen::doxygen "${PROJECT_BINARY_DIR}/Doxyfile.cxx"
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    COMMENT "Generating the OpenTLV C++ API reference"
    VERBATIM
)
# Resolve C references without adding C declarations to C++ navigation.
add_dependencies(cxx-api-docs c-api-docs)
