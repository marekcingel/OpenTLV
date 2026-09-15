set(HEADERS
    src/diagnostics.hpp
    src/options.hpp
    src/presentation.hpp
)

set(SOURCES
    src/main.cpp
    src/options.cpp
    src/presentation.cpp
)

add_executable(opentlv
    ${HEADERS}
    ${SOURCES}
)

target_include_directories(opentlv
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(opentlv PRIVATE tlv++)
target_compile_features(opentlv PRIVATE cxx_std_11)
opentlv_configure_compiler(opentlv)
opentlv_copy_shared_runtime(opentlv)
if(UNIX)
    if(APPLE)
        set(_cli_origin "@loader_path")
    else()
        set(_cli_origin "$ORIGIN")
    endif()
    file(RELATIVE_PATH _cli_lib_relative "${CMAKE_INSTALL_FULL_BINDIR}" "${CMAKE_INSTALL_FULL_LIBDIR}")
    set_target_properties(opentlv PROPERTIES INSTALL_RPATH "${_cli_origin}/${_cli_lib_relative}")
endif()
install(TARGETS opentlv RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(OPENTLV_BUILD_CLI_TESTS)
    add_test(NAME Integration_cli COMMAND ${CMAKE_COMMAND}
        "-DCLI=$<TARGET_FILE:opentlv>"
        "-DHAS_DEFAULT=${OPENTLV_FORMAT_DEFAULT}"
        "-DHAS_FIXED=${OPENTLV_FORMAT_FIXED_1BYTE}"
        "-DHAS_BER=${OPENTLV_FORMAT_BER}"
        "-DHAS_DER=${OPENTLV_FORMAT_DER}"
        "-DHAS_EMV=${OPENTLV_PROFILE_EMV}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/test.cmake")
    set_tests_properties(Integration_cli PROPERTIES LABELS "integration;cli")
endif()
