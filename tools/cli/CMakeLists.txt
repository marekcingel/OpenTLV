set(HEADERS
    src/commands.hpp
    src/console_color.hpp
    src/decode.hpp
    src/diagnostics.hpp
    src/encode.hpp
    src/input.hpp
    src/options.hpp
    src/presentation.hpp
    src/tag.hpp
)

set(SOURCES
    src/commands.cpp
    src/decode.cpp
    src/encode.cpp
    src/input.cpp
    src/main.cpp
    src/options.cpp
    src/presentation.cpp
    src/tag.cpp
)

add_executable(otlv
    ${HEADERS}
    ${SOURCES}
)

target_include_directories(otlv
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Header-only, fetched only for the CLI: --output json (tools/cli/src/commands.cpp)
# is the sole nlohmann/json consumer. tlv and tlv++ remain dependency-free.
include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
set(JSON_BuildTests OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(nlohmann_json)

target_link_libraries(otlv PRIVATE tlv++ nlohmann_json::nlohmann_json)
target_compile_features(otlv PRIVATE cxx_std_11)
opentlv_configure_compiler(otlv)
opentlv_copy_shared_runtime(otlv)
if(UNIX)
    if(APPLE)
        set(_cli_origin "@loader_path")
    else()
        set(_cli_origin "$ORIGIN")
    endif()
    file(RELATIVE_PATH _cli_lib_relative "${CMAKE_INSTALL_FULL_BINDIR}" "${CMAKE_INSTALL_FULL_LIBDIR}")
    set_target_properties(otlv PROPERTIES INSTALL_RPATH "${_cli_origin}/${_cli_lib_relative}")
endif()
install(TARGETS otlv RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(OPENTLV_BUILD_CLI_TESTS)
    add_test(NAME Integration_cli COMMAND ${CMAKE_COMMAND}
        "-DCLI=$<TARGET_FILE:otlv>"
        "-DHAS_DEFAULT=${OPENTLV_FORMAT_DEFAULT}"
        "-DHAS_FIXED=${OPENTLV_FORMAT_FIXED_1BYTE}"
        "-DHAS_BER=${OPENTLV_FORMAT_BER}"
        "-DHAS_DER=${OPENTLV_FORMAT_DER}"
        "-DHAS_EMV=${OPENTLV_PROFILE_EMV}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/test.cmake")
    set_tests_properties(Integration_cli PROPERTIES LABELS "integration;cli")
endif()
