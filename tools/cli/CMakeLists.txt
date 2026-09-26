set(HEADERS
    src/command.hpp
    src/command_factory.hpp
    src/console_color.hpp
    src/decode.hpp
    src/diagnostic_collect.hpp
    src/diagnostic_render.hpp
    src/diagnostics.hpp
    src/input.hpp
    src/json_model.hpp
    src/options.hpp
    src/presentation.hpp
    src/commands/support.hpp
    src/commands/emv_dictionary.hpp
    src/commands/help_command.hpp
    src/commands/version_command.hpp
    src/commands/formats_command.hpp
    src/commands/walk_command.hpp
    src/commands/dump_command.hpp
    src/commands/validate_command.hpp
    src/commands/decode_command.hpp
    src/commands/query_command.hpp
    src/commands/encode_command.hpp
    src/commands/tag_command.hpp
    src/commands/tags_command.hpp
    src/completion/support.hpp
    src/completion/completion_option.hpp
    src/completion/completion_command_spec.hpp
    src/completion/completion_model.hpp
    src/completion/shell_completer.hpp
    src/completion/bash_completer.hpp
    src/completion/zsh_completer.hpp
    src/completion/fish_completer.hpp
    src/completion/powershell_completer.hpp
    src/completion/completion_command.hpp
)

set(SOURCES
    src/command_factory.cpp
    src/diagnostic_collect.cpp
    src/diagnostic_render.cpp
    src/decode.cpp
    src/input.cpp
    src/json_model.cpp
    src/main.cpp
    src/options.cpp
    src/presentation.cpp
    src/commands/support.cpp
    src/commands/emv_dictionary.cpp
    src/commands/help_command.cpp
    src/commands/version_command.cpp
    src/commands/formats_command.cpp
    src/commands/walk_command.cpp
    src/commands/dump_command.cpp
    src/commands/validate_command.cpp
    src/commands/decode_command.cpp
    src/commands/query_command.cpp
    src/commands/encode_command.cpp
    src/commands/tag_command.cpp
    src/commands/tags_command.cpp
    src/completion/support.cpp
    src/completion/completion_option.cpp
    src/completion/completion_command_spec.cpp
    src/completion/completion_model.cpp
    src/completion/bash_completer.cpp
    src/completion/zsh_completer.cpp
    src/completion/fish_completer.cpp
    src/completion/powershell_completer.cpp
    src/completion/completion_command.cpp
)

add_executable(otlv
    ${HEADERS}
    ${SOURCES}
)

target_include_directories(otlv
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Header-only, fetched only for the CLI: --output json, decode and encode --input
# (tools/cli/src) are the only nlohmann/json consumers. tlv and tlv++ remain dependency-free.
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
        "-DHAS_FIXED=${OPENTLV_FORMAT_FIXED}"
        "-DHAS_BLUETOOTH_LTV=${OPENTLV_FORMAT_BLUETOOTH_LTV}"
        "-DHAS_BER=${OPENTLV_FORMAT_BER}"
        "-DHAS_DER=${OPENTLV_FORMAT_DER}"
        "-DHAS_EMV=${OPENTLV_PROFILE_EMV}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/test.cmake")
    set_tests_properties(Integration_cli PROPERTIES LABELS "integration;cli")
endif()
