# Adds convenience targets for applying and checking the project's
# .clang-format style across tlv (C) and tlv++ (C++), plus tools, tests,
# benchmarks and examples. Both targets are opt-in (never part of ALL) and are
# skipped with a warning if no clang-format is found, so their absence never
# breaks a regular build.
set(_OPENTLV_CLANG_FORMAT_MODULE_DIR "${CMAKE_CURRENT_LIST_DIR}")

function(opentlv_add_clang_format_targets)
    find_program(OPENTLV_CLANG_FORMAT_EXECUTABLE clang-format)
    if(NOT OPENTLV_CLANG_FORMAT_EXECUTABLE)
        message(WARNING
            "clang-format was not found; skipping the 'format' and "
            "'format-check' targets. Install clang-format to use them.")
        return()
    endif()

    file(GLOB_RECURSE _opentlv_format_sources
        LIST_DIRECTORIES false
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../tlv/*.c"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../tlv/*.h"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../tlv++/*.hpp"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../tools/*.c"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../tools/*.h"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../tools/*.cpp"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../tools/*.hpp"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../tests/*.c"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../tests/*.h"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../tests/*.cpp"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../tests/*.hpp"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../benchmarks/*.cpp"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../benchmarks/*.hpp"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../examples/*.c"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../examples/*.h"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../examples/*.cpp"
        "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/../examples/*.hpp"
    )

    add_custom_target(format
        COMMAND ${OPENTLV_CLANG_FORMAT_EXECUTABLE} -i ${_opentlv_format_sources}
        WORKING_DIRECTORY "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/.."
        COMMENT "Formatting tlv and tlv++ sources with clang-format"
        VERBATIM
    )
    add_custom_target(format-check
        COMMAND ${OPENTLV_CLANG_FORMAT_EXECUTABLE} --dry-run --Werror ${_opentlv_format_sources}
        WORKING_DIRECTORY "${_OPENTLV_CLANG_FORMAT_MODULE_DIR}/.."
        COMMENT "Checking tlv and tlv++ formatting with clang-format"
        VERBATIM
    )
endfunction()
