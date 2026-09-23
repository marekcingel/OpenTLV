# Adds an opt-in 'clang-tidy' target that runs clang-tidy over tlv (C) and
# tlv++ (C++) using the build's compile_commands.json (CMAKE_EXPORT_COMPILE_
# COMMANDS must be ON). Not part of ALL, and skipped with a warning if
# clang-tidy isn't found (or compile command export isn't enabled), so its
# absence never breaks a regular build. Check selection lives in the
# per-directory .clang-tidy files (repo root, tlv/, tlv++/), not here.
#
# tlv++ is header-only, so unlike tlv's .c files there is no translation
# unit of its own for clang-tidy to attach to. A synthetic TU that merely
# #includes every header would compile, but its templates (codec, walker,
# schema, the compat.hpp polyfills, ...) would never be instantiated and so
# would never actually be analyzed. Instead this points clang-tidy at the
# tlv++ unit test TU (tests/unit/test_tlvpp.cpp), which already
# #includes tlv++/tlv.hpp (transitively pulling in every other tlv++
# header) and exercises it with real instantiations; --header-filter then
# restricts *reported* findings to tlv++/include, but the test file's own
# code is still analyzed as the main file (unavoidably - clang-tidy always
# reports main-file diagnostics), so it must stay clang-tidy-clean too.
set(_OPENTLV_CLANG_TIDY_MODULE_DIR "${CMAKE_CURRENT_LIST_DIR}")

function(opentlv_add_clang_tidy_targets)
    find_program(OPENTLV_CLANG_TIDY_EXECUTABLE NAMES clang-tidy-18 clang-tidy)
    if(NOT OPENTLV_CLANG_TIDY_EXECUTABLE)
        message(WARNING
            "clang-tidy was not found; skipping the 'clang-tidy' target. "
            "Install clang-tidy to use it.")
        return()
    endif()

    if(NOT CMAKE_EXPORT_COMPILE_COMMANDS)
        message(WARNING
            "CMAKE_EXPORT_COMPILE_COMMANDS is OFF; skipping the 'clang-tidy' "
            "target. Configure with -DCMAKE_EXPORT_COMPILE_COMMANDS=ON to use it.")
        return()
    endif()

    get_target_property(_opentlv_clang_tidy_tlv_sources tlv SOURCES)
    set(_opentlv_clang_tidy_c_sources)
    foreach(_opentlv_clang_tidy_source IN LISTS _opentlv_clang_tidy_tlv_sources)
        if(NOT _opentlv_clang_tidy_source MATCHES "\\.c$")
            continue()
        endif()
        if(NOT IS_ABSOLUTE "${_opentlv_clang_tidy_source}")
            set(_opentlv_clang_tidy_source "${OpenTLV_SOURCE_DIR}/tlv/${_opentlv_clang_tidy_source}")
        endif()
        list(APPEND _opentlv_clang_tidy_c_sources "${_opentlv_clang_tidy_source}")
    endforeach()

    add_custom_target(clang-tidy
        COMMAND ${OPENTLV_CLANG_TIDY_EXECUTABLE}
            -p "${CMAKE_BINARY_DIR}"
            "--header-filter=${_OPENTLV_CLANG_TIDY_MODULE_DIR}/../tlv/include/.*"
            ${_opentlv_clang_tidy_c_sources}
        COMMENT "Running clang-tidy static analysis on tlv"
        VERBATIM
    )

    if(OPENTLV_BUILD_CXX AND OPENTLV_BUILD_TESTS AND OPENTLV_BUILD_UNIT_TESTS)
        add_custom_command(TARGET clang-tidy POST_BUILD
            COMMAND ${OPENTLV_CLANG_TIDY_EXECUTABLE}
                -p "${CMAKE_BINARY_DIR}"
                "--header-filter=${_OPENTLV_CLANG_TIDY_MODULE_DIR}/../tlv++/include/.*"
                "${_OPENTLV_CLANG_TIDY_MODULE_DIR}/../tests/unit/test_tlvpp.cpp"
            COMMENT "Running clang-tidy static analysis on tlv++"
            VERBATIM
        )
    else()
        message(WARNING
            "OPENTLV_BUILD_CXX/OPENTLV_BUILD_TESTS/OPENTLV_BUILD_UNIT_TESTS are "
            "required to reach the tlv++ unit test TU the 'clang-tidy' target "
            "analyzes tlv++ through; skipping tlv++ coverage for this build.")
    endif()
endfunction()
