# Adds an opt-in 'cppcheck' target that runs cppcheck's static analysis over
# tlv (C) and tlv++ (C++) sources and public headers. Not part of ALL, and
# skipped with a warning if no cppcheck is found, so its absence never breaks
# a regular build. See cmake/clang_tidy.cmake for the complementary
# 'clang-tidy' target.
set(_OPENTLV_CPPCHECK_MODULE_DIR "${CMAKE_CURRENT_LIST_DIR}")

function(opentlv_add_cppcheck_targets)
    find_program(OPENTLV_CPPCHECK_EXECUTABLE cppcheck)
    if(NOT OPENTLV_CPPCHECK_EXECUTABLE)
        message(WARNING
            "cppcheck was not found; skipping the 'cppcheck' target. "
            "Install cppcheck to use it.")
        return()
    endif()

    # Only .c files are passed for tlv: cppcheck checks an explicitly named
    # file as its own standalone unit, so naming tlv's headers here too would
    # check each of them in isolation from the .c files that use them,
    # producing bogus unusedStructMember-style findings for perfectly used
    # public types. Passing -I below still lets cppcheck resolve and analyze
    # header content reached through #include from a .c file. tlv++ is
    # header-only, so its .hpp files have no such driving .c/.cpp file and
    # must be named directly; the resulting standalone-unit false positives
    # are suppressed in .cppcheck-suppressions instead.
    file(GLOB_RECURSE _opentlv_cppcheck_c_sources
        LIST_DIRECTORIES false
        "${_OPENTLV_CPPCHECK_MODULE_DIR}/../tlv/*.c"
    )
    file(GLOB_RECURSE _opentlv_cppcheck_cxx_sources
        LIST_DIRECTORIES false
        "${_OPENTLV_CPPCHECK_MODULE_DIR}/../tlv++/*.hpp"
    )

    set(_opentlv_cppcheck_common_args
        "--enable=warning,style,performance,portability"
        --check-level=exhaustive
        # tlv++/include/tlv++/compat.hpp guards a C++23-only #include behind
        # a defined(__has_include) check, which is valid but which cppcheck's
        # default multi-configuration preprocessor exploration cannot
        # evaluate (a cppcheck limitation, not a code issue); --max-configs=1
        # restricts it to the single configuration implied by --std below.
        --max-configs=1
        --error-exitcode=1
        --inline-suppr
        "--suppressions-list=${_OPENTLV_CPPCHECK_MODULE_DIR}/../.cppcheck-suppressions"
    )

    add_custom_target(cppcheck
        COMMAND ${OPENTLV_CPPCHECK_EXECUTABLE}
            ${_opentlv_cppcheck_common_args}
            --std=c99 --language=c
            -I "${_OPENTLV_CPPCHECK_MODULE_DIR}/../tlv/include"
            -I "${OpenTLV_BINARY_DIR}/generated/include"
            ${_opentlv_cppcheck_c_sources}
        COMMAND ${OPENTLV_CPPCHECK_EXECUTABLE}
            ${_opentlv_cppcheck_common_args}
            --std=c++11 --language=c++
            -I "${_OPENTLV_CPPCHECK_MODULE_DIR}/../tlv++/include"
            -I "${_OPENTLV_CPPCHECK_MODULE_DIR}/../tlv/include"
            -I "${OpenTLV_BINARY_DIR}/generated/include"
            ${_opentlv_cppcheck_cxx_sources}
        WORKING_DIRECTORY "${_OPENTLV_CPPCHECK_MODULE_DIR}/.."
        COMMENT "Running cppcheck static analysis on tlv and tlv++"
        VERBATIM
    )
endfunction()
