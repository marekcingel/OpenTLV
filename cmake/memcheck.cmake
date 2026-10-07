# Memcheck is a separate, unsanitized native build. Normal builds do not need
# Valgrind or Python, and retain the existing OPENTLV_BUILD_* test switches.
if(OPENTLV_BUILD_MEMCHECK)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_CROSSCOMPILING)
        message(FATAL_ERROR "OPENTLV_BUILD_MEMCHECK requires a native Linux build.")
    endif()
    if(NOT OPENTLV_BUILD_TESTS OR OPENTLV_BUILD_FUZZING OR OPENTLV_BUILD_WASM)
        message(FATAL_ERROR "OPENTLV_BUILD_MEMCHECK requires tests enabled and fuzzing/WASM disabled.")
    endif()
    get_cmake_property(_memcheck_variables VARIABLES)
    foreach(_variable IN LISTS _memcheck_variables)
        if(_variable MATCHES "^CMAKE_(C|CXX|EXE_LINKER|SHARED_LINKER|MODULE_LINKER)_FLAGS($|_)"
           AND "${${_variable}}" MATCHES "[-/]fsanitize[=:]")
            message(FATAL_ERROR "OPENTLV_BUILD_MEMCHECK requires an unsanitized build (${_variable}).")
        endif()
    endforeach()
    find_program(OPENTLV_VALGRIND_EXECUTABLE NAMES valgrind)
    if(NOT OPENTLV_VALGRIND_EXECUTABLE)
        message(FATAL_ERROR "OPENTLV_BUILD_MEMCHECK requires Valgrind; install it or disable the option.")
    endif()
    find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)
    configure_file("${CMAKE_CURRENT_LIST_DIR}/memcheck-valgrind.in"
        "${OpenTLV_BINARY_DIR}/memcheck-valgrind" @ONLY NEWLINE_STYLE UNIX)
    execute_process(COMMAND chmod +x "${OpenTLV_BINARY_DIR}/memcheck-valgrind"
        RESULT_VARIABLE _memcheck_chmod_result)
    if(NOT _memcheck_chmod_result EQUAL 0)
        message(FATAL_ERROR "Could not make the Memcheck launcher executable.")
    endif()
    set(MEMORYCHECK_COMMAND "${OpenTLV_BINARY_DIR}/memcheck-valgrind")
    set(MEMORYCHECK_TYPE "Valgrind")
    set(MEMORYCHECK_COMMAND_OPTIONS
        "--tool=memcheck --leak-check=full --show-leak-kinds=definite,indirect,possible --errors-for-leak-kinds=definite,indirect,possible --track-origins=yes --error-exitcode=99 --trace-children=yes --num-callers=40")
    set(MEMORYCHECK_SUPPRESSIONS_FILE "${OpenTLV_SOURCE_DIR}/tests/valgrind.supp")
    # CTest's BUILD_TESTING is only an implementation detail of this opt-in
    # dashboard setup; the repository's existing switches own test selection.
    set(BUILD_TESTING ON)
    include(CTest)
    configure_file("${CMAKE_CURRENT_LIST_DIR}/CTestCustom.cmake.in"
        "${OpenTLV_BINARY_DIR}/CTestCustom.cmake" @ONLY)
endif()

# The launcher emits this banner only for -T memcheck. Keep ordinary CTest
# timeout limits, including the retained-input complexity regression, intact.
function(opentlv_memcheck_timeout test seconds)
    if(OPENTLV_BUILD_MEMCHECK)
        set_tests_properties(${test} PROPERTIES
            TIMEOUT_AFTER_MATCH "${seconds};OpenTLV Memcheck started")
    endif()
endfunction()
