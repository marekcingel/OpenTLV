function(opentlv_check_compiler)
    foreach(language IN ITEMS C CXX)
        if(CMAKE_${language}_COMPILER_ID STREQUAL "Clang"
           AND CMAKE_${language}_COMPILER_VERSION VERSION_LESS 18)
            message(FATAL_ERROR "OpenTLV requires Clang 18 or newer (${language} compiler).")
        endif()
    endforeach()
endfunction()

# Apply only to OpenTLV build targets, never to dependencies or consumers.
function(opentlv_configure_compiler target)
    opentlv_check_compiler()

    target_compile_options(${target} PRIVATE
        "$<$<COMPILE_LANG_AND_ID:C,Clang>:-Wall;-Wextra;-Wpedantic;-Wstrict-prototypes>"
        "$<$<COMPILE_LANG_AND_ID:CXX,Clang>:-Wall;-Wextra;-Wpedantic>"
        "$<$<AND:$<BOOL:${OPENTLV_WARNINGS_AS_ERRORS}>,$<OR:$<COMPILE_LANG_AND_ID:C,Clang>,$<COMPILE_LANG_AND_ID:CXX,Clang>>>:-Werror>"
    )
endfunction()
