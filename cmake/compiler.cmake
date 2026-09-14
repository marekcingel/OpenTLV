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
        "$<$<AND:$<BOOL:${OPENTLV_WARNINGS_AS_ERRORS}>,$<OR:$<COMPILE_LANG_AND_ID:C,GNU,Clang>,$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>>>:-Werror>"
        "$<$<AND:$<BOOL:${OPENTLV_WARNINGS_AS_ERRORS}>,$<OR:$<COMPILE_LANG_AND_ID:C,MSVC>,$<COMPILE_LANG_AND_ID:CXX,MSVC>>>:/WX>"
    )
endfunction()

# Copies the tlv runtime library next to a Windows executable that links it
# (directly or through tlv++), so it can be launched or run under ctest
# without adjusting PATH. No-op for static tlv builds or non-Windows platforms.
function(opentlv_copy_shared_runtime target)
    if(WIN32 AND OPENTLV_BUILD_SHARED_LIBS)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:tlv>" "$<TARGET_FILE_DIR:${target}>"
        )
    endif()
endfunction()
