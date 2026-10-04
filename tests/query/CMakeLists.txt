add_executable(test-query-conformance native.c)
target_link_libraries(test-query-conformance PRIVATE tlv)
opentlv_configure_compiler(test-query-conformance)
if(WIN32 AND OPENTLV_BUILD_SHARED_LIBS)
    add_custom_command(TARGET test-query-conformance POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:tlv> $<TARGET_FILE_DIR:test-query-conformance>)
endif()
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME query-s0-conformance
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run.py
            --native $<TARGET_FILE:test-query-conformance>)
    set_tests_properties(query-s0-conformance PROPERTIES LABELS "query;conformance")
endif()
