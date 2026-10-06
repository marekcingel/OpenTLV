add_executable(test-query-conformance native.c)
add_executable(test-query-abi abi.c)
target_link_libraries(test-query-abi PRIVATE tlv)
opentlv_configure_compiler(test-query-abi)
target_link_libraries(test-query-conformance PRIVATE tlv)
opentlv_configure_compiler(test-query-conformance)
if(WIN32 AND OPENTLV_BUILD_SHARED_LIBS)
    add_custom_command(TARGET test-query-conformance POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:tlv> $<TARGET_FILE_DIR:test-query-conformance>)
endif()
find_package(Python3 COMPONENTS Interpreter QUIET)
if(OPENTLV_BUILD_CXX)
    add_executable(test-query-cxx-conformance cxx_facade.cpp)
    target_link_libraries(test-query-cxx-conformance PRIVATE tlv++)
    opentlv_configure_compiler(test-query-cxx-conformance)
    if(WIN32 AND OPENTLV_BUILD_SHARED_LIBS)
        add_custom_command(TARGET test-query-cxx-conformance POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:tlv> $<TARGET_FILE_DIR:test-query-cxx-conformance>)
    endif()
    if(Python3_Interpreter_FOUND)
        add_test(NAME query-cxx-conformance
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run.py
                --native $<TARGET_FILE:test-query-cxx-conformance> --property-cases 0)
        set_tests_properties(query-cxx-conformance PROPERTIES LABELS "query;conformance")
    endif()
endif()
if(Python3_Interpreter_FOUND)
    if(NOT CMAKE_CROSSCOMPILING)
        add_test(NAME query-abi-snapshot
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/check_abi.py
                --native $<TARGET_FILE:test-query-abi>)
        set_tests_properties(query-abi-snapshot PROPERTIES LABELS "query;abi")
    endif()
    if(TARGET otlv)
        add_test(NAME query-cli-conformance
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/cli_facade.py
                --cli $<TARGET_FILE:otlv>)
        set_tests_properties(query-cli-conformance PROPERTIES LABELS "query;conformance")
    endif()
    add_test(NAME query-s0-conformance
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run.py
            --native $<TARGET_FILE:test-query-conformance>)
    set_tests_properties(query-s0-conformance PROPERTIES LABELS "query;conformance")
endif()
