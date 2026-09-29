# Compile the actual library source set with presentation physically excluded.
# A poisoned public header also catches newly introduced include dependencies.
get_target_property(_emv_isolated_sources tlv SOURCES)
get_target_property(_emv_source_dir tlv SOURCE_DIR)
set(_emv_isolated_absolute)
foreach(_source IN LISTS _emv_isolated_sources)
    if(_source MATCHES "builtins/emv/presentation\\.c$")
        continue()
    endif()
    if(NOT IS_ABSOLUTE "${_source}")
        set(_source "${_emv_source_dir}/${_source}")
    endif()
    list(APPEND _emv_isolated_absolute "${_source}")
endforeach()
set(_emv_poison "${CMAKE_CURRENT_BINARY_DIR}/without-presentation/include")
# Mirror the headers so even a relative include from another public header
# reaches the poison. configure_file tracks content changes for later rebuilds.
file(GLOB_RECURSE _emv_headers CONFIGURE_DEPENDS
     RELATIVE "${_emv_source_dir}/include" "${_emv_source_dir}/include/*.h")
foreach(_header IN LISTS _emv_headers)
    if(NOT _header STREQUAL "tlv/builtins/emv/presentation.h")
        configure_file("${_emv_source_dir}/include/${_header}"
                       "${_emv_poison}/${_header}" COPYONLY)
    endif()
endforeach()
file(WRITE "${_emv_poison}/tlv/builtins/emv/presentation.h"
     "#error EMV domain code must not depend on the presentation adapter\n")
add_library(test-emv-without-presentation STATIC ${_emv_isolated_absolute})
target_compile_definitions(test-emv-without-presentation PUBLIC TLV_STATIC_DEFINE)
target_include_directories(test-emv-without-presentation PUBLIC
    "${_emv_poison}"
    "${OpenTLV_BINARY_DIR}/generated/include")
target_compile_features(test-emv-without-presentation PUBLIC c_std_99)
opentlv_configure_compiler(test-emv-without-presentation)
add_executable(test-emv-domain-independence
    "${OpenTLV_SOURCE_DIR}/tests/integration/builtins/emv/without_presentation.c")
target_link_libraries(test-emv-domain-independence PRIVATE test-emv-without-presentation)
add_test(NAME Integration_Emv.WithoutPresentation COMMAND test-emv-domain-independence)
set_tests_properties(Integration_Emv.WithoutPresentation PROPERTIES LABELS integration)
