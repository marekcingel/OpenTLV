# Compile tlv++/builtins/fixed/fixed_format.hpp with valid and invalid template parameters.
# Positive controls prevent unrelated include failures from passing the negative cases.
function(opentlv_check_fixed_format)
    if(NOT CMAKE_CXX_COMPILER_LOADED)
        return()
    endif()
    include(CheckCXXSourceCompiles)
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
    set(CMAKE_REQUIRED_INCLUDES
        "${OpenTLV_SOURCE_DIR}/tlv/include"
        "${OpenTLV_SOURCE_DIR}/tlv++/include"
        "${OpenTLV_BINARY_DIR}/generated/include")
    if(MSVC)
        set(CMAKE_REQUIRED_FLAGS "/std:c++11 /W4 /WX /EHsc")
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        set(CMAKE_REQUIRED_FLAGS "-std=c++11 -Wall -Wextra -Werror")
    endif()
    set(header "#include <tlv++/builtins/fixed/fixed_format.hpp>\n")
    set(cases
        "valid_minimum|1, 1, TLV_BYTE_ORDER_BIG_ENDIAN|1"
        "valid_widest|255, 8, TLV_BYTE_ORDER_LITTLE_ENDIAN|1"
        "zero_tag_width|0, 1, TLV_BYTE_ORDER_BIG_ENDIAN|0"
        "zero_length_width|1, 0, TLV_BYTE_ORDER_BIG_ENDIAN|0"
        "oversized_length_width|1, 9, TLV_BYTE_ORDER_BIG_ENDIAN|0"
        "unknown_byte_order|1, 1, TLV_BYTE_ORDER_UNKNOWN|0"
        "invalid_byte_order|1, 1, static_cast<tlv_byte_order_t>(99)|0")
    foreach(case IN LISTS cases)
        string(REPLACE "|" ";" parts "${case}")
        list(GET parts 0 name)
        list(GET parts 1 arguments)
        list(GET parts 2 valid)
        set(result "OPENTLV_FIXED_FORMAT_${name}")
        unset(${result} CACHE)
        check_cxx_source_compiles("${header}
            int main() {
                const tlv_reader_format_t& reader = tlv::fixed_format<${arguments}>::reader();
                const tlv_writer_format_t& writer = tlv::fixed_format<${arguments}>::writer();
                return reader.read_tag == nullptr || writer.write_tag == nullptr;
            }" ${result})
        if(valid AND NOT ${result})
            message(FATAL_ERROR "Valid fixed_format case ${name} must compile")
        elseif(NOT valid AND ${result})
            message(FATAL_ERROR "Invalid fixed_format case ${name} must fail to compile")
        endif()
    endforeach()
endfunction()

opentlv_check_fixed_format()
