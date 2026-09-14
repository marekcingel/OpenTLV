# Check capacity bounds and unchanged C/C++ layout without linking.
function(opentlv_check_tag_configuration)
    include(CheckCSourceCompiles)
    include(CheckCXXSourceCompiles)
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
    set(CMAKE_REQUIRED_INCLUDES "${OpenTLV_SOURCE_DIR}/tlv/include" "${OpenTLV_BINARY_DIR}/generated/include")
    set(languages C)
    if(CMAKE_CXX_COMPILER_LOADED)
        list(APPEND languages CXX)
    endif()
    foreach(language IN LISTS languages)
        foreach(config IN ITEMS default minimum new maximum zero oversized fixed_limit)
            set(definitions "")
            set(expected 8)
            if(config STREQUAL "new")
                set(definitions "#define TLV_TAG_CAPACITY 16")
                set(expected 16)
            elseif(config STREQUAL "minimum")
                set(definitions "#define TLV_TAG_CAPACITY 1")
                set(expected 1)
            elseif(config STREQUAL "maximum")
                set(definitions "#define TLV_TAG_CAPACITY UINT8_MAX")
                set(expected 255)
            elseif(config STREQUAL "zero")
                set(definitions "#define TLV_TAG_CAPACITY 0")
            elseif(config STREQUAL "oversized")
                set(definitions "#define TLV_TAG_CAPACITY (UINT8_MAX + 1)")
            elseif(config STREQUAL "fixed_limit")
                set(definitions "#define TLV_TAG_MAX_SUPPORTED_SIZE 16")
            endif()
            set(result "OPENTLV_TAG_${language}_${config}")
            unset(${result} CACHE)
            # Invalid cases compile only the header, so a failed layout assertion
            # cannot mask a missing configuration diagnostic.
            set(source "${definitions}\n#include <tlv/tag.h>\n")
            if(config MATCHES "^(default|minimum|new|maximum)$")
                string(APPEND source "
                    #ifdef TLV_TAG_MAX_SIZE
                    #error removed_tag_capacity_alias_must_not_be_exposed
                    #endif
                    typedef struct { uint8_t data[${expected}]; uint8_t size; } legacy_tag;
                    typedef char layout_check[sizeof(tlv_tag_t) == sizeof(legacy_tag) ? 1 : -1];
                    typedef char offset_check[offsetof(tlv_tag_t, size) == offsetof(legacy_tag, size) ? 1 : -1];
                    typedef char capacity_check[TLV_TAG_CAPACITY == ${expected} ? 1 : -1];
                    typedef char limit_check[TLV_TAG_MAX_SUPPORTED_SIZE == UINT8_MAX ? 1 : -1];")
            endif()
            if(language STREQUAL "C")
                check_c_source_compiles("${source}" ${result})
            else()
                check_cxx_source_compiles("${source}" ${result})
            endif()
            if(config MATCHES "^(default|minimum|new|maximum)$")
                if(NOT ${result})
                    message(FATAL_ERROR "Valid ${language} tag configuration ${config} must compile")
                endif()
            elseif(${result})
                message(FATAL_ERROR "Invalid ${language} tag configuration ${config} must fail")
            endif()
        endforeach()
    endforeach()
endfunction()

opentlv_check_tag_configuration()
