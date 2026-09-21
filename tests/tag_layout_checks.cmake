# Check that tlv_tag_t is a borrowed pointer and size with no configurable capacity,
# in both C and C++, without linking.
function(opentlv_check_tag_layout)
    include(CheckCSourceCompiles)
    include(CheckCXXSourceCompiles)
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
    set(CMAKE_REQUIRED_INCLUDES "${OpenTLV_SOURCE_DIR}/tlv/include" "${OpenTLV_BINARY_DIR}/generated/include")
    set(languages C)
    if(CMAKE_CXX_COMPILER_LOADED)
        list(APPEND languages CXX)
    endif()
    foreach(language IN LISTS languages)
        foreach(config IN ITEMS default ignored_capacity)
            set(definitions "")
            if(config STREQUAL "ignored_capacity")
                # The removed configuration macro must not change the layout.
                set(definitions "#define TLV_TAG_CAPACITY 16")
            endif()
            set(result "OPENTLV_TAG_LAYOUT_${language}_${config}")
            unset(${result} CACHE)
            set(source "${definitions}
                #include <stddef.h>
                #include <stdint.h>
                #include <tlv/tag.h>
                #ifdef TLV_TAG_MAX_SUPPORTED_SIZE
                #error tag_size_limit_must_not_be_exposed
                #endif
                typedef struct { const uint8_t* data; size_t size; } borrowed_tag;
                typedef char size_check[sizeof(tlv_tag_t) == sizeof(borrowed_tag) ? 1 : -1];
                typedef char data_check[offsetof(tlv_tag_t, data) == offsetof(borrowed_tag, data) ? 1 : -1];
                typedef char size_offset_check[offsetof(tlv_tag_t, size) == offsetof(borrowed_tag, size) ? 1 : -1];")
            if(language STREQUAL "C")
                check_c_source_compiles("${source}" ${result})
            else()
                check_cxx_source_compiles("${source}" ${result})
            endif()
            if(NOT ${result})
                message(FATAL_ERROR "tlv_tag_t must be a borrowed pointer and size in ${language} (${config})")
            endif()
        endforeach()
    endforeach()
endfunction()

opentlv_check_tag_layout()
