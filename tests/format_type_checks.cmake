# Compile the real public constructors in C, including both rejected directions.
# A positive control prevents unrelated compiler/include failures from passing.
function(opentlv_check_format_types)
    include(CheckCSourceCompiles)
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
    set(CMAKE_REQUIRED_INCLUDES "${OpenTLV_SOURCE_DIR}/tlv/include")
    if(MSVC)
        set(CMAKE_REQUIRED_FLAGS "/std:c11 /W4 /WX")
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        set(CMAKE_REQUIRED_FLAGS "-std=c11 -Wall -Wextra -Werror")
    else()
        return()
    endif()
    set(headers "#include <tlv/reader/reader.h>\n#include <tlv/writer/writer.h>\n")
    unset(OPENTLV_FORMAT_TYPES_VALID CACHE)
    check_c_source_compiles("${headers}
        void check(const tlv_reader_format_t* r, const tlv_writer_format_t* w) {
            tlv_reader_t reader;
            tlv_writer_t writer;
            (void)tlv_reader_init(&reader, 0, 0, r);
            (void)tlv_writer_init(&writer, 0, 0, w);
        }" OPENTLV_FORMAT_TYPES_VALID)
    if(NOT OPENTLV_FORMAT_TYPES_VALID)
        message(FATAL_ERROR "Correctly typed C format constructors must compile")
    endif()
    foreach(direction IN ITEMS reader writer)
        if(direction STREQUAL "reader")
            set(other writer)
        else()
            set(other reader)
        endif()
        unset(OPENTLV_${direction}_ACCEPTS_WRONG_FORMAT CACHE)
        check_c_source_compiles("${headers}
            void check(const tlv_${other}_format_t* wrong) {
                tlv_${direction}_t target;
                (void)tlv_${direction}_init(&target, 0, 0, wrong);
            }" OPENTLV_${direction}_ACCEPTS_WRONG_FORMAT)
        if(OPENTLV_${direction}_ACCEPTS_WRONG_FORMAT)
            message(FATAL_ERROR "The C ${direction} constructor accepts the wrong format type")
        endif()
    endforeach()
endfunction()

opentlv_check_format_types()
