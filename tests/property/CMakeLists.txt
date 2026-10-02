find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)

set(OPENTLV_PROPERTY_COUNT 128 CACHE STRING "Generated cases per property configuration")
set(OPENTLV_PROPERTY_SEED "" CACHE STRING "Explicit uint64 property seed; empty derives it from commit")
set(OPENTLV_PROPERTY_COMMIT "" CACHE STRING "Property commit identity; empty uses local Git HEAD")
if(OPENTLV_PROPERTY_COMMIT STREQUAL "")
    execute_process(COMMAND git rev-parse HEAD WORKING_DIRECTORY "${OpenTLV_SOURCE_DIR}"
        RESULT_VARIABLE git_result OUTPUT_VARIABLE OPENTLV_PROPERTY_COMMIT OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT git_result EQUAL 0)
        set(OPENTLV_PROPERTY_COMMIT "source-archive")
    endif()
endif()

add_executable(property-roundtrip roundtrip.cpp)
target_link_libraries(property-roundtrip PRIVATE tlv)
target_compile_features(property-roundtrip PRIVATE cxx_std_11)
opentlv_configure_compiler(property-roundtrip)
opentlv_copy_shared_runtime(property-roundtrip)

function(property_configuration name format)
    add_test(NAME Property_${name} COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/corpus.py"
        --cli "$<TARGET_FILE:otlv>" --checker "$<TARGET_FILE:property-roundtrip>"
        --root "${OpenTLV_BINARY_DIR}/property-data/$<CONFIG>/${name}"
        --failures "${OpenTLV_BINARY_DIR}/property-failures/$<CONFIG>/${name}"
        --format "${format}" --count "${OPENTLV_PROPERTY_COUNT}"
        --commit "${OPENTLV_PROPERTY_COMMIT}" --seed "${OPENTLV_PROPERTY_SEED}"
        --generator-header "${OpenTLV_SOURCE_DIR}/tlv/include/tlv/generator.h" ${ARGN})
    set_tests_properties(Property_${name} PROPERTIES LABELS "property;${format}" TIMEOUT 300)
endfunction()

property_configuration(fixed fixed)
property_configuration(fixed-wide-be fixed --tag-size 3 --length-size 2)
property_configuration(fixed-wide-le fixed --tag-size 2 --length-size 2 --byte-order little)
property_configuration(fixed-empty fixed --max-value-size 0 --max-depth 0)
if(OPENTLV_FORMAT_BER)
    property_configuration(ber ber)
endif()
if(OPENTLV_FORMAT_DER)
    property_configuration(der der)
endif()
if(OPENTLV_EMV)
    property_configuration(emv emv)
endif()
if(OPENTLV_BLUETOOTH)
    property_configuration(bluetooth bluetooth-ltv)
endif()
if(OPENTLV_NFC)
    property_configuration(nfc nfc-type2)
    property_configuration(nfc-controls nfc-type2 --nfc-controls)
endif()

add_test(NAME Property_infrastructure COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/corpus_test.py")
set_tests_properties(Property_infrastructure PROPERTIES LABELS "property;infrastructure")
