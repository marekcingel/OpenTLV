# Capability selection never enables another capability implicitly.
if(NOT OPENTLV_QUERY)
    set(OPENTLV_QUERY_FRONTEND OFF)
    set(OPENTLV_QUERY_SET_OPERATIONS OFF)
endif()

# These consumers currently expose the full composed API. Keep requirements
# explicit rather than producing unresolved symbols in reduced builds.
if(NOT OPENTLV_READER OR NOT OPENTLV_WRITER OR NOT OPENTLV_QUERY OR
   NOT OPENTLV_SCHEMA OR NOT OPENTLV_CODEC)
    foreach(component IN ITEMS CLI EXAMPLES BENCHMARKS FUZZING WASM PYTHON LUA)
        if(OPENTLV_BUILD_${component})
            message(STATUS "Reduced capability build: skipping ${component} (requires Reader, Writer, Query, Schema and Codec)")
            set(OPENTLV_BUILD_${component} OFF)
        endif()
    endforeach()
    set(OPENTLV_BUILD_UNIT_TESTS OFF)
    set(OPENTLV_BUILD_INTEGRATION_TESTS OFF)
    set(OPENTLV_BUILD_PROPERTY_TESTS OFF)
    set(OPENTLV_BUILD_QUERY_TESTS OFF)
endif()
