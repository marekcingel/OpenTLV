# Experimental Lua binding: the OpenTLV C core plus a native extension
# module (src/) exposing Reader, Entry, Tag and tree traversal to Lua 5.1
# through 5.4 and LuaJIT, and a one-line pure-Lua entry point (lua/) that
# `require("opentlv")` resolves to — the same native/pure split as the
# Python opentlv-native/opentlv and Rust opentlv-native/opentlv packages.
# Included only when OPENTLV_BUILD_LUA=ON, so native C/C++ builds never see
# it.
#
#   cmake -S . -B build-lua -DOPENTLV_BUILD_LUA=ON -DCMAKE_BUILD_TYPE=Release \
#       -DOPENTLV_BUILD_CXX=OFF -DOPENTLV_BUILD_CLI=OFF -DOPENTLV_BUILD_TESTS=OFF \
#       -DOPENTLV_BUILD_EXAMPLES=OFF
#   cmake --build build-lua --target opentlv_lua

# On Windows in particular, this must resolve to the same shared lua5x.dll
# the Lua interpreter running the tests/examples uses, not a statically
# linked Lua: two independently linked copies of the Lua runtime sharing one
# lua_State corrupt memory on this module's calls back into Lua (see
# README.md's Build section).
find_package(Lua REQUIRED)

add_library(opentlv_lua MODULE
    src/module.c
    src/common.c
    src/common.h
    src/error.c
    src/error.h
    src/format.c
    src/format.h
    src/reader.c
    src/reader.h
    src/walk.c
    src/walk.h
    src/compat.h
)
target_include_directories(opentlv_lua PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(opentlv_lua PRIVATE tlv ${LUA_LIBRARIES})
opentlv_configure_compiler(opentlv_lua)

# require("opentlv_native") looks for a shared object literally named
# opentlv_native, with no platform library prefix, and expects the
# platform's native module extension except on macOS, where Lua modules are
# still named .so by ecosystem convention (LuaRocks does the same), not the
# default .dylib CMake would otherwise pick for a MODULE library.
# require("opentlv") itself resolves to lua/opentlv/init.lua, which returns
# this module unchanged; see src/module.c's file comment.
set_target_properties(opentlv_lua PROPERTIES
    OUTPUT_NAME opentlv_native
    PREFIX ""
)
if(APPLE)
    set_target_properties(opentlv_lua PROPERTIES SUFFIX ".so")
elseif(WIN32)
    # MSVC does not export any symbols from a DLL by default;
    # luaopen_opentlv_native needs to be visible for the Lua runtime's
    # require() to find it.
    set_target_properties(opentlv_lua PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

option(OPENTLV_BUILD_LUA_TESTS "Register the busted test suite and examples for the Lua binding" ON)
if(OPENTLV_BUILD_LUA_TESTS)
    find_program(OPENTLV_LUA_EXECUTABLE NAMES lua lua5.4 lua5.3 lua5.1 luajit)
    find_program(OPENTLV_BUSTED_EXECUTABLE busted)

    # require("opentlv") resolves through lua/opentlv/init.lua (source tree,
    # nothing to build), so tests and examples need LUA_PATH in addition to
    # the LUA_CPATH entry for the compiled opentlv_native module; the
    # trailing ";;" keeps each interpreter's own default search path too.
    set(_lua_path "${CMAKE_CURRENT_SOURCE_DIR}/lua/?.lua;${CMAKE_CURRENT_SOURCE_DIR}/lua/?/init.lua;;")
    set(_lua_cpath "$<TARGET_FILE_DIR:opentlv_lua>/?$<TARGET_FILE_SUFFIX:opentlv_lua>;;")
    set(_lua_test_environment "LUA_PATH=${_lua_path};LUA_CPATH=${_lua_cpath}")

    if(OPENTLV_BUSTED_EXECUTABLE)
        add_test(NAME Integration_lua
            COMMAND ${OPENTLV_BUSTED_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/tests")
        set_tests_properties(Integration_lua PROPERTIES
            LABELS "integration;lua"
            ENVIRONMENT "${_lua_test_environment}")
    else()
        message(STATUS "busted not found; skipping the Lua binding test suite.")
    endif()

    if(OPENTLV_LUA_EXECUTABLE)
        foreach(example parse quick_start)
            add_test(NAME Integration_example_lua_${example}
                COMMAND ${OPENTLV_LUA_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/examples/${example}.lua")
            set_tests_properties(Integration_example_lua_${example} PROPERTIES
                LABELS "integration;examples;lua"
                ENVIRONMENT "${_lua_test_environment}")
        endforeach()
    else()
        message(STATUS "lua interpreter not found; skipping the Lua binding examples.")
    endif()
endif()
