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

# Only the headers are required on every platform; LUA_LIBRARIES is only
# needed (and only linked) on Windows, so this deliberately does not pass
# REQUIRED, and does not fail here if a Lua install (such as one built by
# leafo/gh-actions-lua into a workspace-local prefix) exposes headers but no
# library CMake's FindLua recognizes.
find_package(Lua)
if(NOT LUA_INCLUDE_DIR)
    message(FATAL_ERROR "Lua headers not found; set LUA_INCLUDE_DIR.")
endif()

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
target_link_libraries(opentlv_lua PRIVATE tlv)
opentlv_configure_compiler(opentlv_lua)

if(WIN32)
    # Windows DLLs must resolve every imported symbol at link time; there is
    # no ELF/Mach-O-style "leave it undefined, resolve it against the
    # process that loads this module" for PE. So on Windows this must link
    # against the same shared lua5x.dll the embedding Lua interpreter uses:
    # two independently linked copies of the Lua runtime sharing one
    # lua_State corrupt memory on this module's calls back into Lua (see
    # README.md's Build section).
    #
    # find_package(Lua)'s own search above only checks standard system
    # locations, so it finds nothing for a Lua installed to a non-standard
    # prefix (for example one leafo/gh-actions-lua built into a
    # workspace-local directory in CI). Every such layout this binding has
    # actually been built against — gh-actions-lua, the upstream Lua
    # Makefile's own "install" target, vcpkg — puts "include" and "lib" (or
    # "bin", for some Windows Lua distributions' import libraries) as
    # siblings under one prefix, so the already-resolved LUA_INCLUDE_DIR
    # (unlike LUA_LIBDIR/LUA_LIBDIR_FILE, LuaRocks' "command" build type
    # does not expose any substitutable variable for the Lua library
    # directly; see opentlv-scm-1.rockspec) locates it without needing a
    # second, separately-resolved hint.
    if(NOT LUA_LIBRARIES)
        get_filename_component(_opentlv_lua_prefix "${LUA_INCLUDE_DIR}" DIRECTORY)
        find_library(LUA_LIBRARY
            NAMES lua54 lua5.4 lua-5.4 lua53 lua5.3 lua-5.3 lua52 lua5.2 lua-5.2 lua51 lua5.1 lua-5.1 lua
            PATHS "${_opentlv_lua_prefix}/lib" "${_opentlv_lua_prefix}/bin"
            NO_DEFAULT_PATH)
        if(LUA_LIBRARY)
            set(LUA_LIBRARIES "${LUA_LIBRARY}")
        endif()
    endif()
    if(NOT LUA_LIBRARIES)
        message(FATAL_ERROR "Lua library not found next to ${LUA_INCLUDE_DIR}; set LUA_LIBRARY explicitly.")
    endif()
    target_link_libraries(opentlv_lua PRIVATE ${LUA_LIBRARIES})
elseif(APPLE)
    # Deliberately not linked against LUA_LIBRARIES here either, for the
    # same reason as the Linux case below; -undefined dynamic_lookup defers
    # every lua_*/luaL_* symbol to load time instead of requiring them at
    # link time, since Mach-O otherwise resolves imports as strictly as PE.
    target_link_options(opentlv_lua PRIVATE -undefined dynamic_lookup)
endif()
# On Linux, GNU ld already permits a shared object to keep symbols
# undefined at link time; they resolve when the module is require()'d,
# against the same already-running Lua interpreter process. Deliberately
# not linking LUA_LIBRARIES here is what makes that the only copy of the
# Lua runtime in the process: linking it (as Windows must) would compile a
# second, independent copy of lua_pcall(), luaV_execute() and friends
# directly into this module, sharing the interpreter's lua_State with a
# runtime that never allocated it — the same corruption the Windows comment
# above describes, not something specific to how Windows loads DLLs.

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
