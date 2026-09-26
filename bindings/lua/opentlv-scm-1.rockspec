package = "opentlv"
version = "scm-1"

source = {
   url = "git+https://github.com/marekcingel/OpenTLV.git"
}

description = {
   summary = "Lua bindings to the OpenTLV C library",
   detailed = [[
      Binds the OpenTLV C reader (Reader, Entry, Tag and preorder tree
      traversal) directly to Lua 5.1 through 5.4 and LuaJIT. Experimental;
      see https://marekcingel.github.io/OpenTLV/development/lua/.
   ]],
   homepage = "https://github.com/marekcingel/OpenTLV",
   license = "MIT"
}

dependencies = {
   "lua >= 5.1"
}

-- Drives the repository's own CMake build (this rockspec's directory is
-- bindings/lua/, two levels below the repository root) instead of LuaRocks'
-- "cmake" build type, since the CMakeLists.txt that defines the tlv target
-- this module links lives at the repository root, not here. Run
-- `luarocks make` from this directory.
build = {
   type = "command",
   -- Only LUA_INCLUDE_DIR is passed directly: CMakeLists.txt only requires
   -- (and only links) a Lua library on Windows, resolving lua_*/luaL_*
   -- symbols at module-load time everywhere else instead (see its own
   -- comments for why). LUA_LIBDIR_HINT carries LuaRocks' own LUA_LIBDIR
   -- through for that Windows case; CMake's find_library() then applies
   -- its usual cross-platform naming rules to it, since there is no
   -- generically substitutable "exact Lua library file" variable for the
   -- "command" build type the way LuaRocks' own "make"/"cmake" build types
   -- get internally (LUA_LIBDIR_FILE/LUALIB) — using either of those names
   -- straight in build_command/install_command is a silent no-op, warned
   -- as "unmatched variable" and substituted as empty.
   build_command = "cmake -S ../.. -B build -DCMAKE_BUILD_TYPE=Release -DOPENTLV_BUILD_LUA=ON " ..
      "-DOPENTLV_BUILD_CXX=OFF -DOPENTLV_BUILD_CLI=OFF -DOPENTLV_BUILD_TESTS=OFF " ..
      "-DOPENTLV_BUILD_EXAMPLES=OFF -DOPENTLV_BUILD_LUA_TESTS=OFF " ..
      "-DLUA_INCLUDE_DIR=$(LUA_INCDIR) -DLUA_LIBDIR_HINT=$(LUA_LIBDIR) && " ..
      "cmake --build build --target opentlv_lua --config Release",
   -- Installs both halves of the native/pure split (see README.md):
   -- opentlv_native (the compiled module) and lua/opentlv/init.lua, the
   -- one-line pure-Lua file require("opentlv") actually resolves to.
   install_command = "cmake -E copy build/bindings/lua/opentlv_native.$(LIB_EXTENSION) $(LIBDIR) && " ..
      "cmake -E make_directory $(LUADIR)/opentlv && " ..
      "cmake -E copy lua/opentlv/init.lua $(LUADIR)/opentlv/init.lua"
}
