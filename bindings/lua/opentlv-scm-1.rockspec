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
   -- CMake's FindLua only searches standard system locations by default, so
   -- when LuaRocks' own Lua (e.g. one leafo/gh-actions-lua built into a
   -- workspace-local prefix in CI) isn't installed system-wide, it finds
   -- LUA_INCLUDE_DIR but not LUA_LIBRARY. LUA_LIBDIR_FILE is LuaRocks'
   -- variable for exactly this: the concrete Lua library file to link,
   -- for build scripts (like this one) that call an external build system
   -- instead of using LuaRocks' own "make"/"cmake" build types.
   build_command = "cmake -S ../.. -B build -DCMAKE_BUILD_TYPE=Release -DOPENTLV_BUILD_LUA=ON " ..
      "-DOPENTLV_BUILD_CXX=OFF -DOPENTLV_BUILD_CLI=OFF -DOPENTLV_BUILD_TESTS=OFF " ..
      "-DOPENTLV_BUILD_EXAMPLES=OFF -DOPENTLV_BUILD_LUA_TESTS=OFF " ..
      "-DLUA_INCLUDE_DIR=$(LUA_INCDIR) -DLUA_LIBRARY=$(LUA_LIBDIR_FILE) && " ..
      "cmake --build build --target opentlv_lua --config Release",
   -- Installs both halves of the native/pure split (see README.md):
   -- opentlv_native (the compiled module) and lua/opentlv/init.lua, the
   -- one-line pure-Lua file require("opentlv") actually resolves to.
   install_command = "cmake -E copy build/bindings/lua/opentlv_native.$(LIB_EXTENSION) $(LIBDIR) && " ..
      "cmake -E make_directory $(LUADIR)/opentlv && " ..
      "cmake -E copy lua/opentlv/init.lua $(LUADIR)/opentlv/init.lua"
}
