-- Pure-Lua entry point for require("opentlv"). Every OpenTLV concept
-- (Reader, Entry, Tag, tree traversal, errors) is bound directly in the
-- native opentlv_native module (bindings/lua/src/); this file only
-- re-exports it under the name callers request, the same native/pure split
-- the Python opentlv-native/opentlv and Rust opentlv-native/opentlv
-- packages use. It stays this thin on purpose: functionality useful outside
-- Lua belongs in the OpenTLV C API, not in this binding (see
-- docs/development/lua.md).
return require("opentlv_native")
