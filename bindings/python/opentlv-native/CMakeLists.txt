# FindPython's USE_SABI/SABIModule support requires CMake 3.26; this only
# raises the required CMake version for this subdirectory, not the repository
# as a whole (OPENTLV_BUILD_PYTHON defaults OFF, so a plain C/C++ build never
# reaches this file), and scikit-build-core supplies its own modern CMake for
# the Python build path regardless.
cmake_minimum_required(VERSION 3.26)

find_package(Python 3.11 REQUIRED COMPONENTS Interpreter Development.Module Development.SABIModule)

# USE_SABI builds against the CPython stable ABI (Py_LIMITED_API) so one wheel
# per platform works on every Python 3.11 and newer. The module is installed
# at the wheel root (not inside a package directory), so `import opentlv_native`
# resolves directly to it, mirroring how the Rust opentlv-native crate root is
# itself the raw extern "C" declarations.
Python_add_library(opentlv_native MODULE USE_SABI 3.11 WITH_SOABI src/module.c)
target_link_libraries(opentlv_native PRIVATE tlv)

install(TARGETS opentlv_native DESTINATION .)
