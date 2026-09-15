import os

from conan import ConanFile
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.files import copy, get, rmdir

required_conan_version = ">=2.0"


class OpenTLVConan(ConanFile):
    name = "opentlv"
    description = (
        "Allocation-free C99 library and header-only C++11 wrapper for "
        "reading, writing and inspecting Tag-Length-Value (TLV) data."
    )
    license = "MIT"
    url = "https://github.com/conan-io/conan-center-index"
    homepage = "https://github.com/marekcingel/OpenTLV"
    topics = ("tlv", "ber-tlv", "der", "cer", "asn1", "emv", "serialization", "embedded")
    package_type = "library"
    settings = "os", "arch", "compiler", "build_type"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "with_cxx": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        "with_cxx": True,
    }

    def config_options(self):
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def layout(self):
        cmake_layout(self, src_folder="src")

    def source(self):
        get(self, **self.conan_data["sources"][self.version], strip_root=True)

        # OpenTLV derives OPENTLV_VERSION_STRING (tlv_version() at runtime)
        # from `git describe` against the checkout; the extracted release
        # tarball has no .git, so recreate a minimal repository tagged at
        # this version, or the packaged library reports version "0.0.0".
        self.run('git init -q')
        self.run('git -c user.email=conan@conan.io -c user.name=conan add -A')
        self.run(f'git -c user.email=conan@conan.io -c user.name=conan commit -q -m "{self.version}"')
        self.run(f'git tag {self.version}')

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["OPENTLV_BUILD_CXX"] = bool(self.options.with_cxx)
        tc.variables["OPENTLV_BUILD_SHARED_LIBS"] = bool(self.options.shared)
        tc.variables["OPENTLV_BUILD_TESTS"] = False
        tc.variables["OPENTLV_BUILD_EXAMPLES"] = False
        tc.variables["OPENTLV_BUILD_CLI"] = False
        tc.variables["OPENTLV_BUILD_BENCHMARKS"] = False
        tc.variables["OPENTLV_BUILD_FUZZING"] = False
        tc.variables["OPENTLV_WARNINGS_AS_ERRORS"] = False
        tc.generate()

        deps = CMakeDeps(self)
        deps.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        copy(self, "LICENSE", src=self.source_folder, dst=os.path.join(self.package_folder, "licenses"))
        cmake = CMake(self)
        cmake.install()
        rmdir(self, os.path.join(self.package_folder, "lib", "cmake"))
        rmdir(self, os.path.join(self.package_folder, "share"))

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "OpenTLV")

        self.cpp_info.components["tlv"].set_property("cmake_target_name", "OpenTLV::tlv")
        self.cpp_info.components["tlv"].libs = ["tlv"]

        if self.options.with_cxx:
            self.cpp_info.components["tlvpp"].set_property("cmake_target_name", "OpenTLV::tlvpp")
            self.cpp_info.components["tlvpp"].requires = ["tlv"]
            self.cpp_info.components["tlvpp"].bindirs = []
            self.cpp_info.components["tlvpp"].libdirs = []

        # OpenTLV's own CMake package exports "OpenTLV::tlv" / "OpenTLV::tlvpp"
        # directly (no top-level "OpenTLV::OpenTLV" alias), matching upstream.
