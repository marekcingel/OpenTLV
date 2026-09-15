import os
import re

from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.files import copy, get, rmdir
from conan.tools.scm import Git

required_conan_version = ">=2.0"

# "<tag>-<commits-since-tag>-g<hash>", as produced by `git describe --tags
# --long`; <tag> may itself carry a SemVer pre-release suffix, e.g.
# "0.3.0-alpha.1-0-gabc1234".
_GIT_DESCRIBE_RE = re.compile(
    r"^(?P<tag>\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)-(?P<count>\d+)-g[0-9a-f]+$"
)


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

    def set_version(self):
        # set_version() runs unconditionally and would otherwise clobber an
        # explicit `conan create --version=...`, which conan-publish.yml and
        # ConanCenter's own CI always pass; only fill in a version here for
        # local development (e.g. `conan create conan/all` with no
        # --version) against a checkout of the OpenTLV repository itself.
        if self.version is not None:
            return
        describe = Git(self, folder=self.recipe_folder).run(
            "describe --tags --long --match [0-9]*"
        ).strip()
        match = _GIT_DESCRIBE_RE.match(describe)
        if not match:
            raise ConanInvalidConfiguration(
                f"Could not parse an OpenTLV version from 'git describe' output: {describe!r}"
            )
        tag, commits_since_tag = match["tag"], int(match["count"])
        self.version = tag if commits_since_tag == 0 else f"{tag}-{commits_since_tag}"

    def config_options(self):
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def layout(self):
        cmake_layout(self, src_folder="src")

    def export_sources(self):
        # Local development only (see set_version()): a version with no
        # conandata.yml entry has no release archive to fetch in source(),
        # so mirror the checkout containing this recipe into the exported
        # recipe now, while self.recipe_folder still points at that
        # checkout, for source() to copy from later.
        if self.version in self.conan_data.get("sources", {}):
            return
        repo_root = os.path.normpath(os.path.join(self.recipe_folder, os.pardir, os.pardir))
        copy(self, "*", src=repo_root, dst=self.export_sources_folder,
             excludes=(".git/*", "build*/*", "conan/all/test_package/build/*"))

    def source(self):
        sources = self.conan_data.get("sources", {})
        if self.version in sources:
            get(self, **sources[self.version], strip_root=True)
        else:
            copy(self, "*", src=self.export_sources_folder, dst=self.source_folder)

        # OpenTLV derives OPENTLV_VERSION_STRING (tlv_version() at runtime)
        # from `git describe` against the checkout; neither the extracted
        # release tarball nor the plain copy above has a .git, so recreate a
        # minimal repository tagged at this version, or the packaged library
        # reports version "0.0.0".
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
