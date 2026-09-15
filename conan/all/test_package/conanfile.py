import os

from conan import ConanFile
from conan.tools.build import can_run
from conan.tools.cmake import CMake, cmake_layout


class OpenTLVTestConan(ConanFile):
    settings = "os", "arch", "compiler", "build_type"
    generators = "CMakeToolchain", "CMakeDeps"

    def requirements(self):
        self.requires(self.tested_reference_str)

    def layout(self):
        cmake_layout(self)

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def test(self):
        if can_run(self):
            c_exe = os.path.join(self.cpp.build.bindir, "test_package_c")
            self.run(c_exe, env="conanrun")

            if self.dependencies[self.tested_reference_str].options.with_cxx:
                cxx_exe = os.path.join(self.cpp.build.bindir, "test_package_cpp")
                self.run(cxx_exe, env="conanrun")
