from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.scm import Git

class Awgconfig(ConanFile):
    name = "awgconfig"
    version = "1.0.20260618.2"
    package_type = "static-library"
    settings = "os", "compiler", "build_type", "arch"

    exports_sources = "src/*"

    def layout(self):
        cmake_layout(self, src_folder="src")

    def source(self):
        src = self.conan_data["sources"][self.version]
        git = Git(self, folder="upstream")
        git.fetch_commit(url=src["url"], commit=src["commit"])

    def generate(self):
        tc = CMakeToolchain(self)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["awgconfig"]
        self.cpp_info.set_property("cmake_target_name", "amnezia::awgconfig")
