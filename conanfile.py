from conan import ConanFile

class Xtun(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "VirtualBuildEnv", "CMakeConfigDeps"

    def requirements(self):
        self.requires("goxtun/1.0.0")
        self.requires("awgconfig/1.0.20260618.2")
        if self.settings.os == "Windows":
            self.requires("wintun/0.14.1")

    def build_requirements(self):
        self.test_requires("gtest/1.17.0")
