from conan import ConanFile

class Xtun(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "VirtualBuildEnv", "CMakeConfigDeps"

    def requirements(self):
        self.requires("goxtun/1.0.0")
        if self.settings.os == "Windows":
            self.requires("wintun/0.14.1")
        if self.settings.os == "Linux":
            self.requires("libsystemd/255.10")

    def build_requirements(self):
        self.test_requires("gtest/1.17.0")
