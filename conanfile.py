from conan import ConanFile

class Xtun(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "VirtualBuildEnv", "CMakeConfigDeps"

    def requirements(self):
        self.requires("goxtun/1.0.0")
