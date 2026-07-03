from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.layout import basic_layout
from conan.tools.files import copy, chdir, collect_libs
from conan.tools.gnu import Autotools, AutotoolsToolchain

import os

class Goxtun(ConanFile):
    name = "goxtun"
    version = "1.0.0"

    package_type = "application"
    settings = "os", "arch"

    exports_sources = "src/*"

    @property
    def _archs(self):
        return str(self.settings.arch).split("|")
    
    @property
    def _is_multiarch(self):
        return len(self._archs) > 1

    def layout(self):
        basic_layout(self)

    def build_requirements(self):
        self.tool_requires("go/1.26.0")

    def validate(self):
        if not self._goos or not self._goarchs:
            raise ConanInvalidConfiguration(
                f"{self.name} v{self.version} does not support {self.settings.os} {self.settings.arch}"
            )

    def generate(self):
        tc = AutotoolsToolchain(self)
        tc.apple_arch_flag = None
        env = tc.environment()
        env.define("OS", self.settings.os)
        env.define("GOPATH", os.path.join(self.build_folder, "go"))
        env.define("GOMODCACHE", os.path.join(self.build_folder, "go", "pkg", "mod"))
        env.define("GOCACHE", os.path.join(self.build_folder, ".cache", "go-build"))
        env.define("BUILD_DIR", self.build_folder)
        tc.generate(env)

    def build(self):
        with chdir(self, self.source_folder):
            at = Autotools(self)
            at.make()

    def package(self):
        copy(self, "libgoxtun.a", self.build_folder, dst=os.path.join(self.package_folder, "lib"), keep_path=False)
        copy(self, "libgoxtun.so", self.build_folder, dst=os.path.join(self.package_folder, "lib"), keep_path=False)
        copy(self, "libgoxtun.dylib", self.build_folder, dst=os.path.join(self.package_folder, "lib"), keep_path=False)
        copy(self, "libgoxtun.lib", self.build_folder, dst=os.path.join(self.package_folder, "lib"), keep_path=False)
        copy(self, "libgoxtun.dll", self.build_folder, dst=os.path.join(self.package_folder, "bin"), keep_path=False)
        copy(self, "libgoxtun.h", self.build_folder, dst=os.path.join(self.package_folder, "include"), keep_path=False)

    def package_info(self):
        self.cpp_info.libs = collect_libs(self)
        self.cpp_info.set_property("cmake_target_name", "amnezia::goxtun")
