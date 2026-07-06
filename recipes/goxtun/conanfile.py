from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.layout import basic_layout
from conan.tools.files import copy, chdir, collect_libs
from conan.tools.gnu import Autotools, AutotoolsToolchain

import os

class Goxtun(ConanFile):
    name = "goxtun"
    version = "1.0.0"
    settings = "os", "arch"
    options = {
        "shared": [True, False],
        "fPIC": [True, False]
    }
    default_options = {
        "shared": False,
        "fPIC": True
    }

    implements = ["auto_shared_fpic"]
    exports_sources = "src/*"

    @property
    def _archs(self):
        return str(self.settings.arch).split("|")

    def layout(self):
        basic_layout(self, src_folder="src")

    def build_requirements(self):
        self.tool_requires("go/1.26.0")

    def generate(self):
        tc = AutotoolsToolchain(self)
        tc.apple_arch_flag = None
        env = tc.environment()
        env.define("OS", str(self.settings.os).lower())
        env.define("GOPATH", os.path.join(self.build_folder, "go"))
        env.define("GOMODCACHE", os.path.join(self.build_folder, "go", "pkg", "mod"))
        env.define("GOCACHE", os.path.join(self.build_folder, ".cache", "go-build"))
        env.define("BUILD_DIR", self.build_folder)
        tc.generate(env)

    def build(self):
        with chdir(self, self.source_folder):
            at = Autotools(self)
            at.make(target=("shared" if self.options.shared else "archive"))

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
