from conan import ConanFile
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

    def config_options(self):
        # Windows has no c-archive target, only a DLL plus a generated import lib.
        if self.settings.os == "Windows":
            del self.options.shared

    @property
    def _archs(self):
        return str(self.settings.arch).split("|")

    def layout(self):
        basic_layout(self, src_folder="src")

    def build_requirements(self):
        self.tool_requires("go/1.26.0")
        if self.settings.os == "Windows":
            self.tool_requires("mingw-builds/15.1.0")
            self.tool_requires("msys2/cci.latest")

    def generate(self):
        tc = AutotoolsToolchain(self)
        tc.apple_arch_flag = None
        env = tc.environment()
        env.define("OS", str(self.settings.os).lower())
        env.define("GOPATH", os.path.join(self.build_folder, "go"))
        env.define("GOMODCACHE", os.path.join(self.build_folder, "go", "pkg", "mod"))
        env.define("GOCACHE", os.path.join(self.build_folder, ".cache", "go-build"))
        # Make's shell is POSIX sh, which would eat Windows path backslashes.
        env.define("BUILD_DIR", self.build_folder.replace("\\", "/"))
        tc.generate(env)

    def build(self):
        with chdir(self, self.source_folder):
            at = Autotools(self)
            shared = self.options.get_safe("shared", True)
            at.make(target=("shared" if shared else "archive"))

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
