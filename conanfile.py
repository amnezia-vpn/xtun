import os
import subprocess

from conan import ConanFile
from conan.errors import ConanException
from conan.tools.scm import Git
from conan.tools.files import update_conandata
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.build import check_min_cppstd

class Xtun(ConanFile):
    name = "xtun"
    user = "amnezia"
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "bundle_goxtun": [True, False],
        "bundle_wintun": [True, False],
    }
    default_options = { "shared": False, "fPIC": True, "bundle_goxtun": True, "bundle_wintun": True }
    generators = "VirtualBuildEnv", "CMakeConfigDeps"
    implements = ["auto_shared_fpic"]

    def set_version(self):
        if self.version:
            return
        script = os.path.join(self.recipe_folder, "cmake", "version.cmake")
        version = subprocess.check_output(["cmake", "-P", script], text=True).strip()
        if not version:
            raise ConanException(f"'cmake -P {script}' printed no version")
        self.version = version

    def requirements(self):
        if self.options.bundle_wintun and self.settings.os == "Windows":
            # revision is used here to clarify the latest version to use; that's because of frequent recipes update
            # FIXME: remove this one on next upgrade
            self.requires("wintun/0.14.1@amnezia#4671cbda56d3d2c1bea585faed62eeac", libs=False, run=True)
        if self.settings.os == "Windows" and self.settings.arch == "x86_64":
            self.requires("win-split-tunnel/1.2.5.0@amnezia", headers=False, libs=False, run=True)
        if self.settings.os == "Linux":
            self.requires("libsystemd/262.2", transitive_libs=True)
    
    def build_requirements(self):
        self.tool_requires("go/[>=1.27]@amnezia")
        if self.settings.os == "Windows":
            self.tool_requires("mingw-builds/15.1.0")
        self.test_requires("gtest/1.17.0")

    def validate_build(self):
        # xtun requires c++20 for building. however, runtime features are limited by c++17
        check_min_cppstd(self, 20)

    def validate(self):
        check_min_cppstd(self, 17)

    def export(self):
        git = Git(self, self.recipe_folder)
        url, commit = git.get_url_and_commit()
        update_conandata(self, {"sources": {"url": url, "commit": commit}})

    def source(self):
        git = Git(self)
        data = self.conan_data["sources"]
        git.clone(url=data["url"], target=".")
        git.checkout(commit=data["commit"])

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.user_presets_path = False
        tc.cache_variables["BUNDLE_GOXTUN"] = bool(self.options.bundle_goxtun)
        tc.cache_variables["BUNDLE_WINTUN"] = bool(self.options.bundle_wintun)
        tc.cache_variables["BUILD_TESTS"] = False
        tc.cache_variables["USE_CONAN_PROVIDER"] = False
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "amnezia::xtun")

        goxtun = self.cpp_info.components["goxtun"]
        goxtun.set_property("cmake_target_name", "amnezia::goxtun")
        goxtun.libs = ["libgoxtun"] if self.settings.os == "Windows" else ["goxtun"]
        goxtun.includedirs = []
        if self.settings.os == "Linux":
            goxtun.system_libs = ["pthread", "dl"]
        elif self.settings.os in ("Macos", "iOS"):
            goxtun.frameworks = ["CoreFoundation", "Security"]
            goxtun.system_libs = ["resolv"]

        core = self.cpp_info.components["core"]
        core.set_property("cmake_target_name", "amnezia::xtun_core")
        core.libs = ["xtun"]
        if self.options.bundle_goxtun:
            core.requires.append("goxtun")
        if self.settings.os == "Windows":
            core.type = "shared-library" if self.options.shared else "static-library"
            if self.options.shared:
                core.location = "bin/xtun.dll"
                core.link_location = "lib/xtun.lib"
            else:
                core.location = "lib/xtun.lib"
            core.system_libs = ["iphlpapi", "ws2_32", "fwpuclnt", "advapi32"]
            if self.options.bundle_wintun:
                core.requires.append("wintun::wintun")
        elif self.settings.os in ("Linux", "Android"):
            core.system_libs = ["pthread"]
            if self.settings.os == "Linux":
                core.requires.append("libsystemd::libsystemd")
        elif self.settings.os in ("Macos", "iOS"):
            core.frameworks = ["SystemConfiguration", "CoreFoundation"]
