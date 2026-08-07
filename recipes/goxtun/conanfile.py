from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.layout import basic_layout
from conan.tools.files import copy, chdir, collect_libs
from conan.tools.gnu import Autotools, AutotoolsToolchain

import os
import shutil
import stat
from io import StringIO


def _make_writable(path):
    # Module-cache copies are read-only; add the owner-write bit so the tree can be
    # patched and later removed.
    if not os.path.isdir(path):
        return
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            p = os.path.join(root, name)
            os.chmod(p, os.stat(p).st_mode | stat.S_IWUSR)
    os.chmod(path, os.stat(path).st_mode | stat.S_IWUSR)

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

    # --- amneziawg-go SetMark bypass patches (TEMPORARY) ---------------------
    # Published amneziawg-go v0.2.18 has no per-socket bypass on darwin (its
    # StdNetBind.SetMark is a no-op there), so libxtun's IP_BOUND_IF bypass never
    # reaches the proxy's own socket. src/_awgpatch/conn/ holds the fixed
    # conn/mark_*.go. Go refuses to -overlay files under GOMODCACHE, so we copy the
    # fetched module to a writable dir, swap those two files in, and `replace` the
    # module with the patched copy — no full vendored fork committed.
    #
    # TO REMOVE, once the SetMark changes are merged upstream into amneziawg-go:
    #   1. bump `require github.com/amnezia-vpn/amneziawg-go` in src/go.mod to the
    #      released version that contains them;
    #   2. delete the src/_awgpatch/ directory;
    #   3. delete _patch_awg_module() below and its call in build().
    _awg_module = "github.com/amnezia-vpn/amneziawg-go"

    def _patch_awg_module(self):
        self.run(f"go mod download {self._awg_module}")
        out = StringIO()
        self.run(f"go list -m -f {{{{.Dir}}}} {self._awg_module}", stdout=out)
        cache_dir = out.getvalue().strip()

        # Copy the module out of the read-only cache (GOMODCACHE can't be replaced
        # in place) and make the copy writable.
        dest = os.path.join(self.build_folder, "awgpatched")
        _make_writable(dest)
        shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(cache_dir, dest)
        _make_writable(dest)

        patch_conn = os.path.join(self.source_folder, "_awgpatch", "conn")
        for name in ("mark_default.go", "mark_darwin.go"):
            shutil.copyfile(os.path.join(patch_conn, name), os.path.join(dest, "conn", name))

        self.run(f"go mod edit -replace {self._awg_module}={dest}")

    def build(self):
        with chdir(self, self.source_folder):
            self._patch_awg_module()
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
