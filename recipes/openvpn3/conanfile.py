from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.files import copy, get
from conan.tools.layout import basic_layout

import os

required_conan_version = ">=2.25"


class OpenVPN3(ConanFile):
    name = "openvpn3"
    version = "3.11.7"

    description = "OpenVPN 3 Core client library"
    homepage = "https://github.com/OpenVPN/openvpn3"
    license = "MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception"

    package_type = "header-library"

    settings = "os", "arch", "compiler", "build_type"
    no_copy_source = True

    def layout(self):
        basic_layout(self, src_folder="src")

    def requirements(self):
        self.requires("asio/1.38.2")
        # Linux's libsystemd/255.10 requires LZ4 1.9.4; 1.10.0 matches prebuilt Windows package from Artifactory
        self.requires("lz4/1.9.4" if self.settings.os == "Linux" else "lz4/1.10.0")
        self.requires("openssl/3.6.1")

    def validate(self):
        if self.settings.os not in ("Windows", "Linux", "Macos"):
            raise ConanInvalidConfiguration(
                "openvpn3 is currently supported only on Windows, Linux and Macos"
            )

        if self.settings.os == "Windows" and self.settings.compiler != "msvc":
            raise ConanInvalidConfiguration(
                "openvpn3 is currently supported only with MSVC on Windows"
            )

    def package_id(self):
        self.info.clear()

    def source(self):
        get(
            self,
            **self.conan_data["sources"][str(self.version)],
            strip_root=True,
        )
        # OpenVPN's Windows headers require tap-windows.h in external TUN mode.
        get(
            self,
            **self.conan_data["tap_windows6"],
            destination="tap-windows6",
            strip_root=True,
        )

    def package(self):
        core_dst = os.path.join(self.package_folder, "src", "openvpn3")
        licenses_dst = os.path.join(self.package_folder, "licenses")

        # Include the license texts for the third-party packages.
        copy(self, "LICENSE.md", src=self.source_folder, dst=licenses_dst)
        copy(
            self,
            "*",
            src=os.path.join(self.source_folder, "LICENSES"),
            dst=os.path.join(licenses_dst, "LICENSES"),
        )
        copy(
            self,
            "COPYRIGHT.MIT",
            src=os.path.join(self.source_folder, "tap-windows6"),
            dst=os.path.join(licenses_dst, "tap-windows6"),
        )
        copy(
            self,
            "*",
            src=os.path.join(self.source_folder, "openvpn"),
            dst=os.path.join(core_dst, "openvpn"),
        )
        copy(
            self,
            "ovpncli.?pp",
            src=os.path.join(self.source_folder, "client"),
            dst=os.path.join(core_dst, "client"),
        )
        copy(
            self,
            "tap-windows.h",
            src=os.path.join(self.source_folder, "tap-windows6", "src"),
            dst=core_dst,
        )

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "openvpn3")
        self.cpp_info.set_property("cmake_target_name", "amnezia::openvpn3")

        self.cpp_info.includedirs = ["src/openvpn3"]
        self.cpp_info.libdirs = []
        self.cpp_info.bindirs = []
        self.cpp_info.frameworkdirs = []
        self.cpp_info.resdirs = []

        # xtun compiles these sources with the OpenVPN backends selected below.
        self.cpp_info.sources = [
            "src/openvpn3/client/ovpncli.cpp",
            "src/openvpn3/openvpn/crypto/data_epoch.cpp",
        ]
        self.cpp_info.languages = ["C++"]
        self.cpp_info.defines = [
            "ASIO_STANDALONE",
            "USE_ASIO",
            "USE_OPENSSL",
            "HAVE_LZ4",
            "OPENVPN_EXTERNAL_TUN_FACTORY",
            "OPENVPN_CORE_API_VISIBILITY_HIDDEN",
        ]

        if self.settings.os == "Windows":
            self.cpp_info.defines.extend([
                # Expose the Windows APIs used by OpenVPN 3 Core.
                "_WIN32_WINNT=0x0600",
                # Shared Windows headers reference this ID without enabling TAP.
                "TAP_WIN_COMPONENT_ID=tap0901",
                # Standalone Asio has no local sockets on Windows.
                "ASIO_DISABLE_LOCAL_SOCKETS",
            ])
            # ovpncli.cpp exceeds MSVC's default object section limit.
            self.cpp_info.cxxflags.append("/bigobj")
            # OpenVPN 3 Core calls these Windows system APIs.
            self.cpp_info.system_libs.extend([
                "fwpuclnt",
                "iphlpapi",
                "wininet",
                "setupapi",
                "rpcrt4",
                "wtsapi32",
            ])
        elif self.settings.os == "Macos":
            self.cpp_info.frameworks.extend([
                "CoreFoundation",
                "IOKit",
                "CoreServices",
                "SystemConfiguration",
            ])
            self.cpp_info.system_libs.append("pthread")
        elif self.settings.os == "Linux":
            self.cpp_info.system_libs.append("pthread")
