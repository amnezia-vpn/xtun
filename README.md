# xtun - eXtended tunneling library

```
                                                          attach_proxy()
                         bypasses in case of              \- works as one-to-many (TBD)
                         a single Proxy without           |- could be changed in runtime
                         split-tunneling is used          v
                                                \    +------------+--------------+-------------+
                                                 \   |            |              |             |
                                                  \  |            v              v             v
    +---- Device ----+       +-- xtun Tunnel --+  |  |    +-- xtun Proxy --+           +-- xtun Proxy --+
    |                |       |                 |  v  |    |                |           |                |
    |      TUN   --------------->  Virt IO ----------+    |  Proto harness |           |                |
    |                |       |        |        |     |    |  |- config     |    ...    |       *        |
    |                |       |        v        |     |    |  |- status     |           |                |
    |                |       |      Split      |     |    |  `- logs       |           |                |
    |       OS    <----+     |    tunneling ---------+    |       |        |     |     |       |        |
    |    features    |  \    |      (TBD)      |          +------ | -------+     |     +------ | -------+
    |                |   \   |                 |                  |              |             |         
    |                |    \  |                 |                  +--------------+-------------+
    |                |     +--- Net Harness    |                                / 
    |   Internet     |       |  |- Routing     |                               /
    |   interface    |   ^   |  |- Killswitch  |                              /
    |       ^        |   |   |  `- DNS         |             +---------------+---------------+              
    +------ | -------+   |   +-----------------+             |                               |
            |            |                                   v                               v
            |            |                         +-- native providers --+       +-- goxtun (go glue) --+
            |       Net Harness                    |   |- OpenVPN     TBD |       |    |- AmneziaWG      |
            |       is optional                    |   `- IPsec/IKEv2 TBD |       |    `- Xray-core      |
            |                                      |          |           |       |          |           |
            |                                      +--------- | ----------+       +--------- | ----------+
            |                                                 |                              |
            +-------------------------------------------------+------------------------------+
                                ^
                    all connections are bound
                        to the interface
```

## Design

xtun is built to be a thin abstraction layer over a network, proxies, and platform features
The idea is to put 2 basic concepts:
- Tunnel, which is L3 (TUN and similar) and L5 (SOCKS/5 and others) packet handler, IO driver for Proxies
- and Proxy, which provides the actual "solution" for the provided packets

The original implementation does only provide IO and harness for the actual solutions, and does not NAT anything (except of the solution providers that require the feature, i.e. Xray-core)
  
Any of Proxies could be changed anytime to another one(s) - once the action happened the Tunnel redirects packet flow to a new Proxy

## Hacking guide

General setup requires 3 things:
- `C/C++` compiler that supports C++20 
- `CMake` version 3.25+
- `Conan` version 2+

Just run CMake in the way you like, and build `xtun` target as static library.  
Use `BUILD_SHARED_LIBS` to compile it as the shared one.

### Language-specific bindings

This project automatically deploys artifacts and recipes to package managers  
The following ones are officially available:

### C/C++ (Conan)

The project's recipe is stored on our [artifactory](artifactory.amnezia.org) in `recipes` repository  
Use this command to utilize this repo:
```
conan remote add amnezia "https://artifactory.amnezia.org/artifactory/api/conan/conan"
```
The recipe's name contains user `@amnezia` at the end, make sure to include it in your Conanfile
```
self.requires("xtun/0.0.2@amnezia")
```

### Java/Android

Prebuilt `.aar` artifacts are stored in Maven repository and available via this link
```
https://maven.amnezia.org/
```
You can find there further instructions of using this repository under different setups  
There is also a [sample project](https://github.com/amnezia-vpn/xtun/tree/master/java/android/sample) that demonstrates how you can use xtun library on Android

### Swift (Swift Package Manager)

SPM-compatible repository for Swift projects is available via this link:
```
https://github.com/amnezia-vpn/xtun-swift
```
You can use it directly in XCode (File->Add package dependencies... and paste the link above into search box at the top)  
There is also a [sample project](https://github.com/amnezia-vpn/xtun/tree/master/swift/Sample) that demonstrates how you can use xtun library on Apple (NetworkExtension)

## Codestyle and coding guidelines

All C++ code of the project _should_ be written based on `.clang-format` and `.clang-tidy` rules, or their interpretations. These 2 files are the main places of the original conventions, and should be referred by the contributors.

The original project use rebase approach in pull requests, meaning all the commits made during PR are being put to the `master` branch once PR is "merged".  
Make commits meaningful, track their amount, and put different features into the separate commits. All commit messages must follow [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) format

## Troubleshooting

Not yet ready - figure it out yourself :)
