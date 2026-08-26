# xtun - eXtended tunneling library

## Hacking guide

General setup requires 3 things:
- `C/C++` compiler that supports C++20 
- `CMake` version 3.25+
- `Conan` version 2+

Just run CMake in the way you like, and build `xtun` target as static library.  
Use `BUILD_SHARED_LIBS` to compile it as the shared one.

### Language-specific bindings

To be done

## Codestyle and coding guidelines

All C++ code of the project _should_ be written based on `.clang-format` and `.clang-tidy` rules, or their interpretations. These 2 files are the main places of the original conventions, and should be referred by the contributors.

The original project use rebase approach in pull requests, meaning all the commits made during PR are being put to the `master` branch once PR is "merged".  
Make commits meaningful, track their amount, and put different features into the separate commits. All commit messages must follow [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) format

## Troubleshooting

Not yet ready - figure it out yourself :)
