# Yet Another Packer

Protector for AMD64 Windows PE's (exe, dll).


## Features

A full list of features can be seen [here](Features.md).


## Building

### Dependencies

Windows (requires [vcpkg](https://learn.microsoft.com/en-us/vcpkg/get_started/get-started-msbuild?pivots=shell-cmd#1---set-up-vcpkg)): `vcpkg install`

Debian: `sudo apt install libasmjit-dev libzydis-dev libglfw3-dev`

### CMake

```
cmake . -DCMAKE_BUILD_TYPE=Release -Bbuild
cd build
make
```

### Visual Studio, only builds Windows binaries

1. Set config to `Release x64`
2. Build solution