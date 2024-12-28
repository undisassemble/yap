# YAP (Yet Another Packer)

Protector for 64-bit windows PE's (exe, dll).


## Features

A full list of features can be seen [here](Features.md).


## Building (requires [vcpkg](https://learn.microsoft.com/en-us/vcpkg/get_started/get-started-msbuild?pivots=shell-cmd#1---set-up-vcpkg))

Clone repo:
```
git clone https://github.com/undisassemble/yap.git
cd yap
vcpkg install
```

### Visual Studio (Recommended)

1. Set config to `Release x64`
2. Build solution

### CMake

```
cmake . -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake
make
```