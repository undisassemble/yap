# Yet Another Packer

Protector for AMD64 Windows PE's (exe, dll).


## Features

A full list of features can be seen [here](Features.md).


## Building

### Dependencies

Get submodules: `git submodule update --init --recursive`

### CMake

```
cmake . -DCMAKE_BUILD_TYPE=Release -Bbuild
cmake --build build
```