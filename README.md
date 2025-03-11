# Yet Another Packer

Protector for AMD64 Windows PE's (exe, dll).


## Features

A full list of features can be seen [here](Features.md).


## Building

### Clone + Build Release

```
git clone https://github.com/undisassemble/yap.git
cd yap
git submodule update --init --recursive
cmake . -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

You probably need to change the encoding of file `YAP/dependencies/zydis/resources/VersionInfo.rc` to utf-8.


### Build Options

`CMAKE_BUILD_TYPE` can be either `Release` or `Debug` (default).

`ENABLE_DUMPING` enables option to dump disassembly in debug builds (increases memory usage). On release builds this is ignored.