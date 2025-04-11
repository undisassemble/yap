# Building

## Clone

```
git clone https://github.com/undisassemble/yap.git
cd yap
git submodule update --init --recursive
```


## Basic build

```
cmake . -DCMAKE_BUILD_TYPE=Release
cmake --build .
```


## Build Options

`CMAKE_BUILD_TYPE` can be either `Release` or `Debug` (default).

`ENABLE_DUMPING` enables option to dump disassembly in debug builds (increases memory usage). On release builds this is ignored.


## Building the installer

The installer build scripts are only produced for `Release` builds. On Windows run `bin/Release/build.bat`, on Linux run `bin/Release/build.sh`.


## Notes

- You probably need to change the encoding of file `YAP/dependencies/zydis/resources/VersionInfo.rc` to utf-8.