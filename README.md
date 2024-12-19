# YAP (Yet Another Packer)

Protector for 64-bit windows PE's (exe, dll).


## Features

A full list of features can be seen [here](Features.md).


## Building

Clone repo:
```
git clone https://github.com/undisassemble/yap.git
cd yap
git submodule update --init --recursive
```

### Visual Studio (Recommended)

1. Set config to `Release x64`
2. Build solution

### CMake

```
cmake . -DCMAKE_BUILD_TYPE=Release
make
```


## Libraries

- [LZMA](https://www.7-zip.org/sdk.html)
- [Zydis](https://github.com/zyantific/zydis)
- [AsmJit](https://asmjit.com/)
- [ImGui](https://github.com/ocornut/imgui)