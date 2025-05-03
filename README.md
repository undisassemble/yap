# Yet Another Packer

> [!Warning]
> YAP is still in development, expect instability and bugs.

Protector for AMD64 Windows PE's (exe, dll).


## Features

Packer
- IAT obfuscation/emulation
- Delayed entry point
- DLL sideloading mitigations
- Hell's Gate
- Anti-dump
- Anti-debug
- Immitation
- Process masquerading
- SDK integration
- Mutation

Reassembler
- Mutation
- Symbol/DOS stub/information stripping
- SDK integration

A more in-depth list of features can be found [here](docs/features.md).

SDK documentation can be found [here](https://undisassemble.dev/yap/docs/yap_8h.html)


## Building

### Basic build

```
cmake . -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

### Build Options

`CMAKE_BUILD_TYPE` can be either `Release` or `Debug` (default).

### Building the installer

The installer build scripts are only produced for `Release` builds. On Windows run `bin/Release/build.bat`, on Linux run `bin/Release/build.sh`.


## Other

- [Main page](https://undisassemble.dev/yap)
- [GitHub](https://github.com/undisassemble/yap)
- [Features](docs/features.md)
- [Documentation](https://undisassemble.dev/yap/docs)


## License

Yet Another Packer is licensed under the MIT License. Third party licenses can be found in `docs/licenses`.