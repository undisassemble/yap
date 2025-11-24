# Tests Directory

Holds a bunch of binaries that should for testing. Source code is provided for manual compiling, details on how they were compiled are provided below.

| File                                     | Compiler + Version | Optimization Flags |
|------------------------------------------|--------------------|--------------------|
| `hello-clangxx-noopt.exe`                | Clang++ 21.1.6     | `-O0`              |
| `hello-clangxx-optsize.exe`              | Clang++ 21.1.6     | `-Oz`              |
| `hello-clangxx-optspeed.exe`             | Clang++ 21.1.6     | `-O3`              |
| `hello-gxx-noopt.exe`                    | G++ 14.0.0         | `-O0`              |
| `hello-gxx-optsize.exe`                  | G++ 14.0.0         | `-Oz`              |
| `hello-gxx-optspeed.exe`                 | G++ 14.0.0         | `-O3`              |
| `hello-msvc-noopt.exe`                   | MSVC 19.50.35718   | `/Od`              |
| `hello-msvc-optsize.exe`                 | MSVC 19.50.35718   | `/O1 /Oi /Os /GL`  |
| `hello-msvc-optspeed.exe`                | MSVC 19.50.35718   | `/O2 /Oi /Ot /GL`  |
| `switches-clang-noopt.exe`               | Clang 21.1.6       | `-O0`              |
| `switches-clang-optsize.exe`             | Clang 21.1.6       | `-Oz`              |
| `switches-clang-optspeed.exe`            | Clang 21.1.6       | `-O3`              |
| `switches-gcc-noopt.exe`                 | GCC 14.0.0         | `-O0`              |
| `switches-gcc-optsize.exe`               | GCC 14.0.0         | `-Oz`              |
| `switches-gcc-optspeed.exe`              | GCC 14.0.0         | `-O3`              |
| `switches-msvc-noopt`                    | MSVC 19.50.35718   | `/Od`              |
| `switches-msvc-optsize.exe`              | MSVC 19.50.35718   | `/O1 /Oi /Os /GL`  |
| `switches-msvc-optspeed.exe`             | MSVC 19.50.35718   | `/O2 /Oi /Ot /GL`  |