# Features

## General

### Highly customizable

Almost every single feature is toggleable, and if it's not, the source code is free for you to modify to your liking!

### CLI + GUI

Project files can be easily modified using the GUI. You can then use either the GUI or CLI to protect your applications.


## Packer

### Dynamic Shellcode Generation & Mutation

Each packed application receives it's own unique assembly, preventing signature based detections. It also adds several anti-disassembly techniques to make analysis more difficult.

### IAT Obfuscation

Imported function names are stored as SHA-256 hashes and get resolved when your application is started. You can also optionally add an extra wrapper to imports, and emulate some API functions.

### Delayed Entry Point

Sets the entry point to an area of memory that is uninitialized, just to add an additional headache to anything that uses static analysis.

### DLL sideloading mitigation

Prioritize loading DLLs in the Windows directory, and/or only allow DLLs signed by Microsoft to be loaded.

### Direct Syscalls

Makes syscalls directly where possible, going around user-mode WINAPI hooks on those functions.

### Anti-dump

Makes it harder for software like Scylla to dump the running process back to disk.

### Partial Unpacking

Instead of unpacking the whole application at once, parts of the code segment get left out and are only loaded/unloaded as needed. This increases the difficulty of dumping the full running application. (Also, it's not threadsafe, if the same function is running in multiple different threads, it may get unloaded while the other thread is still using it)

### Immitation

Changes some details about the packed executable to cause programs like [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) to believe it uses a different protection system. Currently supported protectors are: Themida/WinLicense, UPX, MPRESS, Enigma, and ExeStealth. (ExeStealth is only available if Delayed Entry Point is disabled).

### SDK

Provides a communication layer between your application and the packer.

### Other

Includes other features like anti-debug, anti-dump, anti-vm, anti-patch, and others.


## Reassembler

### Information Stripping

Options to remove the DOS stub, unnecessary header info, and debugging symbols (similar to the `strip` command).

### Mutation

Assembles the original binary using the same mutation engine used for the packer, with options to protect the full program or only select segments (through the SDK).

## VM

TODO