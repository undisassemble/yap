# Features

## General

### Highly customizable

Almost every single feature is toggleable, and if it's not, the source code is free for you to modify to your liking!

### CLI + GUI

Project files can be easily modified using the GUI. You can then use either the GUI or CLI to protect your applications.

## Packer

### Dynamic Shellcode Generation & Mutation

Each packed application receives it's own unique assembly, preventing signature based detections.

### IAT Obfuscation

Imported function names get stored as SHA-256 hashes and are resolved when your application is started. You can also optionally add an extra wrapper to any imported functions, making IAT reconstruction more difficult.

### Delayed Entry Point

Sets the entry point to an area of memory that is uninitialized, just to add an additional headache to anything that uses static analysis.

### Partial Unpacking

Instead of unpacking the whole application at once, parts of the code segment get left out and are only loaded/unloaded as needed. This increases the difficulty of dumping the full running application. (Also, it's not threadsafe, if the same function is running in multiple different threads, it may get unloaded while the other thread is still using it)

### Immitation

Changes some details about the packed executable to cause programs like [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) to believe it uses a different protection system. Currently supported protectors are: Themida/WinLicense, UPX, MPRESS, Enigma, and ExeStealth. (ExeStealth is only available if Delayed Entry Point is disabled).

### Other

Includes other features like anti-debug, 

## Reassembler

### Symbol Stripping

Removes debugging symbols from the selected binary, similar to the `strip` command.


## VM

TODO