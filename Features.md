# Features

## General

### Highly customizable

Almost every single feature is toggleable, and if it's not, the source code is free for you to modify to your liking!

## Packer

### Dynamic Shellcode Generation & Mutation

### IAT Obfuscation

### Delayed Entry Point

### Partial Unpacking

Instead of unpacking the whole application at once, parts of the code segment get left out and are only loaded when needed. The code section gets split into different chunks, and when a call is made to a function inside of that chunk, the loader unloads other chunks and loads the requested function. This increases the difficulty of dumping the full running application.

### Immitation

Changes some details about the packed executable to cause programs like [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) to believe it uses a different protection system. Currently supported protectors are: Themida/WinLicense, UPX, MPRESS, Enigma, and ExeStealth. (ExeStealth is only available if Delayed Entry Point is disabled).

### Other


## Reassembler

### Symbol Stripping

Removes debugging symbols from the selected binary, similar to the `strip` command.


## VM

TODO