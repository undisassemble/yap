# Features

Contains a description of each toggleable feature present, everything is named as it appears in the GUI. All features with the :soon: icon are not present in release builds, and are still being worked on or tested.


## Packer

Compresses and encodes the original program, and wraps a custom loader around it.

### Don't pack resources

Avoids packing the resource directory, maintaining any information stored in it. Useful if your program uses resources.

### Depth

Number of times to pack the application. Similar to packing an already packed app.

### Compression level

How much LZMA should compress the binary.

### Mutation level

How much garbage code should be generated in the loader shellcode. Can optionally be completely disabled in `Advanced`.

### Hide IAT

Encodes imported addresses, to make it harder to recover imported addresses.

### API emulation

Replaces some imported functions with substitutions. Functions behave the same but do not rely on WINAPI calls.

### Delayed entry point

Changes the PE entry point to be in uninitialized memory. This is just because I felt like it, I don't think it actually has a practical purpose.

### DLL sideloading mitigations

Prioritizes DLLs found in Windows directories instead of the local directory.

### Only load Microsoft signed DLLs

Only allows DLLs signed by Microsoft to be loaded.

### Direct syscalls

Replaces WINAPI function calls with direct kernel syscalls where possible. Avoids hooks on some functions.

### Anti-dump

Makes it harder to dump and reconstruct the running process.

> [!IMPORTANT]
> If you enable this feature, you must use `GetSelf()` to get the process base address instead of `GetModuleHandle(NULL)`.

### Anti-debug

Checks for the presence of debuggers before unpacking the application.

> [!IMPORTANT]
> This does not spawn a protective thread, and will not catch debugger attached after launch. To prevent attaching, use the function `CheckForDebuggers()`.

### Anti-patch :soon:

### Anti-VM :soon:

### Allow Hyper-V :soon:

### Anti-sandbox :soon:

### Partial unpacking :soon:

### Immitate packer

### Process masquerading

### Mark critical :soon:

### Leave a message

### SDK

## Reassembler

### Mutation level

### Remove useless data

### Strip debug symbols

### Strip DOS stub

### Instruction substitution

### SDK


## Advanced

### UPX version

### Fake symbol table

### Mutate

### Semi-random section names

### Full-random section names

### Rebase image