%define ASSEMBLER a.

    lea rcx, [NTD]
    call ShellcodeData.Labels.GetModuleHandleW
    lea rcx, [ADDRFL]
    test rax, rax
    strict
    jz ShellcodeData.Labels.FatalError
    mov rcx, rax
    lea rdx, [GCT]
    call ShellcodeData.Labels.GetProcAddress
    lea rcx, [ADDRFL]
    test rax, rax
    strict
    jz ShellcodeData.Labels.FatalError
    lea rdx, [Context]
    mov rsi, rdx
    %if Options.Packing.bDirectSyscalls
        mov r10, 0xFFFFFFFFFFFFFFFE
        mov ecx, [rax]
        cmp ecx, 0xB8D18B4C
        strict
        jnz ret
        mov eax, [rax + 4]
        syscall
    %else
        mov rcx, 0xFFFFFFFFFFFFFFFE
        call rax
    %endif
    mov rdx, rsi
    lea rcx, [DBGFL]
    test rax, rax
    strict
    jnz ShellcodeData.Labels.FatalError
    mov rax, [rdx + offsetof(CONTEXT, Dr7)]
    and rax, 0x20FF
    strict
    jnz ShellcodeData.Labels.FatalError
    mov rax, [rdx + offsetof(CONTEXT, Dr6)]
    and rax, 0x18F
    strict
    jnz ShellcodeData.Labels.FatalError
    mov rax, [rdx + offsetof(CONTEXT, Dr0)]
    or rax, [rdx + offsetof(CONTEXT, Dr1)]
    or rax, [rdx + offsetof(CONTEXT, Dr2)]
    or rax, [rdx + offsetof(CONTEXT, Dr3)]
    strict
    jnz ShellcodeData.Labels.FatalError