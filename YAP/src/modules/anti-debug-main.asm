%define ASSEMBLER a.

    ; Check for HWBP
    lea rcx, [NTD]
    call ShellcodeData.Labels.GetModuleHandleW
    lea rcx, [ADDRFL]
    test rax, rax
    strict
    jz ShellcodeData.Labels.FatalError
    mov rcx, rax
    mov rsi, rax
    lea rdx, [GCT]
    call ShellcodeData.Labels.GetProcAddress
    lea rcx, [ADDRFL]
    test rax, rax
    strict
    jz ShellcodeData.Labels.FatalError
    lea rdx, [Context]
    %if Options.Packing.bDirectSyscalls
        mov r10d, [rax]
        lea rcx, [DBGFL]
        cmp r10d, 0xB8D18B4C
        strict
        jnz ShellcodeData.Labels.FatalError
        mov eax, [rax + 4]
        mov r10, 0xFFFFFFFFFFFFFFFE
        syscall
    %else
        mov rcx, 0xFFFFFFFFFFFFFFFE
        call rax
    %endif
    lea rdx, [Context]
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

    ; Check DSE
    mov rcx, rsi
    lea rdx, [QSI]
    call ShellcodeData.Labels.GetProcAddress
    lea rcx, [ADDRFL]
    test rax, rax
    strict
    jz ShellcodeData.Labels.FatalError
    lea rdx, [INTEG_OPT]
    mov r8, sizeof(SYSTEM_CODEINTEGRITY_INFORMATION)
    mov r9, 0
    %if Options.Packing.bDirectSyscalls
        mov r10d, [rax]
        lea rcx, [DBGFL]
        cmp r10d, 0xB8D18B4C
        strict
        jnz ShellcodeData.Labels.FatalError
        mov eax, [rax + 4]
        mov r10, 103
        syscall
    %else
        mov rcx, 103
        call rax
    %endif
    mov eax, [INTEG_OPT + 4]
    xor rax, CODEINTEGRITY_OPTION_ENABLED
    lea rcx, [DSEFL]
    and rax, CODEINTEGRITY_OPTION_ENABLED | CODEINTEGRITY_OPTION_TESTSIGN | CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED
    strict
    jnz ShellcodeData.Labels.FatalError