%define ASSEMBLER a.

    jmp skipdata

    align AlignMode::kCode, alignof(CONTEXT)
Context:
    embed &context, sizeof(CONTEXT)
NTD:
    embed &Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest)
GCT:
    embed &Sha256Str("ZwGetContextThread"), sizeof(Sha256Digest)

skipdata:
    lea rcx, [NTD]
    call ShellcodeData.Labels.GetModuleHandleW
    mov rcx, rax
    lea rdx, [GCT]
    call ShellcodeData.Labels.GetProcAddress
    test rax, rax
    strict
    jz ret
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
    test rax, rax
    strict
    jnz ret
    mov rax, [rdx + offsetof(CONTEXT, Dr7)]
    and rax, 0x20FF
    strict
    jnz ret
    mov rax, [rdx + offsetof(CONTEXT, Dr6)]
    and rax, 0x18F
    strict
    jnz ret
    mov rax, [rdx + offsetof(CONTEXT, Dr0)]
    or rax, [rdx + offsetof(CONTEXT, Dr1)]
    or rax, [rdx + offsetof(CONTEXT, Dr2)]
    or rax, [rdx + offsetof(CONTEXT, Dr3)]
    strict
    jnz ret