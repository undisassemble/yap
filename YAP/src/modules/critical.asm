    jmp _skip

NTD:
    embed &Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest)
SIP:
    embed &Sha256Str("ZwSetInformationProcess"), sizeof(Sha256Digest)
    align AlignMode::kCode, alignof(BOOL)
data:
    dd 1
ret:
    %ifdef _DEBUG
        %if Options.Debug.bGenerateBreakpoints
            int3
        %endif
    %endif
    ret

_skip:
    lea rcx, [NTD]
    call ShellcodeData.Labels.GetModuleHandleW
    test rax, rax
    strict
    jz ret
    mov rcx, rax
    lea rdx, [SIP]
    call ShellcodeData.Labels.GetProcAddress
    test rax, rax
    strict
    jz ret
    mov edx, 0x1D
    mov r9d, 4
    mov r8, rsp
    and r8, 0b1111
    add r8, 8
    sub rsp, r8
    push r8
    lea r8, [data]
    %if Options.Packing.bDirectSyscalls
        mov r10, 0xFFFFFFFFFFFFFFFF
        mov ecx, [rax]
        cmp ecx, 0xB8D18B4C
        strict
        jnz ret
        mov eax, [rax + 4]
        syscall
    %else
        mov rcx, 0xFFFFFFFFFFFFFFFF
        call rax
    %endif
    pop r8
    add rsp, r8