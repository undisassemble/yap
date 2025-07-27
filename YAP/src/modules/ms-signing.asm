%define ASSEMBLER a.

    lea rcx, [NTD]
    call ShellcodeData.Labels.GetModuleHandleW
    mov rcx, rax
    lea rdx, [SIP]
    call ShellcodeData.Labels.GetProcAddress
    test rax, rax
    strict
    jz ret
    mov edx, 52
    lea r8, [policy]
    mov r9d, holder.labelOffset(NTD) - holder.labelOffset(policy)
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