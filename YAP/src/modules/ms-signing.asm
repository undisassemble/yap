    lea rcx, [NTD]
    call ShellcodeData.Labels.GetModuleHandleW
    mov rcx, rax
    lea rdx, [SIP]
    call ShellcodeData.Labels.GetProcAddress
    test rax, rax
    strict
    jz ret
    ; IF Options.Advanced.bMutateAssembly
        strict
        jnz skippolicy
    ; ELSE
        jmp skippolicy
    ; ENDIF

    align AlignMode::kCode, alignof(PROCESS_MITIGATION_POLICY)

policy:
    embed &_policy, sizeof(PROCESS_MITIGATION_POLICY)
    align AlignMode::kZero, alignof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY)
    embed &sig_policy, sizeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY)

skippolicy:
    mov edx, 52
    lea r8, [policy]
    mov r9d, holder.labelOffset(skippolicy) - holder.labelOffset(policy)
    ; IF Options.Packing.bDirectSyscalls
        mov r10, 0xFFFFFFFFFFFFFFFF
        mov ecx, [rax]
        cmp ecx, 0xB8D18B4C
        strict
        jnz ret
        mov eax, [rax + 4]
        syscall
    ; ELSE
        mov rcx, 0xFFFFFFFFFFFFFFFF
        call rax
    ; ENDIF