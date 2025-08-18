%define ASSEMBLER a.

FL_LDER:
    embed "Failed to initialize", 21
MS_DLL:
    embed "Failed to load DLL", 19
IMP_NM:
    embed "Failed to get address of imported function", 43

; GLOBAL
skip:
    lea rsi, [FL_LDER]
    lea rax, [InternalRelOff]
    sub rax, [rax]
    mov [InternalRelOff], rax
    lea rcx, [KERNEL32DLL]
    call ShellcodeData.Labels.GetModuleHandleW
    test rax, rax
    strict
    cmovz rcx, rsi
    strict
    jz ShellcodeData.Labels.FatalError
    mov rcx, rax
    lea rdx, [LLA]
    call ShellcodeData.Labels.GetProcAddress
    test rax, rax
    strict
    cmovz rcx, rsi
    strict
    jz ShellcodeData.Labels.FatalError
    mov rsi, rax
    lea rdi, [import_offsets]
    %if Options.Packing.bHideIAT
        lea r13, [import_array]
    %else
        mov r13, rdi
    %endif
    lea r12, [import_names]
    mov r14, 0
    
do_item:
    mov r15, [rdi]
    and r15, 0xFFFFFFFF
    test r15, r15
    strict
    jz do_lib
    cmp r15, 1
    strict
    jz done
    test r14, r14
    strict
    jz ret
    mov rcx, r14
    mov rdx, [r12]
    add rdx, [r12 + 0x08]
    add rdx, [r12 + 0x10]
    add rdx, [r12 + 0x18]
    test rdx, rdx
    strict
    jz skiptest
    mov rdx, r12
    %if Options.Packing.bHideIAT
        mov r8, 1
        ror r8, 1
        or rcx, r8
    %endif
    call ShellcodeData.Labels.GetProcAddress
    lea rcx, [IMP_NM]
    test rax, rax
    strict
    jz ShellcodeData.Labels.FatalError

skiptest:
    %if !Options.Packing.bHideIAT
        mov r8, r13
        sub r8, r15
        mov [r8], rax
    %else
        mov r8, 1
        ror r8, 1
        and r8, rax
        strict
        jz obfuscate_ptr
        not r8
        and rax, r8
        jmp end_obfuscation

; Encodes ptr
obfuscate_ptr:
        ; RAW_C for (int i = DecoderProc.Size() - 1; i > 0; i--) {
            %if DecoderProc[i].Mnemonic == DI_XOR
                xor rax, DecoderProc[i].value
            %elif DecoderProc[i].Mnemonic == DI_NOT
                not rax
            %elif DecoderProc[i].Mnemonic == DI_NEG
                neg rax
            %elif DecoderProc[i].Mnemonic == DI_ADD
                sub rax, DecoderProc[i].value
            %elif DecoderProc[i].Mnemonic == DI_SUB
                add rax, DecoderProc[i].value
            %endif
        ; RAW_C }
        ; RAW_C DecoderProc.Release();
        mov [r13], rax
        mov rax, r13
        sub rax, holder.labelOffset(import_array) - holder.labelOffset(jumper_array)
        sub rax, [rax]

end_obfuscation:
        lea r8, [import_offsets]
        sub r8, r15
        mov [r8], rax
        add r13, 8
    %endif
    add r12, sizeof(Sha256Digest)
    jmp next

do_lib:
    mov rcx, rsp
    and rcx, 0b1111
    add rcx, 8
    sub rsp, rcx
    push rcx
    mov rcx, r12
    sub rsp, 0x20
    call rsi
    add rsp, 0x20
    lea rcx, [MS_DLL]
    test rax, rax
    strict
    jz ShellcodeData.Labels.FatalError
    pop rcx
    add rsp, rcx
    mov r14, rax

next_name:
    mov byte [r12], 0
    inc r12
    cmp byte [r12], 0
    strict
    jne next_name
    inc r12

next:
    mov dword [rdi], 0
    add rdi, 4
    jmp do_item

ret:
    push 0
    sub qword [rsp], 1
    popfq 
    jmp entrypt

done: