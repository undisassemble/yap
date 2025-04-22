%define ASSEMBLER a.

    jmp _skip

    align AlignMode::kCode, alignof(LPCSTR)
USR:
    embed "USER32.dll", 11
GCP:
    embed &Sha256Str("GetCursorPos"), sizeof(Sha256Digest)
SLP:
    embed &Sha256Str("Sleep"), sizeof(Sha256Digest)
_KRN:
    embed &Sha256WStr(L"KERNEL32.DLL"), sizeof(Sha256Digest)
LLA:
    embed &Sha256Str("LoadLibraryA"), sizeof(Sha256Digest)
    align AlignMode::kCode, 0x10
PT:
    dq rand64()
    dq rand64()

_skip:
    lea rcx, [_KRN]
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
    push rsi
    push rbx
    call rax
    add rsp, 0x10
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