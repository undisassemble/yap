    jmp skip

    align AlignMode::kCode, alignof(DWORD)
KRN:
    embed &Sha256WStr(L"KERNEL32.DLL"), sizeof(Sha256Digest)
VRT:
    embed &Sha256Str("VirtualProtect"), sizeof(Sha256Digest)
    
skip:
    mov rax, PEB
    mov qword [rax + 0x10], 0
    lea rcx, [KRN]
    call ShellcodeData.Labels.GetModuleHandleW
    test rax, rax
    strict
    jz ret
    mov rcx, rax
    lea rdx, [VRT]
    call ShellcodeData.Labels.GetProcAddress
    test rax, rax
    strict
    jz ret
    mov rcx, pPackedBinary->NTHeaders.OptionalHeader.ImageBase
    add rcx, [Reloc]
    mov edx, [rcx + offsetof(IMAGE_DOS_HEADER, e_lfanew)]
    add rdx, rcx
    mov edx, [rdx + offsetof(IMAGE_NT_HEADERS64, OptionalHeader.SizeOfHeaders)]
    push rdx
    push rcx
    lea r9, [KRN]
    mov rsi, rax
    sub rsp, 0x18
    mov r8, rsp
    and r8, 0b1111
    add r8, 8
    sub rsp, r8
    push r8
    mov r8, 0x40
    sub rsp, 0x20
    call rax
    add rsp, 0x20
    pop r8
    add rsp, r8
    add rsp, 0x18
    pop rcx
    pop rdx
    call ShellcodeData.Labels.RtlZeroMemory