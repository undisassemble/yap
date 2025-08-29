%define ASSEMBLER a.
    
    ; Get imports
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
    
    ; Set header protection +r
    mov rcx, pPackedBinary->NTHeaders.OptionalHeader.ImageBase
    add rcx, [Reloc]
    mov edx, [rcx + offsetof(IMAGE_DOS_HEADER, e_lfanew)]
    add rdx, rcx
    mov edx, [rdx + offsetof(IMAGE_NT_HEADERS64, OptionalHeader.SizeOfHeaders)]
    lea r9, [TMP]
    mov rsi, rax
    mov r8, 0x40
    sub rsp, 0x20
    call rax
    add rsp, 0x20

    ; Clear section headers
    mov rcx, pPackedBinary->NTHeaders.OptionalHeader.ImageBase
    add rcx, [Reloc]
    mov edx, [rcx + offsetof(IMAGE_DOS_HEADER, e_lfanew)]
    add rcx, rdx
    mov rdx, 0
    mov dx, [rcx + offsetof(IMAGE_NT_HEADERS64, FileHeader.SizeOfOptionalHeader)]
    add rcx, rdx
    mov rdx, sizeof(IMAGE_SECTION_HEADER) * 2
    sub rcx, rdx
    call ShellcodeData.Labels.RtlZeroMemory