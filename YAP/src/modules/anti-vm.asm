%define ASSEMBLER a.

    mov eax, 1
    cpuid
    mov edx, ecx
    lea rcx, [VMFL]
    bt edx, 31
    strict 
    %if Options.Packing.bAllowHyperV
        jnc nohv
        mov eax, 0x40000000
        cpuid
        mov eax, ecx
        lea rcx, [VMFL]
        cmp ebx, 0x7263694D
        strict
        jne ShellcodeData.Labels.FatalError
        cmp eax, 0x666F736F
        strict
        jne ShellcodeData.Labels.FatalError
        cmp edx, 0x76482074
        strict
        jne ShellcodeData.Labels.FatalError
    %else
        jc ShellcodeData.Labels.FatalError
    %endif
nohv: