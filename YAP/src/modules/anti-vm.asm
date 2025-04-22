%define ASSEMBLER a.

    mov eax, 1
    cpuid
    bt ecx, 31
    strict 
    %if Options.Packing.bAllowHyperV
        jnc nohv
        mov eax, 0x40000000
        cpuid
        cmp ebx, 0x7263694D
        strict
        jne ret
        cmp ecx, 0x666F736F
        strict
        jne ret
        cmp edx, 0x76482074
        strict
        jne ret
    %else
        jc ret
    %endif
nohv: