%define ASSEMBLER a.

    ; Hypervisor check
    mov rax, 1
    cpuid
    mov edx, ecx
    lea rcx, [VMFL]
    bt edx, 31
    strict 
    %if Options.Packing.bAllowHyperV
        jnc nohv
        mov rax, 0x40000000
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

    ; RDTSC timing check
    mov r8, 0
    mov r9, 0x10
rdtsc_loop:
    rdtsc
    block
    shl rdx, 32
    block
    or rax, rdx
    block
    sub r8, rax
    block
    mov rax, 1
    block
    cpuid
    block
    rdtsc
    shl rdx, 32
    or rax, rdx
    add r8, rax
    dec r9
    strict
    jnz rdtsc_loop
    shr r8, 4
    lea rcx, [VMFL]
    cmp r8, 0x500
    strict
    jg ShellcodeData.Labels.FatalError