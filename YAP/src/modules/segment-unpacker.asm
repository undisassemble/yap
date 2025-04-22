%define ASSEMBLER a.

_UnloadSegment:
    call UnloadSegment
LoadSegment:
    
    ; Check if already loaded
    mov eax, [CurrentlyLoadedSegment]
    %ifdef _DEBUG
        cmp rax, [rsp]
        strict
        jne dontkill
        int3
dontkill:
    %endif
    cmp eax, count
    strict
    jl _UnloadSegment
    
    ; Load segment
    pop rax
    mov [CurrentlyLoadedSegment], eax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    mov rdx, 0
    lea rcx, [Compressed]
    lea r8, [CompressedSizes]
    lea r11, [PointerArray]
    mov r9, [r11 + rax * 8]
findcomploop:
    cmp edx, eax
    strict
    jge findcomploopexit
    mov r10, [r11 + rdx * 8]
    add rcx, [r8]
thing:
    add r8, 8
    inc rdx
    cmp r10, [r11 + rdx * 8]
    strict
    jz thing
    cmp r9, [r11 + rdx * 8]
    strict
    jnz findcomploop
findcomploopexit:
    mov rdx, [r8]
    lea r8, [PointerArray]
    mov r8, [r8 + rax * 8]
    add r8, [InternalRelOff]
    lea r9, [SizeArray]
    mov r9d, [r9 + rax * 4]
    sub rsp, 0x40
    call Unpack
    add rsp, 0x40
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    mov ecx, [CurrentlyLoadedSegment]
    lea rax, [EntryArray]
    mov rax, [rax + ecx * 8]
    add rax, [InternalRelOff]
    pop rcx
    xchg [rsp], rax
    add rsp, 8

    ; Call function
    block
    cmp byte [Flag], 0
    block
    je nflagisset
    mov byte [Flag], 0
    ret
nflagisset:
    block
    call [rsp - 8]
    
    ; Check if return address is in another segment
    xchg [rsp], rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    mov rcx, 0
    dec rcx
    mov r11, 1
    lea r8, [PointerArray]
    lea r9, [SizeArray]
checkloop:
    cmp rcx, count
    strict
    jge checkexit
    inc rcx
    mov rdx, [r8 + rcx * 8]
    add rdx, [InternalRelOff]
    cmp rax, rdx
    strict
    jl checkloop
    mov r10d, [r9 + rcx * 4]
    add rdx, r10
    cmp rax, rdx
    strict
    setl [Flag]
    strict
    jl checkexit
    jmp checkloop
checkexit:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    cmp byte [Flag], 0
    strict
    jne dothingy
    pop rcx
    xchg [rsp], rax
    jmp UnloadSegment
dothingy:
    xchg [rsp + 8], rax
    push rcx
    xchg [rsp + 8], rax
    mov rcx, rax
    jmp LoadSegment

    ; Write function address
    ; RAW_C for (DWORD i = 0; i < FunctionRanges.Size(); i++) {
        ; RAW_C for (int j = 0; j < FunctionRanges[i].Entries.Size(); j++) {
            ; RAW_C pOriginal->WriteRVA<uint64_t>(FunctionRanges[i].Entries[j] + 8, pPackedBinary->NTHeaders.OptionalHeader.ImageBase + holder.labelOffsetFromBase(LoadSegment) + ShellcodeData.BaseAddress);
            ; RAW_C ShellcodeData.Relocations.Relocations.Push(ShellcodeData.BaseOffset + FunctionRanges[i].Entries[j] + 8);
        ; RAW_C }
    ; RAW_C }

UnloadSegment:
    push rax
    push rcx
    push rdx
    push r8
    push r9
    mov eax, [CurrentlyLoadedSegment]
    cmp eax, count
    strict 
    jge finnish
    lea rcx, [PointerArray]
    mov rcx, [rcx + rax * 8]
    add rcx, [InternalRelOff]
    lea rdx, [SizeArray]
    mov edx, [rdx + rax * 4]
    push rax
    mov al, 0x90
loop:
    mov [rcx], al
    inc rcx
    dec rdx
    strict
    jnz loop
    pop r8
    mov r9, r8
    lea rcx, [PointerArray]
decloop:
    dec r9
    mov rdx, [rcx + r8 * 8]
    cmp rdx, [rcx + r9 * 8]
    strict
    jz decloop
    inc r9
    mov r8, r9
setentryloop:
    lea rcx, [EntryArray]
    mov rcx, [rcx + r8 * 8]
    add rcx, [InternalRelOff]
    mov word [rcx], 0x6850
    mov [rcx + 2], r8d
    mov word [rcx + 6], 0xB848
    lea rax, [LoadSegment]
    mov [rcx + 8], rax
    mov qword [rcx + 16], 0xE0FF
    inc r8
    lea rcx, [PointerArray]
    mov rdx, [rcx + r8 * 8]
    cmp rdx, [rcx + r9 * 8]
    strict
    jz setentryloop
finnish:
    mov dword [CurrentlyLoadedSegment], _I32_MAX
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    ret