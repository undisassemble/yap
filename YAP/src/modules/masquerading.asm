%define ASSEMBLER a.

    ; Check buffer size
    mov rax, PEB
    mov rax, [rax + 0x20]
    mov si,  [rax + 0x62]
    cmp si,  2 * (lstrlenA(Options.Packing.Masquerade + 1))
    strict
    jle not_found

    ; Copy string
    mov rcx, [rax + 0x68]
    lea r8,  [new_buf]
    mov dx,  0
    mov rdi, 0

copy_byte:
    mov dl, [r8 + di]
    test dl, dl
    strict
    jz zero_remainder
    xor dl, XORKey
    mov [rcx + di * 2], dx
    inc di
    cmp dl, '\\'
    strict
    jne copy_byte
    mov r9w, di
    shl r9w, 1
    jmp copy_byte

    ; Zero the remainder of the buffer
zero_remainder:
    lea rcx, [rcx + di * 2]
    movzx rdx, si
    shl rdi, 1
    sub rdx, rdi
    sub rdx, 2
    push rax
    push r9w
    call ShellcodeData.Labels.RtlZeroMemory
    mov r9d, 0
    pop r9w
    pop rax

    ; Copy data
    ; bx  = Length
    ; cx  = MaximumLength
    ; rdx = Buffer
    mov bx, 2 * lstrlen(Options.Packing.Masquerade) ; Get data
    mov cx, 2 * (lstrlenA(Options.Packing.Masquerade) + 1)
    mov rdx, [rax + 0x68]
    mov [rax + 0x70], bx ; CommandLine
    mov [rax + 0x72], cx
    mov [rax + 0x78], rdx
    mov [rax + 0xB0], bx ; WindowTitle
    mov [rax + 0xB2], cx
    mov [rax + 0xB8], rdx
    mov [rax + 0x60], bx ; ImagePathName
    mov [rax + 0x62], cx
    mov [rax + 0x68], rdx
    mov rax, PEB
    mov rax, [rax + offsetof(_PEB, Ldr)]
    mov rax, [rax + 0x10]
    mov [rax + 0x48], bx ; FullDllName
    mov [rax + 0x4A], cx
    mov [rax + 0x50], rdx
    sub bx, r9w
    sub cx, r9w
    add rdx, r9
    mov [rax + 0x58], bx ; BaseDllName
    mov [rax + 0x5A], cx
    mov [rax + 0x60], rdx
    jmp not_found