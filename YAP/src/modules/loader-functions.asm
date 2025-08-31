%define ASSEMBLER a.


LLA:
    embed &Sha256Str("LoadLibraryA"), sizeof(Sha256Digest)
MSGBX:
    embed &Sha256Str("MessageBoxA"), sizeof(Sha256Digest) 
ERR:
	embed "Error", 6
USR:
    embed "USER32.dll", 11
KRN:
   	embed &Sha256WStr(L"KERNEL32.DLL"), sizeof(Sha256Digest)
NTD:
    embed &Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest)
TP:
    embed &Sha256Str("NtTerminateProcess"), sizeof(Sha256Digest)

; GLOBAL
ShellcodeData.Labels.FatalError:
    desync
    mov rsi, rsp
    and rsi, 0x0F
    add rsp, 0x10
    sub rsp, rsi
    mov rsi, rcx
    lea rcx, [KRN]
    call ShellcodeData.Labels.GetModuleHandleW
    mov rbx, rax
    mov rcx, rax ; Ignore failures here, if it crashes in this function theres not much that can be done
    lea rdx, [LLA]
    call ShellcodeData.Labels.GetProcAddress
    lea rcx, [USR]
    sub rsp, 0x20
    call rax
    add rsp, 0x20
    mov rcx, rax
    lea rdx, [MSGBX]
    call ShellcodeData.Labels.GetProcAddress
    mov rbp, rax
    lea rcx, [NTD]
    call ShellcodeData.Labels.GetModuleHandleW
    mov rcx, rax
    lea rdx, [TP]
    call ShellcodeData.Labels.GetProcAddress
    mov rbx, rax
    sub rsp, 0x20
    %if Options.Packing.bDirectSyscalls
        mov r10, 0
        mov eax, [rbx + 4]
        syscall
    %else
        mov rcx, 0
        call rbx
    %endif
    add rsp, 0x20
    mov rcx, 0
    mov rdx, rsi
    lea r8, [ERR]
    mov r9, MB_OK | MB_ICONERROR
    sub rsp, 0x20
    call rbp
    %if Options.Packing.bDirectSyscalls
        mov r10, 0xFFFFFFFFFFFFFFFF
        mov eax, [rbx + 4]
        syscall
    %else
        mov rcx, 0xFFFFFFFFFFFFFFFF
        call rbx
    %endif

; GetModuleHandleW
; GLOBAL
ShellcodeData.Labels.GetModuleHandleW:
    desync
    mov rax, PEB
    test rcx, rcx
    strict
    jz GetModuleHandleW_ret_self
    mov rax, [rax + offsetof(_PEB, Ldr)]
    mov rax, [rax + offsetof(_PEB_LDR_DATA, InMemoryOrderModuleList)]
    sub rax, 0x10
    sub rsp, sizeof(CSha256) + sizeof(Sha256Digest)
GetModuleHandleW_item:
    push r8
    push r9
    push r10
    push r11
    push rax
    push rcx
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x30)]
    mov rdx, sizeof(CSha256)
    call ShellcodeData.Labels.RtlZeroMemory
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x30)]
    call Sha256_Init
    pop rcx
    pop rax
    pop r11
    pop r10
    pop r9
    pop r8
    mov rax, [rax + 0x10]
    test rax, rax
    strict
    jz GetModuleHandleW_bad
    sub rax, 0x10
    lea r8, [rax + 0x58]
    mov r9, [r8 + 0x08]
    test r9, r9
    strict
    jz GetModuleHandleW_bad
    mov r10d, 0
GetModuleHandleW_strcmp_loop:
    inc r10
    mov r11w, [r9 + r10 * 2]
    test r11w, r11w
    strict
    jnz GetModuleHandleW_strcmp_loop
    shl r10, 1
    push rax
    push r8
    push r9
    push r10
    push r11
    push rcx
    mov rdx, r9
    mov r8, r10
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x30)]
    call Sha256_Update
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x30)]
    lea rdx, [rsp + 0x30]
    call Sha256_Final
    mov rax, 0
    pop rcx
    lea r11, [rsp + 0x28]
    mov r10, [r11 + offsetof(Sha256Digest, high.high)]
    cmp r10, [rcx + offsetof(Sha256Digest, high.high)]
    strict
    setne al
    strict
    jne GetModuleHandleW_skip
    mov r10, [r11 + offsetof(Sha256Digest, high.low)]
    cmp r10, [rcx + offsetof(Sha256Digest, high.low)]
    strict
    setne al
    strict
    jne GetModuleHandleW_skip
    mov r10, [r11 + offsetof(Sha256Digest, low.high)]
    cmp r10, [rcx + offsetof(Sha256Digest, low.high)]
    strict
    setne al
    strict
    jne GetModuleHandleW_skip
    mov r10, [r11 + offsetof(Sha256Digest, low.low)]
    cmp r10, [rcx + offsetof(Sha256Digest, low.low)]
    strict
    setne al
GetModuleHandleW_skip:
    pop r11
    pop r10
    pop r9
    pop r8
    test al, al
    strict
    pop rax
    strict
    jnz GetModuleHandleW_item
    add rsp, sizeof(CSha256) + sizeof(Sha256Digest)
    mov rax, [rax + 0x30]
    ret
GetModuleHandleW_bad:
    %ifdef _DEBUG
        %if Options.Debug.bGenerateBreakpoints
            int3
        %endif
    %endif
    add rsp, sizeof(CSha256) + sizeof(Sha256Digest)
    mov eax, 0
    ret
GetModuleHandleW_ret_self:
    mov rax, [rax + 0x10]
    ret

; Sha256
%include "SHA256.raw"

; RAW_C GenerateUnpackingAlgorithm(&a, unpack);
; RAW_C DecoderProc.Release();

; GetProcAddress
; GLOBAL
ShellcodeData.Labels.GetProcAddress:
    desync
    push r12
    push r13
    push r14
    push rbx
    mov r12d, 0
    mov r8d, [rcx + 0x3C]
    mov r8d, [rcx + r8 + 0x88]
    mov r9d, [rcx + r8 + 0x18]
    mov r10d, [rcx + r8 + 0x20]
    add r10, rcx
    mov r11d, [rcx + r8 + 0x24]
    add r11, rcx
    sub rsp, sizeof(CSha256) + sizeof(Sha256Digest)
GetProcAddress_loop:
    push r8
    push r9
    push r10
    push r11
    push rdx
    push rcx
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x30)]
    mov rdx, sizeof(CSha256)
    call ShellcodeData.Labels.RtlZeroMemory
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x30)]
    call Sha256_Init
    pop rcx
    pop rdx
    pop r11
    pop r10
    pop r9
    pop r8
    cmp r12, r9
    strict
    je GetProcAddress_bad
    mov r13d, [r10 + r12 * 4]
    inc r12
    add r13, rcx
    mov r14d, 0
GetProcAddress_strcmp_loop:
    mov al, [r13 + r14]
    test al, al
    strict
    jz GetProcAddress_found
    inc r14
    jmp GetProcAddress_strcmp_loop
GetProcAddress_found:
    push r8
    push r9
    push r10
    push r11
    push rdx
    push rcx
    mov rdx, r13
    mov r8, r14
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x30)]
    call Sha256_Update
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x30)]
    lea rdx, [rsp + 0x30]
    call Sha256_Final
    pop rcx
    pop rdx
    lea r11, [rsp + 0x20]
    mov r10, [r11 + offsetof(Sha256Digest, high.high)]
    cmp r10, [rdx + offsetof(Sha256Digest, high.high)]
    strict
    setne al
    strict
    jne GetProcAddress_skip
    mov r10, [r11 + offsetof(Sha256Digest, high.low)]
    cmp r10, [rdx + offsetof(Sha256Digest, high.low)]
    strict
    setne al
    strict
    jne GetProcAddress_skip
    mov r10, [r11 + offsetof(Sha256Digest, low.high)]
    cmp r10, [rdx + offsetof(Sha256Digest, low.high)]
    strict
    setne al
    strict
    jne GetProcAddress_skip
    mov r10, [r11 + offsetof(Sha256Digest, low.low)]
    cmp r10, [rdx + offsetof(Sha256Digest, low.low)]
    strict
    setne al
GetProcAddress_skip:
    pop r11
    pop r10
    pop r9
    pop r8
    test al, al
    strict
    jnz GetProcAddress_loop
    mov eax, [rcx + r8 + 0x1C]
    add rax, rcx
    dec r12
    movzx edx, word [r11 + r12 * 2]
    mov eax, [rax + rdx * 4]
    add rax, rcx
    jmp GetProcAddress_ret
GetProcAddress_bad:
    %ifdef _DEBUG
        %if Options.Debug.bGenerateBreakpoints
            int3
        %endif
    %endif
    mov eax, 0
GetProcAddress_ret:
    add rsp, sizeof(Sha256Digest) + sizeof(CSha256)
    pop rbx
    pop r14
    pop r13
    pop r12
    ret

; RtlZeroMemory
; GLOBAL
ShellcodeData.Labels.RtlZeroMemory:
    test rdx, rdx
    strict
    jz RtlZeroMemory_ret
    test rcx, rcx
    strict
    jz RtlZeroMemory_ret
    mov al, 0
RtlZeroMemory_loop:
    mov [rcx], al
    inc rcx
    dec rdx
    strict
    jnz RtlZeroMemory_loop
RtlZeroMemory_ret:
    ret