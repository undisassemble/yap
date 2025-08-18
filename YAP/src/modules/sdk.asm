%define ASSEMBLER a.

    align AlignMode::kCode, alignof(LPCSTR)
USR:
    embed "USER32.dll", 11
ERR:
	embed "Error", 6
MSGBX:
    embed &Sha256Str("MessageBoxA"), sizeof(Sha256Digest)
EXT:
    embed &Sha256Str("ExitProcess"), sizeof(Sha256Digest)

; GetLastError
%if ShellcodeData.RequestedFunctions.GetLastError.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.GetLastError.Func:
    mov rax, TEB
    mov eax, [rax + 0x68]
    ret
%endif

; SetLastError
%if ShellcodeData.RequestedFunctions.SetLastError.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.SetLastError.Func:
    mov rax, TEB
    mov [rax + 0x68], ecx
    mov rax, 0
    ret
%endif

; GetSelf
%if ShellcodeData.RequestedFunctions.GetSelf.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.GetSelf.Func:
    mov rax, pPackedBinary->NTHeaders.OptionalHeader.ImageBase
    add rax, [InternalRelOff]
    ret
%endif

; GLOBAL
ShellcodeData.Labels.FatalError:
    desync
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
    mov rcx, 0
    mov rdx, rsi
    lea r8, [ERR]
    mov r9, MB_OK | MB_ICONERROR
    sub rsp, 0x20
    call rax
    add rsp, 0x20
    mov rcx, rbx
    lea rdx, [EXT]
    call ShellcodeData.Labels.GetProcAddress
    mov rcx, 1
    sub rsp, 0x20
    call rax
    add rsp, 0x20

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
GetModuleHandleW_item:
    push r8
    push r9
    push r10
    push r11
    push rax
    push rcx
    lea rcx, [hash]
    mov rdx, sizeof(CSha256)
    call ShellcodeData.Labels.RtlZeroMemory
    lea rcx, [hash]
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
    lea rcx, [hash]
    call Sha256_Update
    lea rcx, [hash]
    lea rdx, [digest]
    call Sha256_Final
    mov rax, 0
    pop rcx
    lea r11, [digest]
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
    mov rax, [rax + 0x30]
    ret
GetModuleHandleW_bad:
    %ifdef _DEBUG
        %if Options.Debug.bGenerateBreakpoints
            int3
        %endif
    %endif
    mov eax, 0
    ret
GetModuleHandleW_ret_self:
    mov rax, [rax + 0x10]
    ret

; GetProcAddressByOrdinal
; GLOBAL
ShellcodeData.Labels.GetProcAddressByOrdinal:
    desync
    mov r8d, [rcx + 0x3C]
    mov r8d, [rcx + r8 + 0x88]
    sub edx, [rcx + r8 + 0x10]
    mov eax, [rcx + r8 + 0x1C]
    add rax, rcx
    mov eax, [rax + rdx * 4]
    add rax, rcx
    ret

; GetStdHandle
%if ShellcodeData.RequestedFunctions.GetStdHandle.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.GetStdHandle.Func:
    mov rdx, PEB
    mov rdx, [rdx + 0x20]
    mov r8, [rdx + 0x20]
    mov rax, INVALID_HANDLE_VALUE
    cmp ecx, STD_INPUT_HANDLE
    strict
    cmovz rax, r8
    add r8, 8
    cmp ecx, STD_OUTPUT_HANDLE
    strict
    cmovz rax, r8
    add r8, 8
    cmp ecx, STD_ERROR_HANDLE
    strict
    cmovz rax, r8
    ret
%endif

; Sha256
%include "SHA256.raw"

; GetProcAddress (emulated)
%if ShellcodeData.RequestedFunctions.GetProcAddress.bRequested
sum:
    db 0, sizeof(Sha256Digest)

; GLOBAL
ShellcodeData.RequestedFunctions.GetProcAddress.Func:
    push rcx
    push rdx
    lea rcx, [hash]
    mov rdx, sizeof(CSha256)
    call ShellcodeData.Labels.RtlZeroMemory
    lea rcx, [hash]
    call Sha256_Init
    mov r8, 0
    dec r8
    pop rdx
GetProcAddress_EMU_strlen_loop:
    inc r8
    cmp byte [rdx + r8], 0
    strict
    jnz GetProcAddress_EMU_strlen_loop
    lea rcx, [hash]
    call Sha256_Update
    lea rcx, [hash]
    lea rdx, [sum]
    call Sha256_Final
    pop rcx
    lea rdx, [sum]
    jmp ShellcodeData.Labels.GetProcAddress
%endif

; GetProcAddress
%if Options.Packing.bHideIAT
shit:
    db 0
%endif
; GLOBAL
ShellcodeData.Labels.GetProcAddress:
    desync
    %if Options.Packing.bHideIAT
        mov r8, 1
        ror r8, 1
        and r8, rcx
        strict
        setnz [shit]
        not r8
        and rcx, r8
    %endif
    push r12
    push r13
    push r14
    push rbx
    push rsi
    push rbp
    mov r12d, 0
    mov r8d, [rcx + 0x3C]
    mov ebp, [rcx + r8 + 0x8C]
    mov r8d, [rcx + r8 + 0x88]
    mov esi, r8d
    add rsi, rcx
    add rbp, rsi
    mov r9d, [rcx + r8 + 0x18]
    mov r10d, [rcx + r8 + 0x20]
    add r10, rcx
    mov r11d, [rcx + r8 + 0x24]
    add r11, rcx
GetProcAddress_loop:
    push r8
    push r9
    push r10
    push r11
    push rdx
    push rcx
    lea rcx, [hash]
    mov rdx, sizeof(CSha256)
    call ShellcodeData.Labels.RtlZeroMemory
    lea rcx, [hash]
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
    lea rcx, [hash]
    call Sha256_Update
    lea rcx, [hash]
    lea rdx, [digest]
    call Sha256_Final
    pop rcx
    pop rdx
    lea r11, [digest]
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
    cmp rax, rsi
    strict
    jge GetProcAddress_check_in_e
    jmp GetProcAddress_ret
GetProcAddress_bad:
    %ifdef _DEBUG
        %if Options.Debug.bGenerateBreakpoints
            int3
        %endif
    %endif
    mov eax, 0
GetProcAddress_ret:
    %if Options.Packing.bHideIAT
        ; Verify need to check
        cmp byte [shit], 0
        strict
        jz GetProcAddress_dontcheck
        test rax, rax
        strict
        jz GetProcAddress_dontcheck

        ; Get dll base
        mov rcx, rax
        mov r8, 0xFFF
        not r8
        and rcx, r8
        add rcx, 0x1000
GetProcAddress_base_loop:
        sub rcx, 0x1000
        cmp word [rcx], IMAGE_DOS_SIGNATURE
        strict
        jnz GetProcAddress_base_loop

        ; Get section header
        mov edx, [rcx + offsetof(IMAGE_DOS_HEADER, e_lfanew)]
        mov r8, 0
        add rdx, rcx
        mov r8w, [rdx + (offsetof(IMAGE_NT_HEADERS64, FileHeader) + offsetof(IMAGE_FILE_HEADER, NumberOfSections))]
        lea rdx, [rdx + sizeof(IMAGE_NT_HEADERS64)]
GetProcAddress_getheader_loop:
        test r8, r8
        strict
        jz GetProcAddress_failed
        mov r9d, [rdx + offsetof(IMAGE_SECTION_HEADER, VirtualAddress)]
        add r9, rcx
        cmp rax, r9
        strict
        jl GetProcAddress_failed
        mov ebx, [rdx + offsetof(IMAGE_SECTION_HEADER, Misc.VirtualSize)]
        add r9, rbx
        dec r8
        add rdx, sizeof(IMAGE_SECTION_HEADER)
        cmp rax, r9
        strict
        jg GetProcAddress_getheader_loop
        sub rdx, sizeof(IMAGE_SECTION_HEADER)
        mov r9d, [rdx + offsetof(IMAGE_SECTION_HEADER, Characteristics)]
        and r9d, IMAGE_SCN_MEM_EXECUTE
        strict
        jnz GetProcAddress_dontcheck

GetProcAddress_failed:
        mov r8, 1
        ror r8, 1
        or rax, r8
    %endif

GetProcAddress_dontcheck:
    pop rbp
    pop rsi
    pop rbx
    pop r14
    pop r13
    pop r12
    ret
   
GPA:
    embed &Sha256Str("GetProcAddress"), sizeof(Sha256Digest)
KRN:
    embed &Sha256WStr(L"KERNEL32.DLL"), sizeof(Sha256Digest)
LLA:
    embed &Sha256Str("LoadLibraryA"), sizeof(Sha256Digest)
blank:
    db 0, 64

GetProcAddress_check_in_e:
    cmp rax, rbp
    strict
    jge GetProcAddress_ret
   
    ; Handle import thingy dothingy magigys
    %ifdef _DEBUG
        %if Options.Debug.bGenerateBreakpoints
            int3
        %endif
    %endif
    push r12
    push r13
    push r14
    push r15
    push rax
    lea rcx, [KRN]
    call ShellcodeData.Labels.GetModuleHandleW
    mov rcx, rax
    push rcx
    lea rdx, [GPA]
    %if Options.Packing.bHideIAT
        mov sil, [shit]
    %endif
    call ShellcodeData.Labels.GetProcAddress
    mov r12, rax
    pop rcx
    lea rdx, [LLA]
    call ShellcodeData.Labels.GetProcAddress
    %if Options.Packing.bHideIAT
        mov [shit], sil
    %endif
    mov r13, rax
    pop rax
    lea r14, [blank]
GetProcAddress_lp:
    mov cl, [rax]
    mov [r14], cl
    inc r14
    inc rax
    cmp byte [rax], '.'
    strict
    jne GetProcAddress_lp
    inc rax
    push rax
    mov byte [r14], 0
    mov rcx, rsp
    and rcx, 0b1111
    add rcx, 8
    sub rsp, rcx
    push rcx
    lea rcx, [blank]
    sub rsp, 0x20
    call r13
    add rsp, 0x20
    pop rcx
    add rsp, rcx
    pop rdx
    mov rcx, rsp
    and rcx, 0b1111
    add rcx, 8
    sub rsp, rcx
    push rcx
    mov rcx, rax
    sub rsp, 0x40
    call r12
    add rsp, 0x40
    pop rcx
    add rsp, rcx
    pop r15
    pop r14
    pop r13
    pop r12
    jmp GetProcAddress_ret

; GetTickCount64
%if ShellcodeData.RequestedFunctions.GetTickCount64.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.GetTickCount64.Func:
    mov ecx, [0x7FFE0004]
    shl rcx, 0x20
    mov rax, [0x7FFE0320]
    shl rax, 8
    mul rcx
    mov rax, rdx
    ret
%endif

; CheckForDebuggers
%if ShellcodeData.RequestedFunctions.CheckForDebuggers.bRequested
    ; RAW_C CONTEXT context = { 0 };
    ; RAW_C context.ContextFlags = CONTEXT_ALL;
    align AlignMode::kCode, alignof(CONTEXT)
Context:
    embed &context, sizeof(CONTEXT)
    %if Options.Packing.bDirectSyscalls
ID:
        dd 0
    %endif
NTD:
    embed &Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest)
GCT:
    embed &Sha256Str("ZwGetContextThread"), sizeof(Sha256Digest)

; GLOBAL
ShellcodeData.RequestedFunctions.CheckForDebuggers.Func:
    push rsi

    ; PEB check
    mov rcx, PEB
    mov rax, 0
    %if ShellcodeData.CarryData.bWasAntiDump
        or al, [rcx + 0x10]
        or al, [rcx + 0x11]
        or al, [rcx + 0x12]
        or al, [rcx + 0x13]
        or al, [rcx + 0x14]
        or al, [rcx + 0x15]
        or al, [rcx + 0x16]
        or al, [rcx + 0x17]
    %endif
    or al, [rcx + 0x02]
    mov rdx, 0xBC
    mov r9, 0x70
    mov r8d, [rcx + rdx]
    and r8, r9
    or al, r8b
    or al, [0x7FFE02D4]
    strict
    jnz CheckForDebuggers_ret

    ; HWBP check
    %if Options.Packing.bDirectSyscalls
        mov eax, [ID]
        test eax, eax
        strict
        jnz CheckForDebuggers_hasid
    %endif
    lea rcx, [NTD]
    call ShellcodeData.Labels.GetModuleHandleW
    mov rcx, rax
    lea rdx, [GCT]
    call ShellcodeData.Labels.GetProcAddress
    test rax, rax
    strict
    jz CheckForDebuggers_ret
    %if Options.Packing.bDirectSyscalls
        mov ecx, [rax]
        cmp ecx, 0xB8D18B4C
        strict
        mov rcx, 1
        strict
        cmovnz rax, rcx
        strict
        jnz CheckForDebuggers_ret
        mov eax, [rax + 4]
        mov [ID], eax
CheckForDebuggers_hasid:
    %endif
    lea rdx, [Context]
    mov rsi, rdx
    %if Options.Packing.bDirectSyscalls
        mov r10, 0xFFFFFFFFFFFFFFFE
        syscall
    %else
        mov rcx, 0xFFFFFFFFFFFFFFFE
        call rax
    %endif
    mov rdx, rsi
    test rax, rax
    strict
    jnz CheckForDebuggers_ret
    mov rax, [rdx + offsetof(CONTEXT, Dr7)]
    and rax, 0x20FF
    strict
    jnz CheckForDebuggers_ret
    mov rax, [rdx + offsetof(CONTEXT, Dr6)]
    and rax, 0x0F
    strict
    jnz CheckForDebuggers_ret
    mov rax, [rdx + offsetof(CONTEXT, Dr0)]
    or rax, [rdx + offsetof(CONTEXT, Dr1)]
    or rax, [rdx + offsetof(CONTEXT, Dr2)]
    or rax, [rdx + offsetof(CONTEXT, Dr3)]
CheckForDebuggers_ret:
    pop rsi
    ret
%endif

; GetCurrentThread
%if ShellcodeData.RequestedFunctions.GetCurrentThread.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.GetCurrentThread.Func:
    mov rax, 0xFFFFFFFFFFFFFFFE
    ret
%endif

; GetCurrentThreadId
%if ShellcodeData.RequestedFunctions.GetCurrentThreadId.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.GetCurrentThreadId.Func:
    mov rax, TEB
    mov eax, [rax + 0x48]
    ret
%endif

; GetCurrentProcess
%if ShellcodeData.RequestedFunctions.GetCurrentProcess.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.GetCurrentProcess.Func:
    mov rax, 0xFFFFFFFFFFFFFFFF
    ret
%endif

; GetCurrentProcessId
%if ShellcodeData.RequestedFunctions.GetCurrentProcessId.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.GetCurrentProcessId.Func:
    mov rax, TEB
    mov eax, [rax + 0x40]
    ret
%endif

; RtlZeroMemory
; GLOBAL
ShellcodeData.Labels.RtlZeroMemory:
    test rdx, rdx
    strict
    jz ret
    test rcx, rcx
    strict
    jz ret
    mov al, 0
RtlZeroMemory_loop:
    mov [rcx], al
    inc rcx
    dec rdx
    strict
    jnz RtlZeroMemory_loop
ret:
    ret