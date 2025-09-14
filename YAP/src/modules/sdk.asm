%define ASSEMBLER a.

    align AlignMode::kCode, alignof(LPCSTR)
USR:
    embed "USER32.dll", 11
    align AlignMode::kCode, alignof(LPCSTR)
ERR:
	embed "Error", 6
    align AlignMode::kCode, alignof(LPCSTR)
NTD:
    embed &Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest)
    align AlignMode::kCode, alignof(LPCSTR)
HOOKFL:
    embed "A hook was detected, please avoid hooking WINAPI functions!", 60
MSGBX:
    embed &Sha256Str("MessageBoxA"), sizeof(Sha256Digest)
TP:
    embed &Sha256Str("NtTerminateProcess"), sizeof(Sha256Digest)

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

%if ShellcodeData.RequestedFunctions.ShowErrorAndExit.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.ShowErrorAndExit.Func:
%endif
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
    sub rsp, sizeof(Sha256Digest) + sizeof(CSha256)
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
; GLOBAL
ShellcodeData.RequestedFunctions.GetProcAddress.Func:
    sub rsp, sizeof(CSha256) + sizeof(Sha256Digest)
    push rcx
    push rdx
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x10)]
    mov rdx, sizeof(CSha256)
    call ShellcodeData.Labels.RtlZeroMemory
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x10)]
    call Sha256_Init
    mov r8, 0
    dec r8
    pop rdx
GetProcAddress_EMU_strlen_loop:
    inc r8
    cmp byte [rdx + r8], 0
    strict
    jnz GetProcAddress_EMU_strlen_loop
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x08)]
    call Sha256_Update
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x08)]
    lea rdx, [rsp + 0x08]
    call Sha256_Final
    pop rcx
    mov rdx, rsp
    call ShellcodeData.Labels.GetProcAddress
    add rsp, sizeof(CSha256) + sizeof(Sha256Digest)
    ret
%endif

; GetProcAddress
; GLOBAL
ShellcodeData.Labels.GetProcAddress:
    desync
    sub rsp, sizeof(CSha256) + sizeof(Sha256Digest)
    push r12
    push r13
    push r14
    push r15
    push rbx
    push rsi
    push rbp
    %if Options.Packing.bHideIAT
        mov r8, 1
        ror r8, 1
        and r8, rcx
        strict
        setnz r15b
        not r8
        and rcx, r8
    %endif
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
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x68)]
    mov rdx, sizeof(CSha256)
    call ShellcodeData.Labels.RtlZeroMemory
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x68)]
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
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x68)]
    call Sha256_Update
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x68)]
    lea rdx, [rsp + 0x68]
    call Sha256_Final
    pop rcx
    pop rdx
    lea r11, [rsp + 0x58]
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
        cmp r15b, 0
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
    pop r15
    pop r14
    pop r13
    pop r12
    add rsp, sizeof(CSha256) + sizeof(Sha256Digest)
    ret
   
GPA:
    embed &Sha256Str("GetProcAddress"), sizeof(Sha256Digest)
KRN:
    embed &Sha256WStr(L"KERNEL32.DLL"), sizeof(Sha256Digest)
LLA:
    embed &Sha256Str("LoadLibraryA"), sizeof(Sha256Digest)

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
        mov sil, r15b
    %endif
    call ShellcodeData.Labels.GetProcAddress
    mov r12, rax
    pop rcx
    lea rdx, [LLA]
    call ShellcodeData.Labels.GetProcAddress
    %if Options.Packing.bHideIAT
        mov r15b, sil
    %endif
    mov r13, rax
    pop rax
    sub rsp, 64
    mov r14, rsp
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
    lea rcx, [rsp + 0x08]
    sub rsp, 0x28
    call r13
    add rsp, 0x28
    pop rdx
    mov rcx, rax
    sub rsp, 0x20
    call r12
    add rsp, 0x20
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    jmp GetProcAddress_ret

; CheckForDebuggers
%if ShellcodeData.RequestedFunctions.CheckForDebuggers.bRequested
GCT:
    embed &Sha256Str("ZwGetContextThread"), sizeof(Sha256Digest)
QSI:
    embed &Sha256Str("NtQuerySystemInformation"), sizeof(Sha256Digest)
%if Options.Packing.bAntiDebug
QIT:
    embed &Sha256Str("NtQueryInformationThread"), sizeof(Sha256Digest)
%endif
GNP:
    embed &Sha256Str("NtGetNextProcess"), sizeof(Sha256Digest)
NTCLOSE:
    embed &Sha256Str("NtClose"), sizeof(Sha256Digest)
QIP:
    embed &Sha256Str("NtQueryInformationProcess"), sizeof(Sha256Digest)
%define DEBUG_PROC_BLACKLIST_LEN 21
DEBUG_PROC_BLACKLIST:
	embed &Sha256WStr(L"x96dbg.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"x64dbg.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"x64dbg-unsigned.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"x32dbg.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"x32dbg-unsigned.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"TitanHideGUI.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"ida.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"cutter.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"rizin.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"rz-asm.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"rz-ax.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"rz-bin.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"rz-diff.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"rz-find.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"rz-gg.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"rz-hash.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"rz-run.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"rz-sign.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"binaryninja.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"dbgsrv.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"DbgX.Shell.exe"), sizeof(Sha256Digest)

; GLOBAL
ShellcodeData.RequestedFunctions.CheckForDebuggers.Func:
    push rsi
    push rbx
    push rbp
    sub rsp, sizeof(CONTEXT) + 0x10

    ; -- PEB check --
    mov rbp, rdx
    mov r10, PEB
    mov rax, 0
    or al, [r10 + 0x02]
    mov rdx, 0xBC
    mov r9, 0x70
    mov r8d, [r10 + rdx]
    and r8, r9
    or al, r8b
    or al, [0x7FFE02D4]
    strict
    jnz CheckForDebuggers_ret

    ; Get ntdll and check if HWBP check was requested
    mov rsi, rcx
    lea rcx, [NTD]
    call ShellcodeData.Labels.GetModuleHandleW
    mov rcx, rsi
    mov rsi, rax
    test cl, cl
    strict
    jz CheckForDebuggers_SkipHWBP

    ; -- HWBP check --
    mov rcx, rax
    lea rdx, [GCT]
    call ShellcodeData.Labels.GetProcAddress
    mov dword [rsp + (offsetof(CONTEXT, ContextFlags) + 0x10)], CONTEXT_ALL
    lea rdx, [rsp + 0x10]
    sub rsp, 0x20
    %if Options.Packing.bDirectSyscalls
        mov r10, 0xFFFFFFFFFFFFFFFE
        mov ecx, [rax]
        xchg rax, rcx
        sub eax, 0xB8D18B4C
        strict
        jnz CheckForDebuggers_ret
        mov eax, [rcx + 4]
        syscall
    %else
        mov rcx, 0xFFFFFFFFFFFFFFFE
        call rax
    %endif
    add rsp, 0x20
    test rax, rax
    strict
    jnz CheckForDebuggers_ret
    lea rdx, [rsp + 0x10]
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
    strict
    jnz CheckForDebuggers_ret
CheckForDebuggers_SkipHWBP:

    ; -- DSE check --
    mov rcx, rsi
    lea rdx, [QSI]
    call ShellcodeData.Labels.GetProcAddress
    lea rdx, [rsp + 0x10]
    mov dword [rdx], 8
    mov dword [rdx + 4], 0
    mov r8, sizeof(SYSTEM_CODEINTEGRITY_INFORMATION)
    mov r9, 0
    sub rsp, 0x20
    %if Options.Packing.bDirectSyscalls
        mov r10, 103
        mov ecx, [rax]
        xchg rax, rcx
        sub eax, 0xB8D18B4C
        strict
        jnz CheckForDebuggers_ret
        mov eax, [rcx + 4]
        syscall
    %else
        mov rcx, 103
        call rax
    %endif
    add rsp, 0x20
    mov ecx, [rsp + 0x14]
    xor rcx, CODEINTEGRITY_OPTION_ENABLED
    and rcx, CODEINTEGRITY_OPTION_ENABLED | CODEINTEGRITY_OPTION_TESTSIGN | CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED
    or rax, rcx
    strict
    jnz CheckForDebuggers_ret

    ; -- Hidden thread check --
%if Options.Packing.bAntiDebug
    mov rcx, rsi
    lea rdx, [QIT]
    call ShellcodeData.Labels.GetProcAddress
	mov rdx, 17
    lea r8, [rsp + 0x10]
    mov r9, 1
    push 0
    push 0
    sub rsp, 0x20
    %if Options.Packing.bDirectSyscalls
        mov r10, 0xFFFFFFFFFFFFFFFE
        mov ecx, [rax]
        xchg rax, rcx
        sub eax, 0xB8D18B4C
        strict
        jnz CheckForDebuggers_ret
        mov eax, [rcx + 4]
        syscall
    %else
        mov rcx, 0xFFFFFFFFFFFFFFFE
        call rax
    %endif
    add rsp, 0x30
    mov rcx, 0
    mov rdx, 0
    mov r8, 1
    mov cl, [rsp + 0x10]
    test cl, cl
    strict
    cmovnz rcx, rdx
    strict
    cmovz rcx, r8
    or rax, rcx
    strict
    jnz CheckForDebuggers_ret
%endif

    ; -- Check NtQueryInformationProcess values --
	mov rcx, rsi
	lea rdx, [QIP]
	call ShellcodeData.Labels.GetProcAddress
	mov rbx, rax
	%if Options.Packing.bDirectSyscalls
		mov eax, [rbx]
		sub eax, 0xB8D18B4C
		strict
		jnz CheckForDebuggers_ret
		mov ebx, [rbx + 4]
	%endif

	; ProcessDebugPort
	mov rdx, 7
	push 0
	mov r8, rsp
	push 0
	mov r9, sizeof(HANDLE)
	%if Options.Packing.bDirectSyscalls
		mov r10, 0xFFFFFFFFFFFFFFFF
		sub rsp, 0x28
		mov eax, ebx
		syscall
		add rsp, 0x30
	%else
		mov rcx, 0xFFFFFFFFFFFFFFFF
		sub rsp, 0x20
		call rbx
		add rsp, 0x28
	%endif
	pop rax
	test rax, rax
	strict
	jnz CheckForDebuggers_ret

	; ProcessDebugObjectHandle
	mov rdx, 30
	push 0
	mov r8, rsp
	push 0
	mov r9, sizeof(HANDLE)
	%if Options.Packing.bDirectSyscalls
		mov r10, 0xFFFFFFFFFFFFFFFF
		sub rsp, 0x28
		mov eax, ebx
		syscall
		add rsp, 0x38
	%else
		mov rcx, 0xFFFFFFFFFFFFFFFF
		sub rsp, 0x20
		call rbx
		add rsp, 0x30
	%endif
	sub eax, 0xC0000353
	strict
	jnz CheckForDebuggers_ret

	; ProcessDebugFlags
	mov rdx, 31
	push 0
	mov r8, rsp
	push 0
	mov r9, 4
	%if Options.Packing.bDirectSyscalls
		mov r10, 0xFFFFFFFFFFFFFFFF
		sub rsp, 0x28
		mov eax, ebx
		syscall
		add rsp, 0x30
	%else
		mov rcx, 0xFFFFFFFFFFFFFFFF
		sub rsp, 0x20
		call rbx
		add rsp, 0x28
	%endif
    mov al, 1
	pop rdx
	test rdx, rdx
	strict
	jz CheckForDebuggers_ret

    ; -- Proc list check --
    mov al, 0
    test rbp, rbp
    strict
    jz CheckForDebuggers_ret
    mov rcx, rsi
    lea rdx, [NTCLOSE]
    call ShellcodeData.Labels.GetProcAddress
    mov rbp, rax
    mov rcx, rsi
    lea rdx, [QIP]
    call ShellcodeData.Labels.GetProcAddress
    mov rbx, rax
    mov rcx, rsi
    lea rdx, [GNP]
    call ShellcodeData.Labels.GetProcAddress
    mov rsi, rax
    test rbp, rbp
    strict
    jz CheckForDebuggers_ret
    test rbx, rbx
    strict
    jz CheckForDebuggers_ret
    test rsi, rsi
    strict
    jz CheckForDebuggers_ret

    ; Convert funs to syscall ids
    %if Options.Packing.bDirectSyscalls
        mov eax, [rbp]
        add eax, [rbx]
        add eax, [rsi]
        cmp eax, 0x2A74A1E4
        strict
        jne CheckForDebuggers_ret
        mov ebp, [rbp + 4]
        mov ebx, [rbx + 4]
        mov esi, [rsi + 4]
    %endif

    push 0
CheckForDebuggers_EnumProcesses_loop:
    ; Get next process handle
    mov rcx, rsp
    mov r15, [rsp]
    push rcx
    mov rdx, PROCESS_QUERY_INFORMATION
    mov r8, 0
    mov r9, r8
    sub rsp, 0x20
    %if Options.Packing.bDirectSyscalls
        mov r10, r15
        mov eax, esi
        sub rsp, 0x08
        syscall
        add rsp, 0x08
    %else
        mov rcx, r15
        call rsi
    %endif
    add rsp, 0x28
    mov r14, rax
    test r15, r15
    strict
    jz CheckForDebuggers_EnumProcesses_skipclose

    ; Close old handle
    sub rsp, 0x20
    %if Options.Packing.bDirectSyscalls
        mov r10, r15
        mov eax, ebp
        syscall
    %else
        mov rcx, r15
        call rbp
    %endif
    add rsp, 0x20

CheckForDebuggers_EnumProcesses_skipclose:

    ; Break if no new handles
    mov rcx, 0x8000001A
    mov rax, 0
    sub r14, rcx
    strict
    jz CheckForDebuggers_EnumProcesses_exit

    ; Get process name
    mov r11, [rsp]
    mov rdx, 27
    mov r9, 0x210
    sub rsp, 0x210 - (sizeof(CONTEXT) + 0x10)
    mov word [rsp], 0
    mov word [rsp + 2], 0x198
    lea r8, [rsp + 0x10]
    mov [rsp + 4], r8
    mov r8, rsp
    push 0
    sub rsp, 0x20
    %if Options.Packing.bDirectSyscalls
        mov r10, r11
        mov eax, ebx
        sub rsp, 0x08
        syscall
        add rsp, 0x08
    %else
        mov rcx, r11
        call rbx
    %endif
    add rsp, 0x238 - (sizeof(CONTEXT) + 0x10)
    test rax, rax
    strict
    jnz CheckForDebuggers_EnumProcesses_loop
    sub rsp, 0x210 - (sizeof(CONTEXT) + 0x10)

    ; Hash name
    mov rcx, [rsp + 8]
    mov rdx, 0
    mov dx, [rsp]
    add rcx, rdx
    mov rdx, 0
CheckForDebuggers_EnumProcesses_findend:
    add rdx, 2
    sub rcx, 2
    mov r8w, [rcx]
    sub r8b, '\\'
    strict
    jnz CheckForDebuggers_EnumProcesses_findend
    add rcx, 2
    sub rdx, 2
    sub rsp, sizeof(CSha256) + sizeof(Sha256Digest)
    push rcx
    push rdx
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x10)]
    mov rdx, sizeof(CSha256)
    call ShellcodeData.Labels.RtlZeroMemory
    lea rcx, [rsp + (sizeof(Sha256Digest) + 0x10)]
    call Sha256_Init
    pop r8
    pop rdx
    lea rcx, [rsp + (sizeof(Sha256Digest))]
    call Sha256_Update
    lea rcx, [rsp + (sizeof(Sha256Digest))]
    mov rdx, rsp
    call Sha256_Final

    ; Compare to blacklist
    mov r9, 1
    mov r11, 0
    lea rdx, [DEBUG_PROC_BLACKLIST]
    mov r8, DEBUG_PROC_BLACKLIST_LEN
CheckForDebuggers_EnumProcesses_compare:
    mov rax, 0
    mov r10, [rdx + offsetof(Sha256Digest, high.high)]
    cmp r10, [rsp + offsetof(Sha256Digest, high.high)]
    strict
    cmovne rax, r9
    mov r10, [rdx + offsetof(Sha256Digest, high.low)]
    cmp r10, [rsp + offsetof(Sha256Digest, high.low)]
    strict
    cmovne rax, r9
    mov r10, [rdx + offsetof(Sha256Digest, low.high)]
    cmp r10, [rsp + offsetof(Sha256Digest, low.high)]
    strict
    cmovne rax, r9
    mov r10, [rdx + offsetof(Sha256Digest, low.low)]
    cmp r10, [rsp + offsetof(Sha256Digest, low.low)]
    strict
    cmovne rax, r9
    test rax, rax
    strict
    cmovz r8, r9
    add rdx, sizeof(Sha256Digest)
    dec r8
    strict
    jnz CheckForDebuggers_EnumProcesses_compare

    add rsp, 0x210 + sizeof(CSha256) + sizeof(Sha256Digest) - (sizeof(CONTEXT) + 0x10)
    test rax, rax
    strict
    cmovz rax, r9
    strict
    jz CheckForDebuggers_EnumProcesses_exit
    jmp CheckForDebuggers_EnumProcesses_loop
CheckForDebuggers_EnumProcesses_exit:
    add rsp, 8

CheckForDebuggers_ret:
    add rsp, sizeof(CONTEXT) + 0x10
    pop rbp
    pop rbx
    pop rsi
    test rax, rax
    strict
    setnz al
    ret
%endif

; GetCurrentThread
%if ShellcodeData.RequestedFunctions.GetCurrentThread.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.GetCurrentThread.Func:
    mov rax, 0xFFFFFFFFFFFFFFFE
    ret
%endif

; VirtualProtect(Ex)
%if ShellcodeData.RequestedFunctions.VirtualProtect.bRequested || ShellcodeData.RequestedFunctions.VirtualProtectEx.bRequested
PVM:
    embed &Sha256Str("NtProtectVirtualMemory"), sizeof(Sha256Digest)
PVM_ptr:
    dq 0
    align AlignMode::kCode, alignof(PVOID)
PVM_param:
    dq 0, 2

%if ShellcodeData.RequestedFunctions.VirtualProtect.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.VirtualProtect.Func:
%endif
    push r9
    mov r9, r8
    mov r8, rdx
    mov rdx, rcx
    mov rcx, 0xFFFFFFFFFFFFFFFF
%if ShellcodeData.RequestedFunctions.VirtualProtectEx.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.VirtualProtectEx.Func:
%endif
    mov rax, [PVM_ptr]
    test rax, rax
    strict
    jne VirtualProtectEx_skip_find
    push rcx
    push rdx
    push r8
    push r9
    lea rcx, [NTD]
    call ShellcodeData.Labels.GetModuleHandleW
    mov rcx, rax
    lea rdx, [PVM]
    call ShellcodeData.Labels.GetProcAddress
    mov [PVM_ptr], rax
    pop r9
    pop r8
    pop rdx
    pop rcx
VirtualProtectEx_skip_find:
    mov [PVM_param], rdx
    lea rdx, [PVM_param]
    mov [rdx + 8], r8
    mov r8, rdx
    add r8, 8
    pop r10
    sub rsp, 0x08
    push r10
    sub rsp, 0x20
    %if Options.Packing.bDirectSyscalls
        mov r10, rcx
        mov ecx, [rax]
        xchg rax, rcx
        push rcx
        lea rcx, [HOOKFL]
        sub eax, 0xB8D18B4C
        strict
        jnz ShellcodeData.Labels.FatalError
        pop rax
        mov eax, [rax + 4]
        syscall
    %else
        call rax
    %endif
    add rsp, 0x30
    mov rcx, 0
    test rax, rax
    strict
    mov rax, 1
    strict
    cmovnz rax, rcx
    ret
%endif

; VirtualQuery(Ex)
%if ShellcodeData.RequestedFunctions.VirtualQuery.bRequested || ShellcodeData.RequestedFunctions.VirtualQueryEx.bRequested
QVM:
    embed &Sha256Str("NtQueryVirtualMemory"), sizeof(Sha256Digest)
QVM_ptr:
    dq 0

%if ShellcodeData.RequestedFunctions.VirtualQuery.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.VirtualQuery.Func:
%endif
    mov r9, r8
    mov r8, rdx
    mov rdx, rcx
    mov rcx, 0xFFFFFFFFFFFFFFFF
%if ShellcodeData.RequestedFunctions.VirtualQueryEx.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.VirtualQueryEx.Func:
%endif
    mov rax, [QVM_ptr]
    test rax, rax
    strict
    jne VirtualQueryEx_skip_find
    push rcx
    push rdx
    push r8
    push r9
    lea rcx, [NTD]
    call ShellcodeData.Labels.GetModuleHandleW
    mov rcx, rax
    lea rdx, [QVM]
    call ShellcodeData.Labels.GetProcAddress
    mov [QVM_ptr], rax
    pop r9
    pop r8
    pop rdx
    pop rcx
VirtualQueryEx_skip_find:
    push 0
    push r9
    mov r9, r8
    mov r8, 0
    sub rsp, 0x20
    ; I don't know what the fuck is wrong with this syscall in particular, but I'm not dealing with this right now
    ; For future reference: this is exactly the same as the other syscalls added in this commit, but for some reason this throws 0xC0000004 (STATUS_INFO_LENGTH_MISMATCH) when calling via syscall, despite having the same apparent parameters

    ; %if Options.Packing.bDirectSyscalls
    ;     mov r10, rcx
    ;     mov ecx, [rax]
    ;     xchg rax, rcx
    ;     push rcx
    ;     lea rcx, [HOOKFL]
    ;     sub eax, 0xB8D18B4C
    ;     strict
    ;     jnz ShellcodeData.Labels.FatalError
    ;     pop rax
    ;     mov eax, [rax + 4]
    ;     syscall
    ; %else
        call rax
    ; %endif
    add rsp, 0x30
    mov rcx, 0
    test rax, rax
    strict
    mov rax, 1
    strict
    cmovnz rax, rcx
    ret
%endif

; VirtualFree(Ex)
%if ShellcodeData.RequestedFunctions.VirtualFree.bRequested || ShellcodeData.RequestedFunctions.VirtualFreeEx.bRequested
FVM:
    embed &Sha256Str("NtFreeVirtualMemory"), sizeof(Sha256Digest)
FVM_ptr:
    dq 0
    align AlignMode::kCode, alignof(PVOID)
FVM_param:
    dq 0, 2

%if ShellcodeData.RequestedFunctions.VirtualFree.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.VirtualFree.Func:
%endif
    mov r9, r8
    mov r8, rdx
    mov rdx, rcx
    mov rcx, 0xFFFFFFFFFFFFFFFF
%if ShellcodeData.RequestedFunctions.VirtualFreeEx.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.VirtualFreeEx.Func:
%endif
    mov rax, [FVM_ptr]
    test rax, rax
    strict
    jne VirtualFreeEx_skip_find
    push rcx
    push rdx
    push r8
    push r9
    lea rcx, [NTD]
    call ShellcodeData.Labels.GetModuleHandleW
    mov rcx, rax
    lea rdx, [FVM]
    call ShellcodeData.Labels.GetProcAddress
    mov [FVM_ptr], rax
    pop r9
    pop r8
    pop rdx
    pop rcx
VirtualFreeEx_skip_find:
    mov [FVM_param], rdx
    lea rdx, [FVM_param]
    mov [rdx + 8], r8
    mov r8, rdx
    add r8, 8
    sub rsp, 0x20
    %if Options.Packing.bDirectSyscalls
        mov r10, rcx
        mov ecx, [rax]
        xchg rax, rcx
        push rcx
        lea rcx, [HOOKFL]
        sub eax, 0xB8D18B4C
        strict
        jnz ShellcodeData.Labels.FatalError
        pop rax
        mov eax, [rax + 4]
        syscall
    %else
        call rax
    %endif
    add rsp, 0x20
    mov rcx, 0
    test rax, rax
    strict
    mov rax, 1
    strict
    cmovnz rax, rcx
    ret
%endif

; GetLargePageMinimum
%if ShellcodeData.RequestedFunctions.GetLargePageMinimum.bRequested
; GLOBAL
ShellcodeData.RequestedFunctions.GetLargePageMinimum.Func:
    mov eax, [0x7FFE0244]
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