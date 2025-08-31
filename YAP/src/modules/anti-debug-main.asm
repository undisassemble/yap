%define ASSEMBLER a.

    ; Check for HWBP
    lea rcx, [NTD]
    call ShellcodeData.Labels.GetModuleHandleW
    lea rcx, [ADDRFL]
    test rax, rax
    strict
    jz ShellcodeData.Labels.FatalError
    mov rcx, rax
    mov rsi, rax
    lea rdx, [GCT]
    call ShellcodeData.Labels.GetProcAddress
    lea rcx, [ADDRFL]
    test rax, rax
    strict
    jz ShellcodeData.Labels.FatalError
    lea rdx, [Context]
    %if Options.Packing.bDirectSyscalls
        mov r10d, [rax]
        lea rcx, [DBGFL]
        cmp r10d, 0xB8D18B4C
        strict
        jnz ShellcodeData.Labels.FatalError
        mov eax, [rax + 4]
        mov r10, 0xFFFFFFFFFFFFFFFE
        syscall
    %else
        mov rcx, 0xFFFFFFFFFFFFFFFE
        call rax
    %endif
    lea rdx, [Context]
    lea rcx, [DBGFL]
    test rax, rax
    strict
    jnz ShellcodeData.Labels.FatalError
    mov rax, [rdx + offsetof(CONTEXT, Dr7)]
    and rax, 0x20FF
    strict
    jnz ShellcodeData.Labels.FatalError
    mov rax, [rdx + offsetof(CONTEXT, Dr6)]
    and rax, 0x18F
    strict
    jnz ShellcodeData.Labels.FatalError
    mov rax, [rdx + offsetof(CONTEXT, Dr0)]
    or rax, [rdx + offsetof(CONTEXT, Dr1)]
    or rax, [rdx + offsetof(CONTEXT, Dr2)]
    or rax, [rdx + offsetof(CONTEXT, Dr3)]
    strict
    jnz ShellcodeData.Labels.FatalError

    ; Check DSE
    mov rcx, rsi
    lea rdx, [QSI]
    call ShellcodeData.Labels.GetProcAddress
    lea rcx, [ADDRFL]
    test rax, rax
    strict
    jz ShellcodeData.Labels.FatalError
    lea rdx, [INTEG_OPT]
    mov r8, sizeof(SYSTEM_CODEINTEGRITY_INFORMATION)
    mov r9, 0
    %if Options.Packing.bDirectSyscalls
        mov r10d, [rax]
        lea rcx, [DBGFL]
        cmp r10d, 0xB8D18B4C
        strict
        jnz ShellcodeData.Labels.FatalError
        mov eax, [rax + 4]
        mov r10, 103
        syscall
    %else
        mov rcx, 103
        call rax
    %endif
    mov eax, [INTEG_OPT + 4]
    xor rax, CODEINTEGRITY_OPTION_ENABLED
    lea rcx, [DSEFL]
    and rax, CODEINTEGRITY_OPTION_ENABLED | CODEINTEGRITY_OPTION_TESTSIGN | CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED
    strict
    jnz ShellcodeData.Labels.FatalError
    
	; Get NtQueryInformationProcess
	lea rcx, [NTD]
	call ShellcodeData.Labels.GetModuleHandleW
	mov rcx, rax
	lea rdx, [QIP]
	call ShellcodeData.Labels.GetProcAddress
	lea rcx, [ADDRFL]
	test rax, rax
	strict
	jz ShellcodeData.Labels.FatalError
	mov rsi, rax
	%if Options.Packing.bDirectSyscalls
		lea rcx, [HOOKFL]
		mov eax, [rsi]
		sub eax, 0xB8D18B4C
		strict
		jnz ShellcodeData.Labels.FatalError
		mov esi, [rsi + 4]
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
		mov eax, esi
		syscall
		add rsp, 0x30
	%else
		mov rcx, 0xFFFFFFFFFFFFFFFF
		sub rsp, 0x20
		call rsi
		add rsp, 0x28
	%endif
	pop rdx
	lea rcx, [DBGFL]
	test rdx, rdx
	strict
	jnz ShellcodeData.Labels.FatalError

	; ProcessDebugObjectHandle
	mov rdx, 30
	push 0
	mov r8, rsp
	push 0
	mov r9, sizeof(HANDLE)
	%if Options.Packing.bDirectSyscalls
		mov r10, 0xFFFFFFFFFFFFFFFF
		sub rsp, 0x28
		mov eax, esi
		syscall
		add rsp, 0x38
	%else
		mov rcx, 0xFFFFFFFFFFFFFFFF
		sub rsp, 0x20
		call rsi
		add rsp, 0x30
	%endif
	lea rcx, [DBGFL]
	sub eax, 0xC0000353
	strict
	jnz ShellcodeData.Labels.FatalError

	; ProcessDebugFlags
	mov rdx, 31
	push 0
	mov r8, rsp
	push 0
	mov r9, 4
	%if Options.Packing.bDirectSyscalls
		mov r10, 0xFFFFFFFFFFFFFFFF
		sub rsp, 0x28
		mov eax, esi
		syscall
		add rsp, 0x30
	%else
		mov rcx, 0xFFFFFFFFFFFFFFFF
		sub rsp, 0x20
		call rsi
		add rsp, 0x28
	%endif
	pop rdx
	lea rcx, [DBGFL]
	test rdx, rdx
	strict
	jz ShellcodeData.Labels.FatalError