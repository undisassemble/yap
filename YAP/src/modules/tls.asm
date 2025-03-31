    ; Check if called for process start
    desync
	desync_mov rax
	cmp rdx, 1
	strict
	je _do

	; If it's not, call packed binaries TLS callbacks (if unpacked)
	%if TLSCallbacks.Size()
		%if Options.Packing.bAntiDebug
			cmp rdx, 2
			strict
			jne donthide
			call hidethread
donthide:
		%endif
		
        mov rax, ShellcodeData.LoadedOffset
		add rax, [reloc]
		cmp byte [rax], 0
		strict
		jz isloaded
		ret

isloaded:
		push r8
		push rdx
		push rcx
		; RAW_C for (int i = 0; i < TLSCallbacks.Size(); i++) {
			mov rax, TLSCallbacks.At(i)
			add rax, [reloc]
			mov rcx, [rsp]
			mov rdx, [rsp + 0x08]
			mov r8, [rsp + 0x10]
			call rax
		; RAW_C }
		; RAW_C TLSCallbacks.Release();
		pop rcx
		pop rdx
		pop r8
	%endif
	mov rax, 0
	ret

	; Otherwise do stuff
reloc:
	dq ShellcodeData.BaseAddress + pPackedBinary->NTHeaders.OptionalHeader.ImageBase + a.offset()
_do:
	desync_mov rdx
    %if Options.Packing.bAntiDebug
        call hidethread
	%endif
    push r12
	push r13
	push r14
	push r15
	push rdi
	push rsi
	push rbx
	push rbp
	lea rax, [reloc]
	sub rax, [rax]
	mov [reloc], rax
	%if Options.Packing.bAntiDebug
		mov rax, 0
		desync
		mov rcx, PEB
		mov al, [rcx + 0x02]
		shl rax, 32
		mov rdx, 0xBC
		mov rsi, 0x70
		mov r8d, [rcx + rdx]
		and r8, rsi
		xor r8, rsi
		strict
		setz al
		or al, [0x7FFE02D4]
		mov rcx, rax
		; RAW_C for (int i = 0; i < 32; i++) {
			shl rcx, 1
			or rcx, rax
		; RAW_C }
		push rcx
		mov rcx, 0
		%ifdef _DEBUG
			%if Options.Debug.bGenerateBreakpoints
				int3
				block
			%endif
        %endif
		popfq
		block
		jz pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.BaseAddress - (rand() & 0xFFFF)
	%endif
	%if Options.Packing.bAntiPatch
		jmp checksigs
		garbage
HeaderDigest:
		; RAW_C ShellcodeData.AntiPatchData.dwOffHeaderSum = a.offset();
		db 0, sizeof(Sha256Digest)
hash:
		db 0, sizeof(CSha256)
		garbage
LoaderDigest:
		embed &ShellcodeData.AntiPatchData.LoaderHash, sizeof(Sha256Digest)
		garbage

checksigs:
		lea rcx, [hash]
		push rcx
		call pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.Sha256_InitOff
		mov rcx, [rsp]
		mov rdx, pPackedBinary->NTHeaders.OptionalHeader.ImageBase
		add rdx, [reloc]
		mov r8, pPackedBinary->NTHeaders.OptionalHeader.SizeOfHeaders
		call pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.Sha256_UpdateOff
		pop rcx
		mov rdx, rcx
		add rdx, sizeof(CSha256) ; rdx -> garbage
		push rdx
		call pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.Sha256_FinalOff
		mov rcx, [rsp] ; rcx -> rdx
		pop rdx
		sub rcx, sizeof(Sha256Digest) + sizeof(CSha256) ; rcx -> HeaderDigest
		; RAW_C for (int i = 0; i < sizeof(Sha256Digest) / sizeof(QWORD); i++) {
			mov r8, [rdx]
			sub r8, 8
			sub [rcx], r8
			add rdx, [rcx]
			add rcx, [rcx]
		; RAW_C }
		; fuck me (check the thingymadoodle)
	%endif
	%if Options.Packing.bDelayedEntry
		mov rax, pPackedBinary->NTHeaders.OptionalHeader.ImageBase + pPackedBinary->SectionHeaders[0].VirtualAddress
		add rax, [reloc]
		%if Options.Packing.bAntiDebug
			cmp byte [rax], 0xCC
			strict
			mov rcx, 0
			strict
			cmovnz rcx, rax
			cmp word [rax], 0x03CD
			strict
			mov byte [rax], 0xC3
			strict
			mov rax, rcx
			strict
			cmovz rax, rsp
			call rax
			mov byte [rax], 0x00
		%endif
		add rax, 2 * (rand64() % (pPackedBinary->SectionHeaders[0].Misc.VirtualSize / 2))
		mov word [rax], 0xB848
		add rax, 2
		mov rcx, pPackedBinary->NTHeaders.OptionalHeader.ImageBase + pPackedBinary->NTHeaders.OptionalHeader.AddressOfEntryPoint + ShellcodeData.EntryOff
		add rcx, [reloc]
		mov [rax], rcx
		add rax, 8
		mov word [rax], 0xE0FF
	%endif
	garbage
	pop rbp
	pop rbx
	pop rsi
	pop rdi
	pop r15
	pop r14
	pop r13
	pop r12
	mov rax, 1
	ret

	%if Options.Packing.bAntiDebug
NTD:
		embed &Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest)
STI:
		embed &Sha256Str("NtSetInformationThread"), sizeof(Sha256Digest)
; GLOBAL
hidethread:
		lea rcx, [NTD]
		call pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.GetModuleHandleWOff
		mov rcx, rax
		lea rdx, [STI]
		call pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.GetProcAddressOff
		mov r8, rsp
		and r8, 0b1111
		add r8, 8
		sub rsp, r8
		push r8
		mov rdx, 17
		mov r8, 0
		%if Options.Packing.bDirectSyscalls
            mov r10, 0xFFFFFFFFFFFFFFFE
			lea r9, [thingy]
			mov ecx, [rax]
			cmp ecx, 0xB8D18B4C
			strict
			mov rcx, 0
			strict
			cmovnz r9, rcx
			jmp r9
thingy:
            mov rcx, 0xFFFFFFFFFFFFFFFE
			mov eax, [rax + 4]
			mov r9, 0
			syscall
		%else
			mov r9, 0
			call rax
		%endif
		pop r8
		add rsp, r8
		ret
	%endif