%define ASSEMBLER a.

    %if Options.Advanced.bMutateAssembly
		strict
		jz _entry
		garbage
	%else
		jmp _entry
	%endif

	; Data
	%if Options.Packing.Message[0]
message:
		embed Options.Packing.Message, lstrlenA(Options.Packing.Message) + 1
	%endif
	align AlignMode::kZero, alignof(CSha256)
; GLOBAL
hash:
	embed &sha, sizeof(CSha256)
	align AlignMode::kZero, alignof(Sha256Digest)
; GLOBAL
digest:
	embed &_digest, sizeof(_digest)
ret:
	add rsp, 0x40
	garbage
	ret

	; Entry point
_entry:
	%if Options.Packing.Message[0]
		lea rax, [message]
	%endif
	push rsp
	push rax
	push rcx
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	push rdi
	push rsi
	push rbx
	push rbp
	desync_mov rax
	garbage
	desync_mov rdx
	
	; Get base offset
	jmp SkipReloc
Reloc:
	dq ShellcodeData.BaseAddress + a.offset() + pPackedBinary->NTHeaders.OptionalHeader.ImageBase
	%if Options.Packing.bOnlyLoadMicrosoft
NTD:
		embed &Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest)
SIP:
		embed &Sha256Str("ZwSetInformationProcess"), sizeof(Sha256Digest)
	%endif
	garbage
SkipReloc:
	lea rax, [Reloc]
	sub rax, [rax]
	mov [Reloc], rax

	sub rsp, 0x40
	strict
	desync_jnz

    ; Modules
    ; TODO: Improve anti-vm
    ; TODO: Improve anti-sandbox
	%if Options.Packing.bMitigateSideloading
		%include "modules/anti-sideloading.inc"
	%endif
	%if Options.Packing.bOnlyLoadMicrosoft
		; RAW_C PROCESS_MITIGATION_POLICY _policy = ProcessSignaturePolicy;
		; RAW_C PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig_policy = { 0 };
		; RAW_C sig_policy.MicrosoftSignedOnly = 1;
		%include "modules/ms-signing.inc"
	%endif
	%if Options.Packing.bAntiDebug
		; RAW_C CONTEXT context = { 0 };
		; RAW_C context.ContextFlags = CONTEXT_ALL;
		%include "modules/anti-debug-main.inc"
	%endif
	%if Options.Packing.bAntiVM
		%include "modules/anti-vm.inc"
	%endif
	%if Options.Packing.bAntiSandbox
		%include "modules/anti-sandbox.inc"
	%endif
	%if Options.Packing.bAntiDump
		%include "modules/anti-dump.inc"
	%endif

	; Load each section
	mov rsi, 0
	lea rcx, [CompressedSections]
	mov rbp, pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.BaseOffset
decompressloop:
	mov rax, DecompressKey
	lea rdx, [CompressedSizes]
	mov rdx, [rdx + rsi * 8]
	xor rdx, rax
	lea r8, [VirtualAddrs]
	mov r8, [r8 + rsi * 8]
	xor r8, rax
	add r8, rbp
	add r8, [Reloc]
	lea r9, [DecompressedSizes]
	mov r9, [r9 + rsi * 8]
	xor r9, rax
	mov rax, 0
	call unpack
	inc rsi
	cmp rsi, NumPacked
	strict
	jne decompressloop
	lea rcx, [InternalShell]
	mov rdx, CompressedInternal.u64Size
	mov r8, pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.BaseOffset + pOriginal->NTHeaders.OptionalHeader.SizeOfImage
	add r8, [Reloc]
	mov r9, InternalShellcode.u64Size
	call unpack
	
	; Relocation stuff
	mov rax, [Reloc]
	%if ShellcodeData.Relocations.Relocations.Size()
		; RAW_C for (int i = 0, n = ShellcodeData.Relocations.Relocations.Size(); i < n; i++) {
			mov r10, pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.Relocations.Relocations[i]
			add r10, rax
			add [r10], rax
		; RAW_C }
		; RAW_C ShellcodeData.Relocations.Relocations.Release();
	%endif
	mov rcx, rax

	desync
	mov rax, pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.BaseOffset + pOriginal->NTHeaders.OptionalHeader.SizeOfImage
	add rax, rcx
	%if Options.Packing.bAntiDump
		lea rcx, [rip]
		sub rcx, a.offset()
		mov rdx, [szshell]
	%endif
	%ifdef _DEBUG
		%if Options.Debug.bGenerateBreakpoints
			int3
			block
		%endif
    %endif
	call rax
	garbage