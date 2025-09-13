%define ASSEMBLER a.

	jmp _entry

	; Data
NTD:
	embed &Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest)
	%if Options.Packing.Message[0]
message:
		embed Options.Packing.Message, lstrlenA(Options.Packing.Message) + 1
	%endif
    align AlignMode::kCode, alignof(LPCSTR)
HOOKFL:
    embed "A hook was detected, please avoid hooking WINAPI functions!", 60
    align AlignMode::kCode, alignof(LPCSTR)
VMFL:
    embed "A virtual environment has been detected, execution will not continue.", 70

	%if Options.Packing.bAntiDebug
    	align AlignMode::kZero, alignof(CONTEXT)
Context:
		; RAW_C CONTEXT context = { 0 };
		; RAW_C context.ContextFlags = CONTEXT_ALL;
    	embed &context, sizeof(CONTEXT)
GCT:
    	embed &Sha256Str("ZwGetContextThread"), sizeof(Sha256Digest)
	%endif

	%if Options.Packing.bAntiDump
    	align AlignMode::kZero, alignof(DWORD)
TMP:
		dd 0
VRT:
    	embed &Sha256Str("VirtualProtect"), sizeof(Sha256Digest)
	%endif

	%if Options.Packing.bAntiDebug || Options.Packing.bAntiVM
GNP:
		embed &Sha256Str("NtGetNextProcess"), sizeof(Sha256Digest)
NTCLOSE:
		embed &Sha256Str("NtClose"), sizeof(Sha256Digest)
QIP:
		embed &Sha256Str("NtQueryInformationProcess"), sizeof(Sha256Digest)
	%endif

	%if Options.Packing.bMitigateSideloading
DIR:
   		embed &Sha256Str("SetDllDirectoryA"), sizeof(Sha256Digest)
SSP:
   		embed &Sha256Str("SetSearchPathMode"), sizeof(Sha256Digest)
ZRO:
		db 0
	%endif

	%if Options.Packing.bOnlyLoadMicrosoft
		align AlignMode::kCode, alignof(PROCESS_MITIGATION_POLICY)
		; RAW_C PROCESS_MITIGATION_POLICY _policy = ProcessSignaturePolicy;
		; RAW_C PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig_policy = { 0 };
		; RAW_C sig_policy.MicrosoftSignedOnly = 1;
policy:
		embed &_policy, sizeof(PROCESS_MITIGATION_POLICY)
		align AlignMode::kZero, alignof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY)
		embed &sig_policy, sizeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY)
	%endif

Reloc:
	dq ShellcodeData.BaseAddress + a.offset() + pPackedBinary->NTHeaders.OptionalHeader.ImageBase
KRN:
   	embed &Sha256WStr(L"KERNEL32.DLL"), sizeof(Sha256Digest)
GCP:
    embed &Sha256Str("GetCursorPos"), sizeof(Sha256Digest)
SLP:
    embed &Sha256Str("Sleep"), sizeof(Sha256Digest)
LLA:
    embed &Sha256Str("LoadLibraryA"), sizeof(Sha256Digest)
    align AlignMode::kCode, 0x10
PT:
    dq rand64()
    dq rand64()
MSGBX:
    embed &Sha256Str("MessageBoxA"), sizeof(Sha256Digest)
SIP:
	embed &Sha256Str("ZwSetInformationProcess"), sizeof(Sha256Digest)
	align AlignMode::kZero, alignof(CSha256)

ret:
	add rsp, 0x40
	garbage
	ret

    align AlignMode::kCode, alignof(LPCSTR)
USR:
    embed "USER32.dll", 11
	align AlignMode::kCode, alignof(LPCSTR)
ADDRFL:
	embed "Failed to get address of imported function.", 44
	align AlignMode::kCode, alignof(LPCSTR)
DBGFL:
	embed "Please close any debuggers.", 28
	align AlignMode::kCode, alignof(LPCSTR)
DSEFL:
	embed "Please enable Driver Signature Enforcement and disable Test Signing.", 69
%if Options.Packing.bAntiDebug
QSI:
    embed &Sha256Str("NtQuerySystemInformation"), sizeof(Sha256Digest)
    align AlignMode::kCode, alignof(SYSTEM_CODEINTEGRITY_INFORMATION)
INTEG_OPT:
    dd 8
    dd 0
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
%endif
%if Options.Packing.bAntiVM
%define VM_PROC_BLACKLIST_LEN 5
VM_PROC_BLACKLIST:
	embed &Sha256WStr(L"VBoxTray.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"VBoxService.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"vmtoolsd.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"VGAuthService.exe"), sizeof(Sha256Digest)
	embed &Sha256WStr(L"vm3dservice.exe"), sizeof(Sha256Digest)
%endif

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
	lea rax, [Reloc]
	sub rax, [rax]
	mov [Reloc], rax

	sub rsp, 0x40
	strict
	desync_jnz

    ; Modules
	%if Options.Packing.bMitigateSideloading
		%include "modules/anti-sideloading.inc"
	%endif
	%if Options.Packing.bOnlyLoadMicrosoft
		%include "modules/ms-signing.inc"
	%endif
	%if Options.Packing.bAntiDebug
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
 
 	; Check running processes
 	%if Options.Packing.bAntiDebug || Options.Packing.bAntiVM
 		lea rcx, [NTD]
 		call ShellcodeData.Labels.GetModuleHandleW
 		mov rsi, rax
 		mov rcx, rax
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
 		lea rcx, [ADDRFL]
 		test rbp, rbp
 		strict
 		jz ShellcodeData.Labels.FatalError
 		test rbx, rbx
 		strict
 		jz ShellcodeData.Labels.FatalError
 		test rsi, rsi
 		strict
 		jz ShellcodeData.Labels.FatalError
 		push 0

		; Convert funs to syscall ids
		%if Options.Packing.bDirectSyscalls
 			lea rcx, [HOOKFL]
			mov eax, [rbp]
			add eax, [rbx]
			add eax, [rsi]
			sub eax, 0x2A74A1E4
			strict
			jnz ShellcodeData.Labels.FatalError
			mov ebp, [rbp + 4]
			mov ebx, [rbx + 4]
			mov esi, [rsi + 4]
		%endif
 
EnumProcesses_loop:
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
		jz EnumProcesses_skipclose

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

EnumProcesses_skipclose:

		; Break if no new handles
		mov rcx, 0x8000001A
		sub r14, rcx
		strict
		jz EnumProcesses_exit
 
 		; Get process name
		mov r11, [rsp]
		mov rdx, 27
		mov r9, 0x210
		sub rsp, r9
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
		add rsp, 0x238
		test rax, rax
		strict
		jnz EnumProcesses_loop
		sub rsp, 0x210

		; Hash name
		mov rcx, [rsp + 8]
		mov rdx, 0
		mov dx, [rsp]
		add rcx, rdx
		mov rdx, 0
EnumProcesses_findend:
		add rdx, 2
		sub rcx, 2
		mov r8w, [rcx]
		sub r8b, '\\'
		strict
		jnz EnumProcesses_findend
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
		%if Options.Packing.bAntiDebug
			lea rcx, [DBGFL]
			lea rdx, [DEBUG_PROC_BLACKLIST]
			mov r8, DEBUG_PROC_BLACKLIST_LEN
		%elif Options.Packing.bAntiVM
			lea rcx, [VMFL]
			lea rdx, [VM_PROC_BLACKLIST]
			mov r8, VM_PROC_BLACKLIST_LEN
		%endif
EnumProcesses_compare:
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
		jz ShellcodeData.Labels.FatalError
		add rdx, sizeof(Sha256Digest)
		dec r8
		strict
		jnz EnumProcesses_compare

		%if Options.Packing.bAntiDebug && Options.Packing.bAntiVM
			test r11, r11
			strict
			jnz EnumProcesses_skipvm
			lea rcx, [VMFL]
			lea rdx, [VM_PROC_BLACKLIST]
			mov r8, VM_PROC_BLACKLIST_LEN
			mov r11, 1
			jmp EnumProcesses_compare
EnumProcesses_skipvm:
		%endif

		add rsp, 0x210 + sizeof(CSha256) + sizeof(Sha256Digest)
		jmp EnumProcesses_loop
EnumProcesses_exit:
 		pop rsi
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
	mov rdx, CompressedInternal.Size()
	mov r8, pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.BaseOffset + pOriginal->NTHeaders.OptionalHeader.SizeOfImage
	add r8, [Reloc]
	mov r9, InternalShellcode.Size()
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

	; Call internal
	%if Options.Packing.bAntiDump
		lea rcx, [rip]
		sub rcx, a.offset()
		lea rdx, [end]
		lea r8, [NTD]
		sub rdx, r8
	%endif
	%ifdef _DEBUG
		%if Options.Debug.bGenerateBreakpoints
			int3
			block
		%endif
    %endif
	call rax
	garbage
end: