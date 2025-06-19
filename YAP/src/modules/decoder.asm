%define ASSEMBLER pA->

; Data
destLen:
    dq rand64()
srcLen:
    dq 0
propData:
    embed ShellcodeData.UnpackData.EncodedProp, sizeof(ShellcodeData.UnpackData.EncodedProp)
alloc:
    dq rand64()
    dq rand64()
status:
    dq rand64()

; Alloc
ptr_HeapAlloc:
    dq rand64()
Mem_alloc:
	mov r8, rdx
	mov edx, 0
	mov rcx, PEB
	mov rcx, [rcx + 0x30]
	sub rsp, 0x20
	call [ptr_HeapAlloc]
	add rsp, 0x20
	ret

; Free
ptr_HeapFree:
    dq rand64()
Mem_free:
	mov r8, rdx
	mov edx, 0
	mov rcx, PEB
	mov rcx, [rcx + 0x30]
	sub rsp, 0x20
	call [ptr_HeapFree]
	add rsp, 0x20
	ret

NTD:
    embed &Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest)
HF:
    embed &Sha256Str("RtlFreeHeap"), sizeof(Sha256Digest)
HA:
    embed &Sha256Str("RtlAllocateHeap"), sizeof(Sha256Digest)

; GLOBAL
Entry:
    mov [_rcx], rcx
    mov [_rdx], rdx
	push rcx
	push rdx
	mov al, DecoderProc.At(0).value
dcd_loop:
	; RAW_C for (int i = 1, n = DecoderProc.Size(); i < n; i++) {
	; RAW_C switch (DecoderProc[i].Mnemonic) {
	; RAW_C case DI_XOR:
        %if DecoderProc.At(i).value
            xor byte [rcx], DecoderProc.At(i).value
        %else
            xor byte [rcx], al
        %endif
    ; RAW_C break;
	; RAW_C case DI_NOT:
	    not byte [rcx]
	; RAW_C break;
	; RAW_C case DI_NEG:
	    neg byte [rcx]
	; RAW_C break;
	; RAW_C case DI_ADD:
        %if DecoderProc.At(i).value
            add byte [rcx], DecoderProc.At(i).value
        %else
            add byte [rcx], al
        %endif
	; RAW_C break;
	; RAW_C case DI_SUB:
        %if DecoderProc.At(i).value
            sub byte [rcx], DecoderProc.At(i).value
        %else
            sub byte [rcx], al
        %endif
	; RAW_C }
	; RAW_C }
	add al, [rcx]
	xor al, [rcx]
	inc rcx
	dec rdx
	strict
	jnz dcd_loop
	pop rdx
	pop rcx

	; Load stuff
	push r8
	push r9
	push rdx
	push rcx
	push r8
	push r9
	lea rcx, [NTD]
	call ShellcodeData.Labels.GetModuleHandleW
	mov rcx, rax
	lea rdx, [HF]
	call ShellcodeData.Labels.GetProcAddress
	mov [ptr_HeapFree], rax
	lea rdx, [HA]
	call ShellcodeData.Labels.GetProcAddress
	mov [ptr_HeapAlloc], rax
	pop r9
	pop rcx
	pop r8
	pop rdx

	; Decompress
	mov [srcLen], rdx
	mov [destLen], r9
	lea rdx, [alloc]
	lea r9, [Mem_alloc]
	mov [rdx], r9
	lea r9, [Mem_free]
	mov [rdx + 0x08], r9
	mov [rsp + 0x40], rdx
	lea rdx, [status]
	mov [rsp + 0x38], rdx
	mov dword [rsp + 0x30], 0
	mov dword [rsp + 0x28], 5
	lea r9, [propData]
	mov [rsp + 0x20], r9
	lea r9, [srcLen]
	lea rdx, [destLen]
	call LzmaDecode
	mov rcx, 0
	xchg [_rcx], rcx
	mov rdx, 0
	xchg [_rdx], rdx
	pop r9
	pop r8
	
	; re-encode thingy madoodle
	mov al, DecoderProc[0].value
	mov r8b, al
enc_loop:
	add r8b, [rcx]
	xor r8b, [rcx]
	; RAW_C for (int i = DecoderProc.Size() - 1; i > 0; i--) {
    ; RAW_C switch (DecoderProc[i].Mnemonic) {
    ; RAW_C case DI_XOR:
        %if DecoderProc.At(i).value
            xor byte [rcx], DecoderProc.At(i).value
        %else
            xor byte [rcx], al
        %endif
    ; RAW_C break;
    ; RAW_C case DI_NOT:
        not byte [rcx]
    ; RAW_C break;
    ; RAW_C case DI_NEG:
        neg byte [rcx]
    ; RAW_C break;
    ; RAW_C case DI_ADD:
        %if DecoderProc.At(i).value
            sub byte [rcx], DecoderProc.At(i).value
        %else
            sub byte [rcx], al
        %endif
    ; RAW_C break;
    ; RAW_C case DI_SUB:
        %if DecoderProc.At(i).value
            add byte [rcx], DecoderProc.At(i).value
        %else
            add byte [rcx], al
        %endif
    ; RAW_C }
	; RAW_C }
	mov al, r8b
	inc rcx
	dec rdx
	strict
	jnz enc_loop
	ret
	
_rcx:
	dq 0
_rdx:
	dq 0

    ; LZMA functions
	%include "LzmaDecode.raw"
	%include "LzmaDec_DecodeToDic.raw"
	%include "LzmaDec_TryDummy.raw"
	%include "LzmaDec_DecodeReal.raw"