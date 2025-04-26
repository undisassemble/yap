%define mnem(mnemonic) (instId == Inst::mnemonic)
%define ToGp(op) (child_cast<Gp>(op))
%define ToImm(op) (child_cast<Imm>(op))
%define ToMem(op) (child_cast<Mem>(op))
%define ToLabel(op) (child_cast<Label>(op))

; lea reg, mem
%if mnem(kIdLea) && o0.isGp() && o1.isMem() && ToGp(o0).isGpq() && resolve(ToMem(o1))
	pop ToGp(o0)

; call reg
; TODO: Make sure this works with strict
%elif mnem(kIdCall) && o0.isGp()
	; RAW_C BYTE dist = 0;
	%if !bStrict && !bForceStrict
		; RAW_C dist = 64 + (rand() % 192);
	%endif
	push ToGp(o0)
	push ToGp(o0)
	push ToGp(o0)
	lea ToGp(o0), [call_reg_after]
	%if dist
		add ToGp(o0), dist
	%endif
	mov [rsp + 0x10], ToGp(o0)
	pop ToGp(o0)
	ret
	call_reg_after:
	; RAW_C for (int i = 0; i < dist; i++) {
	; RAW_C BYTE byte = 0;
	; RAW_C do {
	; RAW_C byte = rand() & 0xFF;
	; RAW_C } while (byte == 0xC3 || byte == 0xCB || !byte);
	; RAW_C db(byte);
	; RAW_C }

; call label
; TODO: Make sure this works with strict
%elif mnem(kIdCall) && o0.isLabel()
	; RAW_C Gp reg = truerandreg();
	; RAW_C BYTE dist = 0;
	%if !bStrict && !bForceStrict
		; RAW_C dist = 64 + (rand() % 192);
	%endif
	push reg
	push reg
	push reg
	lea reg, [call_label_after]
	%if dist
		add reg, dist
	%endif
	mov [rsp + 0x10], reg
	lea reg, [ToLabel(o0)]
	mov [rsp + 0x08], reg
	pop reg
	ret
	call_label_after:
	; RAW_C for (int i = 0; i < dist; i++) {
	; RAW_C BYTE byte = 0;
	; RAW_C do {
	; RAW_C byte = rand() & 0xFF;
	; RAW_C } while (byte == 0xC3 || byte == 0xCB || !byte);
	; RAW_C db(byte);
	; RAW_C }

; call mem
; TODO: Make sure this works with strict
%elif mnem(kIdCall) && o0.isMem() && ToMem(o0).baseReg() != rsp
	; RAW_C Gp reg = truerandreg();
	; RAW_C Mem _o0 = ToMem(o0);
	; RAW_C _o0.setSize(8);
	; RAW_C BYTE dist = 0;
	%if !bStrict && !bForceStrict
		; RAW_C dist = 64 + (rand() % 192);
	%endif
	%if resolve(_o0)
		xchg reg, [rsp]
		mov reg, [reg]
		xchg reg, [rsp]
		push qword [rsp]
	%else
		push _o0
		push _o0
	%endif
	push reg
	lea reg, [call_mem_after]
	%if dist
		add reg, dist
	%endif
	mov [rsp + 0x10], reg
	pop reg
	ret
	call_mem_after:
	; RAW_C for (int i = 0; i < dist; i++) {
	; RAW_C BYTE byte = 0;
	; RAW_C do {
	; RAW_C byte = rand() & 0xFF;
	; RAW_C } while (byte == 0xC3 || byte == 0xCB || !byte);
	; RAW_C db(byte);
	; RAW_C }


; mov reg, imm
%elif mnem(kIdMov) && o0.isGp() && o1.isImm() && ToGp(o0).size() >= 4 && ToImm(o1).value() <= 0x7FFFFFFF
	push ToImm(o1)
	pop ToGp(o0).r64()

; mov reg, reg
%elif mnem(kIdMov) && o0.isGp() && o1.isGp() && ToGp(o1).r64() != rsp && ToGp(o0).size() == ToGp(o1).size() && (ToGp(o0).size() == 2 || ToGp(o0).size() == 8)
	push ToGp(o1)
	pop ToGp(o0)

; mov reg, mem
%elif mnem(kIdMov) && o0.isGp() && o1.isMem() && ToMem(o1).baseReg() != rsp && (ToGp(o0).size() == 2 || ToGp(o0).size() == 8)
	; RAW_C Mem _o1 = ToMem(o1);
	; RAW_C _o1.setSize(ToGp(o0).size());
	push _o1
	pop ToGp(o0)

; mov mem, imm
%elif mnem(kIdMov) && o0.isMem() && o1.isImm() && ToMem(o0).size() == 8
	%if resolve(ToMem(o0))
		; RAW_C Gp reg = truerandreg();
		push ToImm(o1)
		xchg reg, [rsp + 8]
		pop qword [reg]
		pop reg
	%else
		push ToImm(o1)
		pop ToMem(o0)
	%endif

; mov mem, reg
%elif mnem(kIdMov) && o0.isMem() && o1.isGp() && (ToGp(o1).size() == 2 || ToGp(o1).size() == 8)
	; RAW_C Mem _o0 = ToMem(o0);
	; RAW_C _o0.setSize(ToGp(o1).size());
	%if resolve(_o0)
		; RAW_C Gp reg;
		; RAW_C do {
		; RAW_C reg = truerandreg();
		; RAW_C } while (reg == ToGp(o1).r64());
		push ToGp(o1)
		%if ToGp(o1).size() == 8
			xchg reg, [rsp + 8]
			pop qword [reg]
		%else
			xchg reg, [rsp + 2]
			pop word [reg]
		%endif
		pop reg
	%else
		push ToGp(o1)
		pop _o0
	%endif
		

; ret
%elif mnem(kIdRet) && !o0.isImm()
	%if stack.Size()
		; RAW_C restorestack();
	%endif
	; RAW_C Gp reg = truerandreg();
	push reg
	mov reg, qword [0x7FFE02F8]
	xchg qword [rsp], reg
	pop qword [rip]
	dq rand64()

%else
	; RAW_C bSubFailed = true;
%endif
%undef ToLabel
%undef ToMem
%undef ToImm
%undef ToGp
%undef mnem