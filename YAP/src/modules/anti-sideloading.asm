   jmp skip

DIR:
   embed &Sha256Str("SetDllDirectoryA"), sizeof(Sha256Digest)
SSP:
   embed &Sha256Str("SetSearchPathMode"), sizeof(Sha256Digest)
ZRO:
   db 0

skip:
   lea rcx, [KERNEL32DLL]
   call ShellcodeData.Labels.GetModuleHandleW
   test rax, rax
   strict
   jz ret
   mov rcx, rax
   mov rsi, rax
   lea rdx, [DIR]
   call ShellcodeData.Labels.GetProcAddress
   test rax, rax
   strict
   jz ret
   mov rcx, rsp
   and rcx, 0b1111
   add rcx, 8
   sub rsp, rcx
   push rcx
   lea rcx, [ZRO]
   sub rsp, 0x20
   call rax
   add rsp, 0x20
   pop rcx
   add rsp, rcx
   mov rcx, rsi
   lea rdx, [SSP]
   call ShellcodeData.Labels.GetProcAddress
   test rax, rax
   strict
   jz ret
   mov rcx, rsp
   and rcx, 0b1111
   add rcx, 8
   sub rsp, rcx
   push rcx
   mov ecx, BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE | BASE_SEARCH_PATH_PERMANENT
   sub rsp, 0x20
   call rax
   add rsp, 0x20
   pop rcx
   add rsp, rcx
    
ret: