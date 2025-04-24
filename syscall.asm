[BITS 64]
DEFAULT REL

EXTERN g_lpSyscallAddr

GLOBAL Syscall

[SECTION .text]
Syscall:
  ; set return value to STATUS_INVALID_SYSTEM_SERVICE.
  ; If the syscall number is not 0, this value will be
  ; overwritten by the syscall to contain the actual 
  ; return status. Otherwise perform a jump to the end
  ; of the function
  mov rax, 0xC000001C
  jrcxz .exit
  ; shift registers
  ; ecx   -> eax (ssn is in the 1st arg)
  ; rdx   -> r10 (1st arg of syscalls is expected in r10)
  ; r8    -> rdx
  ; r9    -> r8
  ; stack -> r9
  mov eax, ecx
  mov r10, rdx
  mov rdx, r8
  mov r8,  r9
  mov r9, qword [rsp+28h]
  ; "push" rbx (overwrite the useless parameter originally 
  ; on the stack since now it's in r9) 
  mov [rsp+28h], rbx 
  ; store the return address in rbx cause we are 
  ; advancing the stack pointer and syscall might 
  ; overwrite the 8 bytes containing the original 
  ; ret address 
  mov rbx, [rsp]
  ; adjust rsp to discard 5th argument in the stack:
  ; the syscall will pop from rsp+0x28, finding the 
  ; 6th argument
  ; NOTE: rsp is increased by 16 instead of 8 since
  ; the call to indirect address will push the current
  ; rip onto the stack
  add rsp, 10h

  ; need to call instead of jump because the next 
  ; three instructions must be executed to restore
  ; the execution environment of the process.
  ; jumping into ntdll would return to the caller
  ; of the Syscall function (or straight up crash 
  ; attempting to return).
  call qword [g_lpSyscallAddr]
  
  sub rsp, 10h ; restore rsp
  mov [rsp], rbx ; restore return address
  mov rbx, [rsp+28h] ; restore rbx
  .exit:
  ret
