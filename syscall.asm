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
  jrcxz _exit
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
  mov [rsp+28h], rbx ; "push" rbx 
  ; store the return address in rbx cause we are 
  ; advancing the stack pointer and syscall might 
  ; overwrite the 8 bytes containing the original 
  ; ret address 
  mov rbx, [rsp]
  ; adjust rsp to discard 5th argument in the stack:
  ; the syscall will pop from rsp+0x28, finding the 
  ; 6th argument
  add rsp, 10h

  call qword [g_lpSyscallAddr]
  
  sub rsp, 10h ; restore rsp
  mov [rsp], rbx ; restore return address
  mov rbx, [rsp+28h] ; restore rbx
_exit:
  ret
