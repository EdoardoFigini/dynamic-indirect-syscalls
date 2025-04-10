#ifndef SYSCALL_H
#define SYSCALL_H

#include <windows.h>

extern NTSTATUS Syscall(DWORD, ...);

DWORD GetSSN(LPVOID lpFuncAddr);

#endif // !SYSCALL_H

#ifdef SYSCALL_IMPLEMENTATION

LPVOID g_lpSyscallAddr = NULL;

DWORD GetSSN(LPVOID lpFuncAddr) {
  if (lpFuncAddr == NULL) return 0;
#ifdef WINE
  // jump into Wine's ntdll to simulate syscall execution
  g_lpSyscallAddr = (LPVOID)((DWORD_PTR)lpFuncAddr + 24); 
  return *(DWORD*)((DWORD_PTR)lpFuncAddr + 0x04L);
#else
  DWORD dwSSN = *(DWORD*)((DWORD_PTR)lpFuncAddr + 0x04L); 
  LPVOID lpSyscallAddr = (LPVOID)((DWORD_PTR)lpFuncAddr + 0x12L); 
  if (*(BYTE*)lpSyscallAddr != 0x0F || *(BYTE*)(lpSyscallAddr + 1) != 0x05) {
    return  0; 
  } else {
    g_lpSyscallAddr = lpSyscallAddr;
    return dwSSN;
  }
#endif // !WINE
} 

#endif // !SYSCALL_IMPLEMENTATION
