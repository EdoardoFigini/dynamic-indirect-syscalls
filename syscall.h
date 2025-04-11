#ifndef SYSCALL_H
#define SYSCALL_H

#include <windows.h>

extern NTSTATUS Syscall(DWORD, ...);

DWORD GetSSN(LPVOID lpFuncAddr);

#endif // !SYSCALL_H
