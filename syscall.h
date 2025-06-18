#ifndef SYSCALL_H
#define SYSCALL_H

#include <windows.h>

#define DEFAULT_TABLE_SIZE 128

typedef struct {
  DWORD ssn;
  LPCSTR lpFuncName;
  LPVOID lpFuncAddr;
} Item;

typedef struct {
  Item *items;
  DWORD size;
  DWORD count;
} SSNTable;

extern NTSTATUS Syscall(DWORD, ...);
extern LPVOID g_lpSyscallAddr;

DWORD SSNTableInit(SSNTable *t);
Item SSNTableSearch(SSNTable *t, LPCSTR lpFuncName);
void SSNTableFree(SSNTable* t);
#ifndef NDEBUG
void SSNTablePrint(SSNTable *t);
#endif

#endif // !SYSCALL_H
