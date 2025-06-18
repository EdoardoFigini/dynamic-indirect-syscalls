#include "syscall.h"
#include <heapapi.h>
#include <winnt.h>
#ifndef NDEBUG
#include <stdio.h>
#endif /* ifndef NDEBUG */

#define RVA_TO_OFFSET(rva, base, section) (((rva) + ((DWORD_PTR)base)) - (section)->VirtualAddress + (section)->PointerToRawData)

LPVOID g_lpSyscallAddr = NULL;

DWORD SSNTableAppend(SSNTable *t, LPCSTR lpProcName, DWORD ssn, LPVOID lpFuncAddr) {
  if (t->count >= t->size) {
    if (t->size == 0) {
      t->size = DEFAULT_TABLE_SIZE;
      t->items = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, t->size * sizeof(*t->items));
    } else {
      t->size <<= 1;
      t->items = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, t->items, t->size * sizeof(*t->items));
    }
  }

  t->items[t->count] = (Item){ .ssn = ssn, .lpFuncName = _strdup(lpProcName), .lpFuncAddr = lpFuncAddr };

  return t->count++;
}

Item SSNTableSearch(SSNTable *t, LPCSTR lpProcName) {
  for (size_t i=0; i < t->count && i < t->size; i++) {
    if (!strcmp(t->items[i].lpFuncName, lpProcName)) {
      return t->items[i];
    }
  }
  return (Item){ 0 };
}

DWORD SSNTableInit(SSNTable *t) {
  // TODO: avoid winapi
  HANDLE hFile = NULL;
  DWORD dwFileSize = 0;
  DWORD dwBytesRead = 0;
  LPVOID lpFileData = NULL;

  hFile = CreateFileA(
    "C:\\windows\\system32\\ntdll.dll",
    GENERIC_READ,
    FILE_SHARE_READ,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL
  );
  if (hFile == INVALID_HANDLE_VALUE) return 1;

  dwFileSize = GetFileSize(hFile, NULL);
  if (dwFileSize == 0) return 1;

  lpFileData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
  ReadFile(hFile, lpFileData, dwFileSize, &dwBytesRead, NULL);
  if (dwBytesRead == 0) return 1;

  CloseHandle(hFile);

  PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpFileData + ((PIMAGE_DOS_HEADER)lpFileData)->e_lfanew);
  DWORD dwExportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  PIMAGE_SECTION_HEADER pTextSection  = NULL;
  PIMAGE_SECTION_HEADER pRdataSection = NULL;
  PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

  for (size_t i = 0; i < pNtHeaders->FileHeader.NumberOfSections && !(pTextSection && pRdataSection); i++) {
    // printf("section: %s\n", (CHAR*)pSectionHeader->Name);
    if (!strcmp((CHAR*)pSectionHeader->Name, ".text")) {
      pTextSection = pSectionHeader;
    } else if (!strcmp((CHAR*)pSectionHeader->Name, ".edata")) {
      pRdataSection = pSectionHeader;
    }

    pSectionHeader++;
  }

  if (!pTextSection || !pRdataSection) {
    return 1;
  }

  PIMAGE_EXPORT_DIRECTORY pImageExportDir = (PIMAGE_EXPORT_DIRECTORY)RVA_TO_OFFSET(dwExportDirRVA, lpFileData, pRdataSection);

  PDWORD pdwNames = (PDWORD)RVA_TO_OFFSET(pImageExportDir->AddressOfNames,        lpFileData, pRdataSection);
  PDWORD pdwFuncs = (PDWORD)RVA_TO_OFFSET(pImageExportDir->AddressOfFunctions,    lpFileData, pRdataSection);
  PWORD  pwOrd    = (PWORD) RVA_TO_OFFSET(pImageExportDir->AddressOfNameOrdinals, lpFileData, pRdataSection);

  for (DWORD i=0; i < pImageExportDir->NumberOfNames; ++i) {
    // LPVOID lpFuncAddr = (LPVOID)(lpFileData + pdwFuncs[pwOrd[i]]);
    // LPVOID lpFuncAddr = (LPVOID)RVA_TO_OFFSET(pdwFuncs[i+1], lpFileData, pTextSection);
    LPVOID lpFuncAddr = (LPVOID)RVA_TO_OFFSET(pdwFuncs[pwOrd[i]], lpFileData, pTextSection);
    CHAR* szFuncName = (CHAR*)RVA_TO_OFFSET(pdwNames[i], lpFileData, pRdataSection);
    if ((*szFuncName == 'N' && *(szFuncName + 1) == 't') || (*szFuncName == 'Z' && *(szFuncName + 1) == 'w'))
      SSNTableAppend(
        t,
        szFuncName,
        *(DWORD*)((DWORD_PTR)lpFuncAddr + 0x04L),
        lpFuncAddr
      );
  }

  return 0;
}

void SSNTableFree(SSNTable* t) {
  for (size_t i=0; i < t->count && i < t->size; i++) {
    free((LPVOID)t->items[i].lpFuncName);
  }
  HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, t->items);

  t->items = NULL;
  t->count = 0;
  t->size = 0;
}

#ifndef NDEBUG
void SSNTablePrint(SSNTable *t) {
  printf("+----------------------------------------------------+-----+\n");
  printf("| %-50s | SSN |\n", "Func Name");
  printf("+----------------------------------------------------+-----+\n");
  for (size_t i=0; i < t->count && i < t->size; i++) {
    printf("| %-50s | %3ld |\n", t->items[i].lpFuncName, t->items[i].ssn);
  }
  printf("+----------------------------------------------------+-----+\n");
}
#endif
