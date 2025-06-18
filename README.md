# Dynamic Indirect Syscall

# Overview

This is yet another implementation of userland hooking bypass, and is by no means a new or revolutionary idea.

> [!WARNING]
> This is an experiment, I do not take responsibility for the misuse of this code.
>
> The `Syscall` function is highly unstable as it messes with the stack in ways Windows doesn't like and may lead to crashes.
>
> I strongly discourage using this in your implants.

## Dependencies

- `nasm` assembler: [Home](https://www.nasm.dev/)
- a C compiler (gcc, mingw, clang, etc.)

By default GNU's make is used to build the example.

## Usage

Add `syscall.asm`, `syscall.c` and `syscall.h` to your project, then in your C source do

```C
#include "syscall.h"
```

Assuming you have a way to retrieve the address of Nt functions you wish to bypass, do

```C
// initialize table
SSNTable t = { 0 };
SSNTableInit(&t);

// retrieve Syscall Number
DWORD dwSyscallNumber = SSNTableSearch(&t, <func_name>).ssn;

// (optional) Free Table
SSNTableFree(&t);

// perform Syscall
NTSTATUS s = Syscall(dwSyscallNumber, ...);
```

the `Syscall` function is declared as variadic, so that it can accept all the arguments of the original Nt function.

Moreover, `Syscall` performs a jump to an address of a `syscall` instruction inside `ntdll`. The code snippet below is used to 
retrieve the address and store it to a global variable. A more elegant solution is in the works.
```C
g_lpSyscallAddr = GetProcAddress(GetModuleHandle("ntdll.dll"), t.items[rand() % t.count].lpFuncName) + 0x12L;
```

The behavior of the `Syscall` function can be found directly in the comment of the [source](syscall.asm)

An example can be found [here](example.c).

## References

- [HellsGate](https://github.com/am0nsec/HellsGate)
- [Crow's blog post](https://www.crow.rip/crows-nest/mal/dev/inject/syscalls/indirect-syscalls)
