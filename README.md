# Dynamic Indirect Syscall

> [!WARNING]
> This is an experiment, I do not take responsibility for the misuse of this code.
>
> The `Syscall` function is highly unstable as it messes with the stack in ways Windows doesn't like and may lead to crashes.
>
> I strongly discourage using this in your implants.

## Dependencies

- `nasm` assembler: [Home](https://www.nasm.dev/)
- a C compiler (gcc, mingw, clang, etc.)

## Usage

Add `syscall.asm`, `syscall.c` and `syscall.h` to your project, then in your C source do

```C
#include "syscall.h"
```

Assuming you have a way to retrieve the address of Nt functions you wish to bypass, do

```C
// retrieve Syscall Number
DWORD dwSyscallNumber = GetSSN(lpFuncAddr);

// perform Syscall
NTSTATUS s = Syscall(dwSyscallNumber, ...);
```

the `Syscall` function is declared as variadic, so that it can accept all the arguments of the original Nt function.

The `GetSSN` function is also responsible for retrieving an address from which the indirect syscall is performed.
Since this is a very naive approach, the address used for all the calls is the one found in the last call to `GetSSN`. 

The behavior of the `Syscall` function can be found directly in the comment of the [source](syscall.asm)

An example can be found [here](example.c).

## References

- [HellsGate](https://github.com/am0nsec/HellsGate)
- [Crow's blog post](https://www.crow.rip/crows-nest/mal/dev/inject/syscalls/indirect-syscalls)
