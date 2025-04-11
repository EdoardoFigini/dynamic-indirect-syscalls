CC = gcc
CFLAGS = -Wall -Wextra -ggdb

ifneq ($(OS),Windows_NT)
	CC = x86_64-w64-mingw32-gcc
	CFLAGS += -DWINE
endif

example: example.obj syscall.c.obj syscall.asm.obj
	$(CC) -o example.exe example.obj syscall.c.obj syscall.asm.obj

example.obj: example.c syscall.h
	$(CC) $(CFLAGS) -o example.obj -c example.c

syscall.c.obj: syscall.c syscall.h
	$(CC) $(CFLAGS) -o syscall.c.obj -c syscall.c

syscall.asm.obj: syscall.asm
	nasm -f win64 -o syscall.asm.obj syscall.asm 

clean:
	rm *.obj
	rm *.exe

