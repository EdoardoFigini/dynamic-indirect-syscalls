CC = gcc
CFLAGS = 

ifneq ($(OS),Windows_NT)
	CC = x86_64-w64-mingw32-gcc
	CFLAGS += -DWINE
endif

example: example.obj syscall.obj
	$(CC) -o example.exe example.obj syscall.obj

example.obj: example.c syscall.h
	$(CC) $(CFLAGS) -ggdb -o example.obj -c example.c

syscall.obj: syscall.asm
	nasm -f win64 syscall.asm

clean:
	rm *.obj
	rm *.exe

