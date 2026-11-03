# FlashCopy - MinGW-w64 / MSYS2 构建
#   运行: mingw32-make   或   make
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11 -finput-charset=UTF-8 -fexec-charset=UTF-8 -D_WIN32_WINNT=0x0600
LDLIBS   = -lws2_32
COMMON   = flash_common.c flash_common.h

.PHONY: all clean

all: FlashSend.exe FlashReceive.exe

FlashSend.exe: FlashSend.c $(COMMON)
	$(CC) $(CFLAGS) FlashSend.c flash_common.c -o $@ $(LDLIBS)

FlashReceive.exe: FlashReceive.c $(COMMON)
	$(CC) $(CFLAGS) FlashReceive.c flash_common.c -o $@ $(LDLIBS)

clean:
	rm -f FlashSend.exe FlashReceive.exe *.o
