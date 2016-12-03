OBJS = ubtrfs.o

INCLUDES = -I/usr/i686-w64-mingw32/usr/include/ddk

CFLAGS = -Wall $(INCLUDES) -fvtable-verify=none

LIBS = -lntdll

CC = i686-w64-mingw32-gcc

all: ../../x86/ubtrfs.dll

ubtrfs.o: ubtrfs.c
	$(CC) $(CFLAGS) -c -o $@ $<

../../x86/ubtrfs.dll: $(OBJS)
	$(CC) -shared -static-libgcc -o $@ $(OBJS) $(LIBS) -Wl,--kill-at -fvtable-verify=none

clean:
	rm -f *.o ../../x86/ubtrfs.dll
