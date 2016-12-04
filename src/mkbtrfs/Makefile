OBJS = mkbtrfs.o

INCLUDES = -I/usr/i686-w64-mingw32/usr/include/ddk

CFLAGS = -Wall $(INCLUDES) -fvtable-verify=none

LIBS = -lntdll

CC = i686-w64-mingw32-gcc

all: mkbtrfs.exe

ubtrfs.o: ubtrfs.c
	$(CC) $(CFLAGS) -c -o $@ $<

mkbtrfs.exe: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

clean:
	rm -f *.o mkbtrfs.exe
