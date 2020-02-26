OBJS = ubtrfs.o crc32c.o crc32c-asm.o xxhash.o sha256.o blake2b-ref.o

INCLUDES = -I/usr/i686-w64-mingw32/usr/include/ddk

CFLAGS = -Wall $(INCLUDES) -fvtable-verify=none -D_USRDLL

LIBS = -lntdll

CC = i686-w64-mingw32-gcc

all: ../../x86/ubtrfs.dll

ubtrfs.o: ubtrfs.c ../btrfs.h ../btrfsioctl.h ../crc32c.h ../xxhash.h
	$(CC) $(CFLAGS) -c -o $@ $<

crc32c.o: ../crc32c.c ../crc32c.h
	$(CC) $(CFLAGS) -c -o $@ $<

crc32c-asm.o: ../crc32c-x86-gas.S
	$(CC) -masm=intel -c $< -o $@

xxhash.o: ../xxhash.c ../xxhash.h
	$(CC) $(CFLAGS) -c -o $@ $<

sha256.o: ../sha256.c
	$(CC) $(CFLAGS) -c -o $@ $<

blake2b-ref.o: ../blake2b-ref.c ../blake2-impl.h
	$(CC) $(CFLAGS) -c -o $@ $<

../../x86/ubtrfs.dll: $(OBJS)
	$(CC) -shared -static-libgcc -o $@ $(OBJS) $(LIBS) -Wl,--kill-at -fvtable-verify=none

clean:
	rm -f *.o ../../x86/ubtrfs.dll
