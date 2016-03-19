OBJS = main.o

INCLUDES = 

CFLAGS = -Wall $(INCLUDES)

LIBS = -lole32

CC = i686-w64-mingw32-gcc

all: ../../x86/shellbtrfs.dll

main.o: main.cpp
	$(CC) $(CFLAGS) -c -o $@ $<
	
../../x86/shellbtrfs.dll: $(OBJS)
	$(CC) -shared -o $@ $(OBJS) $(LIBS) -Wl,--kill-at

clean:
	rm -f *.o ../../x86/shellbtrfs.dll

