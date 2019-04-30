OBJS = main.o factory.o iconoverlay.o contextmenu.o propsheet.o volpropsheet.o devices.o balance.o scrub.o recv.o send.o mountmgr.o

INCLUDES = -I/usr/x86_64-w64-mingw32/usr/include/ddk

CFLAGS = -Wall -Wconversion $(INCLUDES) -fvtable-verify=none -msse4.2 -std=c++17

LIBS = -lole32 -luuid -lntdll -luxtheme -lshlwapi -lcomctl32 -lsetupapi -lcomdlg32 -lwindowscodecs -lgdi32

CC = x86_64-w64-mingw32-g++

all: ../../x86/shellbtrfs.dll

main.o: main.cpp factory.h shellext.h
	$(CC) $(CFLAGS) -c -o $@ $<

factory.o: factory.cpp factory.h iconoverlay.h shellext.h
	$(CC) $(CFLAGS) -c -o $@ $<

iconoverlay.o: iconoverlay.cpp iconoverlay.h shellext.h
	$(CC) $(CFLAGS) -c -o $@ $<

contextmenu.o: contextmenu.cpp contextmenu.h shellext.h
	$(CC) $(CFLAGS) -c -o $@ $<

propsheet.o: propsheet.cpp propsheet.h shellext.h
	$(CC) $(CFLAGS) -c -o $@ $<

volpropsheet.o: volpropsheet.cpp volpropsheet.h shellext.h mountmgr.h
	$(CC) $(CFLAGS) -c -o $@ $<

devices.o: devices.cpp devices.h shellext.h mountmgr.h
	$(CC) $(CFLAGS) -c -o $@ $<

balance.o: balance.cpp balance.h shellext.h
	$(CC) $(CFLAGS) -c -o $@ $<

scrub.o: scrub.cpp scrub.h shellext.h
	$(CC) $(CFLAGS) -c -o $@ $<

recv.o: recv.cpp recv.h shellext.h
	$(CC) $(CFLAGS) -c -o $@ $<

send.o: send.cpp send.h shellext.h
	$(CC) $(CFLAGS) -c -o $@ $<

mountmgr.o: mountmgr.cpp mountmgr.h shellext.h
	$(CC) $(CFLAGS) -c -o $@ $<

../../x86/shellbtrfs.dll: $(OBJS)
	$(CC) -shared -static-libgcc -o $@ $(OBJS) $(LIBS) -Wl,--kill-at -fvtable-verify=none

clean:
	rm -f *.o ../../x86/shellbtrfs.dll

