CC = x86_64-w64-mingw32-gcc
WINDRES = x86_64-w64-mingw32-windres
CFLAGS = -std=c11 -O2 -Wall -Wextra -Wpedantic -Iinclude
LDFLAGS = -mwindows
LDLIBS = -lbcrypt -luser32 -lgdi32
TARGET ?= meoware.exe
SOURCES = src/main.c src/lab.c src/crypto.c
RESOURCE_OBJECT = meoware-assets.o

.PHONY: all clean

all: $(TARGET)

$(RESOURCE_OBJECT): src/assets.rc assets/sample1.txt assets/sample2.txt assets/sample3.txt assets/sample4.txt assets/sample5.txt
	$(WINDRES) -i src/assets.rc -O coff -o $@

$(TARGET): $(SOURCES) include/lab.h include/crypto.h $(RESOURCE_OBJECT)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES) $(RESOURCE_OBJECT) $(LDLIBS)

clean:
	$(RM) $(TARGET) $(RESOURCE_OBJECT)
