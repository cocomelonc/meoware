CC = x86_64-w64-mingw32-gcc
WINDRES = x86_64-w64-mingw32-windres
CFLAGS = -std=c11 -O2 -Wall -Wextra -Wpedantic -Iinclude
LDFLAGS = -mwindows
LDLIBS = -lbcrypt -luser32 -lgdi32
TARGET ?= meoware.exe
SOURCES = src/main.c src/lab.c src/crypto.c src/tea.c src/xtea.c src/rc5.c src/cbc64.c src/receipt.c
RESOURCE_OBJECT = meoware-assets.o

.PHONY: all clean test windows-test-build

all: $(TARGET)

$(RESOURCE_OBJECT): src/assets.rc include/resource.h meoware.ico assets/sample1.txt assets/sample2.txt assets/sample3.txt assets/sample4.txt assets/sample5.txt
	$(WINDRES) -i src/assets.rc -O coff -o $@

$(TARGET): $(SOURCES) include/lab.h include/crypto.h include/tea.h include/xtea.h include/rc5.h include/cbc64.h include/receipt.h include/resource.h $(RESOURCE_OBJECT)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES) $(RESOURCE_OBJECT) $(LDLIBS)

clean:
	$(RM) $(TARGET) $(RESOURCE_OBJECT)

test:
	@set -e; native_test=$$(mktemp /tmp/meoware-test-XXXXXX); \
	trap 'rm -f "$$native_test"' EXIT; \
	for suite in receipt tea xtea rc5; do \
	  $(HOSTCC) $(HOSTCFLAGS) -Iinclude tests/$${suite}_test.c src/$${suite}.c src/cbc64.c -o "$$native_test"; \
	  "$$native_test"; \
	done

HOSTCC ?= cc
HOSTCFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Werror

WINDOWS_TEST ?= /tmp/meoware-lab-tests.exe
windows-test-build: $(RESOURCE_OBJECT)
	$(CC) $(CFLAGS) -Werror -o $(WINDOWS_TEST) tests/windows_lab_test.c \
	  src/lab.c src/crypto.c src/tea.c src/xtea.c src/rc5.c src/cbc64.c $(RESOURCE_OBJECT) $(LDLIBS)
