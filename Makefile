CC = x86_64-w64-mingw32-gcc
WINDRES = x86_64-w64-mingw32-windres
CFLAGS = -std=c11 -O2 -Wall -Wextra -Wpedantic -Iinclude
LDFLAGS = -mwindows
LDLIBS = -lbcrypt -luser32 -lgdi32 -lwinhttp
TARGET ?= meoware.exe
SOURCES = src/main.c src/lab.c src/crypto.c src/tea.c src/xtea.c src/rc5.c src/rc6.c src/a51.c src/skipjack.c src/camellia.c src/speck.c src/cbc.c src/telegram.c src/approval.c src/json.c
RESOURCE_OBJECT = meoware-assets.o

.PHONY: all clean test windows-test-build FORCE

all: $(TARGET)

# Rebuild the executable even when a prebuilt copy is already up to date.
FORCE:

$(RESOURCE_OBJECT): src/assets.rc include/resource.h meoware.ico bot/config.json bot/meoware.png assets/sample1.txt assets/sample2.txt assets/sample3.txt assets/sample4.txt assets/sample5.txt
	$(WINDRES) -i src/assets.rc -O coff -o $@

$(TARGET): FORCE $(SOURCES) include/lab.h include/crypto.h include/tea.h include/xtea.h include/rc5.h include/rc6.h include/a51.h include/skipjack.h include/camellia.h include/speck.h include/cbc.h include/resource.h include/telegram.h include/approval.h include/json.h $(RESOURCE_OBJECT)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES) $(RESOURCE_OBJECT) $(LDLIBS)

clean:
	$(RM) $(TARGET) $(RESOURCE_OBJECT)

test:
	@set -e; native_test=$$(mktemp /tmp/meoware-test-XXXXXX); \
	trap 'rm -f "$$native_test"' EXIT; \
	for suite in tea xtea rc5 rc6 a51 skipjack camellia speck; do \
	  $(HOSTCC) $(HOSTCFLAGS) -Iinclude tests/$${suite}_test.c src/$${suite}.c src/cbc.c -o "$$native_test"; \
	  "$$native_test"; \
	done; \
	$(HOSTCC) $(HOSTCFLAGS) -Iinclude tests/approval_test.c src/approval.c src/json.c -o "$$native_test"; \
	"$$native_test"

HOSTCC ?= cc
HOSTCFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Werror

WINDOWS_TEST ?= /tmp/meoware-lab-tests.exe
windows-test-build: $(RESOURCE_OBJECT)
	$(CC) $(CFLAGS) -Werror -o $(WINDOWS_TEST) tests/windows_lab_test.c \
	  src/lab.c src/crypto.c src/tea.c src/xtea.c src/rc5.c src/rc6.c src/a51.c src/skipjack.c src/camellia.c src/speck.c src/cbc.c $(RESOURCE_OBJECT) $(LDLIBS)
