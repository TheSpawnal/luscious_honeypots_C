CC      ?= gcc
CSTD    := -std=c11
WARN    := -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes \
           -Wmissing-prototypes -Wformat=2 -Wnull-dereference
HARDEN  := -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
           -fstack-clash-protection -fPIE
LDHARDEN:= -pie -Wl,-z,relro,-z,now,-z,noexecstack

CFLAGS  ?= $(CSTD) $(WARN) $(HARDEN)
LDFLAGS ?= $(LDHARDEN)

TARGET  := moat snare

.PHONY: all clean

all: $(TARGET)

moat: moat.c
	$(CC) $(CFLAGS) -o $@ moat.c $(LDFLAGS)

snare: snare.c
	$(CC) $(CFLAGS) -o $@ snare.c $(LDFLAGS)

clean:
	rm -f $(TARGET)
