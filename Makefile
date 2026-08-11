# Makefile for pcsc-uid-reader (macOS, PC/SC via PCSC.framework)

CC      ?= cc
CFLAGS  ?= -std=c99 -Wall -Wextra -O2
LDFLAGS ?= -framework PCSC

TARGET = pcsc-uid-reader

.PHONY: all clean run

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $@ main.c $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
