# Makefile for Folder Integrity and Malicious File Scanner

CC = gcc
CFLAGS = -Wall -std=c99
LDFLAGS = -lssl -lcrypto

SRC_DIR = src
BIN = prog
SRCS = $(SRC_DIR)/prog.c
SHELL_SCRIPT = $(SRC_DIR)/verify_for_malicious.sh

.PHONY: all clean

all: $(BIN)

$(BIN): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
    

check-scripts:
	chmod +x $(SHELL_SCRIPT)

clean:
	rm -f $(BIN) *.o
