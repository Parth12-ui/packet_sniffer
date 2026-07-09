# Makefile for C-Shark Packet Sniffer - Designed to be placed inside the B/ directory

# Project variables
TARGET = c_shark
SRCDIR = .
INCLUDEDIR = include
CC = cc
# -g for debugging, -Wall for all warnings, -I$(INCLUDEDIR) for header path
CFLAGS = -g -Wall -I$(INCLUDEDIR)
# -lpcap links against the libpcap library, required for sniffing
LDFLAGS = -lpcap

# Source files (relative to B/)
SRCS = main.c \
	   functions.c \
	   handler_filter.c \
	   store_packets.c

# Object files: replace .c with .o (results in main.o, functions.o, etc.)
OBJS = $(SRCS:.c=.o)

# Default target: builds the executable
all: $(TARGET)

# Main target: links the executable
$(TARGET): $(OBJS)
	@echo "Linking $(TARGET)..."
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Generic rule to compile C source files into object files
# This rule is now correct for files in the current directory (B/)
%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build files
clean:
	@echo "Cleaning up..."
	rm -f $(OBJS) $(TARGET)
	@echo "Clean complete."

.PHONY: all clean