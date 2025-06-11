# BonAmi mDNS Library and Daemon for AmigaOS 4
# Copyright (C) 2024 Tim
#
# This Makefile is for building on AmigaOS 4 with GCC and newlib
# For classic AmigaOS builds, use the SMAKEFILE instead

# Compiler and flags
CC = gcc
CFLAGS = -Wall -O2 -I./include
LDFLAGS = -lauto

# Directories
SRC_DIR = src
INCLUDE_DIR = include
OBJ_DIR = obj
LIB_DIR = lib
BIN_DIR = bin

# Source files
LIB_SRCS = $(SRC_DIR)/bonami_lib.c
DAEMON_SRCS = $(SRC_DIR)/bonami.c
CTL_SRCS = $(SRC_DIR)/bonami_cmd.c

# Object files
LIB_OBJS = $(LIB_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
DAEMON_OBJS = $(DAEMON_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
CTL_OBJS = $(CTL_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Targets
LIB_TARGET = $(LIB_DIR)/bonami.library
DAEMON_TARGET = $(BIN_DIR)/bonamid
CTL_TARGET = $(BIN_DIR)/bactl

# Default target
all: directories $(LIB_TARGET) $(DAEMON_TARGET) $(CTL_TARGET)

# Create directories
directories:
	@mkdir -p $(OBJ_DIR) $(LIB_DIR) $(BIN_DIR)

# Build library
$(LIB_TARGET): $(LIB_OBJS)
	$(CC) $(LDFLAGS) -nostartfiles -o $@ $(LIB_OBJS) -ldebug

# Build daemon
$(DAEMON_TARGET): $(DAEMON_OBJS) $(LIB_TARGET)
	$(CC) $(CFLAGS) -o $@ $(DAEMON_OBJS) $(LIB_TARGET) $(LDFLAGS)

# Build control utility
$(CTL_TARGET): $(CTL_OBJS) $(LIB_TARGET)
	$(CC) $(CFLAGS) -o $@ $(CTL_OBJS) $(LIB_TARGET) $(LDFLAGS)

# Compile library objects
$(OBJ_DIR)/bonami_lib.o: $(SRC_DIR)/bonami_lib.c $(INCLUDE_DIR)/bonami.h
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# Compile daemon objects
$(OBJ_DIR)/bonami.o: $(SRC_DIR)/bonami.c $(INCLUDE_DIR)/bonami.h
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# Compile control utility objects
$(OBJ_DIR)/bonami_cmd.o: $(SRC_DIR)/bonami_cmd.c $(INCLUDE_DIR)/bonami.h
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# Clean
clean:
	rm -rf $(OBJ_DIR) $(LIB_DIR) $(BIN_DIR)

# Install
install: all
	cp $(LIB_TARGET) LIBS:
	cp $(DAEMON_TARGET) C:
	cp $(CTL_TARGET) C:

.PHONY: all clean install directories 