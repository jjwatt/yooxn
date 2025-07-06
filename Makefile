# Makefile for building uxn tools

# Default target executed when you just run `make`
.DEFAULT_GOAL := all

# ============== Variables ==============

# Core build tools
CC := cc

# Directories
BUILD_DIR   := build
BIN_DIR     := $(BUILD_DIR)/bin
SRC_DIR     := thirdparty/uxn/src
DEVICES_DIR := $(SRC_DIR)/devices

MYTAL_SRC_DIR := mytal
MYTAL_BUILD_DIR := $(BUILD_DIR)/mytal

# Build Flags
# Basic flags for a release build. Relies on sdl2-config for emulator libs.
CFLAGS   := -std=c89 -Wall -Wno-unknown-pragmas -DNDEBUG -O2 -s
LDFLAGS  :=
UXNEMU_LDFLAGS := $(shell sdl2-config --cflags --libs) -lm

# Source files
UXNASM_SRC := $(SRC_DIR)/uxnasm.c
UXNEMU_SRC := $(SRC_DIR)/uxn.c $(wildcard $(DEVICES_DIR)/*.c) $(SRC_DIR)/uxnemu.c

# Executable paths
UXNASM := $(BIN_DIR)/uxnasm
UXNEMU := $(BIN_DIR)/uxnemu

# Phony targets that don't represent files
.PHONY: all clean

# ============== Build Rules ==============

# Default target: build all executables
all: $(UXNASM) $(UXNEMU)

# Rule to build uxnasm
$(UXNASM): $(UXNASM_SRC) | $(BIN_DIR)
	@echo "CC $< -> $@"
	@$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Rule to build uxnemu
$(UXNEMU): $(UXNEMU_SRC) | $(BIN_DIR)
	@echo "CC uxnemu -> $@"
	@$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(UXNEMU_LDFLAGS)

$(MYTAL_BUILD_DIR)/%.rom: $(MYTAL_SRC_DIR)/%.tal $(UXNASM) | $(MYTAL_BUILD_DIR)
	@echo "UXNASM $< -> $@"
	@$(UXNASM) $< $@

# Rule to create the bin directory.
# This is an "order-only prerequisite" for the executables.
$(BIN_DIR):
	@mkdir -p $@

# Create mytal out dir for roms
$(MYTAL_BUILD_DIR):
	@mkdir -p $@

# ============== Utility Rules ==============

# Clean the build directory
clean:
	@echo ">> Cleaning build artifacts"
	@rm -rf $(BUILD_DIR)
