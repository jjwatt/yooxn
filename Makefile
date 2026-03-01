# yooxn Makefile

# --- Configuration ---
CC      := cc
PYTEST  := uv run pytest
YOOXNAS := uv run yooxnas

BUILD_DIR       := build
BIN_DIR         := $(BUILD_DIR)/bin
UXN_SRC_DIR     := thirdparty/uxn/src
DEVICES_SRC_DIR := $(UXN_SRC_DIR)/devices

MYTAL_SRC_DIR   := mytal
MYTAL_BUILD_DIR := $(BUILD_DIR)/mytal

# Official uxn tools
UXNASM  := $(BIN_DIR)/uxnasm
UXNEMU  := $(BIN_DIR)/uxnemu

# Build Flags for official tools
CFLAGS         := -std=c89 -Wall -Wno-unknown-pragmas -DNDEBUG -O2 -s
UXNEMU_LDFLAGS := $(shell sdl2-config --cflags --libs 2>/dev/null || echo "") -lm

# Sources for official tools
UXNASM_SRC := $(UXN_SRC_DIR)/uxnasm.c
UXNEMU_SRC := $(UXN_SRC_DIR)/uxn.c $(wildcard $(DEVICES_SRC_DIR)/*.c) $(UXN_SRC_DIR)/uxnemu.c

# ROM targets
MYTAL_SOURCES  := $(wildcard $(MYTAL_SRC_DIR)/*.tal)
OFFICIAL_ROMS  := $(patsubst $(MYTAL_SRC_DIR)/%.tal,$(MYTAL_BUILD_DIR)/%.rom,$(MYTAL_SOURCES))
YOOXN_ROMS     := $(patsubst $(MYTAL_SRC_DIR)/%.tal,$(MYTAL_BUILD_DIR)/%.yo.rom,$(MYTAL_SOURCES))

# --- Primary Targets ---

.DEFAULT_GOAL := all
.PHONY: all clean test check tools myroms yo-myroms

# Build everything: tools and both sets of ROMs
all: tools myroms yo-myroms

# Build official C tools
tools: $(UXNASM) $(UXNEMU)

# Assemble ROMs using the official C assembler
myroms: $(OFFICIAL_ROMS)

# Assemble ROMs using the Python yooxnas assembler
yo-myroms: $(YOOXN_ROMS)

# Run the Python test suite
test check:
	@echo ">> Running tests"
	@$(PYTEST)

# --- Build Rules ---

# Official C uxnasm
$(UXNASM): $(UXNASM_SRC) | $(BIN_DIR)
	@echo "CC $< -> $@"
	@$(CC) $(CFLAGS) $^ -o $@

# Official C uxnemu
$(UXNEMU): $(UXNEMU_SRC) | $(BIN_DIR)
	@echo "CC uxnemu -> $@"
	@$(CC) $(CFLAGS) $^ -o $@ $(UXNEMU_LDFLAGS)

# Rule for official ROMs
$(MYTAL_BUILD_DIR)/%.rom: $(MYTAL_SRC_DIR)/%.tal $(UXNASM) | $(MYTAL_BUILD_DIR)
	@echo "UXNASM $< -> $@"
	@$(UXNASM) $< $@

# Rule for yooxn ROMs
$(MYTAL_BUILD_DIR)/%.yo.rom: $(MYTAL_SRC_DIR)/%.tal | $(MYTAL_BUILD_DIR)
	@echo "YOOXNAS $< -> $@"
	@$(YOOXNAS) $< -o $@

# --- Utilities ---

$(BIN_DIR) $(MYTAL_BUILD_DIR):
	@mkdir -p $@

clean:
	@echo ">> Cleaning build artifacts"
	@rm -rf $(BUILD_DIR)
