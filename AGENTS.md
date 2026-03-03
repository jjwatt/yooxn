# Agent Guide for yooxn

This document provides architectural context and operational instructions for AI agents working on the `yooxn` project.

## Project Overview
`yooxn` is a Python-based implementation of tools for the **Uxn** ecosystem. The primary component is `yooxnas`, a multi-pass assembler for the `uxntal` language.

## Architecture: `yooxnas.py`
The assembler is structured as a traditional compiler front-end:

1.  **Lexer**: Tokenizes source code into `TOKENTYPE` Enums.
    *   **Start-of-word Rule**: Most runes (operators like `|`, `$`, `@`, `;`) are only recognized at the beginning of a whitespace-separated word.
    *   **Internal Runes**: `&` (sub-label) and `{` (anonymous block) are allowed to follow other runes immediately without intervening whitespace (e.g., `,&label`, `?{`).
    *   **Identifiers**: Support alphanumeric characters plus `_`, `/`, `-`, `?`, `!`, `:`, `<`, `>`, and `.`.

2.  **Parser Pass 1**:
    *   Constructs an **IR (Intermediate Representation)** stream consisting of `IRNode` subclasses (e.g., `IROpcode`, `IRRawBytes`, `IRLabelPlaceholder`).
    *   Populates the **Symbol Table** with label addresses.
    *   Handles **Macro Definitions** (`%`) and expansions.
    *   Manages scoping for sub-labels (`@parent` -> `&sub` resolves to `parent/sub`).

3.  **Parser Pass 2**:
    *   Iterates through the IR stream to produce the final `bytearray`.
    *   Resolves `IRLabelPlaceholder` nodes by calculating absolute addresses or relative offsets.
    *   Ensures program counter (PC) synchronization.

## Project Structure
*   `src/yooxn/`: Core Python package.
    *   `yooxnas.py`: Main assembler logic.
    *   `__main__.py`: CLI entry point.
*   `tests/`: Test suite using `pytest`.
    *   `test_lexer.py`: Unit tests for tokenization.
    *   `test_opcodes.py`: Unit tests for instruction encoding.
    *   `test_yooxnas.py`: Integration tests assembling sample `.tal` files.
*   `examples/`: Standard `uxntal` examples.
*   `thirdparty/uxn/`: Official C implementation of Uxn (used for cross-verification).

## Development Workflow
*   **Install**: `pip install -e .` (uses `hatchling` backend).
*   **Test**: `make test` or `uv run pytest`.
*   **Build Official Tools**: `make tools` (requires `cc` and `sdl2`).
*   **Clean**: `make clean`.

## Engineering Standards
*   **Python**: Target version is 3.14+.
*   **Types**: Use strict type hints and `dataclasses`.
*   **Labels**: Always resolve sub-labels relative to the current `Parser.current_scope`.
*   **Verification**: When fixing assembler bugs, ensure no regressions in `examples/` by running the full integration suite.
