# yooxn Development Plan

This document tracks planned improvements and features for the `yooxn` project.

## 1. Code Quality & Maintenance
- [x] **Complete Type Hinting**: Audit `src/yooxn/yooxnas.py` and ensure 100% type hint coverage. 
    - Currently, some internal methods and IR nodes have partial hinting.
- [x] **Linting & Formatting**: Integrate `ruff` into the project and `Makefile` to enforce consistent style.
- [x] **Docstring Audit**: Standardize docstrings across all classes and methods (preferring Google style).

## 2. Testing Expansion
- [x] **Parser Pass 1 Unit Tests**: Create `tests/test_parser_pass1.py`.
    - Test label definition and scoping without requiring a full Pass 2 run.
    - Test symbol table population.
- [x] **Parser Pass 2 Unit Tests**: Create `tests/test_parser_pass2.py`.
    - Test resolution of absolute vs. relative addresses using pre-constructed IR streams and symbol tables.
- [x] **Macro Unit Tests**: Dedicated tests for macro expansion, including:
    - Nested macros.
    - Recursion detection.
    - Redefinition errors.
- [ ] **Error Handling Tests**: Verify that `SyntaxError` and `ParsingError` are raised with correct line numbers and messages for invalid Tal code.

## 3. Assembler Enhancements
- [ ] **Column Tracking**: Update the `Lexer` to track column numbers in addition to line numbers. This will allow for more precise "caret" style error reporting (e.g., `file.tal:10:15`).
- [ ] **Symbol File Export**: Implement an option to write a `.sym` file (label mapping) alongside the ROM, matching the behavior of the official `uxnasm`.
- [ ] **Redundant Code Removal**: Clean up the `Parser` class to remove unused attributes or methods inherited from earlier drafts.
- [ ] **Performance Profiling**: Audit the multi-pass process for bottlenecks, especially during large file assembly (e.g., `mandelbrot.tal`).

## 4. DevOps & Ecosystem
- [ ] **CI Integration**: Add a GitHub Action to run `make test` on every push and pull request.
- [ ] **PyPI Readiness**: Prepare the package for potential distribution (ensure `description` and `keywords` in `pyproject.toml` are complete).
- [ ] **Official Autotest Suite**: Integrate the official `uxn` autotests (from `thirdparty/uxn/etc/autotest/`) into the `yooxn` test cycle to ensure bit-perfect compatibility.
