"""Unit tests for Macro definition and expansion."""

import pytest
from yooxn.yooxnas import Lexer, Parser, IROpcode, SyntaxError, ParsingError


def parse_source(source: str) -> Parser:
    """Helper to tokenize and run Pass 1 on a source string."""
    lexer = Lexer(source)
    tokens = lexer.scan_all_tokens()
    parser = Parser(tokens)
    parser.parse_pass1()
    return parser


def test_macro_simple():
    """Test standard macro definition and expansion."""
    source = "%PLUS { ADD } @main PLUS"
    parser = parse_source(source)

    assert "PLUS" in parser.macros
    # Skip padding node at index 0
    op_nodes = [n for n in parser.ir_stream if isinstance(n, IROpcode)]
    assert len(op_nodes) == 1
    assert op_nodes[0].mnemonic == "ADD"


def test_macro_nested():
    """Test a macro expanding into another macro."""
    source = """
    %INNER { INC }
    %OUTER { INNER INNER }
    @main OUTER
    """
    parser = parse_source(source)

    op_nodes = [n for n in parser.ir_stream if isinstance(n, IROpcode)]
    assert len(op_nodes) == 2
    assert all(n.mnemonic == "INC" for n in op_nodes)


def test_macro_redefinition():
    """Test that redefining a macro raises a SyntaxError."""
    source = "%M { INC } %M { DUP }"
    with pytest.raises(SyntaxError, match="Duplicate macro definition"):
        parse_source(source)


def test_macro_recursion():
    """Test that infinite macro recursion raises a ParsingError."""
    source = "%M { M } @main M"
    with pytest.raises(ParsingError, match="Infinite macro recursion"):
        parse_source(source)


def test_macro_unclosed():
    """Test that unclosed macro body raises a SyntaxError."""
    source = "%M { INC"
    with pytest.raises(SyntaxError, match="Unclosed macro body"):
        parse_source(source)


def test_macro_label_collision():
    """Test that macro names cannot collide with existing labels."""
    source = "@label %label { INC }"
    with pytest.raises(SyntaxError, match="collides with existing label"):
        parse_source(source)


def test_macro_empty():
    """Test that an empty macro expands to nothing."""
    source = "%EMPTY { } @main EMPTY INC"
    parser = parse_source(source)

    op_nodes = [n for n in parser.ir_stream if isinstance(n, IROpcode)]
    assert len(op_nodes) == 1
    assert op_nodes[0].mnemonic == "INC"
