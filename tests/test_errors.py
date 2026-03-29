"""Tests for error handling in the yooxnas assembler."""

import pytest
from yooxn.yooxnas import Lexer, Parser, ParsingError, SyntaxError, TOKENTYPE

def assemble_with_error(source: str):
    """Helper to tokenize and run Pass 1 and Pass 2 on a source string."""
    lexer = Lexer(source)
    tokens = lexer.scan_all_tokens()
    if any(t.type == TOKENTYPE.ILLEGAL for t in tokens):
         # Lexer already logged error, but we might want to check if it should raise
         pass
    parser = Parser(tokens)
    ir_stream, symbol_table = parser.parse_pass1()
    parser.parse_pass2(ir_stream, symbol_table)

def test_unclosed_comment():
    """Test that an unclosed comment block raises a ParsingError."""
    source = "( unclosed comment"
    with pytest.raises(ParsingError, match="Unclosed comment block"):
        assemble_with_error(source)

def test_undefined_label():
    """Test that referencing an undefined label raises a ParsingError."""
    source = ";undefined-label"
    with pytest.raises(ParsingError, match="Undefined label 'undefined-label' referenced"):
        assemble_with_error(source)

def test_relative_jump_too_far():
    """Test that a relative jump beyond -128 to 127 bytes raises a ParsingError."""
    # |0100 INC (at 0x0100)
    # $80 (skip 128 bytes)
    # @target (at 0x0181)
    # |0100 ,target (LIT 0x81, offset from 0x0103)
    # 0x0181 - 0x0103 = 0x7E (126 bytes) - OK
    # Let's make it more than 127.
    source = "|0100 ,target $90 @target"
    with pytest.raises(ParsingError, match="too far"):
        assemble_with_error(source)

def test_zero_page_address_out_of_range():
    """Test that a zero-page reference to an address > 0xFF raises a ParsingError."""
    source = "@large-addr |0200 .large-addr"
    with pytest.raises(ParsingError, match="outside the zero-page"):
        assemble_with_error(source)

def test_duplicate_macro_definition():
    """Test that redefining a macro raises a SyntaxError."""
    source = "%name { ADD } %name { SUB }"
    with pytest.raises(SyntaxError, match="Duplicate macro definition"):
        assemble_with_error(source)

def test_macro_name_collides_with_label():
    """Test that a macro name colliding with a label raises a SyntaxError."""
    source = "@name %name { ADD }"
    with pytest.raises(SyntaxError, match="collides with existing label"):
        assemble_with_error(source)

def test_nested_macro_definition():
    """Test that nested macro definitions are disallowed."""
    source = "%outer { %inner { ADD } }"
    with pytest.raises(SyntaxError, match="Nested macro definitions are not allowed"):
        assemble_with_error(source)

def test_infinite_macro_recursion():
    """Test that infinite macro recursion is detected."""
    source = "%loop { loop } loop"
    with pytest.raises(ParsingError, match="Infinite macro recursion detected"):
        assemble_with_error(source)

def test_unclosed_macro_body():
    """Test that an unclosed macro body raises a SyntaxError."""
    source = "%name { ADD"
    with pytest.raises(SyntaxError, match="Unclosed macro body"):
        assemble_with_error(source)

def test_unclosed_anonymous_block():
    """Test that an unclosed anonymous block { } raises a SyntaxError."""
    source = ";{ ADD"
    with pytest.raises(SyntaxError, match="Unclosed anonymous block"):
        assemble_with_error(source)

def test_unexpected_closing_delimiter():
    """Test that an unexpected '}' raises a SyntaxError."""
    source = "ADD }"
    with pytest.raises(SyntaxError, match="Unexpected closing delimiter"):
        assemble_with_error(source)

def test_invalid_hex_for_padding():
    """Test that an invalid hex value for padding raises a SyntaxError."""
    source = "|invalid"
    with pytest.raises(SyntaxError, match="Invalid hex value"):
        assemble_with_error(source)

def test_sublabel_outside_scope():
    """Test that a sub-label defined outside a parent scope raises a SyntaxError."""
    source = "&sub"
    with pytest.raises(SyntaxError, match="defined outside of a parent '@' scope"):
        assemble_with_error(source)

def test_sublabel_reference_outside_scope():
    """Test that a sub-label referenced outside a parent scope raises a SyntaxError."""
    source = ",&sub"
    with pytest.raises(SyntaxError, match="used outside of a parent '@' scope"):
        assemble_with_error(source)

def test_include_file_not_found():
    """Test that a missing include file raises a ParsingError."""
    source = "~nonexistent.tal"
    with pytest.raises(ParsingError, match="Include file not found"):
        assemble_with_error(source)

def test_error_location_reporting():
    """Test that errors report the correct line and column."""
    # ; is at line 1, col 3
    source = "  ;undefined"
    with pytest.raises(ParsingError) as excinfo:
        assemble_with_error(source)
    
    # Precise error reporting (e.g., unknown_file:1:3)
    assert ":1:3" in str(excinfo.value)
    assert 'Token "undefined"' in str(excinfo.value)
