"""Tests for the yooxnas lexer."""

import pytest

from yooxn.yooxnas import TOKENTYPE, Lexer


def test_lexer_ascii_chunk():
    """Test lexer with an ascii chunk."""
    lexer = Lexer('"hello')
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.RAW_ASCII_CHUNK
    assert token.word == "hello"


def test_lexer_hex_literal():
    """Test lexer with a hex literal."""
    lexer = Lexer("12ab")
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.IDENTIFIER
    assert token.word == "12ab"


def test_lexer_opcode():
    """Test lexer with an opcode."""
    lexer = Lexer("DUP")
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.OPCODE
    assert token.word == "DUP"
    assert token.value == 0x06


def test_lexer_comments():
    """Test lexer with comments."""
    lexer = Lexer("( comment ) DUP")
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.OPCODE
    assert token.word == "DUP"


@pytest.mark.parametrize(
    "char, expected_type",
    [
        ("|", TOKENTYPE.RUNE_PIPE),
        ("$", TOKENTYPE.RUNE_DOLLAR),
        ("@", TOKENTYPE.RUNE_AT),
        ("&", TOKENTYPE.RUNE_AMPERSAND),
        (",", TOKENTYPE.RUNE_COMMA),
        ("_", TOKENTYPE.RUNE_UNDERSCORE),
        (".", TOKENTYPE.RUNE_PERIOD),
        ("-", TOKENTYPE.RUNE_MINUS),
        (";", TOKENTYPE.RUNE_SEMICOLON),
        ("=", TOKENTYPE.RUNE_EQUAL),
        ("!", TOKENTYPE.RUNE_EXCLAIM),
        ("?", TOKENTYPE.RUNE_QUESTION),
        ("#", TOKENTYPE.RUNE_HASH),
        ("\\", TOKENTYPE.RUNE_BACKSLASH),
        ("%", TOKENTYPE.RUNE_PERCENT),
        ("~", TOKENTYPE.RUNE_TILDE),
        ("{", TOKENTYPE.RUNE_LBRACE),
        ("}", TOKENTYPE.RUNE_RBRACE),
        ("[", TOKENTYPE.RUNE_LBRACKET),
        ("]", TOKENTYPE.RUNE_RBRACKET),
    ],
)
def test_lexer_runes(char, expected_type):
    """Check rune types."""
    lexer = Lexer(char + " ")  # Add space to ensure standalone
    token = lexer.scan_token()
    assert token.type == expected_type


def test_lexer_underscore_prefixed():
    """Test lexer on underscore (_) addressing."""
    lexer = Lexer("_pstr-inline-loop")
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.RUNE_UNDERSCORE
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.IDENTIFIER
    assert token.word == "pstr-inline-loop"


def test_lexer_semicolon_underscore():
    """Test lexer with semicolon then underscore."""
    lexer = Lexer(";_pstr-inline-loop")
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.RUNE_SEMICOLON
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.IDENTIFIER
    assert token.word == "_pstr-inline-loop"


def test_lexer_at_underscore():
    """Test lexer with @ then _."""
    lexer = Lexer("@_divmod32")
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.RUNE_AT
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.IDENTIFIER
    assert token.word == "_divmod32"


def test_lexer_macro_name_with_digit():
    """Test lexer on macro name that begins with a digit."""
    lexer = Lexer("8ADD-X")
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.IDENTIFIER
    assert token.word == "8ADD-X"


def test_lexer_label_with_question_mark():
    """Test lexer on label that ends with a question mark."""
    lexer = Lexer("member?")
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.IDENTIFIER
    assert token.word == "member?"


def test_lexer_whitespace():
    """Test lexer on whitespace."""
    lexer = Lexer("  \n  DUP")
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.OPCODE
    assert token.word == "DUP"
    assert token.line == 2


def test_lexer_column_tracking():
    """Test lexer column tracking."""
    lexer = Lexer("  DUP\n  INC  POP")
    tokens = lexer.scan_all_tokens()
    # tokens[0] is DUP
    assert tokens[0].word == "DUP"
    assert tokens[0].line == 1
    assert tokens[0].column == 3

    # tokens[1] is INC
    assert tokens[1].word == "INC"
    assert tokens[1].line == 2
    assert tokens[1].column == 3

    # tokens[2] is POP
    assert tokens[2].word == "POP"
    assert tokens[2].line == 2
    assert tokens[2].column == 8
