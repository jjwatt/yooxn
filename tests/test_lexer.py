import pytest
from yooxn.yooxnas import Lexer, TOKENTYPE

@pytest.mark.parametrize("char, expected_type", [
    ('|', TOKENTYPE.RUNE_PIPE),
    ('$', TOKENTYPE.RUNE_DOLLAR),
    ('@', TOKENTYPE.RUNE_AT),
    ('&', TOKENTYPE.RUNE_AMPERSAND),
    (',', TOKENTYPE.RUNE_COMMA),
    ('.', TOKENTYPE.RUNE_PERIOD),
    ('-', TOKENTYPE.RUNE_MINUS),
    (';', TOKENTYPE.RUNE_SEMICOLON),
    ('=', TOKENTYPE.RUNE_EQUAL),
    ('!', TOKENTYPE.RUNE_EXCLAIM),
    ('?', TOKENTYPE.RUNE_QUESTION),
    ('#', TOKENTYPE.RUNE_HASH),
    ('\\', TOKENTYPE.RUNE_BACKSLASH),
    ('%', TOKENTYPE.RUNE_PERCENT),
    ('~', TOKENTYPE.RUNE_TILDE),
    ('{', TOKENTYPE.RUNE_LBRACE),
    ('}', TOKENTYPE.RUNE_RBRACE),
    ('[', TOKENTYPE.RUNE_LBRACKET),
    (']', TOKENTYPE.RUNE_RBRACKET),
])
def test_lexer_runes(char, expected_type):
    lexer = Lexer(char)
    token = lexer.scan_token()
    assert token.type == expected_type
    assert token.word == char

def test_lexer_ascii_chunk():
    lexer = Lexer('"hello')
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.RAW_ASCII_CHUNK
    assert token.word == "hello"

def test_lexer_hex_literal():
    lexer = Lexer('12ab')
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.HEX_LITERAL
    assert token.word == '12ab'

def test_lexer_opcode():
    lexer = Lexer('DUP')
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.OPCODE
    assert token.word == 'DUP'
    assert token.value == 0x06

def test_lexer_comments():
    lexer = Lexer('( comment ) DUP')
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.OPCODE
    assert token.word == 'DUP'

def test_lexer_whitespace():
    lexer = Lexer('  \n  DUP')
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.OPCODE
    assert token.word == 'DUP'
    assert token.line == 2
