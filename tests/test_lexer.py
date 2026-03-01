import pytest
from yooxn.yooxnas import Lexer, TOKENTYPE

def test_lexer_ascii_chunk():
    lexer = Lexer('"hello')
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.RAW_ASCII_CHUNK
    assert token.word == "hello"

def test_lexer_hex_literal():
    lexer = Lexer('12ab')
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.IDENTIFIER
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

@pytest.mark.parametrize("char, expected_type", [
    ('|', TOKENTYPE.RUNE_PIPE),
    ('$', TOKENTYPE.RUNE_DOLLAR),
    ('@', TOKENTYPE.RUNE_AT),
    ('&', TOKENTYPE.RUNE_AMPERSAND),
    (',', TOKENTYPE.RUNE_COMMA),
    ('_', TOKENTYPE.RUNE_UNDERSCORE),
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
    lexer = Lexer(char + ' ') # Add space to ensure standalone
    token = lexer.scan_token()
    assert token.type == expected_type

def test_lexer_underscore_prefixed():
    lexer = Lexer('_pstr-inline-loop')
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.RUNE_UNDERSCORE
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.IDENTIFIER
    assert token.word == 'pstr-inline-loop'

def test_lexer_semicolon_underscore():
    lexer = Lexer(';_pstr-inline-loop')
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.RUNE_SEMICOLON
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.IDENTIFIER
    assert token.word == '_pstr-inline-loop'

def test_lexer_at_underscore():
    lexer = Lexer('@_divmod32')
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.RUNE_AT
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.IDENTIFIER
    assert token.word == '_divmod32'

def test_lexer_macro_name_with_digit():
    lexer = Lexer('8ADD-X')
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.IDENTIFIER
    assert token.word == '8ADD-X'

def test_lexer_label_with_question_mark():
    lexer = Lexer('member?')
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.IDENTIFIER
    assert token.word == 'member?'

def test_lexer_whitespace():
    lexer = Lexer('  \n  DUP')
    token = lexer.scan_token()
    assert token.type == TOKENTYPE.OPCODE
    assert token.word == 'DUP'
    assert token.line == 2
