"""Unit tests for Parser Pass 1."""

from yooxn.yooxnas import Lexer, Parser, IROpcode, IRRawBytes


def parse_source(source: str) -> Parser:
    """Helper to tokenize and run Pass 1 on a source string."""
    lexer = Lexer(source)
    tokens = lexer.scan_all_tokens()
    parser = Parser(tokens)
    parser.parse_pass1()
    return parser


def test_pass1_labels():
    """Test standard label definitions and symbol table population.

    Note: Labels at the very beginning trigger the 0x0100 padding.
    """
    source = "@main INC @loop DUP JMP"
    parser = parse_source(source)

    # Addresses:
    # @main -> 0x0100 (Implicit padding applied before @)
    # INC -> 0x0100
    # @loop -> 0x0101
    # DUP -> 0x0101
    # JMP -> 0x0102
    assert parser.symbol_table["main"] == 0x0100
    assert parser.symbol_table["loop"] == 0x0101
    assert parser.current_address == 0x0103


def test_pass1_sub_labels():
    """Test sub-label scoping using & rune."""
    source = "@parent &child INC &child2 DUP"
    parser = parse_source(source)

    assert parser.symbol_table["parent"] == 0x0100
    assert parser.symbol_table["parent/child"] == 0x0100
    assert parser.symbol_table["parent/child2"] == 0x0101


def test_pass1_padding():
    """Test absolute and relative padding."""
    source = "|0200 @label $05 @label2"
    parser = parse_source(source)

    assert parser.symbol_table["label"] == 0x0200
    assert parser.symbol_table["label2"] == 0x0205
    assert parser.current_address == 0x0205


def test_pass1_macros():
    """Test macro definition and expansion."""
    source = "%PLUS { ADD } @main PLUS"
    parser = parse_source(source)

    assert parser.symbol_table["main"] == 0x0100
    op_nodes = [n for n in parser.ir_stream if isinstance(n, IROpcode)]
    assert len(op_nodes) == 1
    assert op_nodes[0].mnemonic == "ADD"
    assert op_nodes[0].address == 0x0100


def test_pass1_raw_bytes():
    """Test raw hex and ASCII chunks."""
    source = '01 0203 "abc'
    parser = parse_source(source)

    # Trigger padding to 0x0100 then:
    # 01 (1b), 0203 (2b), "abc (3b)
    # Total 6 bytes starting at 0x0100
    assert parser.current_address == 0x0106

    raw_nodes = [n for n in parser.ir_stream if isinstance(n, IRRawBytes)]
    assert len(raw_nodes) == 3
    assert raw_nodes[0].byte_values == [0x01]
    assert raw_nodes[1].byte_values == [0x02, 0x03]
    assert raw_nodes[2].byte_values == [ord("a"), ord("b"), ord("c")]


def test_pass1_nested_scopes():
    """Test that @ scope resets sub-label resolution."""
    source = "@A &s @B &s"
    parser = parse_source(source)

    assert "A/s" in parser.symbol_table
    assert "B/s" in parser.symbol_table
    assert parser.symbol_table["A/s"] == 0x0100
    assert parser.symbol_table["B/s"] == 0x0100
