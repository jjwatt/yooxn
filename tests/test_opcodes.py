"""Tests for opcodes."""
import pytest

from yooxn.yooxnas import get_opcode_byte


@pytest.mark.parametrize("mnemonic, expected", [
    ("BRK", 0x00),
    ("INC", 0x01),
    ("POP", 0x02),
    ("NIP", 0x03),
    ("SWP", 0x04),
    ("ROT", 0x05),
    ("DUP", 0x06),
    ("OVR", 0x07),
    ("EQU", 0x08),
    ("NEQ", 0x09),
    ("GTH", 0x0a),
    ("LTH", 0x0b),
    ("JMP", 0x0c),
    ("JCN", 0x0d),
    ("JSR", 0x0e),
    ("STH", 0x0f),
    ("LDZ", 0x10),
    ("STZ", 0x11),
    ("LDR", 0x12),
    ("STR", 0x13),
    ("LDA", 0x14),
    ("STA", 0x15),
    ("DEI", 0x16),
    ("DEO", 0x17),
    ("ADD", 0x18),
    ("SUB", 0x19),
    ("MUL", 0x1a),
    ("DIV", 0x1b),
    ("AND", 0x1c),
    ("ORA", 0x1d),
    ("EOR", 0x1e),
    ("SFT", 0x1f),
    # Modes
    ("ADD2", 0x38),
    ("ADDr", 0x58),
    ("ADDk", 0x98),
    ("ADD2r", 0x78),
    ("ADD2k", 0xb8),
    ("ADDrk", 0xd8),
    ("ADD2rk", 0xf8),
    # LIT special case (default is 0x80)
    ("LIT", 0x80),
    ("LIT2", 0xa0),
    ("LITr", 0xc0),
    ("LITk", 0x80), # redundant but set
    ("LIT2r", 0xe0),
    # Edge cases / Invalid
    ("add", None),
    ("Add", None),
    ("XYZ", None),
    ("ADDx", None),
    ("A", None),
    ("", None),
])
def test_get_opcode_byte(mnemonic, expected):
    """Test opcode produces expected byte."""
    assert get_opcode_byte(mnemonic) == expected
