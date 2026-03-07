"""Tests for opcodes."""

import pytest

from yooxn.yooxnas import get_opcode_byte


@pytest.mark.parametrize(
    "mnemonic, expected",
    [
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
        ("GTH", 0x0A),
        ("LTH", 0x0B),
        ("JMP", 0x0C),
        ("JCN", 0x0D),
        ("JSR", 0x0E),
        ("STH", 0x0F),
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
        ("MUL", 0x1A),
        ("DIV", 0x1B),
        ("AND", 0x1C),
        ("ORA", 0x1D),
        ("EOR", 0x1E),
        ("SFT", 0x1F),
        # Modes
        ("ADD2", 0x38),
        ("ADDr", 0x58),
        ("ADDk", 0x98),
        ("ADD2r", 0x78),
        ("ADD2k", 0xB8),
        ("ADDrk", 0xD8),
        ("ADD2rk", 0xF8),
        # LIT special case (default is 0x80)
        ("LIT", 0x80),
        ("LIT2", 0xA0),
        ("LITr", 0xC0),
        ("LITk", 0x80),  # redundant but set
        ("LIT2r", 0xE0),
        # Edge cases / Invalid
        ("add", None),
        ("Add", None),
        ("XYZ", None),
        ("ADDx", None),
        ("A", None),
        ("", None),
    ],
)
def test_get_opcode_byte(mnemonic, expected):
    """Test opcode produces expected byte."""
    assert get_opcode_byte(mnemonic) == expected
