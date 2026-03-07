"""Unit tests for Parser Pass 2."""

import pytest
from yooxn.yooxnas import (
    Parser,
    IROpcode,
    IRRawBytes,
    IRLabelPlaceholder,
    ParsingError,
)


def test_pass2_basic_emission():
    """Test basic emission of opcodes and raw bytes."""
    # Construct a manual IR stream
    ir_stream = [
        IROpcode(
            address=0x0100,
            size=1,
            source_line=1,
            source_filepath="test.tal",
            mnemonic="INC",
            byte_value=0x01,
        ),
        IRRawBytes(
            address=0x0101,
            size=2,
            source_line=2,
            source_filepath="test.tal",
            byte_values=[0xAB, 0xCD],
        ),
    ]
    symbol_table = {}

    parser = Parser([])
    parser.parse_pass2(ir_stream, symbol_table)

    # 0x0100 bytes of implicit padding (0x00) + 0x01 + 0xab + 0xcd
    assert len(parser.rom_data) == 0x0103
    assert parser.rom_data[0x0100] == 0x01
    assert parser.rom_data[0x0101] == 0xAB
    assert parser.rom_data[0x0102] == 0xCD


def test_pass2_absolute_resolution():
    """Test resolution of absolute addresses (;label and =label)."""
    ir_stream = [
        # ;label -> LIT2 (0xa0) + 2 bytes address
        IRLabelPlaceholder(
            address=0x0100,
            size=3,
            source_line=1,
            source_filepath="test.tal",
            label_name="target",
            ref_type="LITERAL_ABS16_VIA_LIT2",
            placeholder_size=2,
            implied_opcode=0xA0,
        ),
        # =label -> 2 bytes address
        IRLabelPlaceholder(
            address=0x0103,
            size=2,
            source_line=2,
            source_filepath="test.tal",
            label_name="target",
            ref_type="RAW_ABS16",
            placeholder_size=2,
            implied_opcode=None,
        ),
    ]
    symbol_table = {"target": 0xDEAD}

    parser = Parser([])
    parser.parse_pass2(ir_stream, symbol_table)

    # ;target -> 0xa0 0xde 0xad
    assert parser.rom_data[0x0100:0x0103] == bytearray([0xA0, 0xDE, 0xAD])
    # =target -> 0xde 0xad
    assert parser.rom_data[0x0103:0x0105] == bytearray([0xDE, 0xAD])


def test_pass2_relative_resolution():
    """Test resolution of relative offsets (,label and _label)."""
    ir_stream = [
        # ,target -> LIT (0x80) + 1 byte relative offset
        # Offset calculation: target_addr - (inst_addr + inst_size + implied_opcode_size)
        # Note: LITERAL relative references assume a 1-byte opcode follows them in many uxntal contexts,
        # but the current implementation adds 1 to inst_end_addr if "LITERAL" is in ref_type.
        IRLabelPlaceholder(
            address=0x0100,
            size=2,
            source_line=1,
            source_filepath="test.tal",
            label_name="target",
            ref_type="LITERAL_REL8_VIA_LIT",
            placeholder_size=1,
            implied_opcode=0x80,
        ),
        # _target -> 1 byte relative offset
        IRLabelPlaceholder(
            address=0x0102,
            size=1,
            source_line=2,
            source_filepath="test.tal",
            label_name="target",
            ref_type="RAW_REL8",
            placeholder_size=1,
            implied_opcode=None,
        ),
    ]
    # target is at 0x0110
    # ,target offset: 0x0110 - (0x0100 + 2 + 1) = 0x0d
    # _target offset: 0x0110 - (0x0102 + 1) = 0x0d
    symbol_table = {"target": 0x0110}

    parser = Parser([])
    parser.parse_pass2(ir_stream, symbol_table)

    assert parser.rom_data[0x0100:0x0102] == bytearray([0x80, 0x0D])
    assert parser.rom_data[0x0102] == 0x0D


def test_pass2_zero_page_resolution():
    """Test resolution of zero-page addresses (.label and -label)."""
    ir_stream = [
        # .zp -> LIT (0x80) + 1 byte address
        IRLabelPlaceholder(
            address=0x0100,
            size=2,
            source_line=1,
            source_filepath="test.tal",
            label_name="zp",
            ref_type="LITERAL_ZP8_VIA_LIT",
            placeholder_size=1,
            implied_opcode=0x80,
        ),
        # -zp -> 1 byte address
        IRLabelPlaceholder(
            address=0x0102,
            size=1,
            source_line=2,
            source_filepath="test.tal",
            label_name="zp",
            ref_type="RAW_ZP8",
            placeholder_size=1,
            implied_opcode=None,
        ),
    ]
    symbol_table = {"zp": 0x0042}

    parser = Parser([])
    parser.parse_pass2(ir_stream, symbol_table)

    assert parser.rom_data[0x0100:0x0102] == bytearray([0x80, 0x42])
    assert parser.rom_data[0x0102] == 0x42


def test_pass2_jump_resolution():
    """Test resolution of relative jumps (!label and ?label)."""
    ir_stream = [
        # !target -> JMI (0x40) + 2 bytes relative offset
        IRLabelPlaceholder(
            address=0x0100,
            size=3,
            source_line=1,
            source_filepath="test.tal",
            label_name="target",
            ref_type="JMI_REL16_VIA_OPCODE",
            placeholder_size=2,
            implied_opcode=0x40,
        ),
    ]
    # target is at 0x0200
    # !target offset: 0x0200 - (0x0100 + 3) = 0x00fd
    symbol_table = {"target": 0x0200}

    parser = Parser([])
    parser.parse_pass2(ir_stream, symbol_table)

    assert parser.rom_data[0x0100:0x0103] == bytearray([0x40, 0x00, 0xFD])


def test_pass2_relative_too_far():
    """Test that relative jumps that are too far raise a ParsingError."""
    ir_stream = [
        IRLabelPlaceholder(
            address=0x0100,
            size=2,
            source_line=1,
            source_filepath="test.tal",
            label_name="target",
            ref_type="LITERAL_REL8_VIA_LIT",
            placeholder_size=1,
            implied_opcode=0x80,
        ),
    ]
    # target is too far for 8-bit signed relative offset (-128 to 127)
    symbol_table = {"target": 0x0300}

    parser = Parser([])
    with pytest.raises(ParsingError, match="too far"):
        parser.parse_pass2(ir_stream, symbol_table)


def test_pass2_pc_desync():
    """Test that IR nodes with overlapping addresses raise a ParsingError."""
    ir_stream = [
        IRRawBytes(
            address=0x0100,
            size=5,
            source_line=1,
            source_filepath="test.tal",
            byte_values=[0] * 5,
        ),
        # Overlaps with previous node (0x0100-0x0104)
        IRRawBytes(
            address=0x0102,
            size=1,
            source_line=2,
            source_filepath="test.tal",
            byte_values=[1],
        ),
    ]
    symbol_table = {}

    parser = Parser([])
    with pytest.raises(ParsingError, match="PC desync"):
        parser.parse_pass2(ir_stream, symbol_table)
