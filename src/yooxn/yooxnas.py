#!/usr/bin/env python3
"""A multi-pass assembler for the uxntal language.

This module provides a complete implementation of a uxntal assembler, including
lexical analysis, intermediate representation generation (Pass 1), and final
ROM generation (Pass 2). It supports macros, sub-labels, and relative addressing.
"""

import argparse
import logging
import sys
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Base opcodes (index corresponds to bits 0-4 of the opcode byte)
# LIT is special, its effective base is 0x80 (LITk) if no other mode.
_BASE_OPCODES_LIST = [
    "LIT",
    "INC",
    "POP",
    "NIP",
    "SWP",
    "ROT",
    "DUP",
    "OVR",
    "EQU",
    "NEQ",
    "GTH",
    "LTH",
    "JMP",
    "JCN",
    "JSR",
    "STH",
    "LDZ",
    "STZ",
    "LDR",
    "STR",
    "LDA",
    "STA",
    "DEI",
    "DEO",
    "ADD",
    "SUB",
    "MUL",
    "DIV",
    "AND",
    "ORA",
    "EOR",
    "SFT",
    # BRK is a standalone opcode, usually 0x00
]

_BASE_OPCODE_MAP = {name: i for i, name in enumerate(_BASE_OPCODES_LIST)}


def is_hex_digit(char: str) -> bool:
    """Check if a character is a valid hexadecimal digit."""
    if not char:
        return False
    char_lower = char.lower()
    return "0" <= char_lower <= "9" or "a" <= char_lower <= "f"


def is_purely_hex(word: str) -> bool:
    """Check if a word consists entirely of hexadecimal digits."""
    return all(is_hex_digit(char) for char in word)


def get_opcode_byte(mnemonic: str) -> int | None:
    """Calculate the 8-bit opcode byte for a given mnemonic.

    This includes handling the base opcode and OR-ing any mode bits (2, r, k).
    LIT is handled as a special case where its default state is 0x80 (LITk).

    Args:
        mnemonic: The string representation of the opcode (e.g., "ADD2", "LIT2r").

    Returns:
        The 8-bit opcode value, or None if the mnemonic is invalid.

    """
    if mnemonic == "BRK":
        return 0x00

    if len(mnemonic) < 3:
        return None

    base_op_str = mnemonic[:3]
    modes_str = mnemonic[3:]

    # uxnasm.c does not match if base is not uppercase, so we
    # won't either.
    if base_op_str != base_op_str.upper():
        return None

    if base_op_str not in _BASE_OPCODE_MAP:
        return None

    opcode_val = _BASE_OPCODE_MAP[base_op_str]

    if base_op_str == "LIT":
        # LIT is index 0
        # Start LIT as 0x80 (LITk) (its default)
        opcode_val = 0x80
        # Modes will be ORed onto this. 'k' mode would be redundant but
        # harmless. '2' would make it 0xA0. 'r' would make it 0xC0.

    # Apply modes for all opcodes
    for mode_char in modes_str:
        if mode_char == "2":
            opcode_val |= 0x20
        elif mode_char == "r":
            opcode_val |= 0x40
        elif mode_char == "k":
            # For LIT, this is already set if it was plain LIT or became 0x80.
            # For others, it sets the keep bit.
            opcode_val |= 0x80
        else:
            # Invalid mode
            return None

    return opcode_val


class TOKENTYPE(Enum):
    """Enumeration of recognized token types in uxntal."""

    RUNE_PIPE = auto()  # |
    RUNE_DOLLAR = auto()
    RUNE_AT = auto()  # @
    RUNE_AMPERSAND = auto()
    RUNE_COMMA = auto()
    RUNE_UNDERSCORE = auto()
    RUNE_PERIOD = auto()
    RUNE_MINUS = auto()
    RUNE_SEMICOLON = auto()
    RUNE_EQUAL = auto()
    RUNE_EXCLAIM = auto()
    RUNE_QUESTION = auto()
    RUNE_HASH = auto()
    RUNE_BACKSLASH = auto()
    RUNE_FORWARDSLASH = auto()
    RUNE_PERCENT = auto()
    RUNE_TILDE = auto()
    RUNE_LBRACE = auto()
    RUNE_RBRACE = auto()
    RUNE_LBRACKET = auto()
    RUNE_RBRACKET = auto()
    IDENTIFIER = auto()
    OPCODE = auto()
    RAW_ASCII_CHUNK = auto()
    EOF = auto()
    ILLEGAL = auto()


class Token:
    """Represents a single unit of source code emitted by the Lexer.

    Attributes:
        type: The TOKENTYPE classification of this token.
        word: The literal string extracted from the source.
        line: The 1-based line number where the token was found.
        column: The 1-based column number where the token was found.
        value: An optional numeric or string value associated with the token
             (e.g., the byte value for an OPCODE).

    """

    def __init__(
        self,
        token_type: TOKENTYPE,
        word: str,
        line: int,
        column: int,
        value: int | str | None = None,
    ) -> None:
        """Initialize a new Token instance."""
        self.type = token_type
        self.word = word
        self.line = line
        self.column = column
        self.value = value

    def __repr__(self) -> str:
        """Return a developer-friendly string representation of the token."""
        return f"Token(type={self.type.name}, value={self.value!r}, line={self.line}, column={self.column})"

    def __str__(self) -> str:
        """Return a user-friendly string representation of the token."""
        return f"Token: {self.word} at line {self.line}, column {self.column}"

    def print(self) -> None:
        """Log a detailed debug representation of the token."""
        if isinstance(self.value, int):
            value_str = f", Value: {self.value:#04x}"
        elif self.value is not None:
            value_str = f", Value: '{self.value}'"
        else:
            value_str = ""
        logger.debug(
            f"'{self.word}': [TOKEN_{self.type.name}{value_str}] (Line {self.line}, Col {self.column})"
        )


class Lexer:
    """Lexer for uxntal source code.

    Perform lexical analysis, converting raw source strings into a sequence
    of Token instances for the Parser. Track line numbers and word boundaries.
    """

    def __init__(self, source: str, filename: str | Path | None = None) -> None:
        """Initialize a new lexer instance.

        Args:
            source: The raw Tal source code to tokenize.
            filename: Optional path to the source file for error reporting.

        """
        self.src = source
        self.filename = Path(filename) if filename else None
        self.size = len(source)
        # Current position in the input
        self.cursor = 0
        # Start position of the current token being scanned
        self.start = 0
        self.line = 1
        self.line_start = 0
        self.start_of_word = True

    def _is_at_end(self) -> bool:
        """Check if the cursor has reached the end of the source string."""
        return self.cursor >= self.size

    def _advance(self) -> str:
        """Consume and return the next character from the source."""
        char = self.src[self.cursor]
        self.cursor += 1
        return char

    def _peek(self) -> str:
        """Return the next character without consuming it."""
        if self._is_at_end():
            return "\0"
        return self.src[self.cursor]

    def _peek_next(self) -> str:
        """Return the character after the next one without consuming it."""
        if self.cursor + 1 >= self.size:
            return "\0"
        return self.src[self.cursor + 1]

    def _add_token(
        self,
        token_type: TOKENTYPE,
        word: str | None = None,
        value: int | str | None = None,
    ) -> Token:
        """Create and return a new Token based on current lexer state."""
        if word is None:
            word = self.src[self.start : self.cursor]

        # After any token is added, we are no longer at the start of a word
        self.start_of_word = False

        column = self.start - self.line_start + 1
        return Token(token_type, word, self.line, column, value)

    def _skip_whitespace_and_comments(self) -> None:
        """Skip over whitespace and nested comment blocks in the source."""
        while not self._is_at_end():
            char = self._peek()
            if char in " \t\r":
                self.start_of_word = True
                self._advance()
            elif char == "\n":
                self.start_of_word = True
                self.line += 1
                self._advance()
                self.line_start = self.cursor
            # Start block comment
            elif char == "(":
                # When we see the first '(', start a depth counter.
                depth = 1
                comment_start_line = self.line
                # Consume initial '('
                self._advance()

                while not self._is_at_end() and depth > 0:
                    peeked_char = self._peek()
                    if peeked_char == "(":
                        depth += 1
                    elif peeked_char == ")":
                        depth -= 1
                    elif peeked_char == "\n":
                        self.line += 1
                        # We don't really need to track line_start inside
                        # comments for the current purpose of tokens, but
                        # it's good for consistency if we ever care about
                        # positions within comments.
                        # Wait, we do care about line_start after the comment ends.
                        pass
                    
                    # Consume char and continue looping.
                    consumed_char = self._advance()
                    if consumed_char == "\n":
                        self.line_start = self.cursor

                if depth > 0:
                    # We hit the end of the file before closing comment.
                    raise ParsingError(
                        f"Unclosed comment block line {comment_start_line}.",
                        line=comment_start_line,
                        filename=self.filename,
                    )
                # After a comment, we treat it as if whitespace was seen
                self.start_of_word = True
            else:
                # Found a non-whitespace/non-comment char
                break

    def _is_identifier_char(self, char: str) -> bool:
        """Check if a character is valid within a Tal identifier."""
        return char.isalnum() or char in [
            "_",
            "/",
            "-",
            "?",
            "!",
            ":",
            "<",
            ">",
            ".",
        ]

    def scan_token(self) -> Token:
        """Scan and return the next token from the source."""
        self._skip_whitespace_and_comments()
        self.start = self.cursor
        if self._is_at_end():
            return self._add_token(TOKENTYPE.EOF, "")

        char = self._advance()

        # Runes only match at the start of a word, but & and { can follow
        # other runes immediately (like ,&label or ?{ block }).
        if self.start_of_word or char in ["&", "{"]:
            match char:
                case "|":
                    return self._add_token(TOKENTYPE.RUNE_PIPE)
                case "$":
                    return self._add_token(TOKENTYPE.RUNE_DOLLAR)
                case "@":
                    return self._add_token(TOKENTYPE.RUNE_AT)
                case "&":
                    return self._add_token(TOKENTYPE.RUNE_AMPERSAND)
                case ",":
                    return self._add_token(TOKENTYPE.RUNE_COMMA)
                case "_":
                    return self._add_token(TOKENTYPE.RUNE_UNDERSCORE)
                case ".":
                    return self._add_token(TOKENTYPE.RUNE_PERIOD)
                case "-":
                    return self._add_token(TOKENTYPE.RUNE_MINUS)
                case ";":
                    return self._add_token(TOKENTYPE.RUNE_SEMICOLON)
                case "=":
                    return self._add_token(TOKENTYPE.RUNE_EQUAL)
                case "!":
                    return self._add_token(TOKENTYPE.RUNE_EXCLAIM)
                case "?":
                    return self._add_token(TOKENTYPE.RUNE_QUESTION)
                case "#":
                    return self._add_token(TOKENTYPE.RUNE_HASH)
                case "\\":
                    return self._add_token(TOKENTYPE.RUNE_BACKSLASH)
                case "/":
                    return self._add_token(TOKENTYPE.RUNE_FORWARDSLASH)
                case "%":
                    return self._add_token(TOKENTYPE.RUNE_PERCENT)
                case "~":
                    return self._add_token(TOKENTYPE.RUNE_TILDE)
                case "{":
                    return self._add_token(TOKENTYPE.RUNE_LBRACE)
                case "}":
                    return self._add_token(TOKENTYPE.RUNE_RBRACE)
                case "[":
                    return self._add_token(TOKENTYPE.RUNE_LBRACKET)
                case "]":
                    return self._add_token(TOKENTYPE.RUNE_RBRACKET)

        match char:
            case '"':
                self.start = self.cursor
                while not self._is_at_end():
                    if self._peek().isspace():
                        break
                    self._advance()
                return self._add_token(TOKENTYPE.RAW_ASCII_CHUNK)

            case c if self._is_identifier_char(c):
                # Greedily consume all characters that can form an
                # identifier/opcode word.
                while not self._is_at_end() and (
                    self._is_identifier_char(self._peek())
                ):
                    self._advance()
                word = self.src[self.start : self.cursor]

                # Check if it's a known opcode.
                opcode_val = get_opcode_byte(word)
                if opcode_val is not None:
                    return self._add_token(TOKENTYPE.OPCODE, word, value=opcode_val)
                else:
                    # Otherwise it's a general IDENTIFIER.
                    return self._add_token(TOKENTYPE.IDENTIFIER, word)

            # If none of the above matched the first character:
            case _:
                return self._add_token(TOKENTYPE.ILLEGAL, char)

    def scan_all_tokens(self) -> list[Token]:
        """Scan the entire source and return a list of tokens until EOF."""
        tokens = []
        while True:
            token = self.scan_token()
            tokens.append(token)
            logger.debug(token)
            if token.type == TOKENTYPE.EOF:
                break
            if token.type == TOKENTYPE.ILLEGAL:
                logger.error(
                    f"Error: Illegal token '{token.word}' on line '{token.line}', col '{token.column}'"
                )
                # break
        return tokens


# IR Nodes
@dataclass
class IRNode:
    """Base class for all Intermediate Representation nodes.

    Attributes:
        address: The memory address where this node's data begins in the ROM.
        size: The total number of bytes this node occupies in the final output.
        source_line: The line number in the source file that generated this node.
        source_column: The column number in the source file that generated this node.
        source_filepath: The path to the source file that generated this node.

    """

    address: int
    size: int
    source_line: int
    source_column: int
    source_filepath: str


@dataclass
class IRPadding(IRNode):
    """Represent a padding directive (e.g., '|' or '$').

    Attributes:
        target_address: The absolute address we padded to.

    """

    target_address: int


@dataclass
class IRRawBytes(IRNode):
    """Represent raw data like ASCII strings or hexadecimal blocks.

    Attributes:
        byte_values: List of 8-bit integers to be written directly to the ROM.

    """

    byte_values: list[int]


@dataclass
class IROpcode(IRNode):
    """Represent a single Uxn instruction.

    Attributes:
        mnemonic: The string name of the opcode (e.g., "DUP").
        byte_value: The 8-bit value of the instruction.

    """

    mnemonic: str
    byte_value: int


@dataclass
class IRLabelPlaceholder(IRNode):
    """Represent an operation that requires a label address to be resolved.

    Used for relative jumps, literal addresses, and zero-page references
    where the final value is calculated during Pass 2.

    Attributes:
        label_name: The name of the label to resolve.
        ref_type: The type of reference (e.g., "LITERAL_ABS16", "RAW_REL8").
        placeholder_size: Number of bytes reserved for the resolved address.
        implied_opcode: Optional opcode byte that precedes the placeholder.

    """

    label_name: str
    ref_type: str
    placeholder_size: int
    implied_opcode: int | None = None


class ParsingError(Exception):
    """Base class for errors during parsing."""

    def __init__(
        self,
        message: str,
        line: int | None = None,
        column: int | None = None,
        word: str | None = None,
        token: Token | None = None,
        filename: str | Path | None = None,
    ) -> None:
        """Initialize a ParsingError."""
        super().__init__(message)
        self.line = line
        self.column = column
        self.word = word
        self.token = token
        self.filename = filename
        if token and line is None:
            self.line = token.line
        if token and column is None:
            self.column = token.column
        if token and word is None:
            self.word = token.word

    def __str__(self) -> str:
        """Get string version of a ParsingError."""
        filename = self.filename or ""
        line = self.line or ""
        column = self.column or ""
        # Precise error reporting (e.g., file.tal:10:15)
        line_info = f"{filename}:{line}:{column}"
        word_info = f' Token "{word}"' if (word := self.word) else ""
        return f"{line_info}{word_info}: {super().__str__()}"


class SyntaxError(ParsingError):
    """A syntax error found in the parser."""


class FatalParsingError(ParsingError):
    """An error that halts the current parsing pass."""


class InternalParsingError(ParsingError):
    """An internal parsing error."""


class Parser:
    """A multi-pass parser for converting Tal tokens into an IR stream.

    The Parser manages the symbol table, macro expansion, and coordinate resolution.
    It produces an IR stream in Pass 1 and generates final ROM bytes in Pass 2.
    """

    def __init__(
        self, tokens: list[Token], cur_filepath: str | Path | None = None
    ) -> None:
        """Initialize a new parser instance.

        Args:
            tokens: A list of Token instances provided by the Lexer.
            cur_filepath: The path to the main source file being parsed.

        """
        self.tokens = tokens
        self.token_idx = 0
        self.current_token: Token | None = None
        if self.tokens:
            self.current_token = self.tokens[0]
        cur_filepath = Path(cur_filepath) if cur_filepath else Path("unknown_file")
        self.filepath_stack: list[Path] = [cur_filepath]

        self.symbol_table: dict[str, int] = {}
        self.macros: dict[str, list[Token]] = {}
        self.macro_call_stack: list[str] = []
        self.ir_stream: list[IRNode] = []
        # Start at 0x0000
        self.current_address = 0x0000
        self.main_code_block_started = False
        self.rom_data = bytearray()
        self.current_scope = ""

    def _cur_ctx_filepath(self) -> str | Path:
        """Return the path of the file currently being processed."""
        if self.filepath_stack:
            return self.filepath_stack[-1]
        else:
            return "unknown_file"

    def _advance(self) -> None:
        """Consume the current token and advance the cursor to the next one."""
        self.token_idx += 1
        if self.token_idx < len(self.tokens):
            self.current_token = self.tokens[self.token_idx]
        else:
            self.current_token = None

    def write_rom(self, output_filename: str | Path | None = None) -> None:
        """Write the accumulated ROM data to a file.

        Args:
            output_filename: The path to the file to create.

        """
        logger.debug(f"Preparing to write ROM to {output_filename}.")

        # The start address for program data in a UXN ROM
        rom_start_address = 0x0100

        full_rom_image = self.rom_data
        if len(full_rom_image) <= rom_start_address:
            logging.warning(
                f"No program data found at or after"
                f" address 0x{rom_start_address:04x}."
                " Creating an empty ROM file."
            )
            bytes_to_write = bytearray()
        else:
            # Slice to only get data from 0x0100 on
            bytes_to_write = full_rom_image[rom_start_address:]
        try:
            if output_filename:
                with open(output_filename, "wb") as rf:
                    rf.write(bytes_to_write)
                    logger.info(
                        f"Successfully wrote {len(bytes_to_write)}"
                        f" bytes to {output_filename}."
                    )
        except OSError as e:
            raise ParsingError(
                f"Failed to write ROM file '{output_filename}': {e}"
            ) from e

    def _process_token_stream(self) -> None:
        """Iterate through all tokens and dispatch them for Pass 1 processing."""
        try:
            while (
                self.current_token is not None
                and self.current_token.type != TOKENTYPE.EOF
            ):
                self._dispatch_current_token_for_pass1()
        except ParsingError as pe:
            pe.filename = self._cur_ctx_filepath()
            logger.error(str(pe))
            logger.debug("Parser Pass 1 aborted due to error.")
            raise

    def _ensure_default_start_page(self) -> None:
        """Apply default padding to address 0x0100 if code starts earlier."""
        if not self.main_code_block_started and self.current_address < 0x0100:
            logger.debug("First code/data directive encountered below page 0x0100")
            logger.debug("Applying default padding.")
            target_address = 0x0100
            padding_size = target_address - self.current_address
            # Create an IR node for this implict padding
            # for Pass 2 to handle.
            if self.current_token:
                self.ir_stream.append(
                    IRPadding(
                        address=self.current_address,
                        size=padding_size,
                        source_line=self.current_token.line,
                        source_column=self.current_token.column,
                        source_filepath=str(self._cur_ctx_filepath()),
                        target_address=target_address,
                    )
                )
            self.current_address = target_address

        # Once this check is done, we consider the main
        # code block started, so don't run again.
        self.main_code_block_started = True

    def parse_pass1(self) -> tuple[list[IRNode], dict[str, int]]:
        """Perform the first assembly pass.

        Identify labels, define macros, and build the initial IR stream.

        Returns:
            A tuple containing the IR stream and the populated symbol table.

        """
        logger.debug("Starting parser pass 1")

        if not self.tokens or self.tokens[0].type == TOKENTYPE.EOF:
            logger.debug("No tokens to parse.")
            return self.ir_stream, self.symbol_table

        self.current_token = self.tokens[0]

        self._process_token_stream()

        logger.debug("Parser Pass 1 Finished.")

        # NEW: Resolve overwrites and sort IR stream by address.
        # Simulate uxnasm.c's behavior where later definitions
        # at the same address overwrite earlier ones.
        logger.debug("Resolve address overwrites and sorting IR stream...")
        # Use a dict to keep only the LAST node defined at each address.
        final_ir_map = {node.address: node for node in self.ir_stream}
        final_ir_stream = sorted(final_ir_map.values(), key=lambda node: node.address)
        self.ir_stream = final_ir_stream
        logger.debug("Symbol Table:")
        for label, address in self.symbol_table.items():
            logger.debug(f"\t {label}: 0x{address:04x}")
        logger.debug(
            f"Final Calculated Address"
            f" (after pass 1 processing):"
            f" 0x{self.current_address:04x}"
        )
        return self.ir_stream, self.symbol_table

    def _pp2(self, obj: IRNode) -> None:
        """Log a debug message for an emitted IR node during Pass 2."""
        logger.debug(f" PASS2: Emitted {obj} at 0x{obj.address:04x}")

    def _handle_ir_label_placeholder(
        self, ir_node: IRLabelPlaceholder, symbol_table: dict[str, int]
    ) -> None:
        """Resolve a label and emit its value to the ROM.

        Handle absolute, relative, and zero-page address resolution.
        """
        # -- Step 1: Emit the implied opcode byte, if it has one --
        # This implies a literal addressing rune like ';',
        # ',', '.', '!' and '?'
        if ir_node.implied_opcode is not None:
            self.rom_data.append(ir_node.implied_opcode)

        # -- Step 2: Resolve the label name to its absolute address --
        target_addr = symbol_table.get(ir_node.label_name)
        if target_addr is None:
            raise ParsingError(
                f"Undefined label '{ir_node.label_name}' referenced.",
                line=ir_node.source_line,
                column=ir_node.source_column,
                word=ir_node.label_name,
                filename=ir_node.source_filepath,
            )

        # -- Step 3: Calculate the final value to be written --
        value_to_write = 0

        # Is this a "literal" addressing rune that's followed by a consuming
        # opcode? e.g., LITERAL_REL8_VIA_LIT (from ,label), which is then used
        # by JSR, JCN, etc.
        is_literal_for_consuming_op = "LITERAL" in ir_node.ref_type

        # Check if it's any kind of relative ref.
        if "REL" in ir_node.ref_type:
            # Relative offsets calculated from the address of the next inst
            inst_end_addr = ir_node.address + ir_node.size

            # If it's a LITERAL relative reference like `,label`, it's always
            # followed by a 1-byte opcode (like JSR) that consumes it. We must
            # account for that byte.
            if is_literal_for_consuming_op:
                inst_end_addr += 1
            value_to_write = target_addr - inst_end_addr
        else:
            # Absolute or Zero-Page addr used directly
            value_to_write = target_addr

        # -- Step 4: Write calculated value into ROM data --
        if ir_node.placeholder_size == 1:
            # For relative 8-bit jumps,
            # check if offset in range.
            if "REL" in ir_node.ref_type and not (-128 <= value_to_write <= 127):
                raise ParsingError(
                    f"Relative jump to '{ir_node.label_name}'"
                    f"is too far: ({value_to_write} bytes)."
                    " Must be between -128 and 127.",
                    line=ir_node.source_line,
                    column=ir_node.source_column,
                    filename=ir_node.source_filepath,
                )
            # For zero-page, check if address is in range.
            if "ZP" in ir_node.ref_type and not (0 <= value_to_write <= 0xFF):
                # TODO: Write a convenience function for PEs
                raise ParsingError(
                    f"Zero-page address for "
                    f"'{ir_node.label_name}'"
                    f"(0x{value_to_write:02x})"
                    " is outside the zero-page (0x00-0xff).",
                    line=ir_node.source_line,
                    column=ir_node.source_column,
                    filename=ir_node.source_filepath,
                )
            # Write as a single byte
            self.rom_data.append(value_to_write & 0xFF)
        elif ir_node.placeholder_size == 2:
            # Write as 16-bit short (high byte, low byte)
            self.rom_data.append((value_to_write >> 8) & 0xFF)
            self.rom_data.append(value_to_write & 0xFF)

        logger.debug(
            f" PASS2: Resolved {ir_node.label_name}"
            f"-> 0x{target_addr:04x},"
            f" wrote value 0x{value_to_write & 0xFFFF:04x} "
            f" at 0x{ir_node.address:04x}"
            f" (ref_type: {ir_node.ref_type})"
        )

    def _handle_ir_padding(self, ir_node: IRNode) -> None:
        """Apply zero-byte padding to reach the address specified by an IR node."""
        current_rom_len = len(self.rom_data)
        expected_address = ir_node.address

        # Pad if there's a gap between the current end of the ROM and
        # where this node should start.
        if expected_address > current_rom_len:
            padding_needed = expected_address - current_rom_len
            logger.debug(
                f"  PASS2: Padding with {padding_needed} zero bytes"
                f" to reach 0x{expected_address:04x}"
            )
            self.rom_data.extend([0x00] * padding_needed)

        # Sanity check to ensure the padding worked or to catch rewind errors.
        if expected_address != len(self.rom_data):
            raise ParsingError(
                f"Pass 2 PC desync. Expected address"
                f" 0x{len(self.rom_data):04x}, "
                f"but IR node is at 0x{expected_address:04x}."
                f" This can be caused by a "
                f"rewind padding directive "
                " ('|' to a lower address).",
                line=ir_node.source_line,
                column=ir_node.source_column,
                filename=ir_node.source_filepath,
            )

    def parse_pass2(
        self, ir_stream: list[IRNode], symbol_table: dict[str, int]
    ) -> None:
        """Perform the second assembly pass.

        Iterate through the IR stream and generate the final ROM data by
        resolving all addresses and offsets.
        """
        logger.debug("Starting parser pass 2.")
        self.current_address = 0x0000
        self.rom_data = bytearray()

        for ir in ir_stream:
            self._handle_ir_padding(ir)

            # Dispatch based on IR Node
            match ir:
                case IRPadding() as inst:
                    # The _handle_ir_padding call above already padded up to
                    # ir_node.address. Now, we must ensure padding extends from
                    # there to the IRPadding node's target_address.
                    current_rom_len = len(self.rom_data)
                    if inst.target_address > current_rom_len:
                        final_padding = ir.target_address - current_rom_len
                        logger.debug(
                            f"  PASS2: IRPadding node applying"
                            f" {final_padding} zero bytes to"
                            f" reach 0x{inst.target_address:04x}"
                        )
                        self.rom_data.extend([0x00] * final_padding)
                # The case where target_address < current_rom_len was already
                # flagged as a warning/error by the sanity check in
                # _handle_ir_padding if ir_node.address was also less. The
                # logic inside _handle_ir_padding handles this desync error.
                case IRRawBytes() as inst:
                    self.rom_data.extend(inst.byte_values)
                    self._pp2(inst)
                case IROpcode() as inst:
                    self.rom_data.append(inst.byte_value)
                    self._pp2(inst)
                case IRLabelPlaceholder() as inst:
                    self._handle_ir_label_placeholder(ir, symbol_table)
                case _:
                    raise NotImplementedError
        self.current_address = len(self.rom_data)
        logger.debug("Parser Pass 2 Complete.")
        logger.debug(
            f"Final PC (Pass 2): 0x{self.current_address:04x}"
            f" ROM size {len(self.rom_data)} bytes."
        )

    def _dispatch_current_token_for_pass1(self) -> None:
        """Handle a single token based on its type during Pass 1."""
        if self.current_token is None:
            return

        token_type = self.current_token.type

        match token_type:
            case TOKENTYPE.RUNE_PIPE:
                self._handle_padding_rune()
            case TOKENTYPE.RUNE_DOLLAR:
                self._handle_padding_rune()
            case TOKENTYPE.RUNE_AT:
                self._handle_label_definition()
            case TOKENTYPE.RUNE_AMPERSAND:
                self._handle_standalone_sub_label()
            case TOKENTYPE.RAW_ASCII_CHUNK:
                self._handle_raw_ascii_chunk()
            case TOKENTYPE.RUNE_HASH:
                self._handle_hash_literal()
            case TOKENTYPE.RUNE_FORWARDSLASH:
                self._advance()
            case TOKENTYPE.IDENTIFIER:
                self._handle_identifier_token()
            # Literal Absolute pushes an absolute address short to label.
            case TOKENTYPE.RUNE_SEMICOLON:
                self._handle_literal_addressing_rune_op(";", 0xA0, 2)
            # Conditional Jump routine.
            case TOKENTYPE.RUNE_QUESTION:
                self._handle_literal_addressing_rune_op(
                    # JCI is byte 0x20
                    "?",
                    0x20,
                    2,
                )
            # Literal Jump routine.
            case TOKENTYPE.RUNE_EXCLAIM:
                self._handle_literal_addressing_rune_op(
                    # JMI is 0x40
                    "!",
                    0x40,
                    2,
                )
            # Literal Relative pushes a relative distance byte to the label.
            case TOKENTYPE.RUNE_COMMA:
                self._handle_literal_addressing_rune_op(",", 0x80, 1)
            # Literal Zero-Page pushes an absolute address byte to the label.
            case TOKENTYPE.RUNE_PERIOD:
                self._handle_literal_addressing_rune_op(".", 0x80, 1)
            # Raw addressing ops. These don't have implied opcodes.
            # Raw Relative writes a relative distance byte to the label.
            case TOKENTYPE.RUNE_UNDERSCORE:
                self._handle_raw_addressing_rune_op("_", 1)
            # Raw Zero-Page writes an absolute address byte to the label.
            case TOKENTYPE.RUNE_MINUS:
                self._handle_raw_addressing_rune_op("-", 1)
            # Raw Absolute writes an absolute address short to the label.
            case TOKENTYPE.RUNE_EQUAL:
                self._handle_raw_addressing_rune_op("=", 2)
            case TOKENTYPE.RUNE_LBRACE:
                # For raw { ... }
                self._handle_raw_hex_data_block()

            # Include directive
            case TOKENTYPE.RUNE_TILDE:
                self._handle_include_directive()

            case TOKENTYPE.RUNE_LBRACKET:
                # For [ (ignored)
                logger.debug(f"  Ignoring Rune '[' (Line {self.current_token.line})")
                self._advance()

            case TOKENTYPE.RUNE_RBRACKET:
                # ] ignored
                logger.debug(f"  Ignoring Rune ']' (Line {self.current_token.line})")
                self._advance()

            case TOKENTYPE.OPCODE:
                self._handle_opcode_token()

            case TOKENTYPE.RUNE_PERCENT:
                self._handle_macro_definition()

            case TOKENTYPE.RUNE_RBRACE:
                raise SyntaxError(
                    f"Unexpected closing delimiter '{self.current_token.word}'",
                    token=self.current_token,
                )
            case _:
                self._advance()
                # This should ideally be an error for unexpected tokens.
                raise SyntaxError(
                    f"Unexpected token during dispatch: '{self.current_token.word}'",
                    token=self.current_token,
                    filename=self._cur_ctx_filepath(),
                )

    def _parse_anonymous_block_content(
        self, open_brace_token: Token, anonymous_label_end_name: str
    ) -> None:
        """Parse tokens within an anonymous { } block until a matching '}'.

        Relies on the main dispatcher _dispatch_current_token_for_pass1
        to handle content. Advances self.current_address based on the
        content. Consumes the closing '}'.
        """
        logger.debug(
            f"  Entering anonymous block started on line {open_brace_token.line}"
        )
        logger.debug(f"  Will define '{anonymous_label_end_name}'")
        depth = 1
        while self.current_token is not None:
            # Nested block
            if self.current_token.type == TOKENTYPE.RUNE_LBRACE:
                depth += 1
                logger.debug(
                    f"    Nested '{{' found, depth now {depth}"
                    f" (Line {self.current_token.line})"
                )
                # The _dispatch_current_token_for_pass1 called below
                # will handle this if RUNE_LBRACE is an error or leads
                # to another block construct. For now, we assume an
                # outer operator initiates a new anonymous block.
                # This _parse_anonymous_block_content is primarily for
                # the *content* after an operator like `;{`.  If a new
                # `;{` appears inside, its handler would call this
                # again.  For now, just dispatch it.
                self._dispatch_current_token_for_pass1()

            elif self.current_token.type == TOKENTYPE.RUNE_RBRACE:
                depth -= 1
                logger.debug(
                    f"    Found '}}', depth now {depth}"
                    f" (Line {self.current_token.line})"
                )
                if depth == 0:
                    end_label_address = self.current_address
                    self.symbol_table[anonymous_label_end_name] = end_label_address
                    # Consume the final '}'
                    self._advance()
                    logger.debug(
                        f"    Exiting anonymous block."
                        f" PC is now 0x{self.current_address:04x}"
                    )
                    # Successfully parsed and closed the block
                    return
                else:
                    # Closing a nested block
                    # Let dispatcher handle/skip '}' if it's just a delimiter
                    # Or, if '}' is always just consumed: self._advance()
                    self._dispatch_current_token_for_pass1()

            elif self.current_token.type == TOKENTYPE.EOF:
                if self.token_idx < len(self.tokens):
                    token = self.tokens[self.token_idx]
                else:
                    token = self.tokens[-1]
                raise SyntaxError(
                    f"Unclosed anonymous block {{"
                    f" starting on line "
                    f"{open_brace_token.line}."
                    " Reached EOF.",
                    token=token,
                )
            else:
                # Dispatch to handle the actual content of the block
                self._dispatch_current_token_for_pass1()

        # If loop terminates due to self.current_token being None (should be
        # caught by EOF above)
        if self.token_idx < len(self.tokens):
            token = self.tokens[self.token_idx]
        else:
            token = self.tokens[-1]
        raise SyntaxError(
            f"Unclosed anonymous block {{ starting on line {open_brace_token.line}.",
            token=token,
        )

    def _handle_padding_rune(self) -> None:
        """Handle '|' and '$' runes."""
        # Explicit padding always marks the start of the main block.
        self.main_code_block_started = True
        rune_token = self.current_token
        if rune_token is None:
            return
        rune_char = rune_token.word[0]
        # Consume '|' token or '$' token
        self._advance()

        if not (
            self.current_token
            and self.current_token.type == TOKENTYPE.IDENTIFIER
        ):
            # TODO: looking up label in symbol_table
            raise SyntaxError(
                f"Expected hex literal afterpadding rune '{rune_char}'",
                token=rune_token,
            )

        value_str = self.current_token.word
        try:
            val = int(value_str, 16)
        except ValueError as e:
            raise SyntaxError(
                f"Invalid hex value '{value_str}' for padding rune '{rune_char}'",
                token=self.current_token,
            ) from e

        # Absolute padding
        if rune_char == "|":
            target_address = val
            if target_address < self.current_address:
                logger.warning(
                    f"Padding directive on line {rune_token.line}"
                    " rewinds program counter from"
                    f" 0x{self.current_address:04x} to"
                    f" 0x{target_address:04x}."
                )
            self.current_address = target_address

        # Relative padding
        elif rune_char == "$":
            target_address = self.current_address + val
            logging.debug(
                f"Padding by relative offset 0x{val:02x} "
                f"(Line {rune_token.line})."
                f" PC from 0x{self.current_address:04x}"
                f" to 0x{self.current_address + target_address:04x}"
            )
            self.current_address += val

        # Consume the hex literal/label token.
        self._advance()

    def _handle_literal_addressing_rune_op(
        self, rune_char_expected: str, implied_opcode_byte: int, placeholder_size: int
    ) -> None:
        """Handle runes like ';', '!', '?', ',' and '.'.

        Handles runes like ;, !, ?, ,, . that imply an opcode and a placeholder
        for an address/offset.
        rune_char: The character itself (e.g., ';', '!')
        implied_opcode_byte: The byte value of the opcode uxnasm.c writes
                             (e.g., LIT2's opcode, JMI's 0x40)
        placeholder_size: 1 for byte, 2 for short (0xff or 0xffff)
        """
        self._ensure_default_start_page()
        rune_token = self.current_token
        if rune_token is None:
            return
        op_start_address = self.current_address
        # Consume the main addressing rune (';', '?', '!', ',', '.')
        self._advance()

        # Size for the operation prefix (e.g., LIT2 + placeholder, or
        # JMI + placeholder)
        prefix_operation_size = 1 + placeholder_size

        target_label_name = ""
        ref_type = f"LITERAL_{rune_char_expected}_{placeholder_size * 8}"
        match rune_char_expected:
            case ";":
                ref_type = "LITERAL_ABS16_VIA_LIT2"
            case ",":
                ref_type = "LITERAL_REL8_VIA_LIT"
            case ".":
                ref_type = "LITERAL_ZP8_VIA_LIT"
            case "?":
                ref_type = "JCI_REL16_VIA_OPCODE"
            case "!":
                ref_type = "JMI_REL16_VIA_OPCODE"
            case _:
                raise ParsingError(f"Unexpected rune char {ref_type}", token=rune_token)
        if self.current_token and self.current_token.type == TOKENTYPE.RUNE_LBRACE:
            # Operand is an anonymous block { ... }
            lbrace_token = self.current_token
            target_label_name = self._generate_anonymous_label_name(lbrace_token.line)
            logger.debug(
                f"  IR Target: Literal Addressing Rune Op:"
                f"{rune_token.word}{{...}} detected "
                " (Line {rune_token.line})"
            )

            logger.debug(
                f"  Addressing Rune Op: {rune_token.word}{{...}}"
                f" detected (Line {rune_token.line})"
            )
            logger.debug(
                f"    Prefix operation {rune_token.word}{{"
                f" contributes {prefix_operation_size} bytes."
                f" PC from 0x{self.current_address:04x}"
            )
            self.ir_stream.append(
                IRLabelPlaceholder(
                    address=op_start_address,
                    size=prefix_operation_size,
                    label_name=target_label_name,
                    ref_type=ref_type,
                    placeholder_size=placeholder_size,
                    implied_opcode=implied_opcode_byte,
                    source_line=rune_token.line,
                    source_column=rune_token.column,
                    source_filepath=str(self._cur_ctx_filepath()),
                )
            )
            self.current_address += prefix_operation_size
            logger.debug(
                f"    ...to 0x{self.current_address:04x}. Now parsing block content."
            )
            # Consume '{'
            self._advance()
            self._parse_anonymous_block_content(
                lbrace_token, anonymous_label_end_name=target_label_name
            )
            # This will parse until '}' and advance PC for content The
            # address "provided" by { is self.current_address (which
            # is now after the '}'). This address would be used in
            # Pass 2 to fill the placeholder.
        else:
            # Operand is a standard label (&label or label)
            is_sub_label_ref = False
            label_prefix = ""
            if self.current_token and (
                self.current_token.type == TOKENTYPE.RUNE_AMPERSAND
                or self.current_token.type == TOKENTYPE.RUNE_FORWARDSLASH
            ):
                label_prefix = self.current_token.word
                is_sub_label_ref = True
                self._advance()

            if not (
                self.current_token
                and self.current_token.type == TOKENTYPE.IDENTIFIER
            ):
                raise SyntaxError(
                    f"Expected label name or '{{' after rune '{rune_token.word}'.",
                    token=rune_token,
                )

            label_identifier_token = self.current_token
            base_label_name = label_identifier_token.word
            target_label_name = ""
            if is_sub_label_ref:
                if not self.current_scope:
                    raise SyntaxError(
                        "Sub-label reference "
                        f"'{label_prefix}{base_label_name}'"
                        "used outside of a parent '@' scope.",
                        token=label_identifier_token,
                    )
                target_label_name = f"{self.current_scope}/{base_label_name}"
            else:
                target_label_name = base_label_name

            self.ir_stream.append(
                IRLabelPlaceholder(
                    address=op_start_address,
                    size=prefix_operation_size,
                    label_name=target_label_name,
                    ref_type=ref_type,
                    placeholder_size=placeholder_size,
                    implied_opcode=implied_opcode_byte,
                    source_line=rune_token.line,
                    source_column=rune_token.column,
                    source_filepath=str(self._cur_ctx_filepath()),
                )
            )
            displayed_label = base_label_name
            if is_sub_label_ref:
                displayed_label = f"{label_prefix}{base_label_name}"
            logger.debug(
                f"  Addressing Rune Op:"
                f" {rune_token.word}{displayed_label}, "
                f"implies [Opcode 0x{implied_opcode_byte:02x}"
                f" + {placeholder_size}b placeholder], "
                f"total size {prefix_operation_size}"
                f" (Line {rune_token.line})"
            )
            self.current_address += prefix_operation_size
            # Consume label IDENTIFIER
            self._advance()

    _anon_label_counter = 0

    def _generate_anonymous_label_name(self, line: int) -> str:
        Parser._anon_label_counter += 1
        return f"__ANON_END_{line}_{Parser._anon_label_counter}"

    def _handle_raw_addressing_rune_op(
        self, rune_char: str, placeholder_size: int
    ) -> None:
        """Handle raw addressing runes like '_', '-', and '='.

        These directly reserve placeholder_size bytes for an address/offset.
        """
        self._ensure_default_start_page()
        rune_token = self.current_token
        if rune_token is None:
            return
        op_start_address = self.current_address

        # Consume the raw addressing rune ('_', '-', '=').
        self._advance()

        # Size for the operation prefix (just the placeholder for raw modes)
        prefix_operation_size = placeholder_size

        target_label_name = ""
        ref_type = ""

        match rune_char:
            case "_":
                ref_type = "RAW_REL8"
            case "-":
                ref_type = "RAW_ZP8"
            case "=":
                ref_type = "RAW_ABS16"
            case _:
                raise ParsingError(
                    f"Unknown raw rune:'{rune_char}'in _handle_raw_addressing_rune_op",
                    token=rune_token,
                )
        if self.current_token and self.current_token.type == TOKENTYPE.RUNE_LBRACE:
            # Operand is an anonymous block { ... }
            lbrace_token = self.current_token
            target_label_name = self._generate_anonymous_label_name(lbrace_token.line)
            logger.debug(
                f"  Raw Addressing Rune Op: {rune_token.word}{{...}}"
                f" detected (Line {rune_token.line})"
            )
            logger.debug(
                f"    Prefix operation {rune_token.word}{{"
                f"contributes {prefix_operation_size} bytes"
                f" for placeholder."
                f" PC from 0x{self.current_address:04x}"
            )
            self.ir_stream.append(
                IRLabelPlaceholder(
                    address=op_start_address,
                    size=placeholder_size,
                    label_name=target_label_name,
                    ref_type=ref_type,
                    implied_opcode=None,
                    source_line=rune_token.line,
                    source_column=rune_token.column,
                    source_filepath=str(self._cur_ctx_filepath()),
                    placeholder_size=placeholder_size,
                )
            )
            self.current_address += prefix_operation_size
            logger.debug(
                f"    ...to 0x{self.current_address:04x}. Now parsing block content."
            )
            # Consume '{'
            self._advance()
            self._parse_anonymous_block_content(
                lbrace_token, anonymous_label_end_name=target_label_name
            )
        else:
            # Operand is a standard label (&label or label)
            is_sub_label_ref = False
            label_prefix = ""
            if self.current_token and (
                self.current_token.type == TOKENTYPE.RUNE_AMPERSAND
                or self.current_token.type == TOKENTYPE.RUNE_FORWARDSLASH
            ):
                label_prefix = self.current_token.word
                is_sub_label_ref = True
                self._advance()

            if not (
                self.current_token
                and self.current_token.type == TOKENTYPE.IDENTIFIER
            ):
                raise SyntaxError(
                    f"Expected label name or '{{' after rune '{rune_token.word}'.",
                    token=rune_token,
                )

            label_identifier_token = self.current_token
            base_label_name = label_identifier_token.word
            target_label_name = ""
            if is_sub_label_ref:
                if not self.current_scope:
                    raise SyntaxError(
                        "Sub-label reference "
                        f"'{label_prefix}{base_label_name}'"
                        "used outside of a parent '@' scope.",
                        token=label_identifier_token,
                    )
                target_label_name = f"{self.current_scope}/{base_label_name}"
            else:
                target_label_name = base_label_name

            self.ir_stream.append(
                IRLabelPlaceholder(
                    address=op_start_address,
                    size=placeholder_size,
                    label_name=target_label_name,
                    ref_type=ref_type,
                    implied_opcode=None,
                    source_line=rune_token.line,
                    source_column=rune_token.column,
                    source_filepath=str(self._cur_ctx_filepath()),
                    placeholder_size=placeholder_size,
                )
            )
            displayed_label = base_label_name
            if is_sub_label_ref:
                displayed_label = f"{label_prefix}{base_label_name}"
            logger.debug(
                f"  Raw Addressing Rune Op:"
                f" {rune_token.word}{displayed_label}, "
                f"reserves {placeholder_size}-byte placeholder,"
                f" total size {prefix_operation_size}"
                f" (Line {rune_token.line})"
            )
            self.current_address += prefix_operation_size
            # Consume label IDENTIFIER
            self._advance()

    def _handle_opcode_token(self) -> None:
        op_token = self.current_token
        if op_token is None:
            return
        op_addr = self.current_address
        if op_token.value is None or not isinstance(op_token.value, int):
            raise ParsingError(
                f"Internal Error: OPCODE token"
                f" '{op_token.word}' is missing"
                f" a valid integer value attribute.",
                token=op_token,
            )
        # All UXN opcodes are 1 byte.
        size = 1
        logger.debug(
            f"  Opcode: {op_token.word}"
            f" (Byte: {op_token.value:#04x}),"
            f" size {size} (Line {op_token.line})"
        )

        self.ir_stream.append(
            IROpcode(
                address=op_addr,
                size=size,
                source_line=op_token.line,
                source_column=op_token.column,
                source_filepath=str(self._cur_ctx_filepath()),
                mnemonic=op_token.word,
                byte_value=op_token.value,
            )
        )
        self.current_address += size
        self._advance()

    def _handle_include_directive(self) -> None:
        include_rune_token = self.current_token
        if include_rune_token is None:
            return
        self._advance()
        if not (self.current_token and self.current_token.type == TOKENTYPE.IDENTIFIER):
            raise SyntaxError(
                "Expected filepath (IDENTIFIER) after '~'", token=include_rune_token
            )
        filepath_token = self.current_token
        filepath_str = filepath_token.word
        logger.debug(
            f"  Include Directive: ~{filepath_str} (Line {include_rune_token.line})"
        )
        # Consume the filepath_str
        self._advance()

        # Save the Parser's token processing state
        orig_tokens = self.tokens
        orig_token_idx = self.token_idx
        orig_current_token = self.current_token

        self.filepath_stack.append(Path(filepath_str))
        logger.debug(f"filepath_stack: {self.filepath_stack}")
        try:
            with open(filepath_str) as inc_file:
                inc_source = inc_file.read()
        except FileNotFoundError as e:
            raise ParsingError(
                f"Include file not found: '{filepath_str}'",
                line=include_rune_token.line,
                column=include_rune_token.column,
                filename=self._cur_ctx_filepath(),
            ) from e
        logger.debug(f"Lexing included file: {filepath_str}")
        inc_lexer = Lexer(inc_source, filename=filepath_str)
        inc_tokens = inc_lexer.scan_all_tokens()
        if not inc_tokens:
            logger.debug(
                f"Included file '{filepath_str}' is empty or contains no tokens."
            )
        logger.debug(
            f"Starting Pass 1 for included file:"
            f" {filepath_str} PC=0x{self.current_address:04x}"
        )
        # Set this parser's tokens to included file's tokens
        self.tokens = inc_tokens
        self.token_idx = 0
        self.current_token = self.tokens[0] if self.tokens else None
        # Recursively process token stream. It should finish
        # and come back here.
        self._process_token_stream()
        logger.debug(
            f"Finished Pass 1 for included file:"
            f" {filepath_str}"
            f" PC=0x{self.current_address:04x}"
        )
        # Restore previous state of parser
        self.tokens = orig_tokens
        self.token_idx = orig_token_idx
        self.current_token = orig_current_token
        # Restore filepath
        # TODO: Make this a fn
        self.filepath_stack.pop()

    def _handle_raw_ascii_chunk(self) -> None:
        """Handle RAW_ASCII_CHUNK.

        These are prefixed with '"', e.g. "Hello
        """
        self._ensure_default_start_page()
        token = self.current_token
        if token is None:
            return
        content = token.word
        size = len(content)
        byte_values = [ord(c) for c in content]
        self.ir_stream.append(
            IRRawBytes(
                address=self.current_address,
                size=size,
                byte_values=byte_values,
                source_line=token.line,
                source_column=token.column,
                source_filepath=str(self._cur_ctx_filepath()),
            )
        )
        logger.debug(
            f'Raw ASCII Chunk: "{content}", size: {size} bytes Line: {token.line}'
        )
        self.current_address += size
        self._advance()

    def _handle_hash_literal(self) -> None:
        """Handle hash literals.

        These become LIT/LIT2 + value. Calculates size and generates
        IR nodes for the implied LIT/LIT2 opcodes and the value.
        """
        self._ensure_default_start_page()
        token = self.current_token
        if token is None:
            return
        op_start_addr = self.current_address
        # Consume '#'
        self._advance()

        if not (
            self.current_token
            and self.current_token.type == TOKENTYPE.IDENTIFIER
        ):
            # TODO: Handle this error properly
            # SyntaxError("Expected hex literal after #", token=token)
            pass

        hex_literal = self.current_token
        if hex_literal is None:
            return
        val = hex_literal.word

        try:
            # Test conversion to see if it's a valid number.
            val_int = int(val, 16)
        except ValueError as e:
            raise SyntaxError(
                f"Invalid hex value '{val}' after '#'", token=hex_literal
            ) from e

        val_len = len(val)
        size = 0

        if val_len == 0:
            raise SyntaxError("Empty hex literal after #", token=hex_literal)
        elif val_len <= 2:
            size = 2
            logger.debug(f"LIT #{val}, size {size} (Line {token.line})")

            # Create IR node for the LIT opcode.
            lit_opcode_byte = get_opcode_byte("LIT")
            if lit_opcode_byte is not None:
                self.ir_stream.append(
                    IROpcode(
                        address=op_start_addr,
                        size=1,
                        source_line=token.line,
                        source_column=token.column,
                        source_filepath=str(self._cur_ctx_filepath()),
                        mnemonic="LIT",
                        byte_value=lit_opcode_byte,
                    )
                )
            # Create an IR node for the 1-byte value.
            self.ir_stream.append(
                IRRawBytes(
                    address=op_start_addr + 1,
                    size=1,
                    source_line=hex_literal.line,
                    source_column=hex_literal.column,
                    source_filepath=str(self._cur_ctx_filepath()),
                    byte_values=[val_int & 0xFF],
                )
            )
        elif val_len <= 4:
            size = 3
            logger.debug(f"LIT2 #{val}, size {size} (Line {token.line})")
            # Create IR node for LIT2 opcode.
            lit2_opcode_byte = get_opcode_byte("LIT2")
            if lit2_opcode_byte is not None:
                self.ir_stream.append(
                    IROpcode(
                        address=op_start_addr,
                        size=1,
                        source_line=token.line,
                        source_column=token.column,
                        source_filepath=str(self._cur_ctx_filepath()),
                        mnemonic="LIT2",
                        byte_value=lit2_opcode_byte,
                    )
                )
            # Create IR node for 2-byte value (high byte, then low byte).
            high_byte = (val_int >> 8) & 0xFF
            low_byte = val_int & 0xFF
            self.ir_stream.append(
                IRRawBytes(
                    # Starts after the LIT2 opcode.
                    address=op_start_addr + 1,
                    size=2,
                    source_line=hex_literal.line,
                    source_column=hex_literal.column,
                    source_filepath=str(self._cur_ctx_filepath()),
                    byte_values=[high_byte, low_byte],
                )
            )
        else:
            raise SyntaxError(f"Hex literal too long after #: {val}", token=token)
        self.current_address += size
        # Consume hex literal token.
        self._advance()

    def _handle_sub_label_field(self, parent_label_name: str) -> None:
        """Handle sub-labels.

        Handle '&' and '&' followed by '$'.
        These are sub-labels. And '$' is used to
        reserve space.
        """
        ampersand_token = self.current_token
        if ampersand_token is None:
            return
        # Consume '&'
        self._advance()
        if not (self.current_token and self.current_token.type == TOKENTYPE.IDENTIFIER):
            raise SyntaxError(
                f"Expected sub-label name after '&' for parent '{parent_label_name}'.",
                token=ampersand_token,
            )
        sub_label_token = self.current_token
        sub_label_name = sub_label_token.word
        full_sub_label_name = f"{parent_label_name}/{sub_label_name}"

        if full_sub_label_name in self.symbol_table:
            logger.warning("Duplicate sub-label: %s", full_sub_label_name)
            # raise SyntaxError()
        else:
            self.symbol_table[full_sub_label_name] = self.current_address
            logger.debug(
                f"  Defined sub-label '{full_sub_label_name}'"
                f" at 0x{self.current_address:04x}"
            )
        # Consume sub-label identifier
        self._advance()

        # Check for optional $size
        if (tok := self.current_token) and tok.type == TOKENTYPE.RUNE_DOLLAR:
            dollar_token = tok
            # Consume '$'
            self._advance()
            if not (
                (t := self.current_token)
                and t.type == TOKENTYPE.IDENTIFIER
            ):
                raise SyntaxError(
                    "Expected size (IDENTIFIER) after '$'", token=dollar_token
                )
            size_hex_token = t
            try:
                size = int(size_hex_token.word, 16)
                if size < 0:
                    raise ValueError("Size cannot be negative.")
            except ValueError as e:
                raise SyntaxError(
                    f"Invalid size {size_hex_token.word} "
                    f"for sub-label {sub_label_token.word}",
                    token=size_hex_token,
                ) from e
            logger.debug(
                "    Sub-label '%s/%s' field occupies %s byte(s).",
                parent_label_name,
                sub_label_token.word,
                size,
            )
            logger.debug("       Advancing PC.")
            # Represent reserved space as a chunk of zero bytes.
            self.ir_stream.append(
                IRRawBytes(
                    address=self.current_address,
                    size=size,
                    source_line=dollar_token.line,
                    source_column=dollar_token.column,
                    source_filepath=str(self._cur_ctx_filepath()),
                    byte_values=([0x00] * size),
                )
            )
            # Advance PC after creating the IR node.
            self.current_address += size
            # Consume hex size literal.
            self._advance()

    def _handle_label_definition(self) -> None:
        """Handle label definitions.

        Handle '@' label definitions.
        """
        # For @
        directive_token = self.current_token
        if directive_token is None:
            return
        # Ensure padding is applied before defining the label address
        self._ensure_default_start_page()
        # Consume '@'
        self._advance()
        if not (self.current_token and self.current_token.type == TOKENTYPE.IDENTIFIER):
            raise SyntaxError(
                "Expected parent label name after '@'.", token=directive_token
            )
        parent_label_token = self.current_token
        parent_label_name = parent_label_token.word
        self.current_scope = parent_label_name
        logger.debug(f"  Scope set to '{self.current_scope}'")
        if parent_label_name in self.symbol_table:
            # TODO: write a custom warning function with line and label
            logger.warning(
                "Duplicate label: %s, Line %s",
                parent_label_name,
                parent_label_token.line,
            )
        else:
            self.symbol_table[parent_label_name] = self.current_address
            logger.debug(
                f'Define label "{parent_label_name}" at '
                f"0x{self.current_address:04x} "
                f"(Line {parent_label_token.line})"
            )
        # Consume parent label identifier
        self._advance()
        while (t := self.current_token) and t.type == TOKENTYPE.RUNE_AMPERSAND:
            self._handle_sub_label_field(parent_label_name)

    def _handle_standalone_sub_label(self) -> None:
        """Handle a standalone sub-label definition (e.g., '&loop').

        Define a label within the current parent scope stored in
        self.current_scope.
        """
        ampersand_token = self.current_token
        if ampersand_token is None:
            return
        # Ensure padding is applied before defining the label address
        self._ensure_default_start_page()
        # Consume '&'
        self._advance()

        if not (self.current_token and self.current_token.type == TOKENTYPE.IDENTIFIER):
            raise SyntaxError(
                "Expected sub-label name (IDENTIFIER) after standalone '&'.",
                token=ampersand_token,
            )
        sub_label_token = self.current_token
        sub_label_name = sub_label_token.word

        if not self.current_scope:
            raise SyntaxError(
                f"Sub-label '&{sub_label_name}' defined outside of a parent '@' scope.",
                token=sub_label_token,
            )

        full_sub_label_name = f"{self.current_scope}/{sub_label_name}"

        if full_sub_label_name in self.symbol_table:
            logger.warning(
                "Duplicate sub-label definition for "
                f"'{full_sub_label_name}' on line {sub_label_token.line}."
            )
        else:
            self.symbol_table[full_sub_label_name] = self.current_address
            logger.debug(
                f"  Defined sub-label"
                f" '{full_sub_label_name}' at"
                f" 0x{self.current_address:04x}"
                f" (Line {sub_label_token.line})"
            )

        # This directive only defines a label; it has no size itself.
        # The following instructions will advance the PC.
        self._advance()

    def _handle_standalone_hex_data(self) -> None:
        """Handle raw hex literals.

        These are literals without LIT or # in front of them.
        """
        # For hex literal as raw data
        self._ensure_default_start_page()
        data_token = self.current_token
        if data_token is None:
            return
        op_addr = self.current_address
        data_word = data_token.word
        data_len = len(data_word)
        data_size = 0
        if data_len == 0:
            raise SyntaxError("Empty raw hex data.", token=data_token)
        elif data_len <= 2:
            data_size = 1
        elif data_len <= 4:
            data_size = 2
        else:
            raise SyntaxError(f"Raw hex data {data_word} is too long", token=data_token)
        try:
            val_int = int(data_word, 16)
            byte_values = []
            if data_size == 1:
                byte_values.append(val_int & 0xFF)
            elif data_size == 2:
                # High byte, then low byte.
                byte_values.append((val_int >> 8) & 0xFF)
                byte_values.append(val_int & 0xFF)
        except ValueError as e:
            raise SyntaxError(
                f"Invalid hex value for raw data: '{data_word}'", token=data_token
            ) from e
        # Create and append the IR node.
        self.ir_stream.append(
            IRRawBytes(
                address=op_addr,
                size=data_size,
                source_line=data_token.line,
                source_column=data_token.column,
                source_filepath=str(self._cur_ctx_filepath()),
                byte_values=byte_values,
            )
        )
        logger.debug(
            "  Raw Hex Data Byte(s): %s, size: %s (Line %s)",
            data_word,
            data_size,
            data_token.line,
        )
        self.current_address += data_size
        self._advance()

    def _handle_raw_hex_data_block(self) -> None:
        """Handle a raw hex data block: { xx yy zz ... }.

        Called when current_token is RUNE_LBRACE.
        """
        lbrace_token = self.current_token
        if lbrace_token is None:
            return
        logger.debug(f"  Raw Hex Data Block Start {{ (Line {lbrace_token.line})")
        self._advance()  # Consume '{'

        # Loop indefinitely until we find the closing brace or hit an error
        while True:
            if self.current_token is None or self.current_token.type == TOKENTYPE.EOF:
                # We hit the end of the file before finding '}'
                err_msg = (
                    f"Unclosed raw hex data block {{ starting on "
                    f"line {lbrace_token.line}. Reached EOF."
                )
                raise SyntaxError(err_msg, token=lbrace_token)

            # Check for the exit condition FIRST.
            if self.current_token.type == TOKENTYPE.RUNE_RBRACE:
                break  # Found the end of the block, exit the loop.

            # If not the end, it must be a hex literal.
            if self.current_token.type == TOKENTYPE.IDENTIFIER:
                # Delegate to the existing handler. It will update PC,
                # generate IR, and advance the token.
                self._handle_standalone_hex_data()
            else:
                # If not '}' or a hex literal, it's an error.
                err_msg = (
                    "Expected IDENTIFIER or '}' in raw hex data "
                    f"block, found '{self.current_token.word}'"
                )
                raise SyntaxError(err_msg, token=self.current_token)

        # After the loop breaks, self.current_token is the closing brace.
        if self.current_token:
            logger.debug(
                f"  Raw Hex Data Block End }} (Line {self.current_token.line})"
            )
        # Consume '}'
        self._advance()

    def _handle_identifier_token(self) -> None:
        """Handle identifiers or opcodes."""
        self._ensure_default_start_page()
        id_token = self.current_token
        if id_token is None:
            return
        word = id_token.word
        op_addr = self.current_address
        if word in self.macros:
            # It's a macro invocation.
            self._handle_macro_invocation(word, id_token.line, id_token.column)
            self._advance()
            return

        # Not a macro or opcode
        elif is_purely_hex(word):
            hex_len = len(word)
            byte_values = []

            if hex_len == 0:
                raise SyntaxError("Empty Hex", token=id_token)
            elif hex_len <= 2:
                size = 1
                byte_values.append(int(word, 16))
                logger.debug(
                    f"Hex-like identifier (as raw byte)"
                    f", word: '{word}', size: '{size}'"
                    f", line: '{id_token.line}'"
                )
            elif hex_len <= 4:
                size = 2
                val = int(word, 16)
                # High byte
                byte_values.append((val >> 8) & 0xFF)
                # Low byte
                byte_values.append(val & 0xFF)
                logger.debug(
                    f"Hex-like identifier (as raw short)"
                    f", word: '{word}', size: '{size}'"
                    f", line: '{id_token.line}'"
                )
            else:
                logger.warning(
                    f"Long hex-like id '{word}'"
                    f", line: '{id_token.line}'."
                    " Treating as bare word call"
                )
                size = 3
                self.ir_stream.append(
                    IRLabelPlaceholder(
                        address=op_addr,
                        size=size,
                        source_line=id_token.line,
                        source_column=id_token.column,
                        source_filepath=str(self._cur_ctx_filepath()),
                        label_name=word,
                        ref_type="JSR_REL16_BAREWORD",
                        placeholder_size=2,
                        # JSR-like opcode
                        implied_opcode=0x60,
                    )
                )
            if size in [1, 2]:
                self.ir_stream.append(
                    IRRawBytes(
                        address=op_addr,
                        size=size,
                        source_line=id_token.line,
                        source_column=id_token.column,
                        source_filepath=str(self._cur_ctx_filepath()),
                        byte_values=byte_values,
                    )
                )
        else:
            # It's a bare word, not a known opcode or a macro.
            # uxnasm.c treats this as a JSR-like call,
            # with a 16-bit relative offset.
            size = 3
            target_label_name = ""
            # Check for sub-label prefixes
            if word.startswith("&") or word.startswith("/"):
                if not self.current_scope:
                    raise SyntaxError(
                        f"Sub-label reference '{word}'used"
                        "outside of a parent '@' scope.",
                        token=id_token,
                    )
                base_label_name = word[1:]
                target_label_name = f"{self.current_scope}/{base_label_name}"
            else:
                target_label_name = word
            logger.debug(
                f"  Bare Word Call"
                f" (JSR-like to '{word}',)"
                f" size {size} bytes (Line {id_token.line})"
            )
            self.ir_stream.append(
                IRLabelPlaceholder(
                    address=op_addr,
                    size=size,
                    source_line=id_token.line,
                    source_column=id_token.column,
                    source_filepath=str(self._cur_ctx_filepath()),
                    label_name=target_label_name,
                    ref_type="JSR_REL16_BAREWORD",
                    placeholder_size=2,
                    implied_opcode=0x60,
                )
            )
        self.current_address += size
        self._advance()

    def _handle_macro_definition(self) -> None:
        """Handle a macro definition: %name { tokens ... }.

        Consume tokens for the definition and store the macro body.
        """
        # The % token
        percent_token = self.current_token
        if percent_token is None:
            return
        logger.debug(f"Macro Def Start % (Line {percent_token.line})")
        # Consume the '%'
        self._advance()

        # Parse the macro name.
        if not (self.current_token and self.current_token.type == TOKENTYPE.IDENTIFIER):
            raise SyntaxError(
                "Expected macro name (IDENTIFIER) after '%'.", token=percent_token
            )
        macro_name_token = self.current_token
        macro_name = macro_name_token.word
        # Validate macro_name.
        # TODO: More validation. uxnasm.c checks for hex, opcode, rune-start
        # or empty.
        if macro_name in self.macros:
            raise SyntaxError(
                f"Duplicate macro definition for '{macro_name}'.", token=percent_token
            )
        if macro_name in self.symbol_table:
            raise SyntaxError(
                f"Macro name '{macro_name}' (Line {macro_name_token.line}) "
                "collides with existing label.",
                token=percent_token,
                filename=self._cur_ctx_filepath(),
            )
        logger.debug(f"Defining Macro: '{macro_name}'")
        # Consume the macro name IDENTIFIER
        self._advance()

        token = self.current_token
        # Expect and consume opening brace '{'
        if token is None or token.type != TOKENTYPE.RUNE_LBRACE:
            err_token = token if token else macro_name_token
            raise SyntaxError(
                f"Expected '{{' to start macro body for '{macro_name}'.",
                token=err_token,
            )

        lbrace_token = token

        self._advance()
        # Collect Macro Body Tokens
        macro_body_tokens: list[Token] = []
        nesting_depth = 1
        while (tok := self.current_token) is not None and tok.type != TOKENTYPE.EOF:
            # Disallow nested macro definitions
            match tok.type:
                case TOKENTYPE.RUNE_PERCENT:
                    raise SyntaxError(
                        f"Nested macro definitions are not allowed: '{macro_name}'.",
                        token=tok,
                    )
                case TOKENTYPE.RUNE_LBRACE:
                    nesting_depth += 1
                case TOKENTYPE.RUNE_RBRACE:
                    nesting_depth -= 1
                    if nesting_depth == 0:
                        # Matching RBRACE for macro body
                        self._advance()
                        break
                case _:
                    pass
            macro_body_tokens.append(self.current_token)
            self._advance()
        if nesting_depth != 0:
            # We hit EOF or some other issue before closing brace.
            raise SyntaxError(
                f"Unclosed macro body for '{macro_name}'."
                f" Expected '}}' to match '{{' on line"
                f" {lbrace_token.line}",
                token=lbrace_token,
            )
        # Store the macro
        self.macros[macro_name] = macro_body_tokens
        logger.debug(
            f"    Stored macro '{macro_name}' with {len(macro_body_tokens)} "
            "tokens in its body."
        )

        # PC (self.current_address) is NOT advanced for a macro def.

    def _handle_macro_invocation(
        self, macro_name: str, invocation_line: int, invocation_column: int
    ) -> None:
        """Handle a macro invocation.

        Look up the macro, save parser state, process the macro tokens,
        and restore the state.
        """
        logger.debug(
            f"  Expanding macro '{macro_name}'(called on line {invocation_line}, col {invocation_column})"
        )

        # Prevent infinite recursion.
        if macro_name in self.macro_call_stack:
            cs = self.macro_call_stack
            raise ParsingError(
                f"Infinite macro recursion detected for macro '{macro_name}'. "
                f"Call stack: {' -> '.join(cs)} -> {macro_name}",
                line=invocation_line,
                column=invocation_column,
                filename=self._cur_ctx_filepath(),
            )

        # --- Look up and Prepare Macro Tokens ---
        macro_body_tokens = self.macros.get(macro_name)
        if macro_body_tokens is None:
            # This should not be hit if the dispatcher logic is correct (if
            # word in self.macros)
            raise ParsingError(
                f"Internal Error: Attempted to invoke undefined macro '{macro_name}'",
                line=invocation_line,
                filename=self._cur_ctx_filepath(),
            )

        # Handle empty macros.
        if not macro_body_tokens:
            logger.debug(f"    Macro '{macro_name}' is empty.")
            return

        # Save the current parsing state.
        original_tokens = self.tokens
        original_token_idx = self.token_idx
        original_current_token = self.current_token

        self.macro_call_stack.append(macro_name)

        try:
            # Set new state for macro expansion
            logger.debug(
                f"    -> Entering macro '{macro_name}' context. "
                f"PC is 0x{self.current_address:04x}"
            )
            self.tokens = macro_body_tokens
            self.token_idx = 0
            self.current_token = self.tokens[0]

            # Parse macro tokens.
            self._process_token_stream()

        finally:
            # Restore original parser state.
            self.tokens = original_tokens
            self.token_idx = original_token_idx
            self.current_token = original_current_token

            self.macro_call_stack.pop()
            logger.debug(
                f"    <- Exiting macro '{macro_name}' context. "
                f"PC is now 0x{self.current_address:04x}"
            )


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="tal file to assemble")
    parser.add_argument(
        "-o", "--output", help="Output file to write", default="output.rom"
    )
    parser.add_argument("--debug", help="Set loglevel to DEBUG", action="store_true")
    args = parser.parse_args()
    return args


def main() -> int:
    """Handle parsing args and calling the assembler."""
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Python v%s.%s.%s", *sys.version_info[:3])
    if args.file:
        file_path = Path(args.file)
        try:
            with open(file_path) as asmfile:
                source_code = asmfile.read()
                lexer = Lexer(source_code, filename=file_path)
                tokens = lexer.scan_all_tokens()
                logger.debug("Finished tokenizing.")

                if tokens and tokens[-1].type != TOKENTYPE.ILLEGAL:
                    parser = Parser(tokens, cur_filepath=file_path)
                    ir_stream, symbol_table = parser.parse_pass1()
                    try:
                        parser.parse_pass2(ir_stream, symbol_table)
                    except ParsingError:
                        logger.debug("Parsing error in Pass 2")
                        raise
                    parser.write_rom(args.output)
                else:
                    print("Lexer failed. Parsing skipped.")
                    return 1
        except FileNotFoundError:
            print(f"Error: File not found: {file_path}")
            return 1
    return 0


if __name__ == "__main__":
    main()
