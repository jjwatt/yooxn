#!/usr/bin/env python3
"""uxntal assembler."""
import argparse
import logging

from enum import Enum, auto

logging.basicConfig(level=logging.DEBUG,
                    format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class TOKENTYPE(Enum):
    """Token Type."""

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
    RUNE_DOUBLE_QUOTE = auto()
    RUNE_PERCENT = auto()
    RUNE_TILDE = auto()
    RUNE_LBRACE = auto()
    RUNE_RBRACE = auto()
    RUNE_LBRACKET = auto()
    RUNE_RBRACKET = auto()
    LPAREN = auto()
    RPAREN = auto()
    HEX_LITERAL = auto()
    IDENTIFIER = auto()
    WHITESPACE = auto()
    NEWLINE = auto()
    COMMENT = auto()
    RAW_ASCII_CHUNK = auto()
    EOF = auto()
    ILLEGAL = auto()


class Token:
    """Tokens emitted by the Lexer."""

    def __init__(self, token_type: TOKENTYPE, word: str, line: int):
        """Initialize a token of token_type."""
        self.type = token_type
        self.word = word
        self.line = line

    def print(self):
        """Print the token."""
        print(f"'{self.word}': [TOKEN_{self.type.name}]")


class Lexer:
    """Lexer for uxntal."""

    def __init__(self, source: str):
        """Initialize a lexer.

        Args:
            src - str - The source code.

        Return:
            A new lexer object.
        """
        self.src = source
        self.size = len(source)
        # Current position in the input
        self.cursor = 0
        # Start position of the current token being scanned
        self.start = 0
        self.line = 1

    def _is_at_end(self):
        return self.cursor >= self.size

    def _advance(self):
        char = self.src[self.cursor]
        self.cursor += 1
        return char

    def _peek(self):
        if self._is_at_end():
            return '\0'
        return self.src[self.cursor]

    def _peek_next(self):
        if self.cursor + 1 >= self.size:
            return '\0'
        return self.src[self.cursor + 1]

    def _add_token(self, token_type: TOKENTYPE, word: str | None = None):
        if word is None:
            word = self.src[self.start:self.cursor]
        # logger.debug(f"LEXER: Creating Token: Type={token_type.name},"
        #              f"Word='{word}', Line={self.line}, Cursor={self.cursor}")
        return Token(token_type, word, self.line)

    def _skip_whitespace_and_comments(self):
        """Skip whitespace and comments in the tokenizer."""
        while not self._is_at_end():
            char = self._peek()
            if char in ' \t\r':
                self._advance()
            elif char == '\n':
                # logger.debug(f"LEXER: Newline char encountered. "
                #              f"Advancing line from {self.line} to {self.line + 1}. "
                #              f"Cursor: {self.cursor}")
                self.line += 1
                self._advance()
            # Start block comment
            elif char == '(':
                self._advance()
                # Consume until ')' or EOF
                while self._peek() != ')' and not self._is_at_end():
                    if self._peek() == '\n':
                        self.line += 1
                    self._advance()
                # Consume the closeing ')'
                if not self._is_at_end() and self._peek() == ')':
                    self._advance()
                else:
                    # TODO: Handle unclosed comment
                    logger.warning(f"Warning: unclosed comment on line {self.line}")
            else:
                # Found a non-whitespace/non-comment char
                break

    def _is_identifier_char(self, char: str) -> bool:
        return char.isalnum() or char in ['_', '/', '-']

    def _is_hex_digit(self, char: str) -> bool:
        return ('0' <= char.lower() <= '9' or 'a' <= char.lower() <= 'f')

    def scan_token(self) -> Token:
        """Scan a single token."""
        self._skip_whitespace_and_comments()
        self.start = self.cursor
        if self._is_at_end():
            return self._add_token(TOKENTYPE.EOF, "")

        char = self._advance()

        match char:
            # 1. Single-character tokens (Runes)
            case '|': return self._add_token(TOKENTYPE.RUNE_PIPE)
            case '$': return self._add_token(TOKENTYPE.RUNE_DOLLAR)
            case '@': return self._add_token(TOKENTYPE.RUNE_AT)
            case '&': return self._add_token(TOKENTYPE.RUNE_AMPERSAND)
            case ',': return self._add_token(TOKENTYPE.RUNE_COMMA)
            case '_': return self._add_token(TOKENTYPE.RUNE_UNDERSCORE)
            case '.': return self._add_token(TOKENTYPE.RUNE_PERIOD)
            case '-': return self._add_token(TOKENTYPE.RUNE_MINUS)
            case ';': return self._add_token(TOKENTYPE.RUNE_SEMICOLON)
            case '=': return self._add_token(TOKENTYPE.RUNE_EQUAL)
            case '!': return self._add_token(TOKENTYPE.RUNE_EXCLAIM)
            case '?': return self._add_token(TOKENTYPE.RUNE_QUESTION)
            case '#': return self._add_token(TOKENTYPE.RUNE_HASH)
            case '\\': return self._add_token(TOKENTYPE.RUNE_BACKSLASH)
            case '/': return self._add_token(TOKENTYPE.RUNE_FORWARDSLASH)
            case '%': return self._add_token(TOKENTYPE.RUNE_PERCENT)
            case '~': return self._add_token(TOKENTYPE.RUNE_TILDE)
            case '{': return self._add_token(TOKENTYPE.RUNE_LBRACE)
            case '}': return self._add_token(TOKENTYPE.RUNE_RBRACE)
            case '[': return self._add_token(TOKENTYPE.RUNE_LBRACKET)
            case ']': return self._add_token(TOKENTYPE.RUNE_RBRACKET)

            case '"':
                self.start = self.cursor
                while not self._is_at_end():
                    if self._peek().isspace():
                        break
                    self._advance()
                return self._add_token(TOKENTYPE.RAW_ASCII_CHUNK)

            case c if c.isalpha():
                # Greedily consume all characters that can be part of an
                # identifier (alphanumeric, plus '_', '/', '-')
                # TODO: I already consume some of these as runes first.
                # Figure out what exactly I should do with them later.
                while (not self._is_at_end() and
                       (self._peek().isalnum()
                        or self._peek() in ['_', '/', '-'])):
                    self._advance()
                return self._add_token(TOKENTYPE.IDENTIFIER)

            # 3. Hex Literals
            case c if c.isdigit():
                # Consume all subsequent characters that are valid hex digits
                # (0-9, a-f, A-F)
                while (not self._is_at_end() and
                       ('0' <= self._peek().lower() <= '9' or
                        'a' <= self._peek().lower() <= 'f')):
                    self._advance()
                return self._add_token(TOKENTYPE.HEX_LITERAL)

            # If none of the above matched the first character:
            case _:
                return self._add_token(TOKENTYPE.ILLEGAL, char)

    def scan_all_tokens(self) -> list[Token]:
        """Scan all tokens in the lexer."""
        tokens = []
        while True:
            token = self.scan_token()
            tokens.append(token)
            if token.type == TOKENTYPE.EOF:
                break
            if token.type == TOKENTYPE.ILLEGAL:
                logger.error(f"Error: Illegal token '{token.word}'"
                             f"on line '{token.line}'")
                # break
        return tokens


class ParsingError(Exception):
    """Base class for errors during parsing."""

    def __init__(self, message, line=None, word=None, token=None):
        """Initialize a ParsingError."""
        super().__init__(message)
        self.line = line
        self.word = word
        self.token = token
        if token and line is None:
            self.line = token.line
        if token and word is None:
            self.word = token.word

    def __str__(self):
        """Get string version of a ParsingError."""
        line_info = f' (Line {self.line})' if self.line is not None else ''
        word_info = f', Token "{self.word}"' if self.word is not None else ''
        return f'Parse Error{line_info}{word_info}: {super().__str__()}'


class SyntaxError(ParsingError):
    """A syntax error found in the parser."""


class FatalParsingError(ParsingError):
    """An error that halts the current parsing pass."""


class InternalParsingError(ParsingError):
    """An internal parsing error."""


class Parser:
    """A parser for uxntal.

    Uses Tokens from the Lexer.
    """

    OPS = set([name.upper() for name in [
        "LIT", "INC", "POP", "NIP", "SWP", "ROT", "DUP", "OVR",
        "EQU", "NEQ", "GTH", "LTH", "JMP", "JCN", "JSR", "STH",
        "LDZ", "STZ", "LDR", "STR", "LDA", "STA", "DEI", "DEO",
        "ADD", "SUB", "MUL", "DIV", "AND", "ORA", "EOR", "SFT",
        "BRK", "JCI", "JMI"
    ]])

    def __init__(self, tokens: list[Token]):
        """Initialize a new parser object.

        Args:
            tokens: A list of Tokens.
        """
        self.tokens = tokens
        self.token_idx = 0
        self.current_token: Token | None = None
        if self.tokens:
            self.current_token = self.tokens[0]

        self.symbol_table = {}
        # Start at 0. Uxn ROMs will usually set this to 0x0100
        self.current_address = 0x0000
        self.rom_bytes = bytearray()

    def _advance(self):
        """Advance the token.

        Consume the token.
        """
        self.token_idx += 1
        if self.token_idx < len(self.tokens):
            self.current_token = self.tokens[self.token_idx]
        else:
            self.current_token = None

    def _peek_token(self, offset: int = 1):
        peek_idx = self.token_idx + offset
        if 0 <= peek_idx < len(self.tokens):
            return self.tokens[peek_idx]
        return None

    def get_opcode_byte(self, op_word: str) -> int | None:
        """
        Simplified version of uxnasm.c's findopcode.

        Returns the opcode byte or None if not a valid opcode.
        This should handle base opcodes and modes like 'k', '2', 'r'.
        For Pass 1 size calculation, we only care IF it's an opcode (size 1).
        Actual byte value is for Pass 2.
        """
        base_op = op_word[:3].upper()
        if base_op not in self.OPS:
            return None
        return 0x01

    def _handle_padding_rune(self):
        """Handle '|' and '$' runes."""
        rune_token = self.current_token
        rune_char = rune_token.word[0]
        # Consume '|' token
        self._advance()

        if not (self.current_token and
                self.current_token.type == TOKENTYPE.HEX_LITERAL):
            # TODO: looking up label in symbol_table
            raise SyntaxError(f"Expected hex literal after"
                              f"padding rune '{rune_char}'",
                              token=rune_token)

        value_str = self.current_token.word
        try:
            val = int(value_str, 16)
        except ValueError:
            raise SyntaxError(f"Invalid hex value '{value_str}'"
                              f" for padding rune '{rune_char}'",
                              token=self.current_token)

        # Absolute padding
        if rune_char == '|':
            logging.debug(f"Padding to absolute address"
                          f" 0x{val:04x} (Line {rune_token.line})")
            self.current_address = val
        # Relative padding
        elif rune_char == '$':
            logging.debug(f"Padding by relative offset 0x{val:02x} "
                          f"(Line {rune_token.line})."
                          f" PC from 0x{self.current_address:04x}"
                          f" to 0x{self.current_address + val:04x}")
            self.current_address += val
        self._advance()

    def _handle_addressing_rune_op(self, rune_char: str,
                                   implied_opcode_byte: int,
                                   placeholder_size: int):
        """
        Handle runes like ';', '!', '?', ',' and '.'.

        Handles runes like ;, !, ?, ,, . that imply an opcode and a placeholder
        for an address/offset.
        rune_char: The character itself (e.g., ';', '!')
        implied_opcode_byte: The byte value of the opcode uxnasm.c writes
                             (e.g., LIT2's opcode, JMI's 0x40)
        placeholder_size: 1 for byte, 2 for short (0xff or 0xffff)
        """
        rune_token = self.current_token
        if rune_token is None:
            raise ParsingError("Internal Error: _handle_addressing_rune_op"
                               " called with no current token")
        # Consume rune
        self._advance()

        is_sublabel_syntax = False
        label_prefix = ""

        # Check for '&' indicating a sublabel
        if (self.current_token and
                self.current_token.type == TOKENTYPE.RUNE_AMPERSAND):
            is_sublabel_syntax = True
            label_prefix = '&'
            # Consume '&'
            self._advance()

        # Expect the main identifier part of the label
        if not (self.current_token and
                self.current_token.type == TOKENTYPE.IDENTIFIER):
            if is_sublabel_syntax:
                raise SyntaxError(f'Expected label identifier after'
                                  f' {rune_token.word}&.',
                                  token=rune_token)
            else:
                raise SyntaxError(f'Expected label name after'
                                  f' {rune_token.word}.',
                                  token=rune_token)
        label_id_token = self.current_token
        base_label_name = label_id_token.word

        displayed_label = f'{label_prefix}{base_label_name}'
        total_size = 1 + placeholder_size
        logging.debug(f"Addressing Rune Op: {rune_token.word}{displayed_label}"
                      f" -> [Opcode 0x{implied_opcode_byte:02x} +"
                      f" {placeholder_size}-byte placeholder],"
                      f" total size {total_size} (Line {rune_token.line})")
        self.current_address += total_size
        # Consume label identifier token
        self._advance()

    def _handle_conditional_q_lbrace_block(self):
        """
        Handle the ?{ ... } conditional block.

        Assumes current_token is '?' and the next token has already been verified to be '{'.
        """
        # The '?' token
        q_rune_token = self.current_token

        # Size of the conditional jump mechanism based on uxnasm.c
        # (LIT2 offset JCI)
        jump_mechanism_size = 4
        logger.debug(f"  Conditional Block Start ?{{ :"
                     f" jump mechanism size {jump_mechanism_size} bytes"
                     f" (Line {q_rune_token.line})")
        self.current_address += jump_mechanism_size

        # Consume '?'
        self._advance()

        # current_token is now '{'
        if not (self.current_token
                and self.current_token.type == TOKENTYPE.RUNE_LBRACE):
            # This should ideally not be hit if the dispatcher logic is correct
            raise ParsingError("Internal Error: Expected '{' after '?'"
                               " for conditional block.", token=q_rune_token)

        lbrace_token = self.current_token
        logger.debug(f"    Consuming '{{' (Line {lbrace_token.line})")
        # Consume '{'
        self._advance()

        # Parse tokens INSIDE the block until '}' This loop now
        # directly uses the main match/case logic by continuing the
        # outer loop's job The outer loop will break when '}' is found
        # or EOF.  We need a way to tell the outer loop or this
        # function when '}' is encountered.  This requires a bit more
        # thought. A simple way is to let this function loop
        # internally using the dispatcher.

        # Let's use an internal loop that calls a general token dispatcher
        while (self.current_token is not None
               and self.current_token.type != TOKENTYPE.RUNE_RBRACE):
            if self.current_token.type == TOKENTYPE.EOF:
                raise SyntaxError(f"Unclosed conditional block ?{{ "
                                  f" starting on line {q_rune_token.line}."
                                  f" Reached EOF before '}}'.",
                                  token=q_rune_token)
            self._dispatch_current_token_for_pass1()

        if (self.current_token
                and self.current_token.type == TOKENTYPE.RUNE_RBRACE):
            logger.debug(f"  Conditional Block End }}"
                         f" (Line {self.current_token.line})")
            # Consume '}'
            self._advance()
        else:
            raise SyntaxError(f"Unclosed conditional block ?{{"
                              f" starting on line {q_rune_token.line}."
                              f" Missing '}}'.",
                              token=q_rune_token)

    def _dispatch_current_token_for_pass1(self):
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
                self._handle_label_definition()
            case TOKENTYPE.RAW_ASCII_CHUNK:
                self._handle_raw_ascii_chunk()
            case TOKENTYPE.RUNE_HASH:
                self._handle_hash_literal()
            case TOKENTYPE.HEX_LITERAL:
                self._handle_standalone_hex_data()
            case TOKENTYPE.RUNE_SEMICOLON:
                self._handle_addressing_rune_op(
                    ';', self.get_opcode_byte("LIT2"), 2
                )
            case TOKENTYPE.RUNE_QUESTION:
                self._handle_addressing_rune_op(
                    '?', self.get_opcode_byte("JCI"), 2
                )
            case TOKENTYPE.RUNE_EXCLAIM:
                self._handle_addressing_rune_op(
                    '!', self.get_opcode_byte("JMI"), 2
                )
            case TOKENTYPE.RUNE_COMMA:
                self._handle_addressing_rune_op(
                    ',', self.get_opcode_byte("LIT"), 1
                )
            case TOKENTYPE.RUNE_PERIOD:
                self._handle_addressing_rune_op(
                    '.', self.get_opcode_byte("LIT"), 1
                )
            case TOKENTYPE.IDENTIFIER:
                self._handle_identifier_token()

            # Handle delimiters that don't contribute to size but need
            # to be consumed if not part of a larger structure already
            # handled (like RUNE_RBRACE by conditional block)
            case (TOKENTYPE.RUNE_LBRACE | TOKENTYPE.RUNE_RBRACE |
                  TOKENTYPE.RUNE_LBRACKET | TOKENTYPE.RUNE_RBRACKET |
                  TOKENTYPE.LPAREN | TOKENTYPE.RPAREN):
                logger.debug(f"  Skipping Delimiter/Ignored Token: "
                             f"'{self.current_token.word}' type: {token_type}"
                             f" (Line {self.current_token.line})")
                self._advance()
            # Default case for any other unhandled token types
            case _:
                # This should ideally be an error for unexpected tokens.
                raise SyntaxError(f"Unexpected token during dispatch:"
                                  f" '{self.current_token.word}'",
                                  token=self.current_token)
                # logger.debug(...)
                # self._advance()

    def _handle_raw_ascii_chunk(self):
        """Handle RAW_ASCII_CHUNK.

        These are prefixed with '"', e.g. "Hello
        """
        token = self.current_token
        content = token.word
        size = len(content)
        logger.debug(f"Raw ASCII Chunk: \"{content}\", "
                     f"size: {size} bytes"
                     f" Line: {self.current_token.line}")
        self.current_address += size
        self._advance()

    def _handle_hash_literal(self):
        """Handle hash literals.

        These become LIT/LIT2 + value.
        """
        token = self.current_token
        if not (self.current_token and
                self.current_token.type == TOKENTYPE.HEX_LITERAL):
            SyntaxError("Expected hex literal after #", token=token)
        # Consume '#'
        self._advance()

        hex_literal = self.current_token
        val = hex_literal.word
        val_len = len(val)
        size = 0

        if val_len == 0:
            raise SyntaxError("Empty hex literal after #", token=hex_literal)
        elif val_len <= 2:
            size = 2
            logger.debug(f"LIT #{val}, size {size} (Line {token.line})")
        elif val_len <= 4:
            size = 4
            logger.debug(f"LIT2 #{val}, size {size} (Line {token.line})")
        else:
            raise SyntaxError(f"Hex literal too long after #: {val}",
                              token=token)
        self.current_address += size
        # Consume hex literal token.
        self._advance()

    def _handle_sub_label_field(self, parent_label_name: str):
        """Handle sub-labels.

        Handle '&' and '&' followed by '$'.
        These are sub-labels. And '$' is used to
        reserve space.
        """
        ampersand_token = self.current_token
        # Consume '&'
        self._advance()
        if not (self.current_token
                and self.current_token.type == TOKENTYPE.IDENTIFIER):
            raise SyntaxError("Expected sub-label name after '&'"
                              " for parent '%s'." % parent_label_name,
                              token=ampersand_token)
        sub_label_token = self.current_token
        sub_label_name = sub_label_token.word
        full_sub_label_name = f'{parent_label_name}/{sub_label_name}'
        if full_sub_label_name in self.symbol_table:
            logger.warn("Duplicate sub-label: %s", full_sub_label_name)
            # raise SyntaxError()
        else:
            self.symbol_table[full_sub_label_name] = self.current_address
            logger.debug(f"  Defined sub-label '{full_sub_label_name}'"
                         f" at 0x{self.current_address}")
        # Consume sub-label identifier
        self._advance()

        # Check for optional $size
        rune_dollar = (self.current_token
                       and self.current_token.type == TOKENTYPE.RUNE_DOLLAR)
        if (rune_dollar):
            dollar_token = self.current_token
            # Consume '$'
            self._advance()
            if not (self.current_token
                    and self.current_token.type == TOKENTYPE.HEX_LITERAL):
                raise SyntaxError("Expected size (HEX_LITERAL) after '$'",
                                  token=dollar_token)
            size_hex_token = self.current_token
            try:
                size = int(size_hex_token.word, 16)
                if size < 0:
                    raise ValueError("Size cannot be negative.")
            except ValueError:
                raise SyntaxError("Invalid size %s for sub-label %s" % (
                    size_hex_token.word, sub_label_token.word),
                                  token=size_hex_token)
            logger.debug("    Sub-label '%s/%s' field occupies %s byte(s).",
                         parent_label_name, sub_label_token.word, size)
            logger.debug("       Advancing PC.")
            self.current_address += size
            self._advance()

    def _handle_label_definition(self):
        """Handle label definitions.

        Handle '@' label definitions.
        """
        # For @
        directive_token = self.current_token
        # Consume '@'
        self._advance()
        if not (self.current_token
                and self.current_token.type == TOKENTYPE.IDENTIFIER):
            raise SyntaxError("Expected parent label name after '@'.",
                              token=directive_token)
        parent_label_token = self.current_token
        parent_label_name = parent_label_token.word
        if parent_label_name in self.symbol_table:
            # TODO: write a custom warning function with line and label
            logger.warning("Duplicate label: %s, Line %s",
                           parent_label_name,
                           parent_label_token.line)
        else:
            self.symbol_table[parent_label_name] = self.current_address
            logger.debug(f'Define label "{parent_label_name}" at '
                         f'0x{self.current_address:04x} '
                         f'(Line {parent_label_token.line})')
        # Consume parent label identifier
        self._advance()
        while (self.current_token
               and self.current_token.type == TOKENTYPE.RUNE_AMPERSAND):
            self._handle_sub_label_field(parent_label_name)

    def _handle_standalone_hex_data(self):
        """Handle raw hex literals.

        These are literals without LIT or # in front of them.
        """
        # For hex literal as raw data
        data_token = self.current_token
        data_word = data_token.word
        data_len = len(data_word)
        data_size = 0
        if data_len == 0:
            raise SyntaxError("Empty raw hex data.",
                              token=data_token)
        elif data_len <= 2:
            data_size = 1
        elif data_len <= 4:
            data_size = 2
        else:
            raise SyntaxError(f"Raw hex data {data_word} is too long",
                              token=data_token)
        logger.debug("  Raw Hex Data Byte(s): %s,"
                     " size: %s"
                     " (Line %s)",
                     data_word,
                     data_size,
                     data_token.line)
        self.current_address += data_size
        self._advance()

    def _handle_identifier_token(self):
        """Handle identifiers or opcodes."""
        # Just get estimated size for now
        op_token = self.current_token
        logger.debug("Opcode/Identifier: '%s', (assuming 1 byte)"
                     " (Line %s)",
                     op_token.word, op_token.line)
        self.current_address += 1
        self._advance()

    def parse_pass1(self):
        """Parse tokens Pass #1."""
        logger.debug("Starting parser pass 1")
        if not self.tokens or self.tokens[0].type == TOKENTYPE.EOF:
            logger.debug('No tokens to parse.')
            return
        if self.current_token is None and self.tokens: # Should be set by __init__
            self.current_token = self.tokens[0]
        try:
            while (self.current_token is not None
                   and self.current_token.type != TOKENTYPE.EOF):
                # Special check for ?{ construct
                if self.current_token.type == TOKENTYPE.RUNE_QUESTION:
                    next_t = self._peek_token(1)
                    if next_t and next_t.type == TOKENTYPE.RUNE_LBRACE:
                        self._handle_conditional_q_lbrace_block()
                        # _handle_conditional_q_lbrace_block consumes tokens including '}',
                        # so we continue to the next iteration of the while loop.
                        continue
                # For all other cases, use the general dispatcher
                self._dispatch_current_token_for_pass1()
        except ParsingError as pe:
            logger.error(str(pe)) # Use the __str__ method of your custom exception
            logger.debug("Parser Pass 1 aborted due to error.") # Add this for clarity
            # Consider re-raising or returning an error status if parse_pass1 is called by other code

        # This part is outside the try...except, will run even if an error occurred mid-way
        # which might be okay for seeing partial results, or you can move it inside the try.
        # Or only print if no error occurred by checking a flag.
        logger.debug("Parser Pass 1 Finished.")
        logger.debug("Symbol Table:")
        for label, address in self.symbol_table.items():
            logger.debug(f"\t {label}: 0x{address:04x}")
        logger.debug(f"Final Calculated Address (after pass 1 processing): 0x{self.current_address:04x}")

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("file",
                        help="tal file to assemble")
    # TODO: Take more than one file
    args = parser.parse_args()
    return args


def main():
    """Handle parsing args and calling assembler."""
    args = parse_args()
    if args.file:
        with open(args.file, 'r') as asmfile:
            source_code = asmfile.read()
            lexer = Lexer(source_code)
            tokens = lexer.scan_all_tokens()
            logger.debug("Finished tokenizing.")
            # for token in tokens:
            #     token.print()

            if tokens and tokens[-1].type != TOKENTYPE.ILLEGAL:
                parser = Parser(tokens)
                parser.parse_pass1()
            else:
                print("Lexer failed. Parsing skipped.")


if __name__ == "__main__":
    main()
