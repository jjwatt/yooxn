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
        logger.debug(f"LEXER: Creating Token: Type={token_type.name},"
                     f"Word='{word}', Line={self.line}, Cursor={self.cursor}")
        return Token(token_type, word, self.line)

    def _skip_whitespace_and_comments(self):
        """Skip whitespace and comments in the tokenizer."""
        while not self._is_at_end():
            char = self._peek()
            if char in ' \t\r':
                self._advance()
            elif char == '\n':
                logger.debug(f"LEXER: Newline char encountered. "
                             f"Advancing line from {self.line} to {self.line + 1}. "
                             f"Cursor: {self.cursor}")
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
            case '{': return self._add_token(TOKENTYPE.RUNE_RBRACKET)
            case '}': return self._add_token(TOKENTYPE.RUNE_LBRACKET)
            case '[': return self._add_token(TOKENTYPE.RUNE_LBRACE)
            case ']': return self._add_token(TOKENTYPE.RUNE_RBRACE)

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


class FatalParsingError(ParsingError):
    """An error that halts the current parsing pass."""


class SyntaxError(ParsingError):
    """A syntax error found in the parser."""


class Parser:
    """A parser for uxntal.

    Uses Tokens from the Lexer.
    """

    def __init__(self, tokens: list[Token]):
        """Initialize a new parser object.

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
        self.token_idx += 1
        if self.token_idx < len(self.tokens):
            self.current_token = self.tokens[self.token_idx]
        else:
            self.current_token = None

    def _log_hex_literal_content(self, content, op_size):
        """Print out a hex literal token."""
        lit = "LIT"
        if op_size == 3:
            lit = "LIT2"
        logger.debug(f"Literal Number ({lit} + value): #{content},"
                     f"size: {op_size} bytes (Line {self.current_token.line})")

    def _log_err(self, err):
        """Print a line error."""
        line_no = self.current_token.line if self.current_token else '??'
        logger.error(f"Error: Line {line_no}: {err}")

    def _handle_absolute_padding(self):
        # The '|' token
        directive_token = self.current_token
        # Consume '|'
        self._advance()
        current_token = self.current_token
        token_type = self.current_token.type
        if current_token and token_type == TOKENTYPE.HEX_LITERAL:
            try:
                address = int(self.current_token.word, 16)
                self.current_address = address
                logger.debug(f'Padding to address 0x{address:04x} '
                             f'(Line {self.current_token.line})')
                self.current_address = address
                # Consume hex literal
                self._advance()
            except ValueError:
                current_word = self.current_token.word
                msg = f"Invalid hex address '{current_word}' for '|'"
                raise SyntaxError(msg, token=directive_token)
        else:
            msg = "Expected address (HEX_LITERAL) after '|'"
            raise SyntaxError(msg, token=directive_token)

    def _handle_raw_ascii_chunk(self):
        """Handle RAW_ASCII_CHUNK."""
        token = self.current_token
        content = token.word
        size = len(content)
        logger.debug(f"Raw ASCII Chunk: \"{content}\", "
                     f"size: {size} bytes"
                     f" Line: {self.current_token.line}")
        self.current_address += size
        self._advance()

    def _handle_sub_label_field(self, parent_label_name: str):
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
        if not (self.current_token
                and self.current_token.type == TOKENTYPE.RUNE_DOLLAR):
            raise SyntaxError("Expected '$' after sub-label",
                              token=sub_label_token)
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
                         f'Line {parent_label_token.line}')
        # Consume parent label identifier
        self._advance()
        while (self.current_token
               and self.current_token.type == TOKENTYPE.RUNE_AMPERSAND):
            self._handle_sub_label_field(parent_label_name)

    def _handle_literal_number_directive(self):
        raise NotImplementedError

    def _handle_standalone_hex_data(self):
        raise NotImplementedError

    def _handle_identifier_or_opcode(self):
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
        if self.current_token is None and self.tokens:
            self.current_token = self.tokens[0]
        try:
            while (self.current_token is not None
                   and self.current_token.type != TOKENTYPE.EOF):
                token_type = self.current_token.type
                match token_type:
                    case TOKENTYPE.RUNE_PIPE:
                        self._handle_absolute_padding()
                    case TOKENTYPE.RUNE_AT:
                        self._handle_label_definition()
                    case TOKENTYPE.RAW_ASCII_CHUNK:
                        self._handle_raw_ascii_chunk()
                    case TOKENTYPE.RUNE_HASH:
                        self._handle_literal_number_directive()
                    case TOKENTYPE.HEX_LITERAL:
                        self._handle_standalone_hex_data()
                    case TOKENTYPE.IDENTIFIER:
                        self._handle_identifier_or_opcode()
                    case _:
                        logging.debug(' Skipping unhandled token: "%s"'
                                      ' type: %s (Line %s)',
                                      self.current_token.word,
                                      token_type,
                                      self.current_token.line)
                        self._advance()

        except ParsingError as pe:
            logging.error(pe)
        logger.debug("Parser Pass 1 Finished.")
        logger.debug("Symbol Table:")
        for label, address in self.symbol_table.items():
            logger.debug(f"\t {label}: 0x{address:04x}")
        logger.debug(f"Final Calculated Address (approx)"
                     f": 0x{self.current_address:04x}")


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
            lines = asmfile.readlines()
            lexer = Lexer('\n'.join(lines))
            tokens = lexer.scan_all_tokens()
            for token in tokens:
                token.print()

            if tokens and tokens[-1].type != TOKENTYPE.ILLEGAL:
                parser = Parser(tokens)
                parser.parse_pass1()
            else:
                print("Lexer failed. Parsing skipped.")


if __name__ == "__main__":
    main()
