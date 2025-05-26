#!/usr/bin/env python3
"""uxntal assembler."""
import argparse

from enum import Enum, auto


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
        return Token(token_type, word, self.line)

    def _skip_whitespace_and_comments(self):
        """Skip whitespace and comments in the tokenizer."""
        while not self._is_at_end():
            char = self._peek()
            if char in ' \t\r':
                self._advance()
            elif char == '\n':
                self._advance()
                self.line += 1
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
                    print(f"Warning: unclosed comment on line {self.line}")
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
                print(f"Error: Illegal token '{token.word}'"
                      f"on line '{token.line}'")
                # break
        return tokens


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

    def _print_hex_literal_content(self, literal_content_word, op_size):
        """Print out a hex literal token."""
        lit = "LIT"
        if op_size == 3:
            lit = "LIT2"
        print(f"  Literal Number ({lit} + value): #{literal_content_word},"
              f"size: {op_size} bytes (Line {self.current_token.line})")

    def _print_line_err(self, err):
        """Print a line error."""
        line_no = self.current_token.line if self.current_token else '??'
        print(f"Error: Line {line_no}: {err}")

    def parse_pass1(self):
        """Parse tokens Pass #1."""
        print("Starting parser pass 1")
        while (self.current_token is not None
               and self.current_token.type != TOKENTYPE.EOF):
            token_type = self.current_token.type
            if token_type == TOKENTYPE.RUNE_PIPE:
                self._advance()  # Consume |
                if self.current_token and self.current_token.type == TOKENTYPE.HEX_LITERAL:
                    # Convert hex string to integer
                    address = int(self.current_token.word, 16)
                    print(f'    Padding to address 0x{address:04x}')
                    self.current_address = address
                    self._advance()  # Consume hex literal
                else:
                    # Error: expected address after |
                    self._print_line_err("Expected address after '|'")
                    # Potentially skip to next line or stop
                    # For simp;licity, stop on error
                    break
            elif token_type == TOKENTYPE.RUNE_AT:
                # Consume '@'
                self._advance()
                if self.current_token and self.current_token.type == TOKENTYPE.IDENTIFIER:
                    label_name = self.current_token.word
                    if label_name in self.symbol_table:
                        # Error: Duplicate label definition
                        self._print_line_err(f"Duplicate label '{label_name}'")
                    else:
                        self.symbol_table[label_name] = self.current_address
                        print(f"  Defined label '{label_name}' at 0x{self.current_address:04x}")
                    self._advance()
                else:
                    # Error: Expected label name after @
                    self._print_line_err("Expected label name after '@'")
                    break

            elif token_type == TOKENTYPE.RAW_ASCII_CHUNK:
                # Handle ASCII Chunks. e.g., "Hello
                chunk_content = self.current_token.word
                chunk_size = len(chunk_content)
                print(f"  Raw ASCII Chunk: \"{chunk_content}\", "
                      f"size: {chunk_size} bytes"
                      f"  Line: {self.current_token.line}")
                self.current_address += chunk_size
                # Consume RAW_ASCII_CHUNK token
                self._advance()

            # Handle #LITERAL (LIT/LIT2 opcodes + data)
            elif token_type == TOKENTYPE.RUNE_HASH:
                self._advance()
                if self.current_token and self.current_token.type ==TOKENTYPE.HEX_LITERAL:
                    literal_content_word = self.current_token.word
                    literal_len = len(literal_content_word)
                    op_size = 0
                    # Should not happen if lexer is correct
                    if literal_len == 0:
                        self._print_line_err("Empty hex literal after #")
                    # 1-byte value
                    elif literal_len <= 2:
                        # 1 byte for LIT opcode + 1 byte for value (e.g., #1, #0f, #ab)
                        op_size = 2
                        self._print_hex_literal_content(literal_content_word,
                                                        op_size)
                    # 2-byte value
                    elif literal_len <= 4:
                        # 1 byte for LIT2 opcode + 2 bytes for value (e.g., #123, #abcd)
                        op_size = 3
                        self._print_hex_literal_content(literal_content_word,
                                                        op_size)
                    else:
                        print("Error: Line %s: Hex Literal '%s' is too long"
                              % (self.current_token.line,
                                 literal_content_word))
                        break
                    self.current_address += op_size
                    # Consume HEX_LITERAL token
                    self._advance()
            elif token_type == TOKENTYPE.HEX_LITERAL:
                data_content_word = self.current_token.word
                data_len = len(data_content_word)
                data_size = 0
                if data_len == 0:
                    self._print_line_err("Empty raw hex data.")
                    break
                elif data_len <= 2:
                    data_size = 1
                elif data_len <= 4:
                    data_size = 2
                else:
                    self._print_line_err(f"Error raw hex data is too long: {data_len}.")
                    print("Diagnostics: "
                          f"data_content_word: {data_content_word}\n"
                          f"current_address: {self.current_address}\n"
                          f"current_token: {self.current_token.print()}\n")
                    break
                print(f"  Raw Hex Data Byte(s): {data_content_word}, size: {data_size} bytes (Line {self.current_token.line})")
                self.current_address += data_size
                # Consume the HEX_LITERAL
                self._advance()

            # Placeholder for other tokens: For now, just advance past them for Pass 1.
            # In a real Pass 1, you'd calculate their size and increment current_address.
            # For example, an opcode IDENTIFIER might take 1 byte.
            # LIT #12 would take 2 bytes (LIT + #12).
            # LIT #1234 would take 3 bytes (LIT + #1234).
            # Your ";hello-word" would expand to LIT2 #address, taking 3 bytes.
            # The Console definitions like &vector $2 also increment current_address.
            else:
                # For now, let's just assume every other recognized token takes up 1 byte
                # This is a VAST oversimplification but helps test label/padding.
                # You'll refine this later.
                if token_type not in [TOKENTYPE.EOF]: # Add other non-byte tokens if any
                     # print(f"  (Skipping/counting token {self.current_token.word} - type {token_type} - advancing PC by 1 (placeholder))")
                     # self.current_address += 1 # Placeholder increment
                     pass # Let's not increment PC for unknown tokens yet to keep it simple
                self._advance() # Consume the current token

        print("Parser Pass 1 Finished.")
        print("Symbol Table:")
        for label, address in self.symbol_table.items():
            print(f"  {label}: 0x{address:04x}")
        print(f"Final Calculated Address (approx): 0x{self.current_address:04x}")


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
