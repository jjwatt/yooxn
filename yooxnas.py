#!/usr/bin/env python3
import argparse

from enum import Enum, auto

class TOKENTYPE(Enum):
    RUNE_PIPE = auto() # |
    RUNE_DOLLAR = auto()
    RUNE_AT = auto() # @
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
    LPAREN = auto ()
    RPAREN = auto()
    HEX_LITERAL = auto()
    IDENTIFIER = auto()
    WHITESPACE = auto()
    NEWLINE = auto()
    COMMENT = auto()
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
    def __init__(self, source: str):
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

    def _add_token(self, typ: TOKENTYPE, word: str | None = None):
        if word is None:
            word = self.src[self.start:self.cursor]
        return Token(typ, word, self.line)

    def _skip_whitespace_and_comments(self):
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
            case '"': return self._add_token(TOKENTYPE.RUNE_DOUBLE_QUOTE)
            case '%': return self._add_token(TOKENTYPE.RUNE_PERCENT)
            case '~': return self._add_token(TOKENTYPE.RUNE_TILDE)

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
    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.token_idx = 0
        self.current_token: Token | None = None
        if self.tokens:
            self.current_token = self.tokens[0]

        self.symbol_table = {}
        # Start at 0. Uxn ROMs will usually set this to 0x0100
        self.current_address = 0x0000
        self.rom_bytes = bytearray()


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


if __name__ == "__main__":
    main()
