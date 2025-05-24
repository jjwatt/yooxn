#!/usr/bin/env python3
import argparse

from enum import Enum, auto

class TOKENTYPE(Enum):
    RUNE_PIPE = auto() # |
    RUNE_AT = auto() # @
    RUNE_PERIOD = auto()
    RUNE_AMPERSAND = auto()
    RUNE_DOLLAR = auto()
    RUNE_SEMICOLON = auto()
    RUNE_MINUS = auto()
    RUNE_HASH = auto()
    RUNE_QUESTION = auto()
    RUNE_EXCLAIM = auto()
    RUNE_BACKSLASH = auto()
    RUNE_FORWARDSLASH = auto()
    RUNE_UNDERSCORE = auto()
    RUNE_COMMA = auto()
    RUNE_EQUAL = auto()
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
    def __init__(self, typ: TOKENTYPE, word: str, line: int):
        self.type = typ
        self.word = word
        self.line = line

    def print(self):
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
        self._skip_whitespace_and_comments()
        self.start = self.cursor
        if self._is_at_end():
            return self._add_token(TOKENTYPE.EOF, "")

        char = self._advance()

        # Single-character tokens (Runes)
        if char == '|': return self._add_token(TOKENTYPE.RUNE_PIPE)
        if char == '@': return self._add_token(TOKENTYPE.RUNE_AT)
        if char == '&': return self._add_token(TOKENTYPE.RUNE_AMPERSAND)
        if char == '$': return self._add_token(TOKENTYPE.RUNE_DOLLAR)
        if char == '#': return self._add_token(TOKENTYPE.RUNE_HASH)
        # TODO: add more runes

        # Hex Literals (e.g., 10, cafe, 01)
        # char already holds the first character of the potential literal
        if '0' <= char.lower() <= '9' or 'a' <= char.lower() <= 'f':
            # Keep peeking and advancing as long as characters are hex digits
            while not self._is_at_end() and \
                  ('0' <= self._peek().lower() <= '9' or
                   'a' <= self._peek().lower() <= 'f'):
                self._advance()
            return self._add_token(TOKENTYPE.HEX_LITERAL)

        # Identifiers and Opcodes
        if char.isalpha() or char == '_':
            while (self._peek().isalnum() or
                   self._peek() in ['_', '/', '-']):
                self._advance()
            return self._add_token(TOKENTYPE.IDENTIFIER)
        # If none of the above, it's ILLEGAL (for now)
        return self._add_token(TOKENTYPE.ILLEGAL)


    def scan_all_tokens(self) -> list[Token]:
        tokens = []
        while True:
            token = self.scan_token()
            tokens.append(token)
            if token.type == TOKENTYPE.EOF:
                break
            if token.type == TOKENTYPE.ILLEGAL:
                print(f"Error: Illegal token '{token.word}' on line '{token.line}'")
                # break
        return tokens


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("file",
                        help="tal file to assemble")
    # TODO: Take more than one file
    args = parser.parse_args()
    return args

def main():
    args = parse_args()
    if args.file:
        with open(args.file, 'r') as asmfile:
            lines = asmfile.readlines()
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
