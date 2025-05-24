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
        if self._is_at_end:
            return '\0'
        return self.src[self.cursor]

    def _peek_next(self):
        if self.cursor + 1 >= self.size:
            return '\0'
        return self.src[self.cursor + 1]


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
