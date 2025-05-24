#!/usr/bin/env python3
import argparse


class TOKENTYPE(Enum):
    PIPE = auto() # |
    INT = auto()
    AT = auto() # @
    CHAR = auto()
    AMP = auto()
    DOLLAR = auto()
    LPAREN = auto ()
    RPAREN = auto()
    SEMICOLON = auto()
    MINUS = auto()
    HASH = auto()
    QUESTION = auto()
    EXCLAIM = auto()
    SLASH = auto()


class Token:
    def __init__(self, type: TOKENTYPE, word: str, line: int):
        self.type = type
        self.word = word
        self.line = line

    def print(self):
        print(f"'{self.word}': [TOKEN_{self.type.name}]")


class Lexer:
    def __init__(self, source: str):
        self.src = source
        self.size = len(source)
        self.cursor = 0
        self.start = 0
        self.line = 1


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
