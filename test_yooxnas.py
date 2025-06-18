import logging
import unittest

import yooxnas

from pathlib import Path
from unittest import skip


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def load_and_parse_file(input_filename, output_filename):
    file_path = Path(input_filename)
    out_file_path = Path(output_filename)
    with open(file_path, 'r') as asmfile:
        source_code = asmfile.read()
        lexer = yooxnas.Lexer(source_code, filename=file_path)
        tokens = lexer.scan_all_tokens()
        logger.debug("Finished tokenizing.")

        if tokens and tokens[-1].type != yooxnas.TOKENTYPE.ILLEGAL:
            parser = yooxnas.Parser(tokens, cur_filepath=file_path)
            ir_stream, symbol_table = parser.parse_pass1()
            try:
                parser.parse_pass2(ir_stream, symbol_table)
            except yooxnas.ParsingError:
                logger.debug("Parsing error in Pass 2")
                raise
            parser.write_rom(out_file_path)
        else:
            print("Lexer failed. Parsing skipped.")


def build_out_path(in_path: Path) -> Path:
    pass


class TestSimple(unittest.TestCase):
    def setUp(self):
        self.test_out = Path('test_out')
        self.test_out.mkdir(exist_ok=True)
        self.simple = Path('examples/simple.tal')

    def testSimple(self):
        load_and_parse_file('examples/simple.tal',
                            Path(self.test_out / 'simple.rom'))

    def testHello(self):
        load_and_parse_file('examples/hello.tal',
                            Path(self.test_out / 'hello.rom'))

    def testNewHello(self):
        load_and_parse_file('examples/new_hello.tal',
                            'test_out/new_hello.rom')


class TestFizzBuzz(unittest.TestCase):
    def setUp(self):
        self.test_out = Path('test_out')
        self.test_out.mkdir(exist_ok=True)

    def testFizzBuzz(self):
        load_and_parse_file('examples/fizzbuzz.tal',
                            'test_out/fizzbuzz.rom')

    def testNewFizzBuzz(self):
        load_and_parse_file('examples/new_fizzbuzz.tal',
                            'test_out/new_fizzbuzz.rom')

class TestIncludes(unittest.TestCase):
    def setUp(self):
        self.test_out = Path('test_out')
        self.test_out.mkdir(exist_ok=True)

    def testIncludes(self):
        load_and_parse_file('examples/includes.tal',
                            'test_out/includes.rom')


class TestComments(unittest.TestCase):
    def setUp(self):
        self.test_out = Path('test_out')
        self.test_out.mkdir(exist_ok=True)

    def testMath32(self):
        load_and_parse_file('examples/math32.tal',
                            'test_out/math32.rom')


if __name__ == "__main__":
    unittest.main()
