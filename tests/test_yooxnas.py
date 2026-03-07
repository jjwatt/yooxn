"""Tests for yooxnas that fully compile real roms."""

import logging
from pathlib import Path

import pytest

from yooxn import yooxnas

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


@pytest.fixture
def test_out():
    """Fixture to ensure the test_out directory exists."""
    path = Path("test_out")
    path.mkdir(exist_ok=True)
    return path


def load_and_parse_file(input_filename, output_filename):
    """Load and parse a tal file."""
    file_path = Path(input_filename)
    out_file_path = Path(output_filename)
    with open(file_path) as asmfile:
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
            pytest.fail("Lexer failed. Parsing skipped.")


def test_simple(test_out):
    """Test a simple rom."""
    load_and_parse_file("examples/simple.tal", test_out / "simple.rom")


def test_hello(test_out):
    """Test hello world rom."""
    load_and_parse_file("examples/hello.tal", test_out / "hello.rom")


def test_new_hello(test_out):
    """Test a version of hellow world with newer tal."""
    load_and_parse_file("examples/new_hello.tal", test_out / "new_hello.rom")


def test_fizzbuzz(test_out):
    """Test fizzbuzz rom."""
    load_and_parse_file("examples/fizzbuzz.tal", test_out / "fizzbuzz.rom")


def test_new_fizzbuzz(test_out):
    """Test newer version of fizzbuzz."""
    load_and_parse_file("examples/new_fizzbuzz.tal", test_out / "new_fizzbuzz.rom")


def test_includes(test_out):
    """Test using includes."""
    load_and_parse_file("examples/includes.tal", test_out / "includes.rom")


def test_math32(test_out):
    """Test building math32.tal."""
    load_and_parse_file("examples/math32.tal", test_out / "math32.rom")


def test_mandelbrot(test_out):
    """Test building mandelbrot.tal."""
    load_and_parse_file("examples/mandelbrot.tal", test_out / "mandelbrot.rom")
