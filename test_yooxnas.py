import unittest

import yooxnas

def load_and_parse_file(input_filename, output_filename):
    file_path = Path(filename)
    with open(args.file, 'r') as asmfile:
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

class TestSimple(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()
