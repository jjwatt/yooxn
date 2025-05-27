import yooxnas

source = "|10 @Console &vector $2 &read $1 &pad $5 &write $1 &error $1\n|0100 ( -> )"

l = yooxnas.Lexer(source)
tokens = l.scan_all_tokens()

for t in tokens:
    t.print()

parser = yooxnas.Parser(tokens)
parser.parse_pass1()
