# yooxn
WIP uxntal stuff

## yooxnas.py

I'm currently working on a uxntal assembler in Python. It's a 3 stage compiler with an intermediate representation :). Overkill, I know.

```
usage: yooxnas.py [-h] [-o OUTPUT] [--debug] file

positional arguments:
  file                 tal file to assemble

options:
  -h, --help           show this help message and exit
  -o, --output OUTPUT  Output file to write
  --debug              Set loglevel to DEBUG
```

I've tried it on many examples. It compiles most `tal` files now, even newer ones. Includes are implemented and work, too.
