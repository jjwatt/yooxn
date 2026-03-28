# yooxn
[![CI](https://github.com/jjwatt/yooxn/actions/workflows/ci.yml/badge.svg)](https://github.com/jjwatt/yooxn/actions/workflows/ci.yml)
WIP uxntal stuff

## Installation

You can install the package in editable mode:

```bash
pip install -e .
```

## Usage

After installation, you can run the assembler directly:

```bash
yooxnas file.tal
```

Or via `python -m yooxn`:

```bash
python -m yooxn file.tal
```

```
usage: yooxnas [-h] [-o OUTPUT] [--debug] file

positional arguments:
  file                 tal file to assemble

options:
  -h, --help           show this help message and exit
  -o, --output OUTPUT  Output file to write
  --debug              Set loglevel to DEBUG
```

I've tried it on many examples. It compiles most `tal` files now, even newer ones. Includes are implemented and work, too.
