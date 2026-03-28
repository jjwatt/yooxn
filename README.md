# yooxn

Python tools for the **Uxn** ecosystem.

## yooxnas

`yooxnas` is a fast, multi-pass assembler for the `uxntal` language, written in pure Python.

[![CI](https://github.com/jjwatt/yooxn/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/jjwatt/yooxn/actions/workflows/ci-cd.yml)

### Features

- **Multi-pass architecture**: Ensures reliable label resolution and address calculation.
- **Macro support**: Full support for `uxntal` macros, including nested definitions.
- **Sub-label scoping**: Standard `@parent` and `&child` scoping rules.
- **Include system**: Assemble complex projects with multiple source files using `~include`.
- **Pure Python**: No external dependencies for the assembler itself.

### Installation

You can install `yooxn` via pip:

```bash
pip install yooxn
```

Or using [uv](https://github.com/astral-sh/uv):

```bash
uv add yooxn
```

### Usage

After installation, the `yooxnas` command will be available:

```bash
yooxnas file.tal
```

By default, it produces `output.rom`. You can specify the output path with `-o`:

```bash
yooxnas -o project.rom main.tal
```

You can also run it as a Python module:

```bash
python -m yooxn main.tal
```

Or directly with `uv run`:

```bash
uv run yooxnas file.tal
```

### CLI Options

```
usage: yooxnas [-h] [-o OUTPUT] [--debug] file

positional arguments:
  file                 tal file to assemble

options:
  -h, --help           show this help message and exit
  -o, --output OUTPUT  Output file to write
  --debug              Set loglevel to DEBUG
```

## Development

`yooxn` uses `uv` for dependency management and `hatchling` as the build backend.

To install in editable mode:

```bash
pip install -e .
```

To run tests:

```bash
pytest
```

Using `uv`:

```bash
uv run pytest
```
