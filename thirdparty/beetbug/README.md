# Beetbug

Beetbug is a uxn debugger, written in [Uxntal](https://wiki.xxiivv.com/site/uxntal.html).

## Build

You must have an [Uxn](https://git.sr.ht/~rabbits/uxn/) assembler and emulator.

```sh
uxnasm src/beetbug.tal bin/beetbug.rom
uxnemu bin/beetbug.rom etc/some_program.rom
```

If do not wish to assemble it yourself, you can download [beetbug.rom](https://rabbits.srht.site/beetbug/beetbug.rom).

[![builds.sr.ht status](https://builds.sr.ht/~rabbits/beetbug.svg)](https://builds.sr.ht/~rabbits/beetbug?)

## Support

- [theme](https://wiki.xxiivv.com/site/theme.html)
- Linted with [uxnlin](https://git.sr.ht/~rabbits/uxnlin)
- Assembled with [drifblim](https://git.sr.ht/~rabbits/drifblim)
