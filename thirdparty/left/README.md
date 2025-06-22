# Left

[Left](https://100r.co/site/left.html) is a text editor, written in [Uxntal](https://wiki.xxiivv.com/site/uxntal.html).

## Build

You must have an [Uxn](https://git.sr.ht/~rabbits/uxn/) assembler and emulator.

```sh
uxnasm src/left.tal bin/left.rom
uxnemu bin/left.rom
```

If do not wish to assemble it yourself, you can download [left.rom](https://rabbits.srht.site/left/left.rom).

[![builds.sr.ht status](https://builds.sr.ht/~rabbits/left.svg)](https://builds.sr.ht/~rabbits/left?)

## Snarf?

Left uses a [.snarf file](https://wiki.xxiivv.com/snarf) to handle copy/paste. You can write to this snarf file from the host computer like:

```
cat > .snarf
```

Paste your text, press `enter` and exit with `ctrl+c`. 

## Support

- [theme](https://wiki.xxiivv.com/site/theme.html)
- [snarf](https://wiki.xxiivv.com/site/snarf.html)
- [manifest](https://wiki.xxiivv.com/site/manifest.html)
- Linted with [uxnlin](https://git.sr.ht/~rabbits/uxnlin)
- Assembled with [drifblim](https://git.sr.ht/~rabbits/drifblim)
