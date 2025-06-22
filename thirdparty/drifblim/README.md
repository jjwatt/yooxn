# Drifblim

[Drifblim](https://wiki.xxiivv.com/drifblim) is a [Uxntal](https://wiki.xxiivv.com/site/uxntal.html) assembler, written in that same language.

This repository also contains various bootstrap utilities for the Uxn ecosystem.

## Build

This assembler is written in the language it is assembling, creating a chicken-and-egg problem. 
You have two choices: 
- Download a pre-assembled [drifblim.rom](https://rabbits.srht.site/drifblim/drifblim.rom)
- [Bootstrap](https://wiki.xxiivv.com/site/drifblim#bootstrap) from a hex dump.

### Bootstrap

Convert the hex text to a rom binary:

```sh
xxd -r -p etc/drifblim.rom.txt bin/drifblim-seed.rom
```

Assemble a new one from source:

```sh
uxncli bin/drifblim-seed.rom src/drifblim.tal bin/drifblim.rom
```

Compare the two with eq.rom:

```sh
uxncli bin/drifblim.rom etc/eq.tal bin/eq.rom
uxncli bin/eq.rom bin/drifblim-seed.rom bin/drifblim.rom
```

- `PASS`, Success.
- `DATA FAIL`, Content differ.
- `SIZE FAIL`, Sizes differ.

[![builds.sr.ht status](https://builds.sr.ht/~rabbits/drifblim.svg)](https://builds.sr.ht/~rabbits/drifblim?)

_Drifblim is strong enough to lift Pokemon or people but has no control over its flight. This causes it to drift with the wind and end up anywhere._

## Support

- Assembled with [itself](https://git.sr.ht/~rabbits/drifblim)
- Linted with [uxnlin.rom](https://git.sr.ht/~rabbits/uxnlin)
- Formatted with [uxnfor](https://git.sr.ht/~rabbits/uxnfor)
