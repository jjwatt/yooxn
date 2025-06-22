DIR=~/roms
EMU=uxncli
BAL=uxnbal
LIN=${EMU} ${DIR}/uxnlin.rom
ASM=${EMU} bin/drifblim.rom

all: bin/drifblim.rom

run: bin/drifblim.rom bin/drifloon.rom
	@ ${ASM} examples/acid.tal bin/acidblim.rom
	@ ${EMU} bin/acidblim.rom
	@ cat examples/acid.tal | ${EMU} bin/drifloon.rom > bin/acidloon.rom
	@ ${EMU} bin/acidblim.rom

test: bin/drifblim.rom
	@ ./tests.sh

bootstrap: bin/drifblim.rom bin/drifloon.rom bin/eq.rom bin/hx.rom
	@ ${EMU} bin/drifblim.rom src/drifblim.tal bin/drifblim-seed.rom
	@ ${EMU} bin/eq.rom bin/drifblim.rom bin/drifblim-seed.rom
	@ cat bin/drifblim-seed.rom | ${EMU} bin/hx.rom > etc/drifblim.rom.txt
	@ cat src/drifloon.tal src/core.tal | ${EMU} bin/drifloon.rom > bin/drifloon-seed.rom
	@ ${EMU} bin/eq.rom bin/drifloon.rom bin/drifloon-seed.rom
	@ cat bin/drifloon-seed.rom | ${EMU} bin/hx.rom > etc/drifloon.rom.txt

gui: bin/drif.rom
	@ uxn11 bin/drif.rom

clean:
	@ rm -fr bin

bal:
	@ ${BAL} src/drifloon.tal
	@ ${BAL} src/drifblim.tal

lint: all
	@ ${LIN} src/drifloon.tal
	@ ${LIN} src/drifblim.tal
	@ ${LIN} src/drif.tal
	@ ${LIN} etc/hx.tal
	@ ${LIN} etc/xh.tal
	@ ${LIN} etc/eq.tal

archive: all bin/hx.rom
	@ cat src/drifblim.tal src/core.tal | sed 's/~[^[:space:]]\+//' > bin/drifblim.tal
	@ cat src/drifloon.tal src/core.tal | sed 's/~[^[:space:]]\+//' > bin/drifloon.tal
	@ cp bin/drifblim.tal ../oscean/etc/drifblim.tal.txt
	@ cp bin/drifloon.tal ../oscean/etc/drifloon.tal.txt
	@ cat bin/drifblim.rom | ${EMU} bin/hx.rom > ../oscean/etc/drifblim.rom.txt
	@ cat bin/drifloon.rom | ${EMU} bin/hx.rom > ../oscean/etc/drifloon.rom.txt
	@ cp etc/hx.tal ../oscean/etc/hx.tal.txt
	@ cp etc/xh.tal ../oscean/etc/xh.tal.txt
	@ cp etc/eq.tal ../oscean/etc/eq.tal.txt

install: bin/drifloon.rom bin/drifblim.rom bin/drif.rom
	@ cp bin/drifloon.rom ${DIR}
	@ cp bin/drifblim.rom ${DIR}
	@ cp bin/drif.rom ${DIR}

uninstall:
	@ rm -f ${DIR}/drifloon.rom
	@ rm -f ${DIR}/drifblim.rom

.PHONY: all run clean bal lint test bootstrap archive install uninstall

bin/drifblim.rom: src/drifblim.tal src/core.tal
	@ mkdir -p bin
	@ xxd -r -p etc/drifblim.rom.txt bin/drifblim-seed.rom
	@ ${EMU} bin/drifblim-seed.rom src/drifblim.tal bin/drifblim.rom

bin/drifloon.rom: src/drifloon.tal src/core.tal bin/drifblim.rom
	@ mkdir -p bin
	@ cat src/drifloon.tal src/core.tal > bin/drifloon.tal
	@ ${ASM} bin/drifloon.tal bin/drifloon.rom

bin/hx.rom: etc/hx.tal bin/drifblim.rom
	@ mkdir -p bin
	@ ${ASM} etc/hx.tal bin/hx.rom

bin/xh.rom: etc/xh.tal bin/drifblim.rom
	@ mkdir -p bin
	@ ${ASM} etc/xh.tal bin/xh.rom

bin/eq.rom: etc/eq.tal bin/drifblim.rom
	@ mkdir -p bin
	@ ${ASM} etc/eq.tal bin/eq.rom

bin/drif.rom: src/drif.tal src/drif.util.tal src/core.tal
	@ printf "Assemble drif.rom\n"
	@ mkdir -p bin
	@ ${ASM} src/drif.tal bin/drif.rom

