ID=left
DIR=~/roms
ASM=uxncli ${DIR}/drifblim.rom
LIN=uxncli ${DIR}/uxnlin.rom
EMU=uxn11
ROM=bin/${ID}.rom

all: ${ROM}

run: all
	@ ${EMU} ${ROM}
test: all
	@ ${EMU} ${ROM} src/left.tal
lint:
	@ ${LIN} src/${ID}.tal
clean:
	@ rm -f ${ROM} ${ROM}.sym
install: all
	@ cp ${ROM} ${DIR}
uninstall:
	@ rm -f ${DIR}/${ID}.rom
push: ${ROM}
	@ ~/bin/butler push ${ROM} hundredrabbits/${ID}:uxn
archive: all
	@ cat src/${ID}.tal src/menu.tal src/utils.tal src/assets.tal | sed 's/~[^[:space:]]\+//' > bin/res.tal
	@ ${ASM} bin/res.tal bin/res.rom && ${EMU} bin/res.rom
	@ cp bin/res.tal ../oscean/etc/${ID}.tal.txt

.PHONY: all clean lint run test install uninstall push all

${ROM}: src/*
	@ mkdir -p bin
	@ ${ASM} src/${ID}.tal ${ROM}
