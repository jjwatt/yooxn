ID=bicycle
DIR=~/roms
ASM=uxncli ${DIR}/drifblim.rom
LIN=uxncli ${DIR}/uxnlin.rom
EMU=uxn11
ROM=bin/${ID}.rom

all: ${ROM}

clean:
	@ rm -f ${ROM} ${ROM}.sym
lint:
	@ ${LIN} src/${ID}.tal
test:
	@ ${EMU} ${ROM} "#12 #34 ADD"
run: ${ROM}
	@ ${EMU} ${ROM}
install: ${ROM}
	@ cp ${ROM} ${DIR}
uninstall:
	@ rm -f ${DIR}/${ID}.rom
push: ${ROM}
	@ ~/bin/butler push ${ROM} hundredrabbits/${ID}:uxn

.PHONY: all clean lint run install uninstall push

${ROM}: src/*
	@ mkdir -p bin && ${ASM} src/${ID}.tal ${ROM}
