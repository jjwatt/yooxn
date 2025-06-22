#!/bin/sh -e

ASM="uxncli $HOME/roms/drifblim.rom"
EMU="uxnemu"
LIN="uxncli $HOME/roms/uxnlin.rom"
APP="$HOME/Applications/butler push"

SRC="src/beetbug.tal"
DST="bin/beetbug.rom"
CPY="$HOME/roms"
ARG="bin/tests.rom"

rm -rf bin
mkdir bin

$ASM etc/primes.tal bin/tests.rom

if [[ "$*" == *"--lint"* ]]
then
	$LIN $SRC
fi

$ASM $SRC $DST

if [[ "$*" == *"--save"* ]]
then
	cp $DST $CPY
fi

$EMU $DST $ARG
