#!/bin/sh -e

format=0
console=0
install=0
debug=0
norun=0

while [ $# -gt 0 ]; do
	case $1 in
		--format)
			format=1
			shift
			;;

		--console)
			console=1
			shift
			;;

		--install)
			install=1
			shift
			;;

		--debug)
			debug=1
			shift
			;;

		--no-run)
			norun=1
			shift
			;;

		*)
			shift
	esac
done

rm -f bin/*

# When clang-format is present

if [ $format = 1 ];
then
	clang-format -i src/uxnasm.c
	clang-format -i src/uxncli.c
	clang-format -i src/uxnemu.c
	clang-format -i src/devices/*
fi

mkdir -p bin
CC="${CC:-cc}"
CFLAGS="${CFLAGS:--std=c89 -Wall -Wno-unknown-pragmas}"
case "$(uname -s 2>/dev/null)" in
MSYS_NT*|MINGW*) # MSYS2 on Windows
	FILE_LDFLAGS="-liberty"
	if [ $console = 1 ];
	then
		UXNEMU_LDFLAGS="-static $(sdl2-config --cflags --static-libs | sed -e 's/ -mwindows//g')"
	else
		UXNEMU_LDFLAGS="-static $(sdl2-config --cflags --static-libs)"
	fi
	;;
Darwin) # macOS
	CFLAGS="${CFLAGS} -Wno-typedef-redefinition -D_C99_SOURCE"
	UXNEMU_LDFLAGS="$(sdl2-config --cflags --static-libs)"
	;;
Linux|*)
	UXNEMU_LDFLAGS="-L/usr/local/lib $(sdl2-config --cflags --libs)"
	;;
esac

if [ $debug = 1 ];
then
	echo "[debug]"
	CFLAGS="${CFLAGS} -DDEBUG -Wpedantic -Wshadow -Wextra -Werror=implicit-int -Werror=incompatible-pointer-types -Werror=int-conversion -Wvla -g -Og -fsanitize=address -fsanitize=undefined"
else
	CFLAGS="${CFLAGS} -DNDEBUG -O2 -g0 -s"
fi

${CC} ${CFLAGS} src/uxnasm.c -o bin/uxnasm
${CC} ${CFLAGS} src/uxn.c src/devices/system.c src/devices/console.c src/devices/file.c src/devices/datetime.c src/devices/mouse.c src/devices/controller.c src/devices/screen.c src/devices/audio.c src/uxnemu.c ${UXNEMU_LDFLAGS} ${FILE_LDFLAGS} -o bin/uxnemu
${CC} ${CFLAGS} src/uxn.c src/devices/system.c src/devices/console.c src/devices/file.c src/devices/datetime.c src/uxncli.c ${FILE_LDFLAGS} -o bin/uxncli

if [ $install = 1 ]
then
	cp bin/uxnemu bin/uxnasm bin/uxncli $HOME/bin/
fi

if [ $norun = 1 ]; then exit; fi

# Test version

bin/uxnasm -v
bin/uxncli -v
bin/uxnemu -v

# Start potato

bin/uxnemu -2x
