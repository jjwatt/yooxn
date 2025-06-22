#include <stdio.h>
#include <stdlib.h>

#include "../uxn.h"
#include "console.h"

/*
Copyright (c) 2022-2025 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

/* console registers */

int
console_input(int c, int type)
{
	if(c == EOF) c = 0, type = 4;
	uxn.dev[0x12] = c, uxn.dev[0x17] = type;
	uxn_eval(console_vector);
	return type != 4;
}

void
console_arguments(int i, int argc, char **argv)
{
	for(; i < argc; i++) {
		char *p = argv[i];
		while(*p)
			console_input(*p++, CONSOLE_ARG);
		console_input('\n', i == argc - 1 ? CONSOLE_END : CONSOLE_EOA);
	}
}

void
console_deo(Uint8 addr)
{
	FILE *fd;
	switch(addr) {
	case 0x11: console_vector = PEEK2(&uxn.dev[0x10]); return;
	case 0x18: fd = stdout, fputc(uxn.dev[0x18], fd), fflush(fd); break;
	case 0x19: fd = stderr, fputc(uxn.dev[0x19], fd), fflush(fd); break;
	}
}
