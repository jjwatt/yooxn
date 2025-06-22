#include <stdio.h>
#include <stdlib.h>

#include "uxn.h"
#include "devices/system.h"
#include "devices/console.h"
#include "devices/file.h"
#include "devices/datetime.h"

/*
Copyright (c) 2021-2025 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

Uxn uxn;
int console_vector;

Uint8
emu_dei(Uint8 addr)
{
	switch(addr & 0xf0) {
	case 0x00: return system_dei(addr);
	case 0xc0: return datetime_dei(addr);
	}
	return uxn.dev[addr];
}

void
emu_deo(Uint8 addr, Uint8 value)
{
	uxn.dev[addr] = value;
	switch(addr & 0xf0) {
	case 0x00: system_deo(addr); break;
	case 0x10: console_deo(addr); break;
	case 0xa0: file_deo(addr); break;
	case 0xb0: file_deo(addr); break;
	}
}

int
main(int argc, char **argv)
{
	int i = 1;
	if(argc == 2 && argv[1][0] == '-' && argv[1][1] == 'v')
		return !fprintf(stdout, "Uxn(cli) - Varvara Emulator, 31 Jan 2025.\n");
	else if(argc == 1)
		return !fprintf(stdout, "usage: %s [-v] file.rom [args..]\n", argv[0]);
	else if(!system_boot((Uint8 *)calloc(0x10000 * RAM_PAGES, sizeof(Uint8)), argv[i++], argc > 2))
		return !fprintf(stdout, "Could not load %s.\n", argv[i - 1]);
	if(console_vector) {
		console_arguments(i, argc, argv);
		while(!uxn.dev[0x0f] && console_input(fgetc(stdin), 0x1));
	}
	return uxn.dev[0x0f] & 0x7f;
}
