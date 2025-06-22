#include "../uxn.h"
#include "controller.h"

/*
Copyright (c) 2021-2023 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

static int controller_vector;

void
controller_down(Uint8 mask)
{
	if(mask) {
		uxn.dev[0x82] |= mask;
		uxn_eval(controller_vector);
	}
}

void
controller_up(Uint8 mask)
{
	if(mask) {
		uxn.dev[0x82] &= (~mask);
		uxn_eval(controller_vector);
	}
}

void
controller_key(Uint8 key)
{
	if(key) {
		uxn.dev[0x83] = key;
		uxn_eval(controller_vector);
		uxn.dev[0x83] = 0;
	}
}

void
controller_deo(Uint8 addr)
{
	switch(addr) {
	case 0x81: controller_vector = PEEK2(&uxn.dev[0x80]); break;
	}
}
