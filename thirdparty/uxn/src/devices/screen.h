/*
Copyright (c) 2021-2025 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

typedef struct UxnScreen {
	int width, height, vector, x1, y1, x2, y2, scale;
	Uint32 palette[16], *pixels;
	Uint8 *fg, *bg;
} UxnScreen;

extern UxnScreen uxn_screen;
extern int emu_resize(int width, int height);
int screen_changed(void);
void screen_palette(void);
void screen_resize(Uint16 width, Uint16 height, int scale);
void screen_redraw(void);

Uint8 screen_dei(Uint8 addr);
void screen_deo(Uint8 addr);

/* clang-format off */

#define clamp(v,a,b) { if(v < a) v = a; else if(v >= b) v = b; }
#define twos(v) (v & 0x8000 ? (int)v - 0x10000 : (int)v)

/* clang-format on */
