#include <stdlib.h>

#include "../uxn.h"
#include "screen.h"

/*
Copyright (c) 2021-2025 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

UxnScreen uxn_screen;

#define MAR(x) (x + 0x8)
#define MAR2(x) (x + 0x10)

/* c = !ch ? (color % 5 ? color >> 2 : 0) : color % 4 + ch == 1 ? 0 : (ch - 2 + (color & 3)) % 3 + 1; */

static Uint8 blending[4][16] = {
	{0, 0, 0, 0, 1, 0, 1, 1, 2, 2, 0, 2, 3, 3, 3, 0},
	{0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3},
	{1, 2, 3, 1, 1, 2, 3, 1, 1, 2, 3, 1, 1, 2, 3, 1},
	{2, 3, 1, 2, 2, 3, 1, 2, 2, 3, 1, 2, 2, 3, 1, 2}};

int
screen_changed(void)
{
	clamp(uxn_screen.x1, 0, uxn_screen.width);
	clamp(uxn_screen.y1, 0, uxn_screen.height);
	clamp(uxn_screen.x2, 0, uxn_screen.width);
	clamp(uxn_screen.y2, 0, uxn_screen.height);
	return uxn_screen.x2 > uxn_screen.x1 &&
		uxn_screen.y2 > uxn_screen.y1;
}

static void
screen_change(int x1, int y1, int x2, int y2)
{
	if(x1 < uxn_screen.x1) uxn_screen.x1 = x1;
	if(y1 < uxn_screen.y1) uxn_screen.y1 = y1;
	if(x2 > uxn_screen.x2) uxn_screen.x2 = x2;
	if(y2 > uxn_screen.y2) uxn_screen.y2 = y2;
}

void
screen_palette(void)
{
	int i, shift, colors[4];
	for(i = 0, shift = 4; i < 4; ++i, shift ^= 4) {
		Uint8
			r = (uxn.dev[0x8 + i / 2] >> shift) & 0xf,
			g = (uxn.dev[0xa + i / 2] >> shift) & 0xf,
			b = (uxn.dev[0xc + i / 2] >> shift) & 0xf;
		colors[i] = 0x0f000000 | r << 16 | g << 8 | b;
		colors[i] |= colors[i] << 4;
	}
	for(i = 0; i < 16; i++)
		uxn_screen.palette[i] = colors[(i >> 2) ? (i >> 2) : (i & 3)];
	screen_change(0, 0, uxn_screen.width, uxn_screen.height);
}

void
screen_resize(Uint16 width, Uint16 height, int scale)
{
	Uint32 *pixels;
	clamp(width, 8, 0x800);
	clamp(height, 8, 0x800);
	clamp(scale, 1, 3);
	/* on rescale */
	pixels = realloc(uxn_screen.pixels, width * height * sizeof(Uint32) * scale * scale);
	if(!pixels) return;
	uxn_screen.pixels = pixels;
	uxn_screen.scale = scale;
	/* on resize */
	if(uxn_screen.width != width || uxn_screen.height != height) {
		int i, length = MAR2(width) * MAR2(height);
		Uint8 *bg = realloc(uxn_screen.bg, length), *fg = realloc(uxn_screen.fg, length);
		if(!bg || !fg) return;
		uxn_screen.bg = bg, uxn_screen.fg = fg;
		uxn_screen.width = width, uxn_screen.height = height;
		for(i = 0; i < length; i++)
			uxn_screen.bg[i] = uxn_screen.fg[i] = 0;
	}
	screen_change(0, 0, width, height);
	emu_resize(width, height);
}

void
screen_redraw(void)
{
	int i, x, y, k, l;
	for(y = uxn_screen.y1; y < uxn_screen.y2; y++) {
		int ys = y * uxn_screen.scale;
		for(x = uxn_screen.x1, i = MAR(x) + MAR(y) * MAR2(uxn_screen.width); x < uxn_screen.x2; x++, i++) {
			int c = uxn_screen.palette[uxn_screen.fg[i] << 2 | uxn_screen.bg[i]];
			for(k = 0; k < uxn_screen.scale; k++) {
				int oo = ((ys + k) * uxn_screen.width + x) * uxn_screen.scale;
				for(l = 0; l < uxn_screen.scale; l++)
					uxn_screen.pixels[oo + l] = c;
			}
		}
	}
	uxn_screen.x1 = uxn_screen.y1 = 9999;
	uxn_screen.x2 = uxn_screen.y2 = 0;
}

/* screen registers */

static int rX, rY, rA, rMX, rMY, rMA, rML, rDX, rDY;

Uint8
screen_dei(Uint8 addr)
{
	switch(addr) {
	case 0x22: return uxn_screen.width >> 8;
	case 0x23: return uxn_screen.width;
	case 0x24: return uxn_screen.height >> 8;
	case 0x25: return uxn_screen.height;
	case 0x28: return rX >> 8;
	case 0x29: return rX;
	case 0x2a: return rY >> 8;
	case 0x2b: return rY;
	case 0x2c: return rA >> 8;
	case 0x2d: return rA;
	default: return uxn.dev[addr];
	}
}

void
screen_deo(Uint8 addr)
{
	switch(addr) {
	case 0x21: uxn_screen.vector = PEEK2(&uxn.dev[0x20]); return;
	case 0x23: screen_resize(PEEK2(&uxn.dev[0x22]), uxn_screen.height, uxn_screen.scale); return;
	case 0x25: screen_resize(uxn_screen.width, PEEK2(&uxn.dev[0x24]), uxn_screen.scale); return;
	case 0x26: rMX = uxn.dev[0x26] & 0x1, rMY = uxn.dev[0x26] & 0x2, rMA = uxn.dev[0x26] & 0x4, rML = uxn.dev[0x26] >> 4, rDX = rMX << 3, rDY = rMY << 2; return;
	case 0x28:
	case 0x29: rX = (uxn.dev[0x28] << 8) | uxn.dev[0x29], rX = twos(rX); return;
	case 0x2a:
	case 0x2b: rY = (uxn.dev[0x2a] << 8) | uxn.dev[0x2b], rY = twos(rY); return;
	case 0x2c:
	case 0x2d: rA = (uxn.dev[0x2c] << 8) | uxn.dev[0x2d]; return;
	case 0x2e: {
		int ctrl = uxn.dev[0x2e];
		int color = ctrl & 0x3;
		int len = MAR2(uxn_screen.width);
		Uint8 *layer = ctrl & 0x40 ? uxn_screen.fg : uxn_screen.bg;
		/* fill mode */
		if(ctrl & 0x80) {
			int x1, y1, x2, y2, ax, bx, ay, by, hor, ver;
			if(ctrl & 0x10)
				x1 = 0, x2 = rX;
			else
				x1 = rX, x2 = uxn_screen.width;
			if(ctrl & 0x20)
				y1 = 0, y2 = rY;
			else
				y1 = rY, y2 = uxn_screen.height;
			screen_change(x1, y1, x2, y2);
			x1 = MAR(x1), y1 = MAR(y1);
			hor = MAR(x2) - x1, ver = MAR(y2) - y1;
			for(ay = y1 * len, by = ay + ver * len; ay < by; ay += len)
				for(ax = ay + x1, bx = ax + hor; ax < bx; ax++)
					layer[ax] = color;
		}
		/* pixel mode */
		else {
			if(rX >= 0 && rY >= 0 && rX < len && rY < uxn_screen.height)
				layer[MAR(rX) + MAR(rY) * len] = color;
			screen_change(rX, rY, rX + 1, rY + 1);
			if(rMX) rX++;
			if(rMY) rY++;
		}
		return;
	}
	case 0x2f: {
		int ctrl = uxn.dev[0x2f];
		int blend = ctrl & 0xf, opaque = blend % 5;
		int fx = ctrl & 0x10 ? -1 : 1, fy = ctrl & 0x20 ? -1 : 1;
		int qfx = fx > 0 ? 7 : 0, qfy = fy < 0 ? 7 : 0;
		int dxy = fy * rDX, dyx = fx * rDY;
		int wmar = MAR(uxn_screen.width), wmar2 = MAR2(uxn_screen.width);
		int hmar2 = MAR2(uxn_screen.height);
		int i, x1, x2, y1, y2, ax, ay, qx, qy, x = rX, y = rY;
		Uint8 *layer = ctrl & 0x40 ? uxn_screen.fg : uxn_screen.bg;
		if(ctrl & 0x80) {
			int addr_incr = rMA << 2;
			for(i = 0; i <= rML; i++, x += dyx, y += dxy, rA += addr_incr) {
				Uint16 xmar = MAR(x), ymar = MAR(y);
				Uint16 xmar2 = MAR2(x), ymar2 = MAR2(y);
				if(xmar < wmar && ymar2 < hmar2) {
					Uint8 *sprite = &uxn.ram[rA];
					int by = ymar2 * wmar2;
					for(ay = ymar * wmar2, qy = qfy; ay < by; ay += wmar2, qy += fy) {
						int ch1 = sprite[qy], ch2 = sprite[qy + 8] << 1, bx = xmar2 + ay;
						for(ax = xmar + ay, qx = qfx; ax < bx; ax++, qx -= fx) {
							int color = ((ch1 >> qx) & 1) | ((ch2 >> qx) & 2);
							if(opaque || color) layer[ax] = blending[color][blend];
						}
					}
				}
			}
		} else {
			int addr_incr = rMA << 1;
			for(i = 0; i <= rML; i++, x += dyx, y += dxy, rA += addr_incr) {
				Uint16 xmar = MAR(x), ymar = MAR(y);
				Uint16 xmar2 = MAR2(x), ymar2 = MAR2(y);
				if(xmar < wmar && ymar2 < hmar2) {
					Uint8 *sprite = &uxn.ram[rA];
					int by = ymar2 * wmar2;
					for(ay = ymar * wmar2, qy = qfy; ay < by; ay += wmar2, qy += fy) {
						int ch1 = sprite[qy], bx = xmar2 + ay;
						for(ax = xmar + ay, qx = qfx; ax < bx; ax++, qx -= fx) {
							int color = (ch1 >> qx) & 1;
							if(opaque || color) layer[ax] = blending[color][blend];
						}
					}
				}
			}
		}
		if(fx < 0)
			x1 = x, x2 = rX;
		else
			x1 = rX, x2 = x;
		if(fy < 0)
			y1 = y, y2 = rY;
		else
			y1 = rY, y2 = y;
		screen_change(x1 - 8, y1 - 8, x2 + 8, y2 + 8);
		if(rMX) rX += rDX * fx;
		if(rMY) rY += rDY * fy;
		return;
	}
	}
}
