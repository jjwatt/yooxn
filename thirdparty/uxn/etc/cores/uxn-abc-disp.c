#include "uxn.h"

/*
Copyright (u) 2022-2023 Devine Lu Linvega, Andrew Alderwick, Andrew Richards

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

#define FLIP     { s = ins & 0x40 ? &u->wst : &u->rst; }
#define JUMP(x)  { if(m2) pc = (x); else pc += (Sint8)(x); }
#define POP1(o)  { o = s->dat[--*sp]; }
#define POP2(o)  { o = s->dat[--*sp] | (s->dat[--*sp] << 0x8); }
#define POPx(o)  { if(m2) { POP2(o) } else POP1(o) }
#define PUSH1(y) { s->dat[s->ptr++] = (y); }
#define PUSH2(y) { tt = (y); s->dat[s->ptr++] = tt >> 0x8; s->dat[s->ptr++] = tt; }
#define PUSHx(y) { if(m2) { PUSH2(y) } else PUSH1(y) }
#define PEEK(o, x, r) { if(m2) { r = (x); o = ram[r++] << 8 | ram[r]; } else o = ram[(x)]; }
#define POKE(x, y, r) { if(m2) { r = (x); ram[r++] = y >> 8; ram[r] = y; } else ram[(x)] = (y); }
#define DEVR(o, p)    { if(m2) { o = (emu_dei(u, p) << 8) | emu_dei(u, p + 1); } else o = emu_dei(u, p); }
#define DEVW(p, y)    { if(m2) { emu_deo(u, p, y >> 8); emu_deo(u, p + 1, y); } else emu_deo(u, p, y); }
#define next { ins = ram[pc++]; \
	m2 = ins & 0x20; \
	s = ins & 0x40 ? &u->rst : &u->wst; \
	if(ins & 0x80) kp = s->ptr, sp = &kp; else sp = &s->ptr; \
	goto *lut[ins & 0x1f]; }

int
uxn_eval(Uxn *u, Uint16 pc)
{
	Uint8 t, kp, *sp, ins, m2, *ram = u->ram;
	Uint16 tt, a, b, c;
	Stack *s;
	static void* lut[] = {
		&&_imm, &&_inc, &&_pop, &&_nip, &&_swp, &&_rot, &&_dup, &&_ovr,
		&&_equ, &&_neq, &&_gth, &&_lth, &&_jmp, &&_jcn, &&_jsr, &&_sth,
		&&_ldz, &&_stz, &&_ldr, &&_str, &&_lda, &&_sta, &&_dei, &&_deo,
		&&_add, &&_sub, &&_mul, &&_div, &&_and, &&_ora, &&_eor, &&_sft };
	if(!pc || u->dev[0x0f]) return 0;
	next
	_imm: 
		switch(ins) {
			case 0x00: /* BRK */ return 1;
			case 0x20: /* JCI */ POP1(b) if(!b) { pc += 2; break; }
			case 0x40: /* JMI */ a = ram[pc++] << 8 | ram[pc++]; pc += a; break;
			case 0x60: /* JSI */ PUSH2(pc + 2) a = ram[pc++] << 8 | ram[pc++]; pc += a; break;
			case 0x80: case 0xc0: /* LIT  */ PUSH1(ram[pc++]) break;
			case 0xa0: case 0xe0: /* LIT2 */ PUSH1(ram[pc++]) PUSH1(ram[pc++]) break;
		} next
	_inc: POPx(a) PUSHx(a + 1) next
	_pop: POPx(a) next
	_nip: POPx(a) POPx(b) PUSHx(a) next
	_swp: POPx(a) POPx(b) PUSHx(a) PUSHx(b) next
	_rot: POPx(a) POPx(b) POPx(c) PUSHx(b) PUSHx(a) PUSHx(c) next
	_dup: POPx(a) PUSHx(a) PUSHx(a) next
	_ovr: POPx(a) POPx(b) PUSHx(b) PUSHx(a) PUSHx(b) next
	_equ: POPx(a) POPx(b) PUSH1(b == a) next
	_neq: POPx(a) POPx(b) PUSH1(b != a) next
	_gth: POPx(a) POPx(b) PUSH1(b > a) next
	_lth: POPx(a) POPx(b) PUSH1(b < a) next
	_jmp: POPx(a) JUMP(a) next
	_jcn: POPx(a) POP1(b) if(b) JUMP(a) next
	_jsr: POPx(a) FLIP PUSH2(pc) JUMP(a) next
	_sth: POPx(a) FLIP PUSHx(a) next
	_ldz: POP1(a) PEEK(b, a, t) PUSHx(b) next
	_stz: POP1(a) POPx(b) POKE(a, b, t) next
	_ldr: POP1(a) PEEK(b, pc + (Sint8)a, tt) PUSHx(b) next
	_str: POP1(a) POPx(b) POKE(pc + (Sint8)a, b, tt) next
	_lda: POP2(a) PEEK(b, a, tt) PUSHx(b) next
	_sta: POP2(a) POPx(b) POKE(a, b, tt) next
	_dei: POP1(a) DEVR(b, a) PUSHx(b) next
	_deo: POP1(a) POPx(b) DEVW(a, b) next
	_add: POPx(a) POPx(b) PUSHx(b + a) next
	_sub: POPx(a) POPx(b) PUSHx(b - a) next
	_mul: POPx(a) POPx(b) PUSHx(b * a) next
	_div: POPx(a) POPx(b) PUSHx(a ? b / a : 0) next
	_and: POPx(a) POPx(b) PUSHx(b & a) next
	_ora: POPx(a) POPx(b) PUSHx(b | a) next
	_eor: POPx(a) POPx(b) PUSHx(b ^ a) next
	_sft: POP1(a) POPx(b) PUSHx(b >> (a & 0xf) << (a >> 4)) next
}