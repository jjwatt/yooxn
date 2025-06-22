#include "uxn.h"

/*
Copyright (u) 2022-2024 Devine Lu Linvega, Andrew Alderwick, Andrew Richards

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

#define OPC(opc, init, body) {\
	case 0x00|opc: {const int _2=0,_r=0;init body;} break;\
	case 0x20|opc: {const int _2=1,_r=0;init body;} break;\
	case 0x40|opc: {const int _2=0,_r=1;init body;} break;\
	case 0x60|opc: {const int _2=1,_r=1;init body;} break;\
	case 0x80|opc: {const int _2=0,_r=0,k=uxn.wst.ptr;init uxn.wst.ptr=k;body;} break;\
	case 0xa0|opc: {const int _2=1,_r=0,k=uxn.wst.ptr;init uxn.wst.ptr=k;body;} break;\
	case 0xc0|opc: {const int _2=0,_r=1,k=uxn.rst.ptr;init uxn.rst.ptr=k;body;} break;\
	case 0xe0|opc: {const int _2=1,_r=1,k=uxn.rst.ptr;init uxn.rst.ptr=k;body;} break;\
}

/* Microcode */

#define JMI a = uxn.ram[pc] << 8 | uxn.ram[pc + 1], pc += a + 2;
#define REM if(_r) uxn.rst.ptr -= 1 + _2; else uxn.wst.ptr -= 1 + _2;
#define INC(s) uxn.s.dat[uxn.s.ptr++]
#define DEC(s) uxn.s.dat[--uxn.s.ptr]
#define JMP(x) { if(_2) pc = x; else pc += (Sint8)x; }
#define PO1(o) { o = _r ? DEC(rst) : DEC(wst);}
#define PO2(o) { if(_r) o = DEC(rst), o |= DEC(rst) << 8; else o = DEC(wst), o |= DEC(wst) << 8; }
#define POx(o) { if(_2) PO2(o) else PO1(o) }
#define PU1(i) { if(_r) INC(rst) = i; else INC(wst) = i; }
#define RP1(i) { if(_r) INC(wst) = i; else INC(rst) = i; }
#define PUx(i) { if(_2) { c = (i); PU1(c >> 8) PU1(c) } else PU1(i) }
#define GET(o) { if(_2) PO1(o[1]) PO1(o[0]) }
#define PUT(i) { PU1(i[0]) if(_2) PU1(i[1]) }
#define DEI(i,o) o[0] = emu_dei(i); if(_2) o[1] = emu_dei(i + 1); PUT(o)
#define DEO(i,j) emu_deo(i, j[0]); if(_2) emu_deo(i + 1, j[1]);
#define PEK(i,o,m) o[0] = uxn.ram[i]; if(_2) o[1] = uxn.ram[(i + 1) & m]; PUT(o)
#define POK(i,j,m) uxn.ram[i] = j[0]; if(_2) uxn.ram[(i + 1) & m] = j[1];

int
uxn_eval(Uint16 pc)
{
	unsigned int a, b, c, x[2], y[2], z[2], step;
	if(!pc || uxn.dev[0x0f]) return 0;
	for(step = STEP_MAX; step; step--) {
		switch(uxn.ram[pc++]) {
		/* BRK */ case 0x00: return 1;
		/* JCI */ case 0x20: if(DEC(wst)) { JMI break; } pc += 2; break;
		/* JMI */ case 0x40: JMI break;
		/* JSI */ case 0x60: c = pc + 2; INC(rst) = c >> 8; INC(rst) = c; JMI break;
		/* LI2 */ case 0xa0: INC(wst) = uxn.ram[pc++]; /* fall-through */
		/* LIT */ case 0x80: INC(wst) = uxn.ram[pc++]; break;
		/* L2r */ case 0xe0: INC(rst) = uxn.ram[pc++]; /* fall-through */
		/* LIr */ case 0xc0: INC(rst) = uxn.ram[pc++]; break;
		/* INC */ OPC(0x01,POx(a),PUx(a + 1))
		/* POP */ OPC(0x02,REM   ,{})
		/* NIP */ OPC(0x03,GET(x) REM   ,PUT(x))
		/* SWP */ OPC(0x04,GET(x) GET(y),PUT(x) PUT(y))
		/* ROT */ OPC(0x05,GET(x) GET(y) GET(z),PUT(y) PUT(x) PUT(z))
		/* DUP */ OPC(0x06,GET(x),PUT(x) PUT(x))
		/* OVR */ OPC(0x07,GET(x) GET(y),PUT(y) PUT(x) PUT(y))
		/* EQU */ OPC(0x08,POx(a) POx(b),PU1(b == a))
		/* NEQ */ OPC(0x09,POx(a) POx(b),PU1(b != a))
		/* GTH */ OPC(0x0a,POx(a) POx(b),PU1(b > a))
		/* LTH */ OPC(0x0b,POx(a) POx(b),PU1(b < a))
		/* JMP */ OPC(0x0c,POx(a),JMP(a))
		/* JCN */ OPC(0x0d,POx(a) PO1(b),if(b) JMP(a))
		/* JSR */ OPC(0x0e,POx(a),RP1(pc >> 8) RP1(pc) JMP(a))
		/* STH */ OPC(0x0f,GET(x),RP1(x[0]) if(_2) RP1(x[1]))
		/* LDZ */ OPC(0x10,PO1(a),PEK(a, x, 0xff))
		/* STZ */ OPC(0x11,PO1(a) GET(y),POK(a, y, 0xff))
		/* LDR */ OPC(0x12,PO1(a),PEK(pc + (Sint8)a, x, 0xffff))
		/* STR */ OPC(0x13,PO1(a) GET(y),POK(pc + (Sint8)a, y, 0xffff))
		/* LDA */ OPC(0x14,PO2(a),PEK(a, x, 0xffff))
		/* STA */ OPC(0x15,PO2(a) GET(y),POK(a, y, 0xffff))
		/* DEI */ OPC(0x16,PO1(a),DEI(a, x))
		/* DEO */ OPC(0x17,PO1(a) GET(y),DEO(a, y))
		/* ADD */ OPC(0x18,POx(a) POx(b),PUx(b + a))
		/* SUB */ OPC(0x19,POx(a) POx(b),PUx(b - a))
		/* MUL */ OPC(0x1a,POx(a) POx(b),PUx(b * a))
		/* DIV */ OPC(0x1b,POx(a) POx(b),PUx(a ? b / a : 0))
		/* AND */ OPC(0x1c,POx(a) POx(b),PUx(b & a))
		/* ORA */ OPC(0x1d,POx(a) POx(b),PUx(b | a))
		/* EOR */ OPC(0x1e,POx(a) POx(b),PUx(b ^ a))
		/* SFT */ OPC(0x1f,PO1(a) POx(b),PUx(b >> (a & 0xf) << (a >> 4)))
		}
	}
	return 0;
}
