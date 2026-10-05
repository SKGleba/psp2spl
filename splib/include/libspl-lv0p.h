#ifndef __LIBSPL_LV0P_H__
#define __LIBSPL_LV0P_H__

//#define LV0P_NOCJPM

#define LV0P_MAGIC 'LV0P'
#define LV0P_WORKBUF_SIZE 0x40

enum LV0P_JOB_IDS {
    LV0P_JOB_NOP = 0,
	LV0P_JOB_KSP,
	LV0P_JOB_DAT,
	LV0P_JOB_EXE,
	LV0P_JOB_CUS,
};

struct lv0p_j_s {
	uint32_t magic;
	enum LV0P_JOB_IDS idx;
	int ret;
	union {
		struct lv0p_j_s *next;
		uint32_t next_pa;
	};
	union {
		struct {
			union {
				int (*func)();
				uint32_t addr;
				void *src_va;
			};
			int size;
			int argv[8];
		} x;
		struct {
			int id;
			int off;
			int size;
			uint8_t data[0x20];
		} k;
		struct {
			union {
				uint32_t src;
				void *src_va;
			};
			uint32_t dst;
			uint32_t size;
			int ncopyin;
			uint8_t cbuf[0x20];
		} d;
		uint32_t c[0xC];
		uint8_t jbuf[0x30];
	};
};
_Static_assert(sizeof(struct lv0p_j_s) <= 0x40, "lv0p_j_s is too large");


/* CUSTOM JOB MACHINE (sorry)
op types: (S)ingle, e(X)tended, (D)ouble
op subtypes: (J)ump, u(P)date
NAr:
	C - 12-op-sized context window with ops
	I - next op idx in context
	P - result from last Pop
	A - instr arg (0-11: nC, 12-15: gp)|imm
GPr prefill:
	12,13,14: 0
	15: workbuf from caller
opS:
	@0:4 a0
	@4:8 mods
	@12:4 opcode
	@16:4 a1
	 | @16:e a1_imm16 (mod A1IMM)
	@20:12 a1_imm12 (mod PTRA1)
opX:
	@0:4 a0
	@4:6 mods
	@10:6 opcode
	@16:4 a1
	 | @16:12 a1_imm12 (mod A1IMM)
	@20:8 a1_imm8 (mod PTRA1)
	@28:4 a2
opD: (op1 a1 == op2 a0)
	@0:4 op1 a0
	@4:8 op1 mods
	@12:4 op1 opcode
	@16:4 op1 a1
	@16:4 op2 a0
	@20:4 op2 mods[:4]
	@24:4 op2 opcode
	@28:4 op2 a1
*/
#define LV0P_CJPM_JDCA2RILT (0x00010000 / sizeof(uint32_t)) // host AS start for JDC
enum LV0P_CJP_MODS {
	LV0P_CJP_MOD_PTRA0, // use *c[a0] (c[a0] for Jops)
	LV0P_CJP_MOD_PTRA1, // use *(c[a1]+a1_imm12)
	LV0P_CJP_MOD_TIM16 = LV0P_CJP_MOD_PTRA1, // lsh16 a1_imm16 (for A1IMM)
	LV0P_CJP_MOD_SWAPA, // swap a0 and a1 (for non-Jops)
	LV0P_CJP_MOD_JEQUS = LV0P_CJP_MOD_SWAPA, // add equ to comp - !=:=,<:<=,>:>=
	LV0P_CJP_MOD_NOPCG, // dont update the P reg (for Pops)
	LV0P_CJP_MOD_JSIGC = LV0P_CJP_MOD_NOPCG, // signed compare (for Jops)
	LV0P_CJP_MOD_CTXMV, // move C to I
	LV0P_CJP_MOD_A1IMM, // a1 is imm, disables PTRA1 & Dop
	LV0P_CJP_MOD_EXTND = 6, // is an extewnded op, also xop MSB
	LV0P_CJP_MOD_RESERVED = 7, // (for !Xops)
};

// 0-invalid, 1-15 base ops, 32+ extended ops
enum LV0P_CJP_OPS {
	LV0P_CJP_OP_INVALID = 0,
	// start of J-ops
	LV0P_CJP_OP_JDC, // C=c[a1]|reset+c[a1] & I=a0
	LV0P_CJP_OP_JNE, // I=a0 if c[a1] != P
	LV0P_CJP_OP_JLT, // I=a0 if c[a1] < P
	LV0P_CJP_OP_JGT, // I=a0 if c[a1] > P
	LV0P_CJP_OP__JOPSEND = LV0P_CJP_OP_JGT,
	// start of P-ops
	LV0P_CJP_OP_MOV32, // c[a0] = c[a1] 		| P = c[a0]
	LV0P_CJP_OP_ADD, // c[a0] += c[a1]			| P = c[a0]
	LV0P_CJP_OP_SUB, // c[a0] -= c[a1] 			| P = c[a0]
	LV0P_CJP_OP_MUL, // c[a0] *= c[a1] 			| P = c[a0]
	LV0P_CJP_OP_DIV, // c[a0] /= c[a1] 			| P = c[a0]
	LV0P_CJP_OP_AND, // c[a0] &= c[a1] 			| P = c[a0]
	LV0P_CJP_OP_OR, // c[a0] |= c[a1] 			| P = c[a0]
	LV0P_CJP_OP_XOR, // c[a0] ^= c[a1] 			| P = c[a0]
	LV0P_CJP_OP_LSH, // c[a0] <<= c[a1] 		| P = c[a0]
	LV0P_CJP_OP_RSH, // c[a0] >>= c[a1] 		| P = c[a0]
	// start of extended ops
	LV0P_CJP_OP_MOV8 = 32, // c[a0] = c[a1] (8b, pos=a2::b(A<<2)&3)	| P = c[a0]
	LV0P_CJP_OP__XOPSTART = LV0P_CJP_OP_MOV8,
	LV0P_CJP_OP_MOV16, // c[a0] = c[a1] (16b, half=a2::b(A<<1)&1)	| P = c[a0]
};

enum LV0P_CJP_MRETS {
	LV0P_CJPMR_OK = 0,
	LV0P_CJPMR_EBADOP,
	LV0P_CJPMR_EBAD2OP,
	LV0P_CJPMR_EBADMOD,
	LV0P_CJPMR_EZDIV,
	LV0P_CJPMR_EUNKOPC,
	LV0P_CJPMR_EBADJDCD,
};

#endif // __LIBSPL_LV0P_H__