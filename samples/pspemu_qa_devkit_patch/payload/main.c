// from enso_ex->sdrecovery->bootmgr->typespoof

#include "types.h"

void __attribute__((optimize("O0"))) _start(void) {
	char buf[4];
	*(u32_t *)buf = *(u32_t *)0xE006214C; // get flags from keyslot x50a+xc
	buf[0] |= 1 << 2;
	
	// copy keyslot x50a to the KR_PROG
	*(u32_t *)0xE0030000 = *(u32_t *)0xE0062140;
	*(u32_t *)0xE0030004 = *(u32_t *)0xE0062144; // patched type
	*(u32_t *)0xE0030008 = *(u32_t *)0xE0062148;
	*(u32_t *)0xE003000C = *(u32_t *)buf;
	*(u32_t *)0xE0030010 = *(u32_t *)0xE0062150;
	*(u32_t *)0xE0030014 = *(u32_t *)0xE0062154;
	*(u32_t *)0xE0030018 = *(u32_t *)0xE0062158;
	*(u32_t *)0xE003001C = *(u32_t *)0xE006215C;
	
	// tell KR_PROG to write 0xE0030000 (0x20) to the KR in KS x50a
	*(u32_t *)0xE0030020 = (u32_t)0x0000050a;
	return;
}