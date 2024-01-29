/* 
	psp2spl usage example by SKGleba
	This software may be modified and distributed under the terms of the MIT license.
	See the LICENSE file for details.
*/

#include <psp2kern/kernel/modulemgr.h>
#include <stdio.h>
#include <string.h>
#include <taihen.h>
#include <vitasdkkern.h>

#include "bridge/bridge.h"

typedef struct bridge_s {
	uint32_t paddr;
	uint32_t args[8]; // 4 regs + 0x10 stack
} bridge_s;

#define PSPEMU_BOOTROM_PATH "host0:tai/psp_bootram.bin"

#define fud_comms_pa 0x1F85C000
#define fud_comms_size 0x4000
void *fud_comms_va = NULL;

void hexdump(uint8_t *data, int size) {
    for (int i = 0; i < size; i -= -1) {
        if (!(i % 0x10))
            ksceDebugPrintf("\n %04X: ", i);
        ksceDebugPrintf("%02X ", data[i]);
    }
    ksceDebugPrintf("\n");
}

// extended spl_exec_code
int fud_bridge_exec(uint32_t exec_addr, uint32_t argc, uint32_t *argv) {
    if (!fud_comms_va)
        return -1;
	if (!argv || !exec_addr)
		return -2;

    bridge_s *bridge = fud_comms_va;
    memset(bridge, 0, 0x24);
	bridge->paddr = exec_addr;
	for (int i = 0; i < argc; ++i)
		bridge->args[i] = argv[i];

    return spl_exec_code(bridge_nmp, bridge_nmp_len, fud_comms_pa, 1);
}

int mepcpy(uint32_t dst, uint32_t src, uint32_t len) {
    if (!dst || !src || !len)
		return -3;

    uint32_t memcpy_args[3];
    memcpy_args[0] = dst;
    memcpy_args[1] = src;
    memcpy_args[2] = len;

    return fud_bridge_exec(0x00807262, 3, memcpy_args);
}

int fud_write32(uint32_t dst, uint32_t val) { // xd
    if (!dst)
        return -3;

    uint32_t memcpy_args[4];
    memcpy_args[0] = dst;
    memcpy_args[1] = fud_comms_pa + 0x10;
    memcpy_args[2] = 0x4;
    memcpy_args[3] = val;

    return fud_bridge_exec(0x00807262, 4, memcpy_args);
}

void *palloc(uint32_t pa, uint32_t size, int *out_uid, const char *name) {
	if (!pa || !size)
		return NULL;

	void *comms_va = NULL;

    SceKernelAllocMemBlockKernelOpt optp;
	optp.size = 0x58;
	optp.attr = 2;
	optp.paddr = pa;
	int uid = ksceKernelAllocMemBlock(name, 0x10208006, size, &optp);
	ksceKernelGetMemBlockBase(uid, (void**)&comms_va);
	if ((uid < 0) || !comms_va)
		return NULL;

    if (out_uid)
        *out_uid = uid;

    return comms_va;
}

void _start() __attribute__((weak, alias("module_start")));
int module_start(SceSize argc, const void *args)
{
	ksceDebugPrintf("alloc fud comms\n");
	int fud_comms_uid = 0;
	fud_comms_va = palloc(fud_comms_pa, fud_comms_size, &fud_comms_uid, "pspexec_fud_comms");
	if (!fud_comms_va)
		return SCE_KERNEL_START_FAILED;

    ksceDebugPrintf("prep pspcpu\n");
    fud_write32(0xE3101020, 0x3);  // put pspcpu into reset
    fud_write32(0xE3102020, 0x3);  // pspcpu clock gate
    fud_write32(0xE31030A0, 0x1);  // ??
    fud_write32(0xE8000004, 0xA);  // add arm to pspcpu acl

    ksceDebugPrintf("alloc psp sram buf\n");
    int sram_uid = 0;
    void *sram_va = palloc(0xe8100000, 0x1000, &sram_uid, "pspexec_sram");
    if (!sram_va) {
        ksceKernelFreeMemBlock(fud_comms_uid);
		return SCE_KERNEL_START_FAILED;
    }

    ksceDebugPrintf("read pspcpu bootram\n");
    memset(sram_va, 0, 0x1000);
    int fd = ksceIoOpen(PSPEMU_BOOTROM_PATH, SCE_O_RDONLY, 0);
	if (fd < 0) {
        ksceKernelFreeMemBlock(sram_uid);
        ksceKernelFreeMemBlock(fud_comms_uid);
        return SCE_KERNEL_START_FAILED;
	}
    ksceIoRead(fd, sram_va, 0x1000);
    ksceIoClose(fd);

    ksceDebugPrintf("reset pspcpu\n");
    fud_write32(0xE3101020, 0x2);  // put pspcpu out of reset

    { // CUSTOM CODE HERE
        ksceDebugPrintf("wait\n");
        ksceKernelDelayThread(1 * 1000 * 1000);  // or some realistic value

        ksceDebugPrintf("stop pspcpu\n");
        fud_write32(0xE3101020, 0x3);  // put pspcpu back into reset

        ksceKernelCpuDcacheAndL2WritebackInvalidateRange(sram_va, 0x1000); // mblock should be uncached anyways

        // check payload status & kirkd data
        ksceDebugPrintf("did run?: %08X\n", *(volatile uint32_t *)(sram_va + 0x200));
        hexdump(sram_va + 0x400, 0x5e0);
    }

    ksceKernelFreeMemBlock(sram_uid);
    ksceKernelFreeMemBlock(fud_comms_uid);

    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	return SCE_KERNEL_STOP_SUCCESS;
}
