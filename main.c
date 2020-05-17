
/* 
	psp2spl by SKGleba
	This software may be modified and distributed under the terms of the MIT license.
	See the LICENSE file for details.
*/

#include <stdio.h>
#include <string.h>
#include <psp2kern/kernel/modulemgr.h>
#include <vitasdkkern.h>

#include "../psp2renga/Include/nmprunner.h"
#include "spl-defs.h"
#include "cp_payload/inject_framework.h"
#include "framework/framework.h"

static uint32_t current_fw = 0; // fw to be used for stage 2
static void *backup_block = NULL; // store the original SPRAM before work
static int should_init = 1; // setup flag for resume

/*
	init()
	Sets up the framework
	RET (int):
		- 0: all good
		- < 0x10: exploit init failed
		- 0x10: could not cache the SM
		- 0x2X: stage 2 copy failed
		- 0x3X: payloads copy failed
		- 0x4X: jump failed
		- 0x6X: stage 2 configure failed
*/
int spl_init(void) {
	should_init = 0; // make sure to not run it twice
	
	// Cache SM
	if (NMPis_ussm_cached == 0) {
		SceIoStat stat;
		int stat_ret = ksceIoGetstat("os0:hfw_cfg.bin", &stat);
		if (stat_ret < 0) {
			NMPcache_ussm("os0:sm/update_service_sm.self", 1);
			current_fw = *(uint32_t *)(*(int *)(ksceKernelGetSysbase() + 0x6c) + 4);
		} else {
			NMPcache_ussm("os0:zss_ussm.self", 1);
			current_fw = 0x03650000;
		}
		if (NMPis_ussm_cached == 0)
			return 0x10;
	}

	NMPctx = -1; // reset the ctx
	
	// init buffs etc
	int ret = NMPexploit_init(current_fw);
	if (ret != 0)
		return ret;
	
	// fw-configure stage 2
	ret = NMPconfigure_stage2(current_fw);
	if (ret != 0)
		return (0x60 + ret);
	
	memcpy(backup_block, NMPcorridor, 0x300); // backup the part of SPRAM that will be modified
	memset(NMPcorridor, 0, 0x300);
	
	// copy stage 2
	ret = NMPcopy(&NMPstage2_payload, 0, sizeof(NMPstage2_payload), 0);
	if (ret != 0)
		return (0x20 + ret);
	
	// copy main
	ret = NMPcopy(&inject_framework_nmp, 0x100, sizeof(inject_framework_nmp), 0);
	if (ret != 0)
		return (0x30 + ret);
	
	// copy data
	ret = NMPcopy(&framework_nmp, 0x200, sizeof(framework_nmp), 0);
	if (ret != 0)
		return (0x30 + ret);
	
	// jump to stage 2
	ret = NMPf00d_jump((uint32_t)NMPcorridor_paddr, current_fw);
	if (ret != 0)
		return (0x40 + ret);
	
	memcpy(NMPcorridor, backup_block, 0x300); // restore the original SPRAM
	
	ksceSblSmCommStopSm(NMPctx, &NMPstop_res);
	return ret;
}

/*
	exec_code(cbuf, csize, arg, copy_cbuf)
	Runs payload in [cbuf] with [arg] as arg 0
	ARG 1 (void *):
		- payload buf (va if needs copy or pa if direct jump)
	ARG 2 (uint32_t):
		- payload size, set to 0 if [cbuf] is a paddr
	ARG 3 (uint32_t):
		- value that is passed as arg 0 to the payload
	ARG 4 (int):
		- set to 1 if [cbuf] needs to be copied to pacont buffer first ([cbuf] must be a vaddr and [csize] non-0)
	RET (uint32_t):
		- (1): [cbuf] is NULL
		- (2): [csize] too large
		- (3): payload run failed
		- else: payload ret
*/
uint32_t spl_exec_code(void *cbuf, uint32_t csize, uint32_t arg, int copy_cbuf) {
	if (should_init) // make sure that the framework is running
		spl_init();
	
	if (cbuf == NULL) // bad src
		return 1;
	if (csize > (NMPcorridor_size - 0x20)) // too big
		return 2;
	
	memcpy(backup_block, NMPcorridor, csize + 0x20); // backup the part of SPRAM that is about to get modified
	memset(NMPcorridor, 0, csize + 0x20);
	
	if (copy_cbuf) // src is a vaddr
		memcpy((NMPcorridor + 0x20), cbuf, csize);
	
	fm_nfo *fmnfo = NMPcorridor;
	fmnfo->magic = 0x14FF;
	fmnfo->status = 0x34;
	fmnfo->codepaddr = (copy_cbuf) ? 0x1f850020 : (uint32_t)cbuf;
	fmnfo->arg = arg;
	
	ksceSblSmSchedProxyExecuteF00DCommand(0, 0, 0, 0); // run custom code code
	
	uint32_t ret = 3;
	if (fmnfo->status == 0x69) // code did run
		ret = fmnfo->resp;
	
	memcpy(NMPcorridor, backup_block, csize + 0x20); // restore original SPRAM
	return ret;
}

// At sleep-resume cmep is reset, reinstall the framework
static int spl_sysevent_handler(int resume, int eventid, void *args, void *opt) {
	if ((resume) && (eventid == 0x10000))
		should_init = 1; // first event - resume flag set
	else if ((resume) && (eventid == 0x100000) && (should_init))
		spl_init(); // last event - make sure that the framework is running
	return 0;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args)
{
	// Use venezia SPRAM
	NMPcorridor_paddr = 0x1f850000;
	NMPcorridor_size = 0x10000;
	
	// Main com block
	if (NMPreserve_commem(0, 1) != 0)
		return SCE_KERNEL_START_FAILED;
	
	// Block for com backup
	if (ksceKernelGetMemBlockBase(ksceKernelAllocMemBlock("spl_backup", 0x1020D006, NMPcorridor_size, NULL), (void**)&backup_block) < 0)
		return SCE_KERNEL_START_FAILED;
	
	// Hook fcmd_handler and copy the framework
	if (spl_init() != 0)
		return SCE_KERNEL_START_FAILED;
	
	// Sysevent handler for resume
	if (ksceKernelRegisterSysEventHandler("spl_sysevent", spl_sysevent_handler, NULL) < 0)
		return SCE_KERNEL_START_FAILED;
	
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	return SCE_KERNEL_STOP_SUCCESS;
}

