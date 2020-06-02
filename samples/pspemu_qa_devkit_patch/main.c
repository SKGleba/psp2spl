/* 
	psp2spl usage example by SKGleba
	This software may be modified and distributed under the terms of the MIT license.
	See the LICENSE file for details.
*/

#include <stdio.h>
#include <string.h>
#include <taihen.h>
#include <psp2kern/kernel/modulemgr.h>
#include <vitasdkkern.h>
#include "payload/payload.h"

static int sample_sysevent_handler(int resume, int eventid, void *args, void *opt) {
	if ((resume) && (eventid == 0x100000))
		spl_exec_code(&payload_nmp, payload_nmp_len, 0, 1);
	return 0;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args)
{
	
	if (spl_exec_code(&payload_nmp, payload_nmp_len, 0, 1) != 0)
		SCE_KERNEL_START_FAILED;
	
	// Add sehandler to rerun the payload at every resume (crypto reset)
	ksceKernelRegisterSysEventHandler("spl_sample", sample_sysevent_handler, NULL);
	
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	return SCE_KERNEL_STOP_SUCCESS;
}
