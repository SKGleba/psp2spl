
/* 
	psp2spl by SKGleba
	This software may be modified and distributed under the terms of the MIT license.
	See the LICENSE file for details.
*/

#include <psp2kern/kernel/modulemgr.h>
#include <vitasdkkern.h>

#define SPL_CFK_LV0FULL
#define SPL_CFK_TZSFULL
#include <libspl/libspl-cfk.h> // lspl kernel compatibility layer

#include "include/txtcfg.h"

#include "include/splForDriver.h"
#include "include/main.h"


typedef int bool;
#define true 1
#define false 0

#define SPL_DEFAULT_INIT_FLAGS ((SPL_IFL(_LV0) | SPL_IFL(_TZS)))
#define SPL_DEFAULT_BACKUP_MODE SPLM_LV0_COMMBACKUP_CRITICAL

static int splm_icb(enum SPLM_CB_REASONS reason);
struct splm_statu_s splm_status = {
	.state = SPLM_STATE_RESET,
	.lspl_initialized = false,
	.lspl_initstatus = 0,
	.lspl_initflags = SPL_DEFAULT_INIT_FLAGS | (!!SPLM_QUIET_BY_DEFAULT * SPLM_IFL(_QUIET_INIT)) | SPLM_IFL(_ALLOC_USSM),
	.lspl_resumeflags = SPL_DEFAULT_INIT_FLAGS | SPLM_IFL(_RESET) | (!!SPLM_QUIET_ON_RESUME * SPLM_IFL(_QUIET_INIT)),
	.lspl_backupmode = SPL_DEFAULT_BACKUP_MODE,
	.use_inheritance = SPLM_INHERIT_BY_DEFAULT,
	.quiet = SPLM_QUIET_BY_DEFAULT,
	.cb = {
		.count = 0,
		.max = SPLM_MAX_RESUME_CALLBACKS,
		.fun = {NULL},
	},
	.dbgId = "[SPLM]",
	.icb = splm_icb,
	.txtcfg_rmb = {{ NULL, -1, 0, }, { NULL, -1, 0, }}
};

struct splm_statu_s *ksplmGetStatus(void) {
	splm_status.lspl_initstatus = SPLx_INIT_STATUS();
	return &splm_status;
}

int ksplmInit(int flags, enum SPLM_LV0_COMMBACKUP_MODES backup_mode) {
	splm_status.lspl_initialized = false;
	splm_status.use_inheritance = !!(flags & SPLM_IFL(_INHERIT));
	int ret = SPLx_CFK_INIT(flags, !!(flags & SPLM_IFL(_QUIET_INIT)), splm_status.use_inheritance, !!(flags & SPLM_IFL(_ALLOC_USSM)), (enum SPLV0_COMMBACKUP_MODES)backup_mode);
	splm_status.lspl_initialized = (ret >= 0) ? true : false;
	return ret;
}

int ksplmRRC(bool do_register, void (*callback)(enum SPLM_CB_REASONS reason)) {
	if (!callback)
		return -1;
	if (do_register && (splm_status.cb.count >= SPLM_MAX_RESUME_CALLBACKS))
		return -2;
	for (int i = 0; i < SPLM_MAX_RESUME_CALLBACKS; i++) {
		if (do_register) {
			if (!splm_status.cb.fun[i]) {
				splm_status.cb.fun[i] = callback;
				splm_status.cb.count++;
				return 0;
			}
		} else if (splm_status.cb.fun[i] == callback) {
			splm_status.cb.fun[i] = NULL;
			splm_status.cb.count--;
			return 0;
		}
	}
	return -3;
}

int ksplmLv0Cmd(enum SPLM_LV0_COMMANDS cmd, int argx, void *argv, enum SPLM_LV0_COMMBACKUP_MODES backup_mode) {
	if (!splm_status.lspl_initialized && (splm_status.icb(SPLM_CBR_XWAKEUP) < 0))
		return -1;
	int ret = SPLx_INIT_STATUS();
	if ((ret < 0) || !(ret & SPL_IFL(_LV0)))
		return -1;
	ret = -SPL_EBADARG;
	if (!argv)
		return ret;
	switch (cmd) {
		case SPLM_LV0_CMD_READ32:
			*(uint32_t*)argv = SPLx_LV0_READ32((uint32_t)argx, &ret, (enum SPLV0_COMMBACKUP_MODES)backup_mode);
		break; case SPLM_LV0_CMD_WRITE32:
			SPLx_LV0_WRITE32((uint32_t)argx, *(uint32_t*)argv, &ret, (enum SPLV0_COMMBACKUP_MODES)backup_mode);
		break; case SPLM_LV0_CMD_EXEC:
			ret = SPLx_LV0_EXEC((struct splv0_exec_arg_s *)argv, (enum SPLV0_COMMBACKUP_MODES)backup_mode);
		break; case SPLM_LV0_CMD_PATCH:
			SPLx_CFK_LV0P_ARGPREP(argv);
			ret = SPLx_LV0P((struct splv0p_arg_s *)argv, (enum SPLV0_COMMBACKUP_MODES)backup_mode);
		break; default:
			ERRORF("ksplmLv0Cmd: Unknown command: %d\n", cmd);
			break;
	}
	return ret;
}

int ksplmTzsCmd(int cmd, int argx, void *argv) {
	if (!splm_status.lspl_initialized && (splm_status.icb(SPLM_CBR_XWAKEUP) < 0))
		return -1;
	int ret = SPLx_INIT_STATUS();
	if ((ret < 0) || !(ret & SPL_IFL(_TZS)))
		return -1;
	ret = -SPL_EBADARG;
	if (!argv)
		return ret;
	switch (cmd) {
		case SPLM_TZS_CMD_READ32:
			ret = SPLx_TZS_READ32((uint32_t)argx, (uint32_t*)argv);
		break; case SPLM_TZS_CMD_WRITE32:
			ret = SPLx_TZS_WRITE32((uint32_t)argx, *(uint32_t*)argv);
		break; case SPLM_TZS_CMD_SVA2PA:
			ret = SPLx_TZS_SVA2PA((uint32_t)argx, (uint32_t*)argv);
		break; case SPLM_TZS_CMD_SVA2NSVA:
			ret = SPLx_TZS_SVA2NSVA((uint32_t)argx, (void*)argv);
		break; case SPLM_TZS_CMD_SMCADD:
			ret = SPLx_TZS_SMCADD((int)argx, *(uint32_t*)argv);
		break; case SPLM_TZS_CMD_GETMODSVA: {
			struct splmTzsGetModSVA_arg_s *arg = (struct splmTzsGetModSVA_arg_s *)argv;
			ret = SPLx_TZS_GETMODSVA((enum SPLTZ_MODINFO_ENTS)arg->id, (int)arg->seg, arg->off, &arg->sva);
		}
		break; default:
			ERRORF("ksplmTzsCmd: Unknown command: %d\n", cmd);
			break;
	}
	return ret;
}

static int splm_icb(enum SPLM_CB_REASONS reason) {
	int ret = -1;
	INFOF("ICB: reason=%d, state=%d\n", reason, splm_status.state);
	if (reason != SPLM_CBR_STOP) {
		switch (splm_status.state) {
			case SPLM_STATE_ONLINE:
				if (reason != SPLM_CBR_SLEEP)
					return -1;
				splm_status.state = SPLM_STATE_2SLEEP;
				ret = 0;
				break;
			case SPLM_STATE_SLEEPING:
				if ((reason != SPLM_CBR_RESUME) && (reason != SPLM_CBR_XWAKEUP))
					return -1;
				splm_status.state = SPLM_STATE_2RESUME;
				if (ret = ksplmInit(splm_status.lspl_resumeflags | (!!splm_status.use_inheritance * SPLM_IFL(_INHERIT)), splm_status.lspl_backupmode), ret < 0)
					return ret;
				if (splm_status.txtcfg_rmb[SPLM_STATUS_TCRMB_LV0].va) {
					INFOF("ICB: executing txtcfg jobs (lv0p)\n", ret);
					ksplmLv0Cmd(SPLM_LV0_CMD_PATCH, 0, splm_status.txtcfg_rmb[SPLM_STATUS_TCRMB_LV0].va, SPLM_LV0_COMMBACKUP_NEVER); // TODO: observe comm
					splm_status.txtcfg_rmb[SPLM_STATUS_TCRMB_LV0].va = NULL;
				}
				break;
			case SPLM_STATE_RESET:
				if (reason != SPLM_CBR_START)
					return -1;
				SPLx_CFK_PREP(NULL, splm_status.quiet, splm_status.dbgId);
				if (ret = ksplmInit(splm_status.lspl_initflags | (!!splm_status.use_inheritance * SPLM_IFL(_INHERIT)), splm_status.lspl_backupmode), ret < 0)
					return ret;
				splm_status.state = SPLM_STATE_ONLINE;
#ifdef SPLM_DEFAULT_CONFIG
				txtcfg_apx(SPLM_DEFAULT_CONFIG, TXTCFG_SECTION_LV0P_BOOT, 0, NULL, false);
				txtcfg_apx(SPLM_DEFAULT_CONFIG, TXTCFG_SECTION_TZSP_BOOT, 0, NULL, true);
#endif
				break;
			default:
				break;
		}
	} else {
		ERRORF("Stopping SPLM, current state was: %d\n", splm_status.state);
		splm_status.state = SPLM_STATE_2STOP;
	}
	if (ret < 0)
		return ret;
	for (int i = 0; i < SPLM_MAX_RESUME_CALLBACKS; i++) {
		if (splm_status.cb.fun[i])
			splm_status.cb.fun[i](reason);
	}
	ret = 0;
	if (splm_status.state != SPLM_STATE_ONLINE) {
		switch (splm_status.state) {
			case SPLM_STATE_2STOP:
			case SPLM_STATE_2SLEEP:
				SPLx_CFK_DEINIT(SPL_IFL(_LV0) | SPL_IFL(_TZS));
				if (splm_status.state == SPLM_STATE_2SLEEP) {
					SPLx_CFK_USSMALLOC();
#ifdef SPLM_DEFAULT_CONFIG
					txtcfg_apx(SPLM_DEFAULT_CONFIG, TXTCFG_SECTION_LV0P_RESUME, 0, (struct txtcfg_apx_out_s *)&splm_status.txtcfg_rmb[SPLM_STATUS_TCRMB_LV0], false);
					txtcfg_apx(SPLM_DEFAULT_CONFIG, TXTCFG_SECTION_TZSP_RESUME, 0, (struct txtcfg_apx_out_s *)&splm_status.txtcfg_rmb[SPLM_STATUS_TCRMB_TZS], true);
#endif
				}
				splm_status.lspl_initialized = false;
				splm_status.state = (splm_status.state == SPLM_STATE_2STOP) 
					? SPLM_STATE_RESET 
					: SPLM_STATE_SLEEPING;
				break;
			case SPLM_STATE_2RESUME:
				splm_status.state = SPLM_STATE_ONLINE;
				break;
			default:
				ret = -1;
				break;
		}
	}
	return ret;
}

// At sleep-resume cmep & tzsmods are reset, reinstall the framework
static int spl_sysevent_handler(int resume, int eventid, void *args, void *opt) {
	switch (eventid) {
		case 0x100000: //phase1
			if (resume) {
				if (splm_status.icb(SPLM_CBR_RESUME) < 0)
					splm_status.icb(SPLM_CBR_STOP);
			}
			break;
		case 0x20F: //phase2
			if (!resume) {
				if (splm_status.icb(SPLM_CBR_SLEEP) < 0)
					splm_status.icb(SPLM_CBR_STOP);
			}
		default:
			break;
	}
	return 0;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args)
{
	if (splm_status.icb(SPLM_CBR_START) < 0)
		return SCE_KERNEL_START_FAILED;

	// Sysevent handler for sleep/resume
	if (ksceKernelRegisterSysEventHandler("spl_sysevent", spl_sysevent_handler, NULL) < 0)
		return SCE_KERNEL_START_FAILED;
	
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	return SCE_KERNEL_STOP_SUCCESS;
}

