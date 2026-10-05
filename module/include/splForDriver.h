#ifndef __SPL4DRIVER_H__
#define __SPL4DRIVER_H__

#include <stdint.h>

#define SPLM_DEFAULT_CONFIG "uma0:/psp2spl.cfg"

struct splmLv0Exec_arg_s {
    void *payload;
	uint32_t size;
	uint32_t pa_pa;
	uint32_t stack;
	int wait;
	uint32_t arg[4];
	int xret;
};

struct splmLv0pRun_arg_s {
    int gsize;
	uint32_t stack;
	int reserved[2];
    struct splmLv0p_j_s {
		uint32_t magic;
		enum LV0P_JOB_IDS idx;
		int ret;
		union {
			struct splmLv0p_j_s *next;
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
	} *jobs;
	int wait;
    int copy_rets;
};

enum SPLM_LV0_COMMBACKUP_MODES {
    SPLM_LV0_COMMBACKUP_NEVER = 0,
    SPLM_LV0_COMMBACKUP_CRITICAL,
    SPLM_LV0_COMMBACKUP_ALWAYS,
};

enum SPLM_LV0_COMMANDS {
	SPLM_LV0_CMD_READ32 = 0, // argx = addr, argv = val (output)
	SPLM_LV0_CMD_WRITE32, // argx = addr, argv = val (input)
	SPLM_LV0_CMD_EXEC, // argv = struct splmLv0Exec_arg_s *
	SPLM_LV0_CMD_PATCH, // argv = struct splmLv0pRun_arg_s *
};

enum SPLM_TZS_MODIDS {
    SPLM_TZS_MODID_SYSMEM = 0,
    SPLM_TZS_MODID_EXCPMGR,
    SPLM_TZS_MODID_INTRMGR,
    SPLM_TZS_MODID_BUSERR,
    SPLM_TZS_MODID_SMSCHED,
    SPLM_TZS_MODID_DRVR,
    SPLM_TZS_MODID__COUNT
};

enum SPLM_TZS_MODSEGS {
    SPLM_TZS_MODSEG_TEXT = 0,
    SPLM_TZS_MODSEG_DATA,
};

struct splmTzsGetModSVA_arg_s {
	enum SPLM_TZS_MODIDS id;
	enum SPLM_TZS_MODSEGS seg;
	uint32_t off;
	uint32_t sva; // output
};

enum SPLM_TZS_COMMANDS {
	SPLM_TZS_CMD_READ32 = 0, // argx = addr, argv = &val (output)
	SPLM_TZS_CMD_WRITE32, // argx = addr, argv = &val (input)
	SPLM_TZS_CMD_SVA2PA, // argx = sva, argv = &pa (output)
	SPLM_TZS_CMD_SVA2NSVA, // argx = sva, argv = &nsva (output)
	SPLM_TZS_CMD_SMCADD, // argx = idx, argv = &sva (input)
	SPLM_TZS_CMD_GETMODSVA, // argv = struct splmTzsGetModSVA_arg_s *
};

enum SPLM_INIT_FLAGS { // first 24 must match libspl.h:enum SPL_INIT_FLAGS
	SPLM_INITFLAG_LV0 = 0,
	SPLM_INITFLAG_LV0_REINIT,
	SPLM_INITFLAG_TZS,
	SPLM_INITFLAG_TZS_REINIT,
	SPLM_INITFLAG_RESET,
	SPLM_INITFLAG_NOINHERITANCE,
	SPLM_INITFLAG_DROP_TZSB_FW,
	SPLM_INITFLAG_ALLOC_USSM = 24,
	SPLM_INITFLAG_QUIET_INIT,
	SPLM_INITFLAG_INHERIT,
};
#define SPLM_IFL(_flag) (1 << (SPLM_INITFLAG##_flag))

enum SPLM_STATES {
	SPLM_STATE_RESET,
	SPLM_STATE_SLEEPING,
	SPLM_STATE_ONLINE,
	SPLM_STATE_2SLEEP,
	SPLM_STATE_2RESUME,
	SPLM_STATE_2STOP,
};

enum SPLM_CB_REASONS {
	SPLM_CBR_START,
	SPLM_CBR_SLEEP,
	SPLM_CBR_RESUME,
	SPLM_CBR_XWAKEUP,
	SPLM_CBR_STOP
};

enum SPLM_STATUS_TXTCFG_RMBS {
	SPLM_STATUS_TCRMB_LV0 = 0,
	SPLM_STATUS_TCRMB_TZS,
	SPLM_STATUS_TCRMB__COUNT
};

#define SPLM_QUIET_BY_DEFAULT false
#define SPLM_QUIET_ON_RESUME false
#define SPLM_INHERIT_BY_DEFAULT true
#define SPLM_MAX_RESUME_CALLBACKS 32

struct splm_statu_s {
	enum SPLM_STATES state;
	int lspl_initialized;
	int lspl_initstatus; // updated on ksplmGetStatus()
	int lspl_initflags;
	int lspl_resumeflags;
	enum SPLM_LV0_COMMBACKUP_MODES lspl_backupmode;
	int use_inheritance;
	int quiet;
	struct {
		int count;
		int max; // ro:SPLM_MAX_RESUME_CALLBACKS
		void (*fun[SPLM_MAX_RESUME_CALLBACKS])(enum SPLM_CB_REASONS reason);
	} cb;
	char *dbgId;
	int (*icb)(enum SPLM_CB_REASONS reason);
	struct {
		void *va;
		int id;
		int size;
	} txtcfg_rmb[SPLM_STATUS_TCRMB__COUNT]; // lv0,tzs | see txtcfg.h
};

struct splm_statu_s *ksplmGetStatus(void);
int ksplmInit(int flags, enum SPLM_LV0_COMMBACKUP_MODES backup_mode);
int ksplmLv0Cmd(enum SPLM_LV0_COMMANDS cmd, int argx, void *argv, enum SPLM_LV0_COMMBACKUP_MODES backup_mode);
int ksplmTzsCmd(int cmd, int argx, void *argv);
int ksplmRRC(int do_register, void (*callback)(enum SPLM_CB_REASONS reason));

#endif // __SPL4DRIVER_H__