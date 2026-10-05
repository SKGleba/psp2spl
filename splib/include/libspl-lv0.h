#ifndef __LIBSPL_LV0_H__
#define __LIBSPL_LV0_H__

#include "libspl-lv0p.h"
#define splv0p_j_s lv0p_j_s
#define SPLV0P_JOB_MAGIC LV0P_MAGIC
typedef struct {void *va; int size;} spl_lv0p_nmp_t;

struct splv0_cmd_s {
    uint32_t size;
    uint32_t service_id;
    uint32_t response;
    uint32_t unk2;
    uint32_t padding[(0x40 - 0x10) / 4];
    uint32_t arg[];
};
	
#define SPLV0_ARG2PAPA_FLAG 0xF1E2D3C5
struct splv0_exec_arg_s {
	void *payload;
	uint32_t size;
	uint32_t pa_pa;
	uint32_t stack;
	int wait;
	uint32_t arg[4];
	int xret;
};

struct splv0p_arg_s {
    int gsize;
	uint32_t stack;
    spl_lv0p_nmp_t nmp;
    struct splv0p_j_s *j;
	int wait;
    int copy_rets;
};

enum SPLV0_COMMBACKUP_MODES {
    SPLV0_COMMBACKUP_NEVER = 0,
    SPLV0_COMMBACKUP_CRITICAL,
    SPLV0_COMMBACKUP_ALWAYS,
};

enum SPLV0_S2_FCMDS {
    SPLV0_S2_FCMD_RET0 = 0,
    SPLV0_S2_FCMD_READ32 = 2, // a0: addr
    SPLV0_S2_FCMD_WRITE32 = 4, // a0: addr, a1: value
};

#define SPLV0_USSM_PARAM_MAGIC 'USSM' // for inherited/shared parms

enum SPLV0_COMMEMS {
    SPLV0_COMMEM_TZS = 0,
    SPLV0_COMMEM_SMALL,
    SPLV0_COMMEM_LARGE,
    SPLV0_COMMEM__COUNT
};

#endif // __LIBSPL_LV0_H__