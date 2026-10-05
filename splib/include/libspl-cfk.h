#ifndef __LIBSPL_CFK_H__
#define __LIBSPL_CFK_H__

#if defined(SPL_CFK_LV0SMALL) || defined(SPL_CFK_LV0FULL)
    #define LSPL_CFGSEL_LV0EN
    #ifdef SPL_CFK_LV0SMALL
        #define LSPL_CFGSEL_LV0P_NOCUS
    #else
        #define LSPL_CFGSEL_LV0P_FULL
    #endif
#endif

#if defined(SPL_CFK_TZSFULL)
    #define LSPL_CFGSEL_TZS_EN
#endif

#include "libspl.h"

#define SPL_CFK_USSM_DEFAULT_PATH "os0:sm/update_service_sm.self"
#define SPL_CFK_USSM_HFW_PATH "os0:spl_ussm.self"

extern struct spl_selective_s SPLx_CFK_SEL;

#define SPLx_CFK_PREP(ussm_path, quiet, dbgid) do { \
    SPLx_CFK_SEL.lv0_init = LSPL_CFGSEL_LV0_INIT; \
    SPLx_CFK_SEL.lv0_deinit = LSPL_CFGSEL_LV0_DEINIT; \
    SPLx_CFK_SEL.tzs_init = LSPL_CFGSEL_TZS_INIT; \
    SPLx_CFK_SEL.tzs_deinit = LSPL_CFGSEL_TZS_DEINIT; \
    SPLx_CFK_SEL.lv0p_nmp.va = LSPL_CFGSEL_LV0P_NMP_VA; \
    SPLx_CFK_SEL.lv0p_nmp.size = LSPL_CFGSEL_LV0P_NMP_SIZE; \
    SPLx_CFK_PREPS(ussm_path, quiet, dbgid, &SPLx_CFK_SEL); \
} while(0)
void SPLx_CFK_PREPS(char *ussm_path, int quiet, char *dbgid, struct spl_selective_s *sel);
int SPLx_CFK_INIT(int flags, int quiet, int inherit, int alloc, enum SPLV0_COMMBACKUP_MODES backup_mode);
int SPLx_CFK_DEINIT(int flags);
int SPLx_CFK_USSMALLOC(void);
#define SPLx_CFK_LV0P_ARGPREP(_arg) do { \
    ((struct splv0p_arg_s *)(_arg))->nmp.size = LSPL_CFGSEL_LV0P_NMP_SIZE; \
    ((struct splv0p_arg_s *)(_arg))->nmp.va = LSPL_CFGSEL_LV0P_NMP_VA; \
} while(0)

#endif // __LIBSPL_CFK_H__