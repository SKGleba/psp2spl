#ifndef __LIBSPL_H__
#define __LIBSPL_H__

#include "libspl-lv0.h"
#include "libspl-tzs.h"

struct spl_import_s {
    void *(*memset)(void *s, int c, uint32_t n);
    void *(*memcpy)(void *dest, const void *src, uint32_t n);

    void *(*palloc)(uint32_t paddr, uint32_t size);
    void (*pfree)(void *va);

    void *(*malloc)(uint32_t size);
    void (*free)(void *ptr);

    int (*loadussm)(void);
    int (*callussm)(void *cmdbuf);
    int (*unloadussm)(void);

    uint32_t (*getfw)(void);

    int (*smcall)(int idx, int a0, int a1, int a2, int a3);

    void (*debug)(const char *fmt, ...);
    void (*error)(const char *fmt, ...);
};

enum SPL_ERRORS {
	SPL_OK = 0,
	SPL_EBADROOT,
	SPL_EBADARG,
	SPL_LV0X_EBUSY,
	SPL_LV0X_ENOPAFCOMM,
	SPL_LV0X_ENOPAPALLOC,
	SPL_LV0X_EBADICFG,
	SPL_LV0X_ENOBMALLOC,
	SPL_LV0FC_EBUSY,
	SPL_LV0FC_E404,
	SPL_LV0FC_ETOOBIG,
	SPL_LV0FC_ENOPALLOC,
	SPL_LV0FC_EUSSMC,
	SPL_LV0BC_ENOBACKUP,
	SPL_LV0BC_EBADCPARM,
	SPL_LV0BC_ENOBMALLOC,
	SPL_LV0UXS2_ENOPAFCOMM,
	SPL_LV0UXS2_ENOMALLOC,
	SPL_LV0P_ENOPAFCOMM,
	SPL_LV0P_EPAYLERR,
	SPL_LV0P_ETOOBIG,
	SPL_LV0P_EUNKJOB,
	SPL_LV0I_EBADICFG,
	SPL_LV0I_EBADTEST,

	SPL_TZSI_ENOSPALLOC,
	SPL_TZSI_ENOSMCT,
	SPL_TZSI_ENOSMCSVA,
	SPL_TZSI_ENOTESTSVA,
	SPL_TZSI_EBADTEST,
	SPL_TZSI_ENOLV0I,
	SPL_TZSI_EFWDROP,
	SPL_TZSI_ENOOPES,
	SPL_TZSV2P_EOOSRANGE,
	SPL_TZSV2P_EUNRL1PTE,
	SPL_TZSV2P_E404,

	SPL_INIT_ENOIMPORTS,
};

enum SPL_INIT_FLAGS {
	SPL_INITFLAG_LV0 = 0,
	SPL_INITFLAG_LV0_REINIT,
	SPL_INITFLAG_TZS,
	SPL_INITFLAG_TZS_REINIT,
	SPL_INITFLAG_RESET,
	SPL_INITFLAG_NOINHERITANCE,
	SPL_INITFLAG_DROP_TZSB_FW,
};
#define SPL_IFL(_flag) (1 << (SPL_INITFLAG##_flag))

#define SPL_PABUF_ALIGN 0x20
#define SPL_PALIGN(x) (((x) + (SPL_PABUF_ALIGN - 1)) & ~(SPL_PABUF_ALIGN - 1))

struct spl_init_arg_s {
	void *bufC0; // persistent buf of at least 0xC0 (for spl_root)
    struct spl_import_s *imports;
    int ifl; // bits fropm SPL_INIT_FLAGS
    enum SPLV0_COMMBACKUP_MODES lv0_backup_mode;
	char *dbgid;
	uint32_t fw_override;
	struct spl_selective_s {
		int (*lv0_init)(spl_lv0p_nmp_t lv0p, int wait, enum SPLV0_COMMBACKUP_MODES backup_mode);
		int (*lv0_deinit)(void);
		int (*tzs_init)(void);
		int (*tzs_deinit)(void);
		spl_lv0p_nmp_t lv0p_nmp;
	} *sel;
};

#ifdef LSPL_CFGSEL_LV0EN
	#define LSPL_CFGSEL_LV0_INIT SPLx_LV0_INIT
	#define LSPL_CFGSEL_LV0_DEINIT SPLx_LV0_DEINIT
	int SPLx_LV0_FCOMMEM(int minsz, int alloc, int wait, int respect_busy);
	int SPLx_LV0_ACOMMEM(enum SPLV0_COMMEMS idx, int busyf);
	int SPLx_LV0_EXEC(struct splv0_exec_arg_s *xarg, enum SPLV0_COMMBACKUP_MODES backup_mode);
	int SPLx_LV0_FASTCMD(int fcmd, uint32_t *args, int *fret, enum SPLV0_COMMBACKUP_MODES backup_mode);
	int SPLx_LV0P(struct splv0p_arg_s *varg, enum SPLV0_COMMBACKUP_MODES backup_mode);
	int SPLx_LV0_INIT(spl_lv0p_nmp_t lv0p, int wait, enum SPLV0_COMMBACKUP_MODES backup_mode);
	int SPLx_LV0_DEINIT(void);
	#if defined(LSPL_CFGSEL_LV0P_FULL)
		extern uint8_t lspl_lv0p_nmp[];
		extern unsigned int lspl_lv0p_nmp_len;
		#define LSPL_CFGSEL_LV0P_NMP_VA lspl_lv0p_nmp
		#define LSPL_CFGSEL_LV0P_NMP_SIZE lspl_lv0p_nmp_len
	#elif defined(LSPL_CFGSEL_LV0P_NOCUS)
		extern uint8_t lspl_lv0p_noc_nmp[];
		extern unsigned int lspl_lv0p_noc_nmp_len;
		#define LSPL_CFGSEL_LV0P_NMP_VA lspl_lv0p_noc_nmp
		#define LSPL_CFGSEL_LV0P_NMP_SIZE lspl_lv0p_noc_nmp_len
	#else
		#error "Unknown LV0P configuration"
	#endif // defined(LSPL_CFGSEL_LV0P_*)
#else
	#define LSPL_CFGSEL_LV0_INIT NULL
	#define LSPL_CFGSEL_LV0_DEINIT NULL
	#define LSPL_CFGSEL_LV0P_NMP_VA NULL
	#define LSPL_CFGSEL_LV0P_NMP_SIZE 0
#endif // LSPL_CFGSEL_LV0EN

#define SPLx_LV0_READ32(_addr, _fret, _commbackup) SPLx_LV0_FASTCMD(SPLV0_S2_FCMD_READ32, (uint32_t[4]){(_addr),0,0,0}, (_fret), (_commbackup))
#define SPLx_LV0_READ32F(_addr) SPLx_LV0_READ32((_addr), NULL, SPLV0_COMMBACKUP_NONE)
#define SPLx_LV0_WRITE32(_addr, _val, _fret, _commbackup) SPLx_LV0_FASTCMD(SPLV0_S2_FCMD_WRITE32, (uint32_t[4]){(_addr),(_val),0,0}, (_fret), (_commbackup))
#define SPLx_LV0_WRITE32F(_addr, _val) SPLx_LV0_WRITE32((_addr), (_val), NULL, SPLV0_COMMBACKUP_NONE)

#ifdef LSPL_CFGSEL_TZS_EN
	#define LSPL_CFGSEL_TZS_INIT SPLx_TZS_INIT
	#define LSPL_CFGSEL_TZS_DEINIT SPLx_TZS_DEINIT
	#ifndef SPLIB_NODEBUG
		int SPLx_TZS_PRINTTBR(int printl2);
	#endif
	int SPLx_TZS_SVA2PA(uint32_t sva, uint32_t *rpa);
	int SPLx_TZS_SVA2NSVA(uint32_t sva, void **rnsva);
	int SPLx_TZS_READ32(uint32_t sva, uint32_t *rval);
	int SPLx_TZS_WRITE32(uint32_t sva, uint32_t val);
	int SPLx_TZS_SMCADD(int idx, uint32_t funcsva);
	int SPLx_TZS_GETMODSVA(enum SPLTZ_MODINFO_ENTS mod, int seg, uint32_t off, uint32_t *rsva);
	int SPLx_TZS_INIT(void);
	int SPLx_TZS_DEINIT(void);
#else
	#define LSPL_CFGSEL_TZS_INIT NULL
	#define LSPL_CFGSEL_TZS_DEINIT NULL
#endif // LSPL_CFGSEL_TZS_EN

int SPLx_INIT_STATUS(void);
int SPLx_INIT(struct spl_init_arg_s *init_arg);
int SPLx_DEINIT(struct spl_init_arg_s *init_arg);

#endif // __LIBSPL_H__