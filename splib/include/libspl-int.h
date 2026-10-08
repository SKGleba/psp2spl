#ifndef __LIBSPL_INT_H__
#define __LIBSPL_INT_H__

#include "hardware/types.h"
#include "hardware/paddr.h"
#include "hardware/maika.h"
#include "hardware/xbar.h"

#define SPLTZ_MODINFO__COUNT 6 // from enum SPLTZ_MODINFO_ENTS in libspl-tzs.h
#define SPLV0_COMMEM__COUNT 3 // from enum SPLV0_COMMEMS in libspl-lv0.h

typedef int bool;
#define true 1
#define false 0
#define NULL ((void *)0)

/*
* LV0 stuff
*/
#ifndef SPLV0_COMMEM_PA
	#define SPLV0_COMMEM_PA (SPAD128K_OFFSET + (SPAD128K_SIZE / 2))
	#define SPLV0_COMMEM_SIZE 0x1000
#endif

#ifndef SPLV0_COMMBIG_PA
	#define SPLV0_COMMBIG_PA TACHYON_EDRAM_OFFSET
	#define SPLV0_COMMBIG_SIZE TACHYON_EDRAM_SIZE
#endif

#define SPLV0_SKFCMDID 0xB01
#define SPLV0_CALLSK(_i) SPLi_SMCALL(0x13C, (_i), 0, 0, 0)

// -v- USSM corrupt -v-
struct splv0_ussm5_carg_s {
    uint32_t unused_0[7];
    uint32_t list_count;  // must be < 0x1F1
    uint32_t unused_20[4];
    uint32_t total_count;  // only used in LV1 mode
    uint32_t unused_34[1];
    struct {
        uint32_t addr;
        uint32_t length;
    } palist[3];
};
// -^- USSM corrupt -^-

// -v- USSM stage2 -v-
#define SPLS2_USEDSZ 0x1000
enum SPLP_STAGE2_ENTRIES {
    SPLS2E_PAYLOAD = 1,
    SPLS2E_U5C_DIRJMP,
    SPLS2E_U5C_INDIRJMP,
};
#define SPLS2T2M_JMPBA SPLOPEM_UNIQ
#define SPLS2T2M_PAIRS (SPLS2T2M_JMPBA + 1)

#define SPLS2T3M_JMPBA SPLOPEM_UNIQ
#define SPLS2T3M_JMPOA (SPLS2T3M_JMPBA + 1)
#define SPLS2T3M_PAIRS (SPLS2T3M_JMPOA + 1)

#define SPLS2T1M_NSKCLS SPLOPEM_UNIQ
#define SPLS2T1M_CODE (SPLS2T1M_NSKCLS + 1)

#define SPLS2T1_MAXSZ 0x100
#define SPLS2T1_MINSZ 0x2C
typedef volatile struct splv0_t1s2pb_s {
    uint32_t skfcmdid;
	union {
		uint32_t magic;
		uint32_t _start;
	};
	union {
		uint32_t src;
		uint32_t status;
	};
	int ret;
	uint32_t func;
	uint32_t arg[4];
	uint32_t sp;
    union {
        uint32_t gp;
        uint32_t s2t1jmpba;
    };
	uint8_t code[SPLS2T1_MAXSZ - SPLS2T1_MINSZ];
} splv0_t1s2pb_t;
_Static_assert(sizeof(splv0_t1s2pb_t) == SPLS2T1_MAXSZ, "splv0_t1s2pb_t size mismatch");
// -^- USSM stage2 -^-

// -v- SK patch chain -v-
#define SPLSKFCHPE_SIMPLE 1
#define SPLSKFCHP_MAX_ENTRIES 8

/*
* TZS stuff
*/
#define SPLTZ_DDRFWAE_U64OFF (XBAR_CONFIG_DEV(MAIN_XBAR, XBAR_CFG_FAMILY_ACCESS_CONTROL, XBAR_TA_MXB_DEV_LPDDR0) + 0xA0)

#define TT_SECTION_SIZE (1024 * 1024)
#define TT_PAGE_SIZE (4096)
#define TT_LPAGE_SIZE (16 * TT_PAGE_SIZE)

#define LENUM_MASK(_s) ((1 << (1 + (_s##__L) - (_s))) - 1)
#define LENUM_PUT(_s, _v) (((_v) & LENUM_MASK(_s)) << (_s))
#define LENUM_GET(_s, _f) (((_f) >> (_s)) & LENUM_MASK(_s))

#define BENUM_MASK(_s) (1 << (_s))
#define BENUM_PUT(_s, _v) (((_v) & 1) << (_s))
#define BENUM_GET(_s, _f) (((_f) >> (_s)) & 1)

enum TTSDC_TYPES {
    TTSDC_T_INVALID = 0,
    TTSDC_T_L1_L2PT,
    TTSDC_T_L1_S,
    TTSDC_T_L1_SS,
    TTSDC_T_L2_LP,
    TTSDC_T_L2_SP,
    TTSDC_T__COUNT
};

enum TTSDC_MRAS {
    TTSDC_M_BUFFR = 0,
    TTSDC_M_CACHE,
    TTSDC_M_TEX,
    TTSDC_M_TEX__L = TTSDC_M_TEX + 2,
    TTSDC_M_S,
    TTSDC_M__COUNT
};


enum TTSDC_SECS {
    TTSDC_S_PXN,
    TTSDC_S_XN,
    TTSDC_S_NS,
    TTSDC_S_AP0,
    TTSDC_S_AP1,
    TTSDC_S_AP2,
    TTSDC_S__COUNT
};

enum TTSDC_MISCS {
    TTSDC_X_NG,
    TTSDC_X_IMP,
    TTSDC_X_DOMAIN,
    TTSDC_X_DOMAIN__L = TTSDC_X_DOMAIN + 3,
    TTSDC_X__COUNT
};

enum TTSDC_MPARS {
    TTSDC_MPAR_TYPE = 0,
    TTSDC_MPAR_TYPE__L = TTSDC_MPAR_TYPE + 2,
    TTSDC_MPAR_MRA,
    TTSDC_MPAR_MRA__L = (TTSDC_MPAR_MRA + (TTSDC_M__COUNT - 1)),
    TTSDC_MPAR_SEC,
    TTSDC_MPAR_SEC__L = (TTSDC_MPAR_SEC + (TTSDC_S__COUNT - 1)),
    TTSDC_MPAR_MISC,
    TTSDC_MPAR_MISC__L = (TTSDC_MPAR_MISC + (TTSDC_X__COUNT - 1))
};

#define TTSDC_MPAR_MASK(_e) (LENUM_MASK(TTSDC_MPAR##_e))
#define TTSDC_MPAR_PUT(_e, _v) (LENUM_PUT(TTSDC_MPAR##_e, _v))
#define TTSDC_MPAR_GET(_e, _p) (LENUM_GET(TTSDC_MPAR##_e, _p))


enum TTSDR_L1_L2PT_BITS {
    TTSDR_L1_L2PT_PXN = 2,
    TTSDR_L1_L2PT_NS,
    TTSDR_L1_L2PT_DOMAIN = 5,
    TTSDR_L1_L2PT_DOMAIN__L = TTSDR_L1_L2PT_DOMAIN + 3,
    TTSDR_L1_L2PT_IMP,
    TTSDR_L1_L2PT_ADDR,
    TTSDR_L1_L2PT_ADDR__L = TTSDR_L1_L2PT_ADDR + 21
};

enum TTSDR_L1_S_BITS {
    TTSDR_L1_S_B = 2,
    TTSDR_L1_S_C,
    TTSDR_L1_S_XN,
    TTSDR_L1_S_DOMAIN,
    TTSDR_L1_S_DOMAIN__L = TTSDR_L1_S_DOMAIN + 3,
    TTSDR_L1_S_IMP,
    TTSDR_L1_S_AP0,
    TTSDR_L1_S_AP1,
    TTSDR_L1_S_TEX,
    TTSDR_L1_S_TEX__L = TTSDR_L1_S_TEX + 2,
    TTSDR_L1_S_AP2,
    TTSDR_L1_S_S,
    TTSDR_L1_S_NG,
    TTSDR_L1_S_NS = 19,
    TTSDR_L1_S_ADDR,
    TTSDR_L1_S_ADDR__L = TTSDR_L1_S_ADDR + 11
};

enum TTSDR_L1_SS_BITS {
    TTSDR_L1_SS_B = 2,
    TTSDR_L1_SS_C,
    TTSDR_L1_SS_XN,
    TTSDR_L1_SS_XBAS3936,
    TTSDR_L1_SS_XBAS3936__L = TTSDR_L1_SS_XBAS3936 + 3,
    TTSDR_L1_SS_IMP,
    TTSDR_L1_SS_AP0,
    TTSDR_L1_SS_AP1,
    TTSDR_L1_SS_TEX,
    TTSDR_L1_SS_TEX__L = TTSDR_L1_SS_TEX + 2,
    TTSDR_L1_SS_AP2,
    TTSDR_L1_SS_S,
    TTSDR_L1_SS_NG,
    TTSDR_L1_SS_NS = 19,
    TTSDR_L1_SS_XBAS3532,
    TTSDR_L1_SS_XBAS3532__L = TTSDR_L1_SS_XBAS3532 + 3,
    TTSDR_L1_SS_ADDR,
    TTSDR_L1_SS_ADDR__L = TTSDR_L1_SS_ADDR + 7
};

enum TTSDR_L2_LP_BITS {
    TTSDR_L2_LP_B = 2,
    TTSDR_L2_LP_C,
    TTSDR_L2_LP_AP0,
    TTSDR_L2_LP_AP1,
    TTSDR_L2_LP_AP2 = 9,
    TTSDR_L2_LP_S,
    TTSDR_L2_LP_NG,
    TTSDR_L2_LP_TEX,
    TTSDR_L2_LP_TEX__L = TTSDR_L2_LP_TEX + 2,
    TTSDR_L2_LP_XN,
    TTSDR_L2_LP_ADDR,
    TTSDR_L2_LP_ADDR__L = TTSDR_L2_LP_ADDR + 15
};

enum TTSDR_L2_SP_BITS {
    TTSDR_L2_SP_XN = 0,
    TTSDR_L2_SP_B = 2,
    TTSDR_L2_SP_C,
    TTSDR_L2_SP_AP0,
    TTSDR_L2_SP_AP1,
    TTSDR_L2_SP_TEX,
    TTSDR_L2_SP_TEX__L = TTSDR_L2_SP_TEX + 2,
    TTSDR_L2_SP_AP2,
    TTSDR_L2_SP_S,
    TTSDR_L2_SP_NG,
    TTSDR_L2_SP_ADDR,
    TTSDR_L2_SP_ADDR__L = TTSDR_L2_SP_ADDR + 19
};

#define TTSDX_LMASK(_x, _y, _e) (LENUM_MASK(TTSD##_x##_##_y##_e))
#define TTSDX_BMASK(_x, _y, _e) (BENUM_MASK(TTSD##_x##_##_y##_e))
#define TTSDX_LPUT(_x, _y, _e, _v) (LENUM_PUT(TTSD##_x##_##_y##_e, (_v)))
#define TTSDX_BPUT(_x, _y, _e, _v) (BENUM_PUT(TTSD##_x##_##_y##_e, (_v)))
#define TTSDX_LGET(_x, _y, _e, _f) (LENUM_GET(TTSD##_x##_##_y##_e, (_f)))
#define TTSDX_BGET(_x, _y, _e, _f) (BENUM_GET(TTSD##_x##_##_y##_e, (_f)))

#define IS_AMOVW(insn)  ((((uint32_t)(insn) >> 20) & 0xFF) == 0x30)
#define MOVW_AGETA(insn) \
    ((((uint32_t)(insn) >> 16) & 0xFUL) << 12 | ((uint32_t)(insn) & 0xFFFUL))

#define IS_AMOVT(insn)  ((((uint32_t)(insn) >> 20) & 0xFF) == 0x34)
#define MOVT_AGETA(insn) \
    (((((uint32_t)(insn) >> 16) & 0xFUL) << 12 | ((uint32_t)(insn) & 0xFFFUL)) << 16)

#define IS_TMOVW(insn) (((uint32_t)(insn) & 0xFBF0) == 0xF240)
#define IS_TMOVT(insn) (((uint32_t)(insn) & 0xFBF0) == 0xF2C0)
#define MOVW_TGETA(insn) \
    ((((uint32_t)(insn) >> 16) & 0xFF) \
   | (((uint32_t)(insn) & 0xF) << 12) \
   | ((((uint32_t)(insn) >> 28) & 0b111) << 8) \
   | (((uint32_t)(insn) & 0x400) << 1))
#define MOVT_TGETA(insn) (MOVW_TGETA(insn) << 16)

#define IS_MOVW(insn)  (IS_AMOVW(insn) || IS_TMOVW(insn))
#define IS_MOVT(insn)  (IS_AMOVT(insn) || IS_TMOVT(insn))
#define MOVW_GETA(insn)  (IS_TMOVW(insn) ? MOVW_TGETA(insn) : MOVW_AGETA(insn))
#define MOVT_GETA(insn)  (IS_TMOVT(insn) ? MOVT_TGETA(insn) : MOVT_AGETA(insn))

#define TZS_SMC_FLUSH_L1C 0x10f

enum SPLP_TZS_OFF_ENTRIES {
    SPLTZOE_STATICS = 1,
    SPLTZOE_MODFIND,
    SPLTZOE_INTRMGR,
    SPLTZOE_SYSMEM,
};

enum SPLTZ_STATIC_ENTS {
    SPLTZ_STATIC_RST = 0,
    SPLTZ_STATIC_LEN,
    SPLTZ_STATIC_SYSROOT,
    SPLTZ_STATIC_TTBR0,
    SPLTZ_STATIC_TTBR1,
    SPLTZ_STATIC__COUNT
};

enum SPLTZ_MODFIND_OPES {
    SPLTZ_MFOPE_SMCP = 0, // (smc_off << 12) | smc_idx
    SPLTZ_MFOPE_WAT0x10, // val at *(.text+0x10)
    SPLTZ_MFOPE_DATAMP, // (m2data_off << 16) | data_movp_off
    SPLTZ_MFOPE__MSIZE,
    SPLTZ_MFOPE__COUNT = (SPLTZ_MFOPE__MSIZE * SPLTZ_MODINFO__COUNT)
};

enum SPLTZ_INTRMGR_OPES {
    SPLTZOPE_INTRMGR_SR_MHV_AO32 = 0, // (0xC7) : sysroot -> mon handler vectors
    SPLTZOPE_INTRMGR_MHV_SMCH_AO32, // (2 + 8) : mhv -> intrmgr's smc handler
    SPLTZOPE_INTRMGR_FSMCT_AO32, // (0xA280 - 0x2000) : fast smc table in .data
    SPLTZOPE_INTRMGR_P2SMCT_AO32, // (0xA6A0 - 0x2000) : ptr to normal smc table
    SPLTZOPE_INTRMGR_XW4KBMP_SYSMEM_AO32, // (0x13C4) : movp for sysmem export within first page
    SPLTZOPE_INTRMGR_XW4KBMP_EXCPMGR_AO32, // (0x1274) : excpmgr ^
    SPLTZOPE_INTRMGR_RET0, // (0x6a3) : intrmgr:ret0
    SPLTZOPE_INTRMGR_READ32, // (0x6BB) : &FFFF:intrmgr:read32 with mask &FFFF_0 deciding reg layout
    SPLTZOPE_INTRMGR_WRITE32, // (0x30B) : &FFFF:intrmgr:write32 with mask &FFFF_0 deciding reg layout
    SPLTZOPE_INTRMGR_PTESTO, // (0x4C) : some intrmgr addr to read from and compare with next
    SPLTZOPE_INTRMGR_PTESTV, // (0xF57FF01F) : exp result of read32 ^
    SPLTZOPE_INTRMGR__COUNT
};

enum SPLTZ_SYSMEM_OPES {
    SPLTZOPE_SYSMEM_XWSP, // (0x61) : sysmem:exec_with_sp(arg, sp, func)
    SPLTZOPE_SYSMEM_MBALLOC, // (0x4909) : sysmem:mballoc
    SPLTZOPE_SYSMEM_MBFREE, // (0x4AE9) : sysmem:mbfree
    SPLTZOPE_SYSMEM__COUNT
};

enum SPLTZ_ISMC_PARMS { // gadgets that can have diff arg lays
    SPLTZ_ISMC_PARM_WRITE32 = 0,
    SPLTZ_ISMC_PARM_READ32,
    SPLTZ_ISMC_PARM__COUNT
};

#define SPLTZ_ISMC_READ32_PARM_DIRPTR 1
#define SPLTZ_ISMC_WRITE32_PARM_DIRPTR 1
#define SPLTZ_ISMC_WRITE32_PARM_DIRVAL 2

struct tzs_layout_s {
    void *mbase;
    uint32_t statics[SPLTZ_STATIC__COUNT];
    uint32_t xsmct[2];
    struct {
        uint32_t text;
        uint32_t data;
    } msva[SPLTZ_MODINFO__COUNT];
    uint32_t ismcparm[SPLTZ_ISMC_PARM__COUNT];
};
#define SPLTZ_SMCT_FAST 0
#define SPLTZ_SMCT_FULL 1

extern const uint32_t SPLTZl_OPS[];
extern const int SPLTZl_OPS_len;


/*
* Internal global
*/
struct spl_root_s {
    uint32_t magic;
    uint32_t fw;
    struct {
        struct {
            void *va;
            uint32_t pa;
            int sz;
            bool busy;
            void *backup;
        } commem[SPLV0_COMMEM__COUNT];
        bool initialized;
        int xbusy;
    } lv0;
    struct {
        bool initialized;
        bool fw_dropped;
        struct tzs_layout_s layout;
    } tzs;
    uint32_t csum;
};
#define SPLROOT_MAGIC 'SPLR'
#define SPLROOT_MAXSZ 0xC0
_Static_assert(sizeof(struct spl_root_s) <= SPLROOT_MAXSZ, "fm_nfo struct too large!");

#define SPLOP_MAGIC 0xABCDEF00
#define SPLOP_MMASK 0xFFFFFF00
#define SPLOP_DMASK 0xFFFFFFF0
#define SPLOP_EMASK -1
#define SPLOP_DEMASK 0xF
#define SPLOPDE_START 0x0
#define SPLOPDE_EXTEND 0xE
#define SPLOPDE_END 0xF // MUST be the last entry
#define SPLOPEM_MINFW 0x1 // if entry is per fw then this
#define SPLOPEM_MAXFW 0x2
#define SPLOPEM_UNIQ 0x3 // start of per-entry uniq ems
#define SPLOPDEV(_d, _e) (SPLOP_MAGIC | (((_d) << 4) & 0xF0) | ((_e) & 0xF))
#define SPLOPDV(_d) (SPLOP_MAGIC | (((_d) << 4) & 0xF0))

enum SPLOP_DOMAINS {
    SPLOPD_SYS = 0,
    SPLOPD_LV0_SKFCHP,
    SPLOPD_LV0_STAGE2,
    SPLOPD_TZS_OFFS,
    SPLOPD_ANY = 0xF
};

extern struct spl_root_s *spl_root;
extern void *spl_imports;
extern char *spl_dbgId;
extern uint8_t *SPLl_FINDOPE(uint8_t *end, uint8_t *cur, enum SPLOP_DOMAINS domain, int find, uint32_t fw);
extern int SPLl_ROOTCHK(bool update);
extern int (*spl_tzs_write32)(uint32_t addr, uint32_t value);
extern int (*spl_lv0_write32)(uint32_t addr, uint32_t value);

// -v- IMPORTS -v-
#define SPLi_MEMSET(s, c, n) (((struct spl_import_s *)spl_imports)->memset((s), (c), (n)))
#define SPLi_MEMCPY(dest, src, n) (((struct spl_import_s *)spl_imports)->memcpy((dest), (src), (n)))
#define SPLi_PALLOC(paddr, size) (((struct spl_import_s *)spl_imports)->palloc((paddr), (size)))
#define SPLi_PFREE(va) (((struct spl_import_s *)spl_imports)->pfree((va)))
#define SPLi_MALLOC(size) (((struct spl_import_s *)spl_imports)->malloc((size)))
#define SPLi_FREE(ptr) (((struct spl_import_s *)spl_imports)->free((ptr)))
#define SPLi_LOADUSSM() (((struct spl_import_s *)spl_imports)->loadussm())
#define SPLi_CALLUSSM(cmdbuf) (((struct spl_import_s *)spl_imports)->callussm((cmdbuf)))
#define SPLi_UNLOADUSSM() (((struct spl_import_s *)spl_imports)->unloadussm())
#define SPLi_GETFW() (((struct spl_import_s *)spl_imports)->getfw())
#define SPLi_SMCALL(idx, a0, a1, a2, a3) (((struct spl_import_s *)spl_imports)->smcall((idx), (a0), (a1), (a2), (a3)))
#define SPLi_ERROR(_fmt, ...) (((struct spl_import_s *)spl_imports)->error("%s E: " _fmt, spl_dbgId, ##__VA_ARGS__))

#ifndef SPLIB_NODEBUG
    #define SPLi_DEBUG(_fmt, ...) (((struct spl_import_s *)spl_imports)->debug("%s I: " _fmt, spl_dbgId, ##__VA_ARGS__))
#else
    #define SPLi_DEBUG(...)
#endif // SPLIB_NODEBUG

#undef SPLTZ_MODINFO__COUNT // pretend you didnt see that
#undef SPLV0_COMMEM__COUNT // ^

#endif // __LIBSPL_INT_H__