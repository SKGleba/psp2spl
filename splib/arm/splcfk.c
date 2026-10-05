/*
 Example libspl -> kernel compatibility layer
    sorry for the AIO format ~SK
*/

#include <psp2kern/kernel/modulemgr.h>
#include <vitasdkkern.h>

#include "libspl.h"

#include "libspl-cfk.h"

typedef int bool;
#define true 1
#define false 0

#define ERRORF(_fmt, ...) ksceDebugPrintf("%s E: " _fmt, splCl_dbgId, ##__VA_ARGS__)
#ifndef SPLIB_NODEBUG
#define INFOF(_fmt, ...) if (!splCl_quiet) ksceDebugPrintf("%s I: " _fmt, splCl_dbgId, ##__VA_ARGS__)
#else
#define INFOF(_fmt, ...)
#endif
static char *splCl_dbgId = "[KSPL]";

/*
    lSPL CFK: misc
*/
#define SPL_MAX_MEMBLOCKS 16
static struct spl_memgr_s {
	int mb_count;
	struct {
		int mbid;
		void *va;
	} memblocks[SPL_MAX_MEMBLOCKS];
} spl_memgr = {
	.mb_count = 0,
	.memblocks = {{0}},
};

static int splCl_stub(void) {
	return 0;
}

static bool splCl_quiet = false;
static bool splCl_squiet(bool quiet, struct spl_import_s *sis) {
	bool prev = splCl_quiet;
	splCl_quiet = quiet;
	if (sis)
		sis->debug = splCl_quiet ? splCl_stub : ksceDebugPrintf;
	return prev;
}

static void *splCl_alloc(uint32_t paddr, uint32_t size) {
	if (spl_memgr.mb_count >= SPL_MAX_MEMBLOCKS)
		return NULL;
	SceKernelAllocMemBlockKernelOpt optp;
	memset(&optp, 0, sizeof(optp));
	optp.size = sizeof(optp);
	optp.attr = 2;
	optp.paddr = (paddr & ~0b11);
	int mbid = ksceKernelAllocMemBlock("", 0x10208006, size, (paddr & ~0b11) ? &optp : NULL);
	if (mbid < 0)
		return NULL;
	void *va = NULL;
	ksceKernelGetMemBlockBase(mbid, &va);
	if (!va) {
		ksceKernelFreeMemBlock(mbid);
		return NULL;
	}
	spl_memgr.mb_count++;
	for (int i = 0; i < SPL_MAX_MEMBLOCKS; i++) {
		if (!spl_memgr.memblocks[i].va) {
			spl_memgr.memblocks[i].mbid = mbid;
			spl_memgr.memblocks[i].va = va;
			break;
		}
	}
	INFOF("BA: %08X[%08X] <=> %08X(%08X)\n", (paddr & ~0b11), size, va, mbid);
	return va;
}

static void splCl_free(void *va) {
	int mbid = -1;
	for (int i = 0; i < SPL_MAX_MEMBLOCKS; i++) {
		if (spl_memgr.memblocks[i].va == va) {
			mbid = spl_memgr.memblocks[i].mbid;
			spl_memgr.memblocks[i].mbid = 0;
			spl_memgr.memblocks[i].va = NULL;
			spl_memgr.mb_count--;
			break;
		}
	}
	if (mbid >= 0 && ksceKernelFreeMemBlock(mbid) < 0)
		ERRORF("Failed to free memblock: %08x!\n", mbid);
	else
		INFOF("BF: %08x\n", mbid);
}

int splCl_smc(int a0, int a1, int a2, int a3, int idx);
__asm__ (
    ".text\n\t"
    ".global splCl_smc\n\t"
    ".type splCl_smc, %function\n\t"
    "splCl_smc:\n\t"
    "    ldr r12, [sp, #0x0]\n\t"
    "    smc #0\n\t"
    "    bx lr\n\t"
);

static void *splCl_kblp = NULL;
static void *splCl_getkblp(void) {
	if (!splCl_kblp)
		splCl_kblp = (void*)(*(uint32_t*)((uint32_t)ksceSysrootGetSysroot() + 0x6c));
	return splCl_kblp;
}


/*
    lSPL CFK: lv0 (f00d)
*/
// dfl sm_auth_info
static const unsigned char splCl_lv0_ctx_130_data[0x90] =
{
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x28, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
  0xc0, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
  0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x09,
  0x80, 0x03, 0x00, 0x00, 0xc3, 0x00, 0x00, 0x00, 0x80, 0x09,
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

struct lv0_ctx130_s {
    uint32_t unk_0;
    uint32_t self_type;  // 2 - user = 1 / kernel = 0
    char data0[0x90];    // hardcoded data
    char data1[0x90];
    uint32_t pathId;  // 2 (2 = os0)
    uint32_t unk_12C;
};

struct lv0_ussm_param_s {
    uint32_t magic; // for externals
    int akidx;
    void *cached;
    int size;
};

#define lv0_cmd_s splv0_cmd_s

static struct lv0_ussm_param_s *splCl_lv0_ussm_param = NULL;
static struct lv0_ussm_param_s splCl_lv0_ussm_param_l = {SPLV0_USSM_PARAM_MAGIC, 0, NULL, 0};

static int splCl_lv0_alloc_ussm(const char *path, uint32_t *out_ussm_fw) {
    int ret = 0;
    if (!path)
        return -1;
    if (!splCl_lv0_ussm_param || splCl_lv0_ussm_param->magic != (uint32_t)SPLV0_USSM_PARAM_MAGIC)
        splCl_lv0_ussm_param = &splCl_lv0_ussm_param_l;
    struct lv0_ussm_param_s *param = splCl_lv0_ussm_param;
    if (!param->cached) {
        INFOF("Allocating USSM from path: %s\n", path);
        param->akidx = 0;
        param->cached = splCl_alloc(0, 0xC000);
        if (!param->cached) {
            ERRORF("Failed to allocate USSM cache!\n");
            return -2;
        }
        SceIoStat stat;
        ret = ksceIoGetstat(path, &stat);
        if (ret < 0) {
            ERRORF("Failed to get USSM fstat: %08x!\n", ret);
l_splv0_csm_abt:
            splCl_free(param->cached);
            param->cached = NULL;
            param->size = 0;
            return ret;
        }
        param->size = stat.st_size;
        if (param->size > 0xC000) {
            ERRORF("USSM too large for cache: %08x!\n", param->size);
            goto l_splv0_csm_abt;
        }
        ret = ksceIoOpen(path, SCE_O_RDONLY, 0);
        if (ret < 0) {
            ERRORF("Failed to open USSM: %08x!\n", ret);
            goto l_splv0_csm_abt;
        }
        int fd = ret;
        ret = ksceIoRead(fd, param->cached, param->size);
        ksceIoClose(fd);
        if (ret < 0) {
            ERRORF("Failed to read USSM: %08x!\n", ret);
            goto l_splv0_csm_abt;
        }
        ret = 1;
    }
    param->akidx += 1;
    uint32_t fwv = *(uint32_t *)((uint32_t)param->cached + 0x92); // static from at least 0.940
    if (out_ussm_fw)
        *out_ussm_fw = fwv;
    INFOF("%s USSM cache: akidx=%d, cache=0x%08X, ussm_fw=0x%08X\n", ret > 0 ? "Allocated" : "Using existing", param->akidx, (uint32_t)param->cached, fwv);
    return ret;
}

static int splCl_lv0_free_ussm(void) {
    if (!splCl_lv0_ussm_param || splCl_lv0_ussm_param->magic != (uint32_t)SPLV0_USSM_PARAM_MAGIC)
        splCl_lv0_ussm_param = &splCl_lv0_ussm_param_l;
    struct lv0_ussm_param_s *param = splCl_lv0_ussm_param;
    param->akidx -= 1;
    if (param->cached && (param->akidx <= 0)) {
        INFOF("Freeing USSM cache\n");
        splCl_free(param->cached);
        param->cached = NULL;
        param->size = 0;
        param->akidx = 0;
    } else {
        INFOF("USSM cache still in use, akidx=%d, cache=0x%08X\n", param->akidx, (uint32_t)param->cached);
    }
    return 0;
}

static int splCl_lv0_ussm_loaded = -1;
static int splCl_lv0_load_ussm(void) {
	if (splCl_lv0_ussm_loaded >= 0) {
		ERRORF("USSM already loaded : %d!\n", splCl_lv0_ussm_loaded);
		return -1;
	}
    if (!splCl_lv0_ussm_param || splCl_lv0_ussm_param->magic != (uint32_t)SPLV0_USSM_PARAM_MAGIC)
        splCl_lv0_ussm_param = &splCl_lv0_ussm_param_l;
    struct lv0_ussm_param_s *param = splCl_lv0_ussm_param;
    if (!param->cached || !param->size) {
        ERRORF("USSM not allocated or empty!\n");
        return -2;
    }
    struct lv0_ctx130_s ctx;
    memset(&ctx, 0, sizeof(ctx));
    memcpy(ctx.data0, splCl_lv0_ctx_130_data, 0x90);
    ctx.pathId = 2;  // 2 = os0
    ctx.self_type = (ctx.self_type & 0xFFFFFFF0) | 2;
	return ksceSblSmCommStartSmFromData(0, param->cached, param->size, 0, &ctx, &splCl_lv0_ussm_loaded);
}

static int splCl_lv0_stop_ussm(void) {
    if (splCl_lv0_ussm_loaded < 0) {
        ERRORF("USSM not loaded!\n");
        return -1;
    }
    uint32_t stop_res[4];
    int ret = ksceSblSmCommStopSm(splCl_lv0_ussm_loaded, stop_res);
    if (ret < 0) {
        ERRORF("Failed to stop USSM: %08x!\n", ret);
        return ret;
    }
    splCl_lv0_ussm_loaded = -1;
    splCl_lv0_free_ussm();
    return 0;
}

static int splCl_lv0_call_ussm(void *argv) {
    struct lv0_cmd_s *cmd = (struct lv0_cmd_s *)argv;
    if (!argv || !cmd->size) {
		ERRORF("Invalid arguments for USSM call\n");
		return -1;
	}
    INFOF("lv0_call_ussm(svc=0x%X, argv=%08X, size=0x%X)\n", cmd->service_id, argv, cmd->size);
	if (splCl_lv0_ussm_loaded < 0) {
		ERRORF("USSM not loaded!\n");
		return -1;
	}
    cmd->response = -1;
    return ksceSblSmCommCallFunc(splCl_lv0_ussm_loaded, cmd->service_id, &cmd->response, argv + sizeof(struct lv0_cmd_s), cmd->size - sizeof(struct lv0_cmd_s));
}


/*
    lSPL CFK: libCL
*/
static struct spl_import_s splCl_imports;

static void *splCl_lCL_malloc(uint32_t size) {
	return splCl_alloc(0, size);
}

static uint32_t splCl_lcl_fwv = 0;
static uint32_t splCl_lCL_getfw(void) {
	if (!splCl_lcl_fwv)
		splCl_lcl_fwv = *(uint32_t*)((uint32_t)splCl_getkblp() + 4);
	return splCl_lcl_fwv;
}

static int splCl_lCL_smcall(int idx, int a0, int a1, int a2, int a3) {
	return splCl_smc(a0, a1, a2, a3, idx);
}

static struct spl_import_s *splCl_dispatch(void) {
	struct spl_import_s *sis = &splCl_imports;
	sis->memset = memset;
	sis->memcpy = memcpy;
	sis->palloc = splCl_alloc;
	sis->pfree = splCl_free;
	sis->malloc = splCl_lCL_malloc;
	sis->free = splCl_free;
	sis->loadussm = splCl_lv0_load_ussm;
	sis->callussm = splCl_lv0_call_ussm;
	sis->unloadussm = splCl_lv0_stop_ussm;
	sis->getfw = splCl_lCL_getfw;
	sis->smcall = splCl_lCL_smcall;
	sis->debug = splCl_quiet ? splCl_stub : ksceDebugPrintf;
	sis->error = ksceDebugPrintf;
	return sis;
}


/*
    lSPL CFK: exports
*/
static struct spl_import_s *splCl_sis = NULL;
static char *splCl_ussm_path = SPL_CFK_USSM_DEFAULT_PATH;
struct spl_selective_s SPLx_CFK_SEL = {0};
static struct spl_selective_s *splCl_selective = NULL;
static struct spl_init_arg_s splCl_initArg;
void SPLx_CFK_PREPS(char *ussm_path, bool quiet, char *dbgid, struct spl_selective_s *sel) {
	splCl_sis = splCl_dispatch();
    splCl_squiet(quiet, splCl_sis);
    splCl_selective = sel;
	if (!ussm_path) {
        SceIoStat stat;
	    if (ksceIoGetstat(SPL_CFK_USSM_HFW_PATH, &stat) >= 0)
		    splCl_ussm_path = SPL_CFK_USSM_HFW_PATH;
    }
    if (dbgid)
		splCl_dbgId = dbgid;
}

int SPLx_CFK_INIT(int flags, bool quiet, bool inherit, bool alloc, enum SPLV0_COMMBACKUP_MODES backup_mode) {
    bool pq = splCl_squiet(quiet, splCl_sis);
    struct spl_init_arg_s *arg = &splCl_initArg;
	memset(arg, 0, sizeof(struct spl_init_arg_s));
	void *kblp_va = splCl_getkblp();
	if (kblp_va && (*(uint32_t *)kblp_va == 0x02000001) && inherit) {
        INFOF("Using KBLP for bufC0 & USSM params\n");
		arg->bufC0 = (void*)((uint32_t)kblp_va + 0x120);
		splCl_lv0_ussm_param = (void*)((uint32_t)kblp_va + 0x120 + 0xC0);
        if (splCl_lv0_ussm_param->magic != (uint32_t)SPLV0_USSM_PARAM_MAGIC) {
            memset(splCl_lv0_ussm_param, 0, sizeof(struct lv0_ussm_param_s));
		    splCl_lv0_ussm_param->magic = (uint32_t)SPLV0_USSM_PARAM_MAGIC;
        }
	} else {
		arg->bufC0 = NULL;
		splCl_lv0_ussm_param = NULL;
	}
	arg->imports = splCl_sis;
	arg->ifl = flags & ~(SPL_IFL(_LV0) | SPL_IFL(_TZS)); //nop
	arg->lv0_backup_mode = backup_mode;
	arg->dbgid = splCl_dbgId;
    arg->fw_override = 0;
    arg->sel = splCl_selective;
    int ret = SPLx_INIT(arg);
    if (ret >= 0) {
        if (ret & SPL_IFL(_LV0))
            splCl_lcl_fwv = arg->fw_override;
        else if (alloc)
            ret = splCl_lv0_alloc_ussm(splCl_ussm_path, &arg->fw_override);
        arg->ifl = flags;
        if (ret >= 0) {
            ret = SPLx_INIT(arg);
            if (ret < 0)
                ERRORF("SPLx_INIT returned %d\n", ret);
        }
    } else
        ERRORF("BUG: nop SPLx_INIT ret %d\n", ret);
	splCl_squiet(pq, splCl_sis);
	return ret;
}

int SPLx_CFK_DEINIT(int flags) {
    splCl_initArg.ifl = flags;
    int ret = SPLx_DEINIT(&splCl_initArg);
    if (ret < 0)
        ERRORF("SPLx_DEINIT returned %d\n", ret);
    memset(&splCl_initArg, 0, sizeof(struct spl_init_arg_s));
    return ret;
}

int SPLx_CFK_USSMALLOC(void) {
    return splCl_lv0_alloc_ussm(splCl_ussm_path, &splCl_lcl_fwv);
}