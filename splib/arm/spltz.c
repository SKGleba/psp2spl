#include "libspl-int.h"
#include "libspl.h"

static uint32_t SPLTZl_TT_SDGETPAR(uint32_t sdescr, uint32_t l2p, uint32_t *paddr) {
    uint32_t parm = l2p &~ TTSDC_MPAR_MASK(_TYPE);

    // TYPE
    enum TTSDC_TYPES type = TTSDC_T_INVALID;
    switch (sdescr & 0b11) {
        case 0b01:
            if (l2p)
                type = TTSDC_T_L2_LP;
            else
                type = TTSDC_T_L1_L2PT;
            break;
        case 0b10:
            if (l2p)
                type = TTSDC_T_L2_SP;
            else if (sdescr & (1 << 18))
                type = TTSDC_T_L1_SS;
            else
                type = TTSDC_T_L1_S;
            break;
        case 0b11:
            if (l2p) {
                type = TTSDC_T_L2_SP;
                break;
            }
        default:
            return 0;
    }
    parm |= TTSDC_MPAR_PUT(_TYPE, type);

    // Mem region attrs
    uint32_t wb = 0;
    if (type != TTSDC_T_L1_L2PT) {
        wb |= TTSDX_BPUT(C, M, _BUFFR, (TTSDX_BGET(R, L1_S, _B, sdescr)));
        wb |= TTSDX_BPUT(C, M, _CACHE, (TTSDX_BGET(R, L1_S, _C, sdescr)));
        switch (type) {
            case TTSDC_T_L2_LP:
            case TTSDC_T_L2_SP:
                wb |= TTSDX_BPUT(C, M, _S, (TTSDX_BGET(R, L2_SP, _S, sdescr)));
                if (type == TTSDC_T_L2_SP)
                    wb |= TTSDX_LPUT(C, M, _TEX, (TTSDX_LGET(R, L2_SP, _TEX, sdescr)));
                else
                    wb |= TTSDX_LPUT(C, M, _TEX, (TTSDX_LGET(R, L2_LP, _TEX, sdescr)));
                break;
            default:
                wb |= TTSDX_BPUT(C, M, _S, (TTSDX_BGET(R, L1_S, _S, sdescr)));
                wb |= TTSDX_LPUT(C, M, _TEX, (TTSDX_LGET(R, L1_S, _TEX, sdescr)));
                break;
        }
        parm |= TTSDC_MPAR_PUT(_MRA, wb);
    }
    
    // Security attrs
    wb = 0;
    switch (type) {
        case TTSDC_T_L2_LP:
        case TTSDC_T_L2_SP:
            wb |= TTSDX_BPUT(C, S, _AP0, (TTSDX_BGET(R, L2_SP, _AP0, sdescr)));
            wb |= TTSDX_BPUT(C, S, _AP1, (TTSDX_BGET(R, L2_SP, _AP1, sdescr)));
            wb |= TTSDX_BPUT(C, S, _AP2, (TTSDX_BGET(R, L2_SP, _AP2, sdescr)));
            if (type == TTSDC_T_L2_SP)
                wb |= TTSDX_BPUT(C, S, _XN, (TTSDX_BGET(R, L2_SP, _XN, sdescr)));
            else
                wb |= TTSDX_BPUT(C, S, _XN, (TTSDX_BGET(R, L2_LP, _XN, sdescr)));
            break;
        case TTSDC_T_L1_L2PT:
            wb |= TTSDX_BPUT(C, S, _PXN, (TTSDX_BGET(R, L1_L2PT, _PXN, sdescr)));
            wb |= TTSDX_BPUT(C, S, _NS, (TTSDX_BGET(R, L1_L2PT, _NS, sdescr)));
            break;
        default:
            wb |= TTSDX_BPUT(C, S, _AP0, (TTSDX_BGET(R, L1_S, _AP0, sdescr)));
            wb |= TTSDX_BPUT(C, S, _AP1, (TTSDX_BGET(R, L1_S, _AP1, sdescr)));
            wb |= TTSDX_BPUT(C, S, _AP2, (TTSDX_BGET(R, L1_S, _AP2, sdescr)));
            wb |= TTSDX_BPUT(C, S, _XN, (TTSDX_BGET(R, L1_S, _XN, sdescr)));
            wb |= TTSDX_BPUT(C, S, _NS, (TTSDX_BGET(R, L1_S, _NS, sdescr)));
            break;
    }
    parm |= TTSDC_MPAR_PUT(_SEC, wb);

    // Misc
    wb = 0;
    switch (type) {
        case TTSDC_T_L2_LP:
        case TTSDC_T_L2_SP:
            wb |= TTSDX_BPUT(C, X, _NG, (TTSDX_BGET(R, L2_SP, _NG, sdescr)));
            break;
        default:
            if (type != TTSDC_T_L1_L2PT)
                wb |= TTSDX_BPUT(C, X, _NG, (TTSDX_BGET(R, L1_S, _NG, sdescr)));
            wb |= TTSDX_BPUT(C, X, _IMP, (TTSDX_BGET(R, L1_S, _IMP, sdescr)));
            if (type != TTSDC_T_L1_SS)
                wb |= TTSDX_LPUT(C, X, _DOMAIN, (TTSDX_LGET(R, L1_S, _DOMAIN, sdescr)));
            break;
    }
    parm |= TTSDC_MPAR_PUT(_MISC, wb);

    if (paddr) {
        switch (type) {
            case TTSDC_T_L2_SP: *paddr = (TTSDX_LGET(R, L2_SP, _ADDR, sdescr) << TTSDR_L2_SP_ADDR); break;
            case TTSDC_T_L2_LP: *paddr = (TTSDX_LGET(R, L2_LP, _ADDR, sdescr) << TTSDR_L2_LP_ADDR); break;
            case TTSDC_T_L1_S: *paddr = (TTSDX_LGET(R, L1_S, _ADDR, sdescr) << TTSDR_L1_S_ADDR); break;
            case TTSDC_T_L1_L2PT: *paddr = (TTSDX_LGET(R, L1_L2PT, _ADDR, sdescr) << TTSDR_L1_L2PT_ADDR); break;
            default: // TODO: xbase, though we are on a 32bit sys?
                *paddr = (TTSDX_LGET(R, L1_SS, _ADDR, sdescr) << TTSDR_L1_SS_ADDR);
                break;
        }
    }

    return parm;
}

#ifndef SPLIB_NODEBUG
static const char *SPLTZl_TT_SDPAR_T2S[TTSDC_T__COUNT] = {
    [TTSDC_T_INVALID] = "INVALID",
    [TTSDC_T_L1_L2PT] = "L1_L2TBL",
    [TTSDC_T_L1_S] = "L1_SECTn",
    [TTSDC_T_L1_SS] = "L1_LARGE",
    [TTSDC_T_L2_LP] = "L2_LARGE",
    [TTSDC_T_L2_SP] = "L2_SMALL"
};

static const char *SPLTZl_TT_SDPAR_T2SS[TTSDC_T__COUNT] = {
    [TTSDC_T_INVALID] = "0K",
    [TTSDC_T_L1_L2PT] = "1M",
    [TTSDC_T_L1_S] = "1M",
    [TTSDC_T_L1_SS] = "16M",
    [TTSDC_T_L2_LP] = "64K",
    [TTSDC_T_L2_SP] = "4K"
};

static inline void SPLTZl_TT_SDPARPRINT(uint32_t pparm, uint32_t paddr, uint32_t va) {
    if (!pparm && !paddr && !va) {
        SPLi_DEBUG("TYPE VADDR [SZ] <-> PADDR : SCB, TEX : XNS, AP20 : MISC, DOMAIN\n");
        return;
    }
    int type = TTSDC_MPAR_GET(_TYPE, pparm);
    if (!type || type >= TTSDC_T__COUNT) {
        SPLi_DEBUG("INVALID (%d 0x%08X <-> 0x%08X)\n", type, va, paddr);
        return;
    }
    uint32_t mra = TTSDC_MPAR_GET(_MRA, pparm);
    uint32_t sec = TTSDC_MPAR_GET(_SEC, pparm);
    uint32_t misc = TTSDC_MPAR_GET(_MISC, pparm);
    SPLi_DEBUG("%s 0x%08X [%s] %s 0x%08X : %s%s%s, 0x%X : %s%s%s, %d%d%d : %s%s, 0x%X\n", 
        SPLTZl_TT_SDPAR_T2S[type], va, SPLTZl_TT_SDPAR_T2SS[type], 
        (type == TTSDC_T_L1_L2PT) ? "<-" : "->", paddr,
        TTSDX_BGET(C, M, _S, mra) ? " S" : "",
        TTSDX_BGET(C, M, _CACHE, mra) ? " C" : "",
        TTSDX_BGET(C, M, _BUFFR, mra) ? " B" : "",
        TTSDX_LGET(C, M, _TEX, mra),
        TTSDX_BGET(C, S, _PXN, sec) ? " PXN" : "",
        TTSDX_BGET(C, S, _XN, sec) ? " XN" : "",
        TTSDX_BGET(C, S, _NS, sec) ? " NS" : "",
        TTSDX_BGET(C, S, _AP2, sec),
        TTSDX_BGET(C, S, _AP1, sec),
        TTSDX_BGET(C, S, _AP0, sec),
        TTSDX_BGET(C, X, _NG, misc) ? " nG" : "",
        TTSDX_BGET(C, X, _IMP, misc) ? " IMPL" : "",
        TTSDX_LGET(C, X, _DOMAIN, misc)
    );
}

int SPLx_TZS_PRINTTBR(bool printl2) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    struct tzs_layout_s *layout = &spl_root->tzs.layout;
    volatile uint32_t *ttbr = NULL;
    for (int t = 0; t < 2; t++) {
        SPLi_DEBUG("=== TTBR%d ===\n", t);
        ttbr = (volatile uint32_t *)((uint32_t)layout->mbase + layout->statics[SPLTZ_STATIC_TTBR0 + t]);
        SPLTZl_TT_SDPARPRINT(0, 0, 0);
        uint32_t paddr = 0, pparm = 0;
        for (int i = 0; i < 4096; i++) {
            paddr = 0;
            pparm = SPLTZl_TT_SDGETPAR(ttbr[i], 0, &paddr);
            if (!pparm)
                continue;
            SPLTZl_TT_SDPARPRINT(pparm, paddr, i * TT_SECTION_SIZE);
            if (printl2 && (TTSDC_MPAR_GET(_TYPE, pparm) == TTSDC_T_L1_L2PT) && paddr) {
                uint32_t l2pt_off = paddr - layout->statics[SPLTZ_STATIC_RST];
                if (l2pt_off >= layout->statics[SPLTZ_STATIC_LEN])
                    continue;
                volatile uint32_t *l2ptv = (volatile uint32_t *)((uint32_t)layout->mbase + l2pt_off);
                uint32_t l2parm = 0;
                for (int j = 0; j < 256; j++) {
                    paddr = 0;
                    l2parm = SPLTZl_TT_SDGETPAR(l2ptv[j], pparm, &paddr);
                    if (!TTSDC_MPAR_GET(_TYPE, l2parm))
                        continue;
                    if (((TTSDC_MPAR_GET(_TYPE, l2parm) == TTSDC_T_L2_SP) || (!(j % 16) && (TTSDC_MPAR_GET(_TYPE, l2parm) == TTSDC_T_L2_LP))) && paddr)
                        SPLTZl_TT_SDPARPRINT(l2parm, paddr, (i * TT_SECTION_SIZE) + (j * TT_PAGE_SIZE));
                }
                SPLi_DEBUG("\n");
            }
        }
    }
    return 0;
}
#endif /* SPLIB_NODEBUG */

int SPLx_TZS_SVA2PA(uint32_t sva, uint32_t *rpa) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    if (!rpa)
        return -SPL_EBADARG;
    struct tzs_layout_s *layout = &spl_root->tzs.layout;
    volatile uint32_t *ttbr = NULL;
    uint32_t pparm = 0, paddr = 0, type = 0;
    for (int t = 0; t < 2; t++) {
        ttbr = (volatile uint32_t *)((uint32_t)layout->mbase + layout->statics[SPLTZ_STATIC_TTBR0 + t]);
        pparm = SPLTZl_TT_SDGETPAR(ttbr[sva / TT_SECTION_SIZE], 0, &paddr);
        type = TTSDC_MPAR_GET(_TYPE, pparm);
        if (pparm && (type != TTSDC_T_INVALID) && (type < TTSDC_T_L2_LP)) {
            if (type == TTSDC_T_L1_S) {
                *rpa = paddr + (sva % TT_SECTION_SIZE);
                return 0;
            } else if (type == TTSDC_T_L1_L2PT) {
                if ((paddr < layout->statics[SPLTZ_STATIC_RST]) || (paddr >= (layout->statics[SPLTZ_STATIC_RST] + layout->statics[SPLTZ_STATIC_LEN]))) {
                    SPLi_ERROR("tzs_va2pa: L2PT sPA out of nsVA range: 0x%08X!\n", paddr);
                    return -SPL_TZSV2P_EOOSRANGE;
                }
                volatile uint32_t *l2ptv = (volatile uint32_t *)((uint32_t)layout->mbase + (paddr - layout->statics[SPLTZ_STATIC_RST]));
                pparm = SPLTZl_TT_SDGETPAR(l2ptv[(sva % TT_SECTION_SIZE) / TT_PAGE_SIZE], pparm, &paddr);
                type = TTSDC_MPAR_GET(_TYPE, pparm);
                if (pparm) {
                    if (type == TTSDC_T_L2_SP)
                        *rpa = paddr + (sva % TT_PAGE_SIZE);
                    else
                        *rpa = paddr + (sva % TT_LPAGE_SIZE);
                    return 0;
                }
            } else {
                SPLi_ERROR("tzs_va2pa: Unexpected L1PT entry: %X\n", pparm);
                return -SPL_TZSV2P_EUNRL1PTE;
            }
        }
    }
    return -SPL_TZSV2P_E404;
}

int SPLx_TZS_SVA2NSVA(uint32_t sva, void **rnsva) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    if (!rnsva)
        return -SPL_EBADARG;
    struct tzs_layout_s *layout = &spl_root->tzs.layout;
    uint32_t pa = 0;
    int ret = SPLx_TZS_SVA2PA(sva, &pa);
    if (ret < 0)
        return ret;
    if ((pa < layout->statics[SPLTZ_STATIC_RST]) || (pa >= (layout->statics[SPLTZ_STATIC_RST] + layout->statics[SPLTZ_STATIC_LEN]))) {
        SPLi_ERROR("tzs_sva2nsva: sPA out of nsVA range: 0x%08X\n", pa);
        return -SPL_TZSV2P_EOOSRANGE;
    }
    //SPLi_DEBUG("tzs_sva2nsva: sVA 0x%08X -> sPA 0x%08X -> nsVA 0x%08X\n", sva, pa, (uint32_t)layout->mbase + (pa - layout->statics[SPLTZ_STATIC_RST]));
    *rnsva = (void *)((uint32_t)layout->mbase + (pa - layout->statics[SPLTZ_STATIC_RST]));
    return 0;
}

// Futureproof :tm:
int SPLx_TZS_READ32(uint32_t sva, uint32_t *rval) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    if (!rval)
        return -SPL_EBADARG;
    struct tzs_layout_s *layout = &spl_root->tzs.layout;
    uint32_t parm = layout->ismcparm[SPLTZ_ISMC_PARM_READ32] >> 16;
    uint32_t arg[4];
    for (int i = 0; i < 4; i++) {
        switch ((parm >> (i * 4)) & 0xF) {
            case SPLTZ_ISMC_READ32_PARM_DIRPTR:
                arg[i] = (uint32_t)sva;
                break;
            default:
                arg[i] = 0;
                break;
        }
    }
    SPLi_DEBUG("tzs_read32: sva=0x%08X, arg={0x%08X, 0x%08X, 0x%08X, 0x%08X}\n", sva, arg[0], arg[1], arg[2], arg[3]);
    *rval = (uint32_t)SPLi_SMCALL((SPLTZ_SMC_READ32P), arg[0], arg[1], arg[2], arg[3]);
    return 0;
}

int SPLx_TZS_WRITE32(uint32_t sva, uint32_t val) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    struct tzs_layout_s *layout = &spl_root->tzs.layout;
    uint32_t parm = layout->ismcparm[SPLTZ_ISMC_PARM_WRITE32] >> 16;
    uint32_t arg[4];
    for (int i = 0; i < 4; i++) {
        switch ((parm >> (i * 4)) & 0xF) {
            case SPLTZ_ISMC_WRITE32_PARM_DIRPTR:
                arg[i] = (uint32_t)sva;
                break;
            case SPLTZ_ISMC_WRITE32_PARM_DIRVAL:
                arg[i] = val;
                break;
            default:
                arg[i] = 0;
                break;
        }
    }
    SPLi_DEBUG("tzs_write32: sva=0x%08X, val=0x%08X, arg={0x%08X, 0x%08X, 0x%08X, 0x%08X}\n", sva, val, arg[0], arg[1], arg[2], arg[3]);
    SPLi_SMCALL((SPLTZ_SMC_WRITE32P), arg[0], arg[1], arg[2], arg[3]);
    return 0;
}

int SPLx_TZS_GETMODSVA(enum SPLTZ_MODINFO_ENTS mod, int seg, uint32_t off, uint32_t *rsva);

int SPLx_TZS_SMC_SET(int idx, int funcsva) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    SPLi_DEBUG("SMC_SET(0x%X): funcsva=0x%08X\n", idx, funcsva);
    if (idx < 0 || idx > 0x4FF)
        return -SPL_EBADARG;

    int ret = 0;
    struct tzs_layout_s *layout = &spl_root->tzs.layout;
    if (!layout->xsmct[0] || !layout->xsmct[1]) {
        uint32_t *fope = (uint32_t *)SPLl_FINDOPE((uint8_t*)((uint32_t)SPLTZl_OPS + SPLTZl_OPS_len), (uint8_t*)SPLTZl_OPS, SPLOPD_TZS_OFFS, SPLTZOE_INTRMGR, spl_root->fw);
        if (!fope) { 
            SPLi_ERROR("No OPEs available for m%d on fw=0x%08X\n", 0, spl_root->fw); 
            return -SPL_EBADARG; 
        }
        ret = SPLx_TZS_GETMODSVA(SPLTZ_MODINFO_INTRMGR, 1, fope[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_FSMCT_AO32], &layout->xsmct[SPLTZ_SMCT_FAST]);
        if (ret < 0)
            return ret;
        SPLl_ROOTCHK(true);
        uint32_t wb = fope[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_P2SMCT_AO32];
        ret = SPLx_TZS_GETMODSVA(SPLTZ_MODINFO_INTRMGR, 1, wb, &wb);
        if (ret < 0)
            return ret;
        ret = SPLx_TZS_SVA2NSVA(wb, (void*)&wb);
        if (ret < 0) { 
            SPLi_ERROR("Failed to get m%d %d+0x%X SVA: ret=%d\n", SPLTZ_MODINFO_INTRMGR, 1, fope[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_P2SMCT_AO32], ret); 
            return ret; 
        }
        layout->xsmct[SPLTZ_SMCT_FULL] = *(uint32_t*)wb;
        SPLl_ROOTCHK(true);
        SPLi_DEBUG("TZS3: xsmct: 0x%08X, 0x%08X\n", layout->xsmct[SPLTZ_SMCT_FAST], layout->xsmct[SPLTZ_SMCT_FULL]);
    }

    int idxsva = (idx < 0x100) 
        ? (layout->xsmct[SPLTZ_SMCT_FAST] + (idx * sizeof(uint32_t))) 
        : (layout->xsmct[SPLTZ_SMCT_FULL] + ((idx - 0x100) * sizeof(uint32_t)));
    if ((funcsva < 0) || !spl_tzs_write32) {
        if (!spl_tzs_write32) {
            int *idxnsva = NULL;
            ret = SPLx_TZS_SVA2NSVA(idxsva, (void*)&idxnsva);
            if ((ret < 0) || !idxnsva) { 
                SPLi_ERROR("Failed to get SMC 0x%X NSVA: ret=%d|0x%08X\n", idx, ret, (uint32_t)idxnsva); 
                return ret; 
            }
            if (funcsva >= 0) {
                *idxnsva = funcsva;
                return SPLi_SMCALL(TZS_SMC_FLUSH_L1C, 0, 0, 0, 0);
            }
            return *idxnsva;
        }
        ret = SPLx_TZS_READ32(idxsva, (uint32_t*)&funcsva);
        if (ret < 0)
            return ret;
        return funcsva;
    }
    return SPLx_TZS_WRITE32(idxsva, funcsva);
}

int SPLx_TZS_GETMODSVA(enum SPLTZ_MODINFO_ENTS mod, int seg, uint32_t off, uint32_t *rsva) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    if (!rsva || (mod >= SPLTZ_MODINFO__COUNT) || (seg && (seg != 1)))
        return -SPL_EBADARG;
    struct tzs_layout_s *layout = &spl_root->tzs.layout;
    if (!layout->msva[mod].text || !layout->msva[mod].data) {
        volatile uint32_t *sb = NULL;
        uint32_t *fope = NULL;
        uint32_t wb;
        int ret = 0;
        switch (mod) {
            case SPLTZ_MODINFO_INTRMGR:
            case SPLTZ_MODINFO_SYSMEM:
            case SPLTZ_MODINFO_EXCPMGR:
                if (!layout->msva[mod].text) {
                    fope = (uint32_t *)SPLl_FINDOPE((uint8_t*)((uint32_t)SPLTZl_OPS + SPLTZl_OPS_len), (uint8_t*)SPLTZl_OPS, SPLOPD_TZS_OFFS, SPLTZOE_INTRMGR, spl_root->fw);
                    if (!fope) { 
                        SPLi_ERROR("No OPEs available for m%d on fw=0x%08X\n", SPLTZ_MODINFO_INTRMGR, spl_root->fw); 
                        return -SPL_TZSGMSV_EBADICFG; 
                    }
                    if (mod == SPLTZ_MODINFO_INTRMGR) {
                        sb = (volatile uint32_t *)((uint32_t)layout->mbase + layout->statics[SPLTZ_STATIC_SYSROOT]);
                        wb = sb[fope[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_SR_MHV_AO32]];
                    } else if (mod == SPLTZ_MODINFO_SYSMEM)
                        wb = fope[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_XW4KBMP_SYSMEM_AO32] + layout->msva[SPLTZ_MODINFO_INTRMGR].text;
                    else
                        wb = fope[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_XW4KBMP_EXCPMGR_AO32] + layout->msva[SPLTZ_MODINFO_INTRMGR].text;
                    ret = SPLx_TZS_SVA2NSVA(wb, (void*)&sb);
                    if (ret < 0) { 
                        SPLi_ERROR("Failed to get m%d .text W4KB(m%d, 0x%08X) nsva: %d\n", SPLTZ_MODINFO_INTRMGR, mod, wb, ret); 
                        return ret; 
                    }
                    if (mod == SPLTZ_MODINFO_INTRMGR)
                        layout->msva[mod].text = sb[fope[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_MHV_SMCH_AO32]] & ~0xFFF;
                    else {
                        if (!IS_MOVW(sb[0]) || !IS_MOVT(sb[1])) { 
                            SPLi_ERROR("!movp @ mod %d .text(0x%08X+0x%X): [0x%08X, 0x%08X, 0x%08X, 0x%08X]\n", 0, layout->msva[0].text, wb, sb[0], sb[1], sb[2], sb[3]);
                            return -SPL_TZSGMSV_EBADMOVP; 
                        }
                        layout->msva[mod].text = (MOVW_GETA(sb[0]) | MOVT_GETA(sb[1])) & ~0xFFF; 
                    }
                    SPLl_ROOTCHK(true);
                }
            default:
                fope = (uint32_t *)SPLl_FINDOPE((uint8_t*)((uint32_t)SPLTZl_OPS + SPLTZl_OPS_len), (uint8_t*)SPLTZl_OPS, SPLOPD_TZS_OFFS, SPLTZOE_MODFIND, spl_root->fw);
                if (!fope) { 
                    SPLi_ERROR("No OPEs available for m%d on fw=0x%08X\n", mod, spl_root->fw); 
                    return -SPL_TZSGMSV_EBADICFG; 
                }
                if (!layout->msva[mod].text) {
                    if (!layout->xsmct[0] || !layout->xsmct[1]) {
                        SPLi_ERROR("BUG: xsmct not initialized! mod=%d\n", mod);
                        return -SPL_EBADARG;
                    }
                    wb = fope[SPLOPEM_UNIQ + (SPLTZ_MFOPE__MSIZE * mod) + SPLTZ_MFOPE_SMCP];
                    if (!wb) {
                        SPLi_ERROR("Invalid SMCp for m%d\n", mod);
                        return -SPL_TZSGMSV_EBADICFG;
                    }
                    ret = SPLx_TZS_SMC_SET(wb & 0xFFF, -1);
                    if (ret < 0) { 
                        SPLi_ERROR("Failed to get SMC 0x%08X: %d\n", wb, ret); 
                        return ret; 
                    }
                    layout->msva[mod].text = ret - (wb >> 12);
                    SPLl_ROOTCHK(true);
                }
                ret = SPLx_TZS_SVA2NSVA(layout->msva[mod].text + 0x10, (void*)&sb);
                if (ret < 0) { 
                    SPLi_ERROR("Failed to get m%d %d+0x%X SVA: ret=%d\n", mod, 0, 0x10, ret); 
                    return ret; 
                }
                if (sb[0] != fope[SPLOPEM_UNIQ + (SPLTZ_MFOPE__MSIZE * mod) + SPLTZ_MFOPE_WAT0x10]) { 
                    SPLi_ERROR("Unexpected value at m%d .text+0x10: [0x%08X, 0x%08X]\n", mod, sb[0], sb[1]); 
                    return -SPL_TZSGMSV_EBADICFG; 
                }
                if (!layout->msva[mod].data && (wb = fope[SPLOPEM_UNIQ + (SPLTZ_MFOPE__MSIZE * mod) + SPLTZ_MFOPE_DATAMP], wb)) {
                    ret = SPLx_TZS_SVA2NSVA(layout->msva[mod].text + (wb & 0xFFFF), (void*)&sb);
                    if (ret < 0) { 
                        SPLi_ERROR("Failed to get m%d %d+0x%X SVA: ret=%d\n", mod, 1, wb & 0xFFFF, ret); 
                        return ret; 
                    }
                    if (!IS_MOVW(sb[0]) || !IS_MOVT(sb[1])) { 
                        SPLi_ERROR("!movp @ mod %d .text(0x%08X+0x%X): [0x%08X, 0x%08X, 0x%08X, 0x%08X]\n", mod, layout->msva[mod].text, wb & 0xFFFF, sb[0], sb[1], sb[2], sb[3]);
                        return -SPL_TZSGMSV_EBADMOVP; 
                    }
                    layout->msva[mod].data = (uint32_t)(MOVW_GETA(sb[0]) | MOVT_GETA(sb[1])) - (uint32_t)((wb >> 16) & 0xFFFF);
                    SPLl_ROOTCHK(true);
                }
                SPLi_DEBUG("TZSGMS: m%d .text: 0x%08X | .data: 0x%08X\n", mod, layout->msva[mod].text, layout->msva[mod].data);
                break;
        }
    }

    switch (seg) {
        case 0: 
            *rsva = layout->msva[mod].text + off;
        break; case 1: 
            *rsva = layout->msva[mod].data + off;
        break; default:
            return -SPL_EBADARG;
    }
    return 0;
}

int SPLx_TZS_INIT(void) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    if (spl_root->tzs.initialized)
        return 0;

    int ret = 0;
    if (!spl_root->tzs.fw_dropped) {
        if (!spl_root->lv0.initialized || !spl_lv0_write32) {
            SPLi_ERROR("TZSI: LV0 not initialized => cannot drop firewall\n");
            return -SPL_TZSI_ENOLV0I;
        }
        ret = spl_lv0_write32(SPLTZ_DDRFWAE_U64OFF, 0x0);
        if (ret >= 0)
            ret = spl_lv0_write32(SPLTZ_DDRFWAE_U64OFF + 4, 0x0);
        if (ret < 0) {
            SPLi_ERROR("TZSI: Failed to drop ddrs firewall: %d\n", ret);
            return -SPL_TZSI_EFWDROP;
        }
        spl_root->tzs.fw_dropped = true;
    }

    struct tzs_layout_s *layout = &spl_root->tzs.layout;
    SPLi_MEMSET(layout, 0, sizeof(struct tzs_layout_s));
    spl_tzs_write32 = NULL;

    // Statics
    uint32_t *pfw_statics = (uint32_t *)SPLl_FINDOPE((uint8_t*)((uint32_t)SPLTZl_OPS + SPLTZl_OPS_len), (uint8_t*)SPLTZl_OPS, SPLOPD_TZS_OFFS, SPLTZOE_STATICS, spl_root->fw);
    if (!pfw_statics) { SPLi_ERROR("TZSI: No statics found for fw=0x%08X\n", spl_root->fw); return -SPL_TZSI_ENOOPES; }
    SPLi_MEMCPY(layout->statics, &pfw_statics[SPLOPEM_UNIQ], sizeof(uint32_t) * SPLTZ_STATIC__COUNT);

    // After firewall is dropped, we can simply use these sections from NS
    layout->mbase = SPLi_PALLOC(layout->statics[SPLTZ_STATIC_RST], layout->statics[SPLTZ_STATIC_LEN]);
    if (!layout->mbase) {
        SPLi_ERROR("TZSI: Failed to allocate nsVA of sPA!\n");
        return -SPL_TZSI_ENOSPALLOC;
    }
    SPLi_DEBUG("TZSI: tzsb[0]: 0x%08X\n", *(uint32_t*)(layout->mbase));

    //SPLl_ROOTCHK(true);
    //SPLx_TZS_PRINTTBR(true); // TEMP

    // Add primitives
    uint32_t smcsva;
    uint32_t *intrmgr_opes = (uint32_t *)SPLl_FINDOPE((uint8_t*)((uint32_t)SPLTZl_OPS + SPLTZl_OPS_len), (uint8_t*)SPLTZl_OPS, SPLOPD_TZS_OFFS, SPLTZOE_INTRMGR, spl_root->fw);
    uint32_t *sysmem_opes = (uint32_t *)SPLl_FINDOPE((uint8_t*)((uint32_t)SPLTZl_OPS + SPLTZl_OPS_len), (uint8_t*)SPLTZl_OPS, SPLOPD_TZS_OFFS, SPLTZOE_SYSMEM, spl_root->fw);
    if (!intrmgr_opes || !sysmem_opes) { 
        SPLi_ERROR("TZSI: No intrmgr or sysmem opes found for fw=0x%08X\n", spl_root->fw); 
        return -SPL_TZSI_ENOOPES; 
    }
    layout->ismcparm[SPLTZ_ISMC_PARM_WRITE32] = intrmgr_opes[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_WRITE32];
    layout->ismcparm[SPLTZ_ISMC_PARM_READ32] = intrmgr_opes[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_READ32];
    SPLl_ROOTCHK(true);
    ret = SPLx_TZS_SMC_SET(SPLTZ_SMC_RET0, -1);
    if (ret < 0)
        return ret;
    else if (!ret) { // fresh, add
        int mod = SPLTZ_MODINFO_INTRMGR;
        if ((ret = SPLx_TZS_GETMODSVA(mod, 0, layout->ismcparm[SPLTZ_ISMC_PARM_WRITE32] & 0xFFFF, &smcsva), ret < 0) || (ret = SPLx_TZS_SMC_SET(SPLTZ_SMC_WRITE32P, smcsva), ret < 0)) {
tzspli_apf:
            SPLi_ERROR("TZSI: Failed to add tzspl m%d primitives: 0x%X\n", mod, ret);
            return ret;
        } else
            spl_tzs_write32 = SPLx_TZS_WRITE32;
        if ((ret = SPLx_TZS_GETMODSVA(mod, 0, layout->ismcparm[SPLTZ_ISMC_PARM_READ32] & 0xFFFF, &smcsva), ret < 0) || (ret = SPLx_TZS_SMC_SET(SPLTZ_SMC_READ32P, smcsva), ret < 0))
            goto tzspli_apf;
        if ((ret = SPLx_TZS_GETMODSVA(mod, 0, (intrmgr_opes[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_RET0]), &smcsva), ret < 0) || (ret = SPLx_TZS_SMC_SET(SPLTZ_SMC_RET0, smcsva), ret < 0))
            goto tzspli_apf;
        mod = SPLTZ_MODINFO_SYSMEM;
        if ((ret = SPLx_TZS_GETMODSVA(mod, 0, sysmem_opes[SPLOPEM_UNIQ + SPLTZOPE_SYSMEM_XWSP], &smcsva), ret < 0) || (ret = SPLx_TZS_SMC_SET(SPLTZ_SMC_EXEC_WITH_SP, smcsva), ret < 0))
            goto tzspli_apf;
        if ((ret = SPLx_TZS_GETMODSVA(mod, 0, sysmem_opes[SPLOPEM_UNIQ + SPLTZOPE_SYSMEM_MBALLOC], &smcsva), ret < 0) || (ret = SPLx_TZS_SMC_SET(SPLTZ_SMC_MBALLOC, smcsva), ret < 0))
            goto tzspli_apf;
        if ((ret = SPLx_TZS_GETMODSVA(mod, 0, sysmem_opes[SPLOPEM_UNIQ + SPLTZOPE_SYSMEM_MBFREE], &smcsva), ret < 0) || (ret = SPLx_TZS_SMC_SET(SPLTZ_SMC_MBFREE, smcsva), ret < 0))
            goto tzspli_apf;
    }

    // Tests
    SPLi_DEBUG("TZSI: Testing primitives..\n");
    if ((ret = SPLx_TZS_GETMODSVA(SPLTZ_MODINFO_INTRMGR, 0, intrmgr_opes[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_PTESTO], &smcsva), ret < 0) || (ret = SPLx_TZS_READ32(smcsva, &smcsva), ret < 0)) {
        SPLi_ERROR("TZSI: Failed to read test primitive nsVA: %d\n", ret);
        spl_tzs_write32 = NULL;
        return -SPL_TZSI_ENOTESTSVA;
    }
    if (smcsva != intrmgr_opes[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_PTESTV]) {
        SPLi_ERROR("TZSI: Test smc_read32 returned !magic: 0x%X\n", smcsva);
        spl_tzs_write32 = NULL;
        return -SPL_TZSI_EBADTEST;
    }

    SPLi_DEBUG("TZSI: success\n");
    spl_root->tzs.initialized = true;
    SPLl_ROOTCHK(true);
    return 0;
}

int SPLx_TZS_DEINIT(void) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    spl_root->tzs.initialized = false;
    spl_root->tzs.fw_dropped = false;
    spl_tzs_write32 = NULL;
    struct tzs_layout_s *layout = &spl_root->tzs.layout;
    SPLi_PFREE(layout->mbase);
    SPLi_MEMSET(layout, 0, sizeof(struct tzs_layout_s));
    SPLl_ROOTCHK(true);
    return 0;
}