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
                if (pparm && (type >= TTSDC_T_L2_LP) && (type <= TTSDC_T_L2_SP)) {
                    *rpa = paddr + (sva % TT_PAGE_SIZE);
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

int SPLx_TZS_SMCADD(int idx, uint32_t funcsva) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    SPLi_DEBUG("SPLx_TZS_SMCADD: idx=0x%X, funcsva=0x%08X\n", idx, funcsva);
    return SPLi_SMCALL((SPLTZ_SMC_ADDSMC), idx, funcsva, 0, 0);
}

int SPLx_TZS_GETMODSVA(enum SPLTZ_MODINFO_ENTS mod, int seg, uint32_t off, uint32_t *rsva) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    if (!rsva)
        return -SPL_EBADARG;
    struct tzs_layout_s *layout = &spl_root->tzs.layout;
    if (mod >= SPLTZ_MODINFO__COUNT)
        return -SPL_EBADARG;
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

static inline void SPLTZl_SMC_SET(int idx, uint32_t funcsva, bool flushl1) {
    struct tzs_layout_s *layout = &spl_root->tzs.layout;
    SPLi_DEBUG("SPLTZl_SMC_SET(0x%X): funcsva=0x%08X, flushl1=%d\n", idx, funcsva, flushl1);
    if (idx < 0x100 || idx > 0x4FF) { SPLi_DEBUG("Invalid SMC index: 0x%X\n", idx); return; }
    layout->smct[idx - 0x100] = funcsva;
    if (flushl1) {
        SPLi_DEBUG("Flushing sL1C\n");
        SPLi_SMCALL(TZS_SMC_FLUSH_L1C, 0, 0, 0, 0);
    }
}

static void *SPLTZl_SMCTABLE_FIND1(void) {
    SPLl_ROOTCHK(true); // we use X funcs from L ctx, so need to make sure SPL root chksum is valid
    struct tzs_layout_s *layout = &spl_root->tzs.layout;
    //volatile uint32_t *ttbr0 = (volatile uint32_t *)((uint32_t)layout->mbase + layout->statics[SPLTZ_STATIC_TTBR0]);
    volatile uint32_t *sb = (volatile uint32_t *)((uint32_t)layout->mbase + layout->statics[SPLTZ_STATIC_SYSROOT]);
    uint32_t *ft1_ope = (uint32_t *)SPLl_FINDOPE((uint8_t*)((uint32_t)SPLTZl_OPS + SPLTZl_OPS_len), (uint8_t*)SPLTZl_OPS, SPLOPD_TZS_OFFS, SPLTZOE_FT1S, spl_root->fw);
    if (!ft1_ope) { SPLi_ERROR("No OPEs available for FT1 on fw=0x%08X\n", spl_root->fw); return NULL; }
    // sysroot+0x31c = mon handler vectors
    uint32_t wb = sb[ft1_ope[SPLOPEM_UNIQ + SPLTZOPE_FT1_SR_MHV_AO32]];
    int ret = SPLx_TZS_SVA2NSVA(wb, (void*)&sb);
    if (ret < 0) { SPLi_ERROR("Failed to find the xhandler table: %d\n", ret); return NULL; }

    // mhv+40 = intrmgr's smc handler
    wb = sb[ft1_ope[SPLOPEM_UNIQ + SPLTZOPE_FT1_MHV_SMCH_AO32]];
    ret = SPLx_TZS_SVA2NSVA(wb, (void*)&sb);
    if (ret < 0) { SPLi_ERROR("Failed to find the smc handler: %d\n", ret); return NULL; }

    // smch has a reld movw/movt pair containing addr of a ptr to the SMC table
    wb = sb[ft1_ope[SPLOPEM_UNIQ + SPLTZOPE_FT1_SMCH_SMCTMOVW_AO32]];
    if (!IS_MOVW(wb)) { SPLi_ERROR("!movw @ 0x%08X: 0x%08X\n", &sb[ft1_ope[SPLOPEM_UNIQ + SPLTZOPE_FT1_SMCH_SMCTMOVW_AO32]], wb); return NULL; }
    uint32_t tb = sb[ft1_ope[SPLOPEM_UNIQ + SPLTZOPE_FT1_SMCH_SMCTMOVT_AO32]];
    if (!IS_MOVT(tb)) { SPLi_ERROR("!movt @ 0x%08X: 0x%08X\n", &sb[ft1_ope[SPLOPEM_UNIQ + SPLTZOPE_FT1_SMCH_SMCTMOVT_AO32]], tb); return NULL; }
    wb = MOVW_GETA(wb) | MOVT_GETA(tb);
    ret = SPLx_TZS_SVA2NSVA(wb, (void*)&sb);
    if (ret < 0) { SPLi_ERROR("Failed to find the smc table ptr: %d\n", ret); return NULL; }
    wb = sb[0];
    SPLi_DEBUG("smc table sVA: 0x%08X\n", wb);
    ret = SPLx_TZS_SVA2NSVA(wb, (void*)&sb);
    if (ret < 0) { SPLi_ERROR("Failed to find the smc table: %d\n", ret); return NULL; }

    return (void *)sb;
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

    // Statics
    uint32_t *pfw_statics = (uint32_t *)SPLl_FINDOPE((uint8_t*)((uint32_t)SPLTZl_OPS + SPLTZl_OPS_len), (uint8_t*)SPLTZl_OPS, SPLOPD_TZS_OFFS, SPLTZOE_STATICS, spl_root->fw);
    if (!pfw_statics) { SPLi_DEBUG("TZSI: No statics found for fw=0x%08X\n", spl_root->fw); return -SPL_TZSI_ENOOPES; }
    SPLi_MEMCPY(layout->statics, &pfw_statics[SPLOPEM_UNIQ], sizeof(uint32_t) * SPLTZ_STATIC__COUNT);

    // After firewall is dropped, we can simply use these sections from NS
    layout->mbase = SPLi_PALLOC(layout->statics[SPLTZ_STATIC_RST], layout->statics[SPLTZ_STATIC_LEN]);
    if (!layout->mbase) {
        SPLi_ERROR("TZSI: Failed to allocate nsVA of sPA!\n");
        return -SPL_TZSI_ENOSPALLOC;
    }
    SPLi_DEBUG("TZSI: tzsb[0]: 0x%08X\n", *(uint32_t*)(layout->mbase));

    // Find intrmgr's SMC handlers table
    layout->smct = SPLTZl_SMCTABLE_FIND1();
    if (!layout->smct)
        return -SPL_TZSI_ENOSMCT;
    SPLi_DEBUG("TZSI: tzsmct: 0x%08X\n", layout->smct);

    // Add primitives
    uint32_t *intrmgr_opes = (uint32_t *)SPLl_FINDOPE((uint8_t*)((uint32_t)SPLTZl_OPS + SPLTZl_OPS_len), (uint8_t*)SPLTZl_OPS, SPLOPD_TZS_OFFS, SPLTZOE_INTRMGR, spl_root->fw);
    layout->msva[SPLTZ_MODINFO_INTRMGR].text = (layout->smct[intrmgr_opes[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_IMSW4KB] - 0x100] & ~0xFFF);
    SPLi_DEBUG("TZSI: intrmgr text base: 0x%08X\n", layout->msva[SPLTZ_MODINFO_INTRMGR].text);
    uint32_t smcsva = 0, test0sva = 0;
    SPLl_ROOTCHK(true);
    ret = SPLx_TZS_GETMODSVA(SPLTZ_MODINFO_INTRMGR, 0, intrmgr_opes[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_PTESTO], &test0sva);
    if (ret < 0) {
        SPLi_ERROR("TZSI: Failed to get test primitive nsVA: %d\n", ret);
        return -SPL_TZSI_ENOTESTSVA;
    }

    // If not already, add primitives
    layout->ismcparm[SPLTZ_ISMC_PARM_WRITE32] = intrmgr_opes[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_WRITE32];
    layout->ismcparm[SPLTZ_ISMC_PARM_READ32] = intrmgr_opes[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_READ32];
    SPLl_ROOTCHK(true);
    if ((SPLx_TZS_READ32(test0sva, &smcsva) < 0) || (smcsva != intrmgr_opes[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_PTESTV])) {
        if (ret = SPLx_TZS_GETMODSVA(SPLTZ_MODINFO_INTRMGR, 0, (intrmgr_opes[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_IMSADD]), &smcsva), ret < 0) {
            SPLi_ERROR("TZSI: Failed to get smc handler nsVA: %d\n", ret);
            return -SPL_TZSI_ENOSMCSVA;
        }
        SPLTZl_SMC_SET(SPLTZ_SMC_ADDSMC, smcsva, true);
        SPLi_DEBUG("TZSI: Adding primitives\n");
        
        if ((ret = SPLx_TZS_GETMODSVA(SPLTZ_MODINFO_INTRMGR, 0, (intrmgr_opes[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_IMRET0]), &smcsva), ret < 0) || (ret = SPLx_TZS_SMCADD(SPLTZ_SMC_RET0, smcsva), ret < 0)) {
    tzspli_apf:
            SPLi_ERROR("TZSI: Failed to add tzspl primitives: 0x%X\n", ret);
            return ret;
        }
        if ((ret = SPLx_TZS_GETMODSVA(SPLTZ_MODINFO_INTRMGR, 0, layout->ismcparm[SPLTZ_ISMC_PARM_WRITE32] & 0xFFFF, &smcsva), ret < 0) || (ret = SPLx_TZS_SMCADD(SPLTZ_SMC_WRITE32P, smcsva), ret < 0))
            goto tzspli_apf;
        if ((ret = SPLx_TZS_GETMODSVA(SPLTZ_MODINFO_INTRMGR, 0, layout->ismcparm[SPLTZ_ISMC_PARM_READ32] & 0xFFFF, &smcsva), ret < 0) || (ret = SPLx_TZS_SMCADD(SPLTZ_SMC_READ32P, smcsva), ret < 0))
            goto tzspli_apf;
    }

    // Tests
    SPLi_DEBUG("TZSI: Testing primitives..\n");
    if (ret = SPLx_TZS_READ32(test0sva, &smcsva), ret < 0) {
        SPLi_ERROR("TZSI: Failed to read test primitive nsVA: %d\n", ret);
        return -SPL_TZSI_ENOTESTSVA;
    }
    if (smcsva != intrmgr_opes[SPLOPEM_UNIQ + SPLTZOPE_INTRMGR_PTESTV]) {
        SPLi_ERROR("TZSI: Test smc_read32 returned !magic: 0x%X\n", smcsva);
        return -SPL_TZSI_EBADTEST;
    }

    SPLi_DEBUG("TZSI: success\n");
    spl_tzs_write32 = SPLx_TZS_WRITE32;
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