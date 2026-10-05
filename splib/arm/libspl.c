#include "libspl-int.h"

#include "libspl.h"
#include "libspl-lv0.h"
#include "libspl-tzs.h"

static struct spl_root_s my_spl_root;
struct spl_root_s *spl_root = &my_spl_root;
void *spl_imports;
char *spl_dbgId = "[LSPL]";
int (*spl_tzs_write32)(uint32_t addr, uint32_t value) = NULL;
int (*spl_lv0_write32)(uint32_t addr, uint32_t value) = NULL;

uint8_t *SPLl_FINDOPE(uint8_t *end, uint8_t *cur, enum SPLOP_DOMAINS domain, int find, uint32_t fw) {
    if (!cur || !end)
        return NULL;
    //SPLi_DEBUG("SPLl_FINDOPE(domain=%d, find=%d, fw=0x%08X)\n", domain, find, fw);
    uint32_t *em = (uint32_t *)cur;
l_lspl_fope_retry:
    while ((cur + 3) < end) {
        em = (uint32_t *)cur;
        if ((em[0] & SPLOP_MMASK) == SPLOP_MAGIC) {
            if ((em[0] & SPLOP_EMASK) == SPLOPDEV(SPLOPD_SYS, SPLOPDE_END))
                return NULL;
            else if (domain == SPLOPD_ANY)
                break;
            else if ((em[0] & SPLOP_DMASK) == SPLOPDV(domain)) {
                if (find < 0) // any
                    break;
                else if ((em[0] & SPLOP_EMASK) == SPLOPDEV(domain, find))
                    break;
            }
        }
        cur++;
    }
    if ((cur + 3) >= end)
        return NULL;
    if ((int)fw >= 0) {
        if ((fw < em[SPLOPEM_MINFW]) || (fw > em[SPLOPEM_MAXFW]))
            goto l_lspl_fope_retry;
    }
    return cur;
}

int SPLl_ROOTCHK(bool update) {
    if (!spl_root || (spl_root->magic != SPLROOT_MAGIC) || !spl_root->fw)
        return -SPL_EBADROOT;
    if (spl_root == &my_spl_root)
        return 0; // shouldnt get modified by ext
    uint32_t csum = 0;
    for (uint32_t *_p = &(spl_root)->magic; _p < &(spl_root)->csum; _p++)
        csum ^= *_p;
    if (update)
        spl_root->csum = csum;
    else if (spl_root->csum != csum)
        return -SPL_EBADROOT;
    return 0;
}

int SPLx_INIT_STATUS(void) {
    if (!spl_imports || (SPLl_ROOTCHK(false) < 0))
        return -SPL_EBADROOT;
    return (!!spl_root->lv0.initialized * SPL_IFL(_LV0)) | (!!spl_root->tzs.initialized * SPL_IFL(_TZS));
}

int SPLx_INIT(struct spl_init_arg_s *init_arg) {
    if (!init_arg || !init_arg->sel)
        return -SPL_EBADARG;
    if (!init_arg->imports)
        return -SPL_INIT_ENOIMPORTS;
    if (init_arg->dbgid)
        spl_dbgId = init_arg->dbgid;

    spl_imports = init_arg->imports; // always update

    if (init_arg->bufC0 && !(init_arg->ifl & SPL_IFL(_NOINHERITANCE))) {
        spl_root = (struct spl_root_s *)init_arg->bufC0;
        SPLi_DEBUG("%s global SPL root at 0x%X\n", (SPLl_ROOTCHK(false) < 0) ? "Creating" : "Inherited", (uint32_t)init_arg->bufC0);
    } else
        spl_root = &my_spl_root;
    
    if ((init_arg->ifl & SPL_IFL(_RESET)) || (SPLl_ROOTCHK(false) < 0)) {
        SPLi_MEMSET(spl_root, 0, sizeof(struct spl_root_s));
        spl_root->fw = SPLi_GETFW();
        spl_root->magic = SPLROOT_MAGIC;
    }

    if (init_arg->fw_override) // for hfw
        spl_root->fw = init_arg->fw_override;
    else
        init_arg->fw_override = spl_root->fw;

    if (init_arg->ifl & SPL_IFL(_LV0_REINIT))
        spl_root->lv0.initialized = false;
    if (init_arg->ifl & SPL_IFL(_TZS_REINIT))
        spl_root->tzs.initialized = false;
    if (init_arg->ifl & SPL_IFL(_DROP_TZSB_FW))
        spl_root->tzs.fw_dropped = false;

    SPLl_ROOTCHK(true);

    int ret = 0;
    if ((init_arg->ifl & SPL_IFL(_LV0)) && init_arg->sel->lv0_init)
        ret = init_arg->sel->lv0_init((spl_lv0p_nmp_t){.va = init_arg->sel->lv0p_nmp.va, .size = init_arg->sel->lv0p_nmp.size}, false, init_arg->lv0_backup_mode);
    
    if (ret >= 0 && (init_arg->ifl & SPL_IFL(_TZS)) && init_arg->sel->tzs_init)
        ret = init_arg->sel->tzs_init();
    
    if (ret < 0)
        spl_root->magic = 0;
    else
        ret = (!!spl_root->lv0.initialized * SPL_IFL(_LV0)) | (!!spl_root->tzs.initialized * SPL_IFL(_TZS));
    return ret;
}

int SPLx_DEINIT(struct spl_init_arg_s *init_arg) {
    if (SPLl_ROOTCHK(false) < 0)
        return -SPL_EBADROOT;
    if ((init_arg->ifl & SPL_IFL(_LV0)) && init_arg->sel->lv0_deinit)
        init_arg->sel->lv0_deinit();
    if ((init_arg->ifl & SPL_IFL(_TZS)) && init_arg->sel->tzs_deinit)
        init_arg->sel->tzs_deinit();
    spl_root->magic = 0;
    return 0;
}