#include <psp2kern/kernel/modulemgr.h>
#include <vitasdkkern.h>

#include <libspl/libspl.h> // core
#include <libspl/libspl-cfk.h> // kernel compatibility layer

#include "include/splForDriver.h"
#include "include/main.h"
#include "include/txtcfg.h"

/*
*BOOT
LV0_EXE=<arg>,<arg>
LV0_DAT=..
*RESUME
LV0_KSP=..
*BOOT # run in a second call
*/

typedef int bool;
#define true 1
#define false 0

extern struct splm_statu_s splm_status;

static struct txtcfg_arg_s lv0c_args[LV0C_DCOUNT] = {
    [LV0C_STACK] = {
		.name = "LV0_STACK",
        .uarg = {
            [0] = {.min_len = 1, .max_len = 4}, // stack ptr
        },
        .types = TXTCFG_TYPES_ALLOW(0, _UINT),
    },
    [LV0C_KSP] = {
		.name = "LV0_KSP",
        .uarg = {
            [0] = {.min_len = 1, .max_len = 4}, // keyslot idx
            [1] = {.min_len = 1, .max_len = 0x20}, // patch offset or patch data
            [2] = {.min_len = 1, .max_len = 0x20}, // patch size or patch data
            [3] = {.min_len = 1, .max_len = 0x20}, // patch data
        },
        .types = TXTCFG_TYPES_ALLOW(0, _UINT) | TXTCFG_TYPES_ALLOW(1, _UINT, _RDATA, _FDATA) | TXTCFG_TYPES_ALLOW(2, _UINT, _RDATA, _FDATA) | TXTCFG_TYPES_ALLOW(3, _UINT, _RDATA, _FDATA)
    },
    [LV0C_DAT] = {
		.name = "LV0_DAT",
        .uarg = {
            [0] = {.min_len = 3, .max_len = 4}, // dst
            [1] = {.min_len = 1, .max_len = (1024 * 1024)}, // sz or data
            [2] = {.min_len = 1, .max_len = (1024 * 1024)}, // src or data
        },
        .types = TXTCFG_TYPES_ALLOW(0, _UINT) | TXTCFG_TYPES_ALLOW(1, _UINT, _RDATA, _FDATA) | TXTCFG_TYPES_ALLOW(2, _UINT, _RDATA, _FDATA)
    },
    [LV0C_EXE] = {
		.name = "LV0_EXE",
        .uarg = {
            [0] = {.min_len = 1, .max_len = (1024 * 1024)}, // arg or data
            [1] = {.min_len = 1, .max_len = (1024 * 1024)}, // addr or data
        },
        .types = TXTCFG_TYPES_ALLOW(0, _UINT, _RDATA, _FDATA) | TXTCFG_TYPES_ALLOW(1, _UINT, _RDATA, _FDATA)
    },
    [LV0C_CUS] = {
		.name = "LV0_CUS",
        .uarg = {
            [0] = {.min_len = sizeof(uint32_t), .max_len = (12 * sizeof(uint32_t))}, // custom arg or data
        },
        .types = TXTCFG_TYPES_ALLOW(0, _UINT, _RDATA, _FDATA)
    },
};

static int get_fsz(char *path) {
    SceIoStat stat;
    int ret = ksceIoGetstat(path, &stat);
    if (ret < 0)
        return 0;
    return stat.st_size;
}

int antoh(const char *input, uint8_t *output, int output_len, bool endian) {
    for (int i = 0; i < (output_len * 2); i++) {
        if (input[i] < '0' || (input[i] > '9' && input[i] < 'A') || input[i] > 'F')
            return -1;
    }

    for (int i = 0; i < output_len; i++) {
		int a = endian ? (output_len - 1 - i) : i;
        if (input[i * 2] < 'A')
            output[a] = 0x10 * (input[i * 2] - '0');
        else
            output[a] = 0x10 * (input[i * 2] - '7');

        if (input[(i * 2) + 1] < 0x40)
            output[a] += (input[(i * 2) + 1] - '0');
        else
            output[a] += (input[(i * 2) + 1] - '7');
    }

    return 0;
}

static inline uint32_t str2u32(const char *str) {
    const char *end = str;
    if (*(uint16_t *)str != 'x0')
        return 0;
    int l = 2;
    for (l = 2; l < 10; l++) {
        if (end[l] < '0' || (end[l] > '9' && end[l] < 'A') || end[l] > 'F')
            break;
    }
    if (l < 4)
        return 0;
    l = (l - 2) / 2;
    uint32_t val = 0;
    antoh(str + 2, (uint8_t *)&val, l, true);
    return val;
}

static int strarr2ux(char *str, char div, void *out, int msz, int maxc, char *end) {
    if (!str || maxc <= 0 || !end)
        return -1;
    int c = 0;
    char *p = str;
    while (c < maxc && p < end) {
        char *q = strchr(p, div);
        if (!q)
            q = end;
        int l = (int)(q - p);
        if ((l < 4) || strncmp(p, "0x", 2))
            return -2;
        l = (l - 2) / 2;
        if (l > sizeof(uint32_t))
            l = sizeof(uint32_t);
        uint32_t val = 0;
        if (antoh(p + 2, (uint8_t *)&val, l, true) < 0)
            return -3;
        if (c < maxc) {
            if (out)
                memcpy((void *)((uint32_t)out + (c * msz)), &val, (msz > sizeof(uint32_t)) ? sizeof(uint32_t) : msz);
            c++;
        } else
            return -3;
        if (*q == '\0')
            break;
        p = q + 1;
    }
    return c;
}

static int get_file(char *path, void *out, int *size) {
    if (!out)
        return -TXTCFG_ENOMEM;
    int fsize = size ? *size : 0;
    if (!fsize)
        fsize = get_fsz(path);
    if (!fsize) {
        ERRORF("failed to get fsz(%s)\n", path);
        return -TXTCFG_EFOPEN;
    }
    int fd = ksceIoOpen(path, SCE_O_RDONLY, 0);
    if (fd < 0) {
        ERRORF("failed to open %s : 0x%08X\n", path, fd);
        return -TXTCFG_EFOPEN;
    }
    int ret = ksceIoRead(fd, out, fsize);
    ksceIoClose(fd);
    if (ret < 0)
        ERRORF("failed to read %s : 0x%08X\n", path, ret);
    if (size && !*size)
        *size = fsize;
    return ret;
}

static int txtcfg_lv0cAll(struct txtcfg_section_s *section, int idx, char *ae) {
    if (!section || !section->args || !section->argc || idx <= 0 || idx >= section->argc || !ae)
        return -TXTCFG_EBADPARG;
    struct txtcfg_arg_s *arg = &section->args[idx];
    char b = *ae; // we use fsize+1 for txt buf
    *ae = '\0';
    int ret = 0;
    bool dry = !!(section->type & BITN(31));
    if (!section->rmb.size) {
        if (dry)
            section->rmb.size = sizeof(struct splmLv0pRun_arg_s);
        else {
            ERRORF("txtcfg_l0A: !rmb.size\n");
            ret = -TXTCFG_EBADSARG;
            goto l_txtcfg_lv0pAll_exit;
        }
    }
    struct splmLv0pRun_arg_s *ma = NULL;
    struct splmLv0p_j_s *cj = NULL;
    struct splmLv0p_j_s **cjp = NULL;
    if (!dry) {
        if (!section->rmb.va) {
            ERRORF("txtcfg_l0A: !rmb.va\n");
            ret = -TXTCFG_EBADSARG;
            goto l_txtcfg_lv0pAll_exit;
        }
        ma = (struct splmLv0pRun_arg_s *)section->rmb.va;
        if (!section->rmb.off)
            section->rmb.off = sizeof(struct splmLv0pRun_arg_s);
        if (idx != LV0C_STACK) {
            cjp = &ma->jobs;
            while (*cjp)
                cjp = &(*cjp)->next;
            cj = (struct splmLv0p_j_s *)((uint32_t)section->rmb.va + section->rmb.off);
            if ((section->rmb.off + sizeof(struct splmLv0p_j_s)) > section->rmb.size) {
                ERRORF("txtcfg_l0A: out of rmb.size(@%08X)!\n", section->rmb.off);
                ret = -TXTCFG_EBADSARG;
                goto l_txtcfg_lv0pAll_exit;
            }
            memset(cj, 0, sizeof(struct splmLv0p_j_s));
        }
    }

    ret = -TXTCFG_EPARSE;
    int ai = 0;
    switch (idx) {
        case LV0C_STACK:
            if (!dry) {
                ma->stack = str2u32(arg->uarg[ai].ascii);
                if (!ma->stack || (ma->stack & 3)) {
                    ERRORF("txtcfg_l0A: stack=%08X (bad txtarg?)\n", ma->stack);
                    goto l_txtcfg_lv0pAll_exit;
                }
                INFOF("LV0P stack set to 0x%08X\n", ma->stack);
            }
            ret = 0;
        break; case LV0C_KSP:
            if (dry) {
                section->rmb.size += sizeof(struct splmLv0p_j_s);
                ret = 0;
                break;
            }
            cj->idx = LV0P_JOB_KSP;
            if (arg->types & TXTCFG_TYPES_PARSE(ai, _UINT)) {
                cj->k.id = str2u32(arg->uarg[ai].ascii);
                ai++;
                if (arg->types & TXTCFG_TYPES_PARSE(ai, _UINT)) {
                    cj->k.off = str2u32(arg->uarg[ai].ascii);
                    ai++;
                }
                if ((ai == 2) && (arg->types & TXTCFG_TYPES_PARSE(ai, _UINT))) {
                    cj->k.size = str2u32(arg->uarg[ai].ascii);
                    ai++;
                }
                if ((arg->types & TXTCFG_TYPES_PARSE(ai, _RDATA, _FDATA)) && arg->uarg[ai].act_len) {
                    if (ai == 1)
                        cj->k.off = 0;
                    else if (ai == 2)
                        cj->k.size = arg->uarg[ai].act_len;
                    if (cj->k.size <= sizeof(cj->k.data)) {
                        if (arg->types & TXTCFG_TYPES_PARSE(ai, _RDATA))
                            ret = antoh(arg->uarg[ai].ascii, cj->k.data, cj->k.size, false);
                        else
                            ret = get_file(arg->uarg[ai].ascii, cj->k.data, &cj->k.size);
                        if (ret >= 0) {
                            INFOF("Added KSP: [0x%08X] => 0x%08X @ 0x%08X\n", cj->k.size, cj->k.id, cj->k.off);
                            ma->gsize += SPL_PALIGN(sizeof(struct splmLv0p_j_s));
                            section->rmb.off += sizeof(struct splmLv0p_j_s);
                            *cjp = cj;
                            goto l_txtcfg_lv0pAll_exit;
                        } else
                            ERRORF("Failed to convert/read KSP patch data: %d\n", ret);
                    } else
                        ERRORF("KSP patch data too large\n");
                } else
                    ERRORF("Invalid KSP data arg\n");
            } else
                ERRORF("Invalid keyslot index type\n");
        break; case LV0C_DAT:
            if (dry) {
                section->rmb.size += sizeof(struct splmLv0p_j_s);
                for (int i = 1; i < 3; i++) {
                    if (arg->types & TXTCFG_TYPES_PARSE(i, _RDATA, _FDATA))
                        section->rmb.size += arg->uarg[i].act_len;
                }
                ret = 0;
                break;
            }
            cj->idx = LV0P_JOB_DAT;
            if (arg->types & TXTCFG_TYPES_PARSE(ai, _UINT)) {
                cj->d.dst = str2u32(arg->uarg[ai].ascii);
                ai++;
                if (arg->types & TXTCFG_TYPES_PARSE(ai, _UINT)) {
                    cj->d.size = str2u32(arg->uarg[ai].ascii);
                    ai++;
                    if (arg->types & TXTCFG_TYPES_PARSE(ai, _UINT)) {
                        cj->d.src = str2u32(arg->uarg[ai].ascii);
                        cj->d.ncopyin = true;
                        INFOF("Added LV0_DAT: [0x%08X] 0x%08X => 0x%08X\n", cj->d.size, cj->d.src, cj->d.dst);
                        ma->gsize += SPL_PALIGN(sizeof(struct splmLv0p_j_s));
                        section->rmb.off += sizeof(struct splmLv0p_j_s);
                        *cjp = cj;
                        ret = 0;
                        goto l_txtcfg_lv0pAll_exit;
                    }
                }
                if ((arg->types & TXTCFG_TYPES_PARSE(ai, _RDATA, _FDATA)) && arg->uarg[ai].act_len) {
                    if (ai == 1)
                        cj->d.size = arg->uarg[ai].act_len;
                    ma->gsize += SPL_PALIGN(sizeof(struct splmLv0p_j_s));
                    section->rmb.off += sizeof(struct splmLv0p_j_s);
                    if ((section->rmb.off + arg->uarg[ai].act_len) <= section->rmb.size) {
                        cj->d.src_va = (void *)((uint32_t)section->rmb.va + section->rmb.off);
                        if (arg->types & TXTCFG_TYPES_PARSE(ai, _RDATA))
                            ret = antoh(arg->uarg[ai].ascii, cj->d.src_va, arg->uarg[ai].act_len, false);
                        else
                            ret = get_file(arg->uarg[ai].ascii, cj->d.src_va, &arg->uarg[ai].act_len);
                        if (ret >= 0) {
                            INFOF("Added LV0_DAT: [0x%08X] => 0x%08X\n", arg->uarg[ai].act_len, cj->d.dst);
                            ma->gsize += SPL_PALIGN(arg->uarg[ai].act_len);
                            section->rmb.off += arg->uarg[ai].act_len;
                            *cjp = cj;
                            goto l_txtcfg_lv0pAll_exit;
                        } else
                            ERRORF("Failed to convert/read LV0_DAT src: %d\n", ret);
                    } else
                        ERRORF("LV0_DAT src too large: 0x%08X > 0x%08X\n", arg->uarg[ai].act_len, section->rmb.size - section->rmb.off);
                } else
                    ERRORF("Invalid LV0_DAT src arg\n");
            } else
                ERRORF("Invalid LV0_DAT dest arg\n");
        break; case LV0C_EXE:
            if (dry) {
                section->rmb.size += sizeof(struct splmLv0p_j_s);
                for (int i = 0; i < 3; i++) {
                    if (arg->types & TXTCFG_TYPES_PARSE(i, _RDATA, _FDATA))
                        section->rmb.size += arg->uarg[i].act_len;
                }
                ret = 0;
                break;
            }
            cj->idx = LV0P_JOB_EXE;
            if (arg->types & TXTCFG_TYPES_PARSE(ai, _UINT)) {
                char *ad = strchr(arg->uarg[ai].ascii, ',');
                if (ret = strarr2ux(arg->uarg[ai].ascii, '|', cj->x.argv, sizeof(uint32_t), 8, ad ? ad : NULL), ret < 0) {
                    ERRORF("BUG: LV0X src uint arr invalid: %d\n", ret);
                    goto l_txtcfg_lv0pAll_exit;
                }
                ai++;
                if (arg->types & TXTCFG_TYPES_PARSE(ai, _UINT)) {
                    cj->x.addr = str2u32(arg->uarg[ai].ascii);
                    INFOF("Added LV0X: 0x%08X(0x%08X)\n", cj->x.addr, cj->x.argv[0]);
                    ma->gsize += SPL_PALIGN(sizeof(struct splmLv0p_j_s));
                    section->rmb.off += sizeof(struct splmLv0p_j_s);
                    *cjp = cj;
                    ret = 0;
                    goto l_txtcfg_lv0pAll_exit;
                }
            }
            if ((arg->types & TXTCFG_TYPES_PARSE(ai, _RDATA, _FDATA)) && arg->uarg[ai].act_len) {
                ma->gsize += SPL_PALIGN(sizeof(struct splmLv0p_j_s));
                section->rmb.off += sizeof(struct splmLv0p_j_s);
                if ((section->rmb.off + arg->uarg[ai].act_len) <= section->rmb.size) {
                    cj->x.size = arg->uarg[ai].act_len;
                    cj->x.src_va = (void *)((uint32_t)section->rmb.va + section->rmb.off);
                    if (arg->types & TXTCFG_TYPES_PARSE(ai, _RDATA))
                        ret = antoh(arg->uarg[ai].ascii, cj->x.src_va, arg->uarg[ai].act_len, false);
                    else
                        ret = get_file(arg->uarg[ai].ascii, cj->x.src_va, &arg->uarg[ai].act_len);
                    if (ret >= 0) {
                        INFOF("Added LV0X: dyn(0x%08X)\n", cj->x.argv[0]);
                        ma->gsize += SPL_PALIGN(arg->uarg[ai].act_len);
                        section->rmb.off += arg->uarg[ai].act_len;
                        *cjp = cj;
                        goto l_txtcfg_lv0pAll_exit;
                    } else
                        ERRORF("Failed to convert/read LV0X src: %d\n", ret);
                } else
                    ERRORF("LV0X src too large: 0x%08X > 0x%08X\n", arg->uarg[ai].act_len, section->rmb.size - section->rmb.off);
            } else
                ERRORF("Invalid LV0X src arg\n");
        break; case LV0C_CUS:
            if (dry) {
                section->rmb.size += sizeof(struct splmLv0p_j_s);
                ret = 0;
                break;
            }
            cj->idx = LV0P_JOB_CUS;
            if (arg->types & TXTCFG_TYPES_PARSE(ai, _UINT)) {
                char *ad = strchr(arg->uarg[ai].ascii, ',');
                if (ret = strarr2ux(arg->uarg[ai].ascii, '|', cj->c, sizeof(uint32_t), 12, ad ? ad : NULL), ret < 0) {
                    ERRORF("BUG: LV0C src uint arr invalid: %d\n", ret);
                    goto l_txtcfg_lv0pAll_exit;
                }
            } else if (arg->types & TXTCFG_TYPES_PARSE(ai, _FDATA)) {
                ret = get_file(arg->uarg[ai].ascii, cj->c, &arg->uarg[ai].act_len);
                if (ret < 0) {
                    ERRORF("Failed to read LV0C src file: %d\n", ret);
                    goto l_txtcfg_lv0pAll_exit;
                }
            } else if (arg->types & TXTCFG_TYPES_PARSE(ai, _RDATA)) {
                ret = antoh(arg->uarg[ai].ascii, (uint8_t *)cj->c, arg->uarg[ai].act_len, false);
                if (ret < 0) {
                    ERRORF("Failed to convert LV0C src ascii: %d\n", ret);
                    goto l_txtcfg_lv0pAll_exit;
                }
            }
            if (ret >= 0) {
                ma->gsize += SPL_PALIGN(sizeof(struct splmLv0p_j_s));
                section->rmb.off += sizeof(struct splmLv0p_j_s);
                *cjp = cj;
                goto l_txtcfg_lv0pAll_exit;
            }
            break;
    }

l_txtcfg_lv0pAll_exit:
    *ae = b;
    return ret;
}

static char *find_endline(char *start, char *end) {
    //INFOF("txtcfg_fel: find_endline start=0x%08X end=0x%08X\n", (unsigned int)start, (unsigned int)end);
    for (char *ret = start; ret < end; ret++) {
        if (*(uint16_t *)ret == 0x0A0D || *(uint8_t *)ret == 0x0A)
            return ret;
    }
    return end;
}

static char *find_nextline(char *current_line_end, char *end) {
    //INFOF("txtcfg_fnl: find_nextline current_line_end=0x%08X end=0x%08X\n", (unsigned int)current_line_end, (unsigned int)end);
    for (char *next_line = current_line_end; next_line < end; next_line++) {
        if (*(uint8_t *)next_line != 0x0D && *(uint8_t *)next_line != 0x0A && *(uint8_t *)next_line != 0x00)
            return next_line;
    }
    return NULL;
}

static char *find_section(char *start, char *end, const char *section) {
    //INFOF("txtcfg_fs: find_section start=0x%08X end=0x%08X section=%s\n", (unsigned int)start, (unsigned int)end, section);
    char *cl = start, *el = start;
    while (cl < end) {
        el = find_endline(cl, end);
        if (el == end) break;
        if (*(uint8_t *)cl == '*') {
            if (!section) return cl;
            if (strncmp(cl, section, strlen(section)) == 0)
                return find_nextline(el, end);
            //INFOF("txtcfg_fs: found unknown section: %.*s\n", (int)(el - cl), cl);
        }
        cl = find_nextline(el, end);
        if (!cl) break;
    }
    return NULL;
}

static int parse_cmd(struct txtcfg_section_s *section, int idx, char *as, char *ae) {
    if (!section || !section->args || !section->argc || idx <= 0 || idx >= section->argc || !as || !ae)
        return -TXTCFG_EBADPARG;
    if (!section->handler)
        return -TXTCFG_ENOHANDLER;
    struct txtcfg_arg_s *arg = &section->args[idx];
    char b = *ae; // we use fsize+1 for txt buf
    *ae = '\0';
    //INFOF("txtcfg_pc: parsing command idx=%d start=0x%08X end=0x%08X: %s\n", idx, (unsigned int)as, (unsigned int)ae, as);
    
    char *ac = as;
    for (int a = 0; a < 4; a++) {
        char *ad = strchr(ac, ',');
        if (!ad || ad > ae)
            ad = ae;
        arg->uarg[a].act_len = 0;
        arg->uarg[a].ascii = NULL;
        arg->types &= ~TXTCFG_TYPES_PARSE_ALL(a);
        if (ad != ae)
            *ad = '\0';
        if ((arg->types & TXTCFG_TYPES_ALLOW(a, _UINT)) && !strncmp(ac, "0x", 2)) {
            arg->uarg[a].act_len = strarr2ux(ac, '|', NULL, sizeof(uint32_t), 1, ad);
            if (arg->uarg[a].act_len <= 0) {
                arg->uarg[a].act_len = 0;
                ERRORF("txtcfg_pc: arg %d:%d invalid uint/array\n", idx, a);
            } else {
                arg->uarg[a].act_len *= sizeof(uint32_t);
                arg->types |= TXTCFG_TYPES_PARSE(a, _UINT);
            }
        } else if ((arg->types & TXTCFG_TYPES_ALLOW(a, _FDATA)) && strchr(ac, ':')) {
            arg->uarg[a].act_len = get_fsz(ac);
            if (arg->uarg[a].act_len > 0)
                arg->types |= TXTCFG_TYPES_PARSE(a, _FDATA);
            else
                ERRORF("txtcfg_pc: file not found '%s'\n", ac);
        } else if (arg->types & TXTCFG_TYPES_ALLOW(a, _RDATA)) {
            arg->uarg[a].act_len = (int)(ad - ac);
            if ((arg->uarg[a].act_len <= 0) || (arg->uarg[a].act_len & 1)) {
                ERRORF("txtcfg_pc: arg %d:%d invalid rdata length (%d)\n", idx, a, arg->uarg[a].act_len);
                arg->uarg[a].act_len = 0;
            } else {
                arg->uarg[a].act_len /= 2;
                arg->types |= TXTCFG_TYPES_PARSE(a, _RDATA);
            }
        } else if ((arg->types & TXTCFG_TYPES_ALLOW(a, _ASCII))) {
            arg->uarg[a].act_len = (int)(ad - ac);
            arg->types |= TXTCFG_TYPES_PARSE(a, _ASCII);
        }
        if ((arg->uarg[a].act_len < arg->uarg[a].min_len) || (arg->uarg[a].act_len > arg->uarg[a].max_len)) {
            arg->uarg[a].act_len = 0;
            arg->types &= ~TXTCFG_TYPES_PARSE_ALL(a);
            ERRORF("txtcfg_pc: arg %d:%d(%08X) oob (%d<%d<%d)\n", idx, a, arg->types, arg->uarg[a].min_len, arg->uarg[a].act_len, arg->uarg[a].max_len);
            *ae = b;
            return -TXTCFG_EPARSE;
        }
        arg->uarg[a].ascii = ac;
        if (ad == ae)
            break;
        else 
            *ad = ',';
        ac = ad + 1;
        if (ac >= ae)
            break;
    }
    *ae = b;
    return section->handler(section, idx, ae);
}

static int parse_section(struct txtcfg_section_s *section) {
    if (!section || !section->args || !section->argc)
        return -1;
    char *start = section->start;
    char *end = section->end;
    if (!start || !end)
        return -1;

    int ret = 0, s_line = 0;
    char *cl = start, *el = start;
    while (cl < end) {
        el = find_endline(cl, end);
        s_line++;
        ret = 0;

        char *as, *ae;
        int idx = 0, line_len = 0;
        if (line_len = (int)(el - cl), line_len) {
            for (int i = 1; i < section->argc; i++) {
                int cmd_len = strlen(section->args[i].name);
                if (cmd_len >= line_len) // must have space for =..
                    continue;
                if (!memcmp(cl, section->args[i].name, cmd_len)) {
                    if (cl[cmd_len] != '=')
                        continue;
                    as = cl + cmd_len + 1;
                    ae = el;
                    // cut invalid and comments (" " and "#")
                    for (int x = 0; x < (int)(el - as); x++) {
                        if (*(uint8_t *)(as + x) == ' ' || *(uint8_t *)(as + x) == '#') {
                            ae = as + x;
                            break;
                        }
                    }
                    idx = i;
                    break;
                }
            }
        }

        if ((ret < 0) || (idx && (ret = parse_cmd(section, idx, as, ae), ret < 0))) {
            ERRORF("txtcfg_ps: parse error at line %d(%d): %d\n", s_line, idx, ret);
            break;
        }

        if ((el == end) || (cl = find_nextline(el, end), !cl))
            break;
    }

    return ret;
}

#define SCE_MEMBLOCK_MIN_SIZE (0x1000) // 1sp
#define SCE_MEMBLOCK_ALIGN(_s) (((_s) + (SCE_MEMBLOCK_MIN_SIZE - 1)) & ~(SCE_MEMBLOCK_MIN_SIZE - 1))
int txtcfg_apx(char *path, enum TXTCFG_SECTION_TYPES section_type, int knrmbsz, struct txtcfg_apx_out_s *out, bool rcfg_free) {
    static int rcfg_mbid = -1;
    static int rcfg_sz = 0;

    int ret = 0;
    if (!path && rcfg_free)
        goto l_txtcfg_apx_c1;

    bool fresh_alloc = false;
    if (rcfg_mbid < 0) {
        fresh_alloc = true;
        rcfg_sz = get_fsz(path);
        if (rcfg_sz == 0) {
            INFOF("txtcfg_apx: file not found: %s\n", path);
            return -TXTCFG_E404;
        }
        rcfg_mbid = ksceKernelAllocMemBlock("", 0x1020D006, SCE_MEMBLOCK_ALIGN(rcfg_sz + 1), NULL);
        if (rcfg_mbid < 0) {
            ERRORF("txtcfg_apx: mballoc failed: 0x%08X\n", rcfg_mbid);
            return -TXTCFG_ENOMEM;
        }
    }
    void *mbuf = NULL;
    if ((ret = ksceKernelGetMemBlockBase(rcfg_mbid, &mbuf), ret < 0) || !mbuf) {
        ERRORF("txtcfg_apx: mbget(0x%08X) failed: 0x%08X\n", rcfg_mbid, ret);
        ksceKernelFreeMemBlock(rcfg_mbid);
        rcfg_mbid = -1;
        return -TXTCFG_ENOMEM;
    }

    if (fresh_alloc && (ret = get_file(path, mbuf, &rcfg_sz), ret < 0))
        goto l_txtcfg_apx_c1;

    //INFOF("txtcfg_apx: file size: %d, path: %s, mbuf: 0x%08X\n", rcfg_sz, path, mbuf);
    
    char *sstart = mbuf;
    sstart[rcfg_sz] = 0;
    int rmboff = 0, rmbid = -1, rmbsz = knrmbsz;
    void *rmbva = NULL;
    int dry = 1;
l_txtcfg_apx_loop:
    if (rmbsz)
        dry = 0;
    while (1) {
        //INFOF("txtcfg_apx: processing section start: 0x%08X | dry: %d | sz: %d\n", sstart, dry, rmbsz);
        char *lsstart = sstart;
        switch (section_type) {
            case TXTCFG_SECTION_LV0P_BOOT:
            case TXTCFG_SECTION_TZSP_BOOT:
                lsstart = find_section(sstart, &sstart[rcfg_sz], "*BOOT");
                break;
            case TXTCFG_SECTION_LV0P_RESUME:
            case TXTCFG_SECTION_TZSP_RESUME:
                lsstart = find_section(sstart, &sstart[rcfg_sz], "*RESUME");
                break;
            default:
                ERRORF("txtcfg_apx: unknown section type1: %d\n", section_type);
                ret = -TXTCFG_EBADSARG;
                goto l_txtcfg_apx_c1;
        }
        if (!lsstart) {
            sstart = find_section(sstart, &sstart[rcfg_sz], "*ALL");
            if (!sstart)
                break;
        } else
            sstart = lsstart;

        char *send = find_section(sstart, &sstart[rcfg_sz], NULL);
        if (!send)
            send = &sstart[rcfg_sz];
        //INFOF("txtcfg_apx: section start: 0x%08X end: 0x%08X\n", sstart, send);

        struct txtcfg_section_s section;
        memset(&section, 0, sizeof(section));
        section.type = section_type;
        section.start = sstart;
        section.end = send;
        section.rmb.off = rmboff;
        section.rmb.size = rmbsz;
        section.rmb.va = rmbva;
        section.rmb.mbid = rmbid;
        switch (section_type) {
            case TXTCFG_SECTION_LV0P_BOOT:
            case TXTCFG_SECTION_LV0P_RESUME:
                section.args = lv0c_args;
                section.argc = LV0C_DCOUNT;
                section.handler = txtcfg_lv0cAll;
                break;
            default:
                ERRORF("txtcfg_apx: unknown section type2: %d\n", section_type);
                ret = -TXTCFG_EBADSARG;
                goto l_txtcfg_apx_c1;
        }

        if (dry)
            section.type |= BITN(31);
        ret = parse_section(&section);
        if (ret < 0)
            goto l_txtcfg_apx_c1;
        if (dry)
            rmbsz += section.rmb.size;

        if (send == &sstart[rcfg_sz])
            break;
    }

    if (!rmbsz) {
        ERRORF("txtcfg_apx: rmbsz is zero\n");
        ret = -TXTCFG_EBADSARG;
        goto l_txtcfg_apx_c1;
    }

    if (dry) {
        rmbid = ksceKernelAllocMemBlock("", 0x1020D006, SCE_MEMBLOCK_ALIGN(rmbsz), NULL);
        if ((rmbid < 0) || (ret = ksceKernelGetMemBlockBase(rmbid, &rmbva), ret < 0) || !rmbva) {
            rmbva = NULL;
            ERRORF("txtcfg_srmballoc: failed: 0x%08X:0x%08X\n", rmbid, ret);
            goto l_txtcfg_apx_c2;
        }
        sstart = mbuf;
        goto l_txtcfg_apx_loop;
    } else if (!rmbva || !rmbsz) {
        ERRORF("txtcfg_apx: BUG: !rmbva||!rmbsz: rmbid=0x%08X|rmbsz=0x%08X|rmbva=0x%08X\n", rmbid, rmbsz, rmbva);
        goto l_txtcfg_apx_c2;
    }
    
    if (out) {
        INFOF("txtcfg_apx: skipping section %d exec for out\n", section_type);
        out->rmb_va = rmbva;
        out->rmb_id = rmbid;
        out->rmb_size = rmbsz;
        ret = rmbsz;
        goto l_txtcfg_apx_c1;
    }

    switch (section_type) {
        case TXTCFG_SECTION_LV0P_BOOT:
        case TXTCFG_SECTION_LV0P_RESUME:
            ret = ksplmLv0Cmd(SPLM_LV0_CMD_PATCH, 0, rmbva, SPLM_LV0_COMMBACKUP_CRITICAL);
            INFOF("txtcfg_apx: ksplmLv0Cmd returned: %d\n", ret);
            if (ret < 0)
                goto l_txtcfg_apx_c2;
            break;
        default:
            ERRORF("txtcfg_apx: unknown section type3: %d\n", section_type);
            break;
    }

    INFOF("txtcfg_apx: section %d processed\n", section_type);
    ret = rmbsz;

l_txtcfg_apx_c2:
    ksceKernelFreeMemBlock(rmbid);
l_txtcfg_apx_c1:
    if (rcfg_free) {
        ksceKernelFreeMemBlock(rcfg_mbid);
        rcfg_mbid = -1;
    }
    return ret;
}