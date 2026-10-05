#include "hardware/types.h"
#include "hardware/paddr.h"
#include "hardware/maika.h"

typedef int bool;
#define true 1
#define false 0
#include "libspl-lv0p.h"

#define NULL ((void *)0)

#define AME_COUNT 4
struct actually_me_s {
    int (*main)(struct actually_me_s *me, struct lv0p_j_s *job);
	void *(*memcpy)(void *dest, const void *src, uint32_t n);
    int (*patch_vis_keyslot)(struct actually_me_s *me, uint32_t id, uint32_t off, uint32_t sz, void *data, uint8_t *buf);
    int (*cjp_machine)(struct actually_me_s *me, uint32_t *reset, unsigned int num, void *work);
    uint32_t magic;
};
struct actually_me_s actually_me;

void *memcpy(void *dest, const void *src, uint32_t n) {
    if (((uint32_t)src | (uint32_t)dest | (uint32_t)n) & 3) {
        const uint8_t *s = src;
        uint8_t *d = dest;
        while (n) {
            *d++ = *s++;
            n--;
        }
    } else {
        const uint32_t *s = src;
        uint32_t *d = dest;
        while (n) {
            *d++ = *s++;
            n -= 4;
        }
    }
    return dest;
}
#define memset0(_d, _n) me->memcpy((_d), (const void *)DEVNULL_OFFSET, (_n))

int patch_vis_keyslot(struct actually_me_s *me, uint32_t id, uint32_t off, uint32_t sz, void *data, uint8_t *buf) {
    // uint8_t buf[MAIKA_KEYSLOT_SIZE];
    maika_s *maika = (maika_s *)MAIKA_OFFSET;
    me->memcpy(buf, (const void *)maika->keyring[id - MAIKA_KEYSLOT_COUNT], MAIKA_KEYSLOT_SIZE);
	if ((off + sz) > MAIKA_KEYSLOT_SIZE)
        return -1;
    me->memcpy(buf + off, (const void *)data, sz);
    me->memcpy((void *)maika->keyring_ctrl.data, (const void *)buf, MAIKA_KEYSLOT_SIZE);
    maika->keyring_ctrl.keyslot = id;
	return 1;
}

// WIP
#ifndef LV0P_NOCJPM
#define CJP_MOD(_m, _n) ((_m) & (1 << (LV0P_CJP_MOD##_n)))
#define xorswap(_a, _b, _it, _ot) { _a = _ot (_it _a ^ _it _b); _b = _ot (_it _b ^ _it _a); _a = _ot (_it _a ^ _it _b); } // heh
int cjp_machine(struct actually_me_s *me, uint32_t *reset, unsigned int num, void *work) {
    uint32_t *c = reset;    // 12-op-sized context window with ops
    unsigned int i = 0; // current op idx in context
    uint32_t p = 0;     // result from last Pop
    uint32_t a[4];      // instr arg a0, a1|a1_imm16, a2, a1_imm12|a1_imm8
    uint32_t g[4];      // GPr
    int r = LV0P_CJPMR_OK;
    memset0(a, sizeof(a));
    memset0(g, sizeof(g));
    g[3] = (uint32_t)work;
    unsigned int r_pos = 0;
    while ((r_pos + i) < num) {
        r = -LV0P_CJPMR_EBADOP;
        uint32_t op = c[i], t;
        int o = (op >> 10) & 0b111111;
        if (!o)
            break;
        i++;
        
        r = -LV0P_CJPMR_EBADMOD;
        int m = (op >> 4) & 0xFF;
        bool is2 = false;
        bool isx = !!CJP_MOD(m, _EXTND);
        bool a1i = !!CJP_MOD(m, _A1IMM);
        a[0] = op & 0b1111;
        a[1] = (op >> 16) & 0xFFFF;
        a[2] = (op >> 28) & 0b1111;
        a[3] = a1i ? 0 : (op >> 20) & 0xFFF;
        if (isx) {
            a[1] &= 0xFFF;
            a[3] &= 0xFF;
        } else {
            o &= 0b1111;
            if (!o) { r = -LV0P_CJPMR_EBADOP; break; }
        }
        if (!a1i) {
            if (a[3] && !CJP_MOD(m, _PTRA1)) {
                if (isx)
                    break;
                is2 = true;
                a[3] = 0;
            }
            a[1] &= 0b1111;
        } else if (CJP_MOD(m, _TIM16))
            a[1] <<= 16;

        uint32_t *ca0, *ca1, *ca2;
l_CJPm_pdop:
        ca0 = (a[0] >= 12) ? &g[a[0] - 12] : &c[a[0]];
        ca1 = a1i ? &a[1] : ((a[1] >= 12) ? &g[a[1] - 12] : &c[a[1]]);
        ca2 = (a[2] >= 12) ? &g[a[2] - 12] : &c[a[2]];
        if (CJP_MOD(m, _PTRA0)) {
            if (o > LV0P_CJP_OP__JOPSEND)
                ca0 = (uint32_t *)(*ca0);
        } else if (o <= LV0P_CJP_OP__JOPSEND)
            ca0 = &a[0];
        if (!a1i && CJP_MOD(m, _PTRA1))
            ca1 = (uint32_t *)((uint32_t)*ca1 + a[3]);
        if (CJP_MOD(m, _SWAPA) && (o > LV0P_CJP_OP__JOPSEND))
            xorswap(ca0, ca1, (uint32_t), (uint32_t *));

        r = LV0P_CJPMR_OK;
        if (o < LV0P_CJP_OP__XOPSTART)
            t = *ca1;
        switch (o) {
            case LV0P_CJP_OP_JDC: // warn: absolute _host_ addr jump if > JDCA2RILT
                if (t < LV0P_CJPM_JDCA2RILT) {
                    if (t > num) { r = -LV0P_CJPMR_EBADJDCD; break; }
                    r_pos = t;
                    t = (uint32_t)reset + (t * sizeof(uint32_t));
                }
                c = (uint32_t *)t;
            break; case LV0P_CJP_OP_JNE:
                if (CJP_MOD(m, _JEQUS)) {
                    if (t == p)
                        i = *ca0;
                } else if (t != p)
                    i = *ca0;
            break; case LV0P_CJP_OP_JLT:
                if (CJP_MOD(m, _JSIGC)) {
                    if ((int)t < (int)p)
                        i = *ca0;
                    else if (CJP_MOD(m, _JEQUS) && ((int)t <= (int)p))
                        i = *ca0;
                } else {
                    if (t < p)
                        i = *ca0;
                    else if (CJP_MOD(m, _JEQUS) && (t <= p))
                        i = *ca0;
                }
            break; case LV0P_CJP_OP_JGT:
                if (CJP_MOD(m, _JSIGC)) {
                    if ((int)t > (int)p)
                        i = *ca0;
                    else if (CJP_MOD(m, _JEQUS) && ((int)t >= (int)p))
                        i = *ca0;
                } else {
                    if (t > p)
                        i = *ca0;
                    else if (CJP_MOD(m, _JEQUS) && (t >= p))
                        i = *ca0;
                }
            break;
            case LV0P_CJP_OP_MOV32:
            break; case LV0P_CJP_OP_ADD:
                t += *ca0;
            break; case LV0P_CJP_OP_SUB:
                t = *ca0 - t;
            break; case LV0P_CJP_OP_MUL:
                t *= *ca0;
            break; case LV0P_CJP_OP_DIV:
                if (t)
                    t = *ca0 / t;
                else
                    r = -LV0P_CJPMR_EZDIV;
            break; case LV0P_CJP_OP_AND:
                t = *ca0 & t;
            break; case LV0P_CJP_OP_OR:
                t |= *ca0;
            break; case LV0P_CJP_OP_XOR:
                t ^= *ca0;
            break; case LV0P_CJP_OP_LSH:
                t = *ca0 << (t % 32);
            break; case LV0P_CJP_OP_RSH:
                t = *ca0 >> (t % 32);
                break;
            case LV0P_CJP_OP_MOV8:
                t = *(uint8_t *)((uint32_t)ca1 + ((*ca2 >> 2) & 3));
                *(uint8_t *)((uint32_t)ca0 + (*ca2 & 3)) = (uint8_t)t;
            break; case LV0P_CJP_OP_MOV16:
                t = *(uint16_t *)((uint32_t)ca1 + (((*ca2 >> 1) & 1) * 2));
                *(uint16_t *)((uint32_t)ca0 + ((*ca2 & 1) * 2)) = (uint16_t)t;
            break;
            default:
                r = -LV0P_CJPMR_EUNKOPC;
                break;
        }
        if (r < 0)
            break;
        if (o > LV0P_CJP_OP__JOPSEND) {
            if (o < LV0P_CJP_OP__XOPSTART)
                *ca0 = t;
            if (!(CJP_MOD(m, _NOPCG)))
                p = t;
        }
        if (CJP_MOD(m, _CTXMV)) {
            c = &c[i];
            r_pos += i;
        }
        if (is2) {
            o = (op >> 24) & 0b1111;
            if (!o) { r = -LV0P_CJPMR_EBAD2OP; break; }
            m = (op >> 20) & 0b1111;
            a[0] = (op >> 16) & 0b1111;
            a[1] = (op >> 28) & 0b1111;
            a[2] = 0;
            a[3] = 0;
            is2 = isx = a1i = false;
            goto l_CJPm_pdop;
        }
    }
    return r;
}
#else
int cjp_machine(struct actually_me_s *me, uint32_t *reset, unsigned int num, void *work) {
    return -1;
}
#endif // LV0P_NOCJPM

int main(struct actually_me_s *me, struct lv0p_j_s *job) {
    uint8_t work[LV0P_WORKBUF_SIZE];
    while (job) {
        if (job->magic != LV0P_MAGIC)
            return -1;
        switch (job->idx) {
            case LV0P_JOB_NOP:
                job->ret = 0;
                break;
            case LV0P_JOB_KSP:
                job->ret = me->patch_vis_keyslot(me, job->k.id, job->k.off, job->k.size, job->k.data, work);
                break;
            case LV0P_JOB_DAT:
                job->ret = (int)me->memcpy(job->d.dst ? (void *)job->d.dst : job->d.cbuf, job->d.src ? (void *)job->d.src : job->d.cbuf, job->d.size);
                break;
            case LV0P_JOB_EXE:
                job->ret = job->x.func(job->x.argv[0], job->x.argv[1], job->x.argv[2], job->x.argv[3], job->x.argv[4], job->x.argv[5], job->x.argv[6], job->x.argv[7]);
                break;
            case LV0P_JOB_CUS:
                job->ret = me->cjp_machine(me, job->c, 12, work);
                break;
            default:
                job->ret = 0xBADC0DE0 | job->idx;
                return -1;
        }
        job = job->next;
    }
    return 0;
}

__attribute__((section(".text.start"))) int start(uint32_t actual_start, struct lv0p_j_s *jobs) {
    if (!actual_start || (actual_start & 3))
        return -1;
    struct actually_me_s *me = (struct actually_me_s *)((actual_start + (uint32_t)&actually_me));
    if (me->magic != LV0P_MAGIC)
        return -2;
	uint32_t *funcs = (uint32_t *)me;
	for (int i = 0; i < AME_COUNT; i++)
		funcs[i] += actual_start;  // adj
    return me->main(me, jobs);
}

__attribute__((aligned(0x4))) struct actually_me_s actually_me = {
    .main = main,
	.memcpy = memcpy,
	.patch_vis_keyslot = patch_vis_keyslot,
    .cjp_machine = cjp_machine,
    .magic = LV0P_MAGIC
};