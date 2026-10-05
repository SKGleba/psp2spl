#ifndef __TXTCFG_H__
#define __TXTCFG_H__

#define BITF(n) (~(-1 << (n)))
#define BITFL(n) (BITF((n) + 1))
#define BITN(n) (1 << (n))
#define BITNVAL(n, val) ((val) << (n))
#define BITNVALM(n, val, mask) (((val) & (mask)) << (n))
#define XBITN(v, n) (((v) >> (n)) & 1)
#define XBITNVALM(v, n, mask) (((v) >> (n)) & (mask))

#define BSWAP16(x) ((((uint32_t)x << 8) & 0xff00) | (((uint32_t)x >> 8) & 0x00ff))
#define BSWAP24(x) ((((uint32_t)x << 16) & 0xff0000) | (((uint32_t)x >> 8) & 0x00ff00) | (((uint32_t)x >> 24) & 0x0000ff))
#define BSWAP32(x) ((((uint32_t)x << 24) & 0xff000000) | (((uint32_t)x << 8) & 0x00ff0000) | (((uint32_t)x >> 8) & 0x0000ff00) | (((uint32_t)x >> 24) & 0x000000ff))

enum TXTCFG_ARG_TYPES {
    TXTCFG_ARG_TYPE_ASCII = 0,
    TXTCFG_ARG_TYPE_UINT,
    TXTCFG_ARG_TYPE_RDATA,
    TXTCFG_ARG_TYPE_FDATA,
};

// function selector based on argc
#define FUN_VAR4(_1, _2, _3, _4, _fun, ...) _fun

#define TXTCFG_GET_BITPOS(_idx, _type) (((_idx) * 4) + (TXTCFG_ARG_TYPE##_type))
#define _TXTCFG_TYPES_ALLOW1(_idx, _type1) (BITN(TXTCFG_GET_BITPOS(_idx, _type1)))
#define _TXTCFG_TYPES_ALLOW2(_idx, _type1, _type2) (_TXTCFG_TYPES_ALLOW1(_idx, _type1) | BITN(TXTCFG_GET_BITPOS(_idx, _type2)))
#define _TXTCFG_TYPES_ALLOW3(_idx, _type1, _type2, _type3) (_TXTCFG_TYPES_ALLOW2(_idx, _type1, _type2) | BITN(TXTCFG_GET_BITPOS(_idx, _type3)))
#define TXTCFG_TYPES_ALLOW(...) FUN_VAR4(__VA_ARGS__, _TXTCFG_TYPES_ALLOW3, _TXTCFG_TYPES_ALLOW2, _TXTCFG_TYPES_ALLOW1)(__VA_ARGS__)
#define TXTCFG_TYPES_ALLOW_ALL(_idx) (TXTCFG_TYPES_ALLOW((_idx), _UINT, _RDATA, _FDATA) | BITN(TXTCFG_GET_BITPOS((_idx), _ASCII)))
#define TXTCFG_TYPES_PARSE(...) BITNVAL(16, TXTCFG_TYPES_ALLOW(__VA_ARGS__))
#define TXTCFG_TYPES_PARSE_ALL(_idx) BITNVAL(16, TXTCFG_TYPES_ALLOW_ALL(_idx))

enum TXTCFG_SECTION_TYPES {
    TXTCFG_SECTION_LV0P_BOOT,
    TXTCFG_SECTION_LV0P_RESUME,
    TXTCFG_SECTION_TZSP_BOOT,
    TXTCFG_SECTION_TZSP_RESUME,
};

struct txtcfg_section_s {
    int type; // |=BITN(31) for dry run
    int (*handler)(struct txtcfg_section_s *section, int idx, char *ae);
    char *start;
    char *end;
    struct txtcfg_arg_s *args;
    int argc;
    struct {
        int mbid;
        int size;
        int off;
        void *va;
    } rmb;
};

struct txtcfg_arg_s {
	const char *name;
    struct {
        const int min_len;
        const int max_len;  // we assume no args larger than signed int +range...
        int act_len;
        char *ascii;
    } uarg[4];
    uint32_t types;
};

enum TXTCFG_ERRS {
    TXTCFG_OK = 0,
    TXTCFG_E404,
    TXTCFG_ENOMEM,
    TXTCFG_EFOPEN,

    TXTCFG_EPARSE,
    TXTCFG_ENOHANDLER,
    TXTCFG_ECACHE,
    TXTCFG_EBADPARG,
    TXTCFG_EBADSARG,
};

enum LV0C_ENUMS {
    LV0C_INVALID = 0,
    LV0C_STACK,
    LV0C_KSP,
    LV0C_DAT,
    LV0C_EXE,
    LV0C_CUS,
    LV0C_DCOUNT
};

struct txtcfg_apx_out_s {
    void *rmb_va;
    int rmb_id;
    int rmb_size;
};
int txtcfg_apx(char *path, enum TXTCFG_SECTION_TYPES section_type, int knrmbsz, struct txtcfg_apx_out_s *out, int free);

#endif // __TXTCFG_H__