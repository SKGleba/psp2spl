#ifndef __MAIN_H__
#define __MAIN_H__

#include "splForDriver.h"

#define ERRORF(_fmt, ...) ksceDebugPrintf("%s E: " _fmt, splm_status.dbgId, ##__VA_ARGS__)
#define INFOF(_fmt, ...) if (!splm_status.quiet) ksceDebugPrintf("%s I: " _fmt, splm_status.dbgId, ##__VA_ARGS__)

extern struct splm_statu_s splm_status;

#endif // __MAIN_H__