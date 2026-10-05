.section .text.stage2

.global stage2_arr
.type	stage2_arr, @object
stage2_arr:
.word 0xABCDEF20 # ARR_START
#if defined(S2FW360_370) || defined(S2FW_ALL)
    .word 0xABCDEF21    # stage2 ENTRY_START, type 01 (wrapper w/nskcl, +0x4 = params)
    .word 0x03600000    # MINFW
    .word 0x03740000    # MAXFW
    .short (l_s2t1_nskcls - l_s2t1_start) # NSKCLS - non-sk compatibility layer start
    .short (l_s2t1_nskcl1 - l_s2t1_start) # NSKCL1
l_s2t1_start:
        mov $7, $sp
        bra 1f
        .word 0x0               # src (magic) & status
        .word 0xDEADBABE        # ret
        .word 0x0               # code
        .word 0x0,0x0,0x0,0x0   # args
        .word 0x0               # req sp
        .word 0x0               # gpz/JMPBA
    1:
        bne $sp,$1,23f # check if fcmdh
        bne $sp,$0,23f # both must pass
        ldc $5, $lp
    2:
        lw $0,0xC($sp)
        lw $1,0x10($sp)
        lw $2,0x14($sp)
        lw $3,0x18($sp)
        lw $4,0x1C($sp)
        lw $sp,0x20($sp)
        bnez $sp, 3f
        mov $sp, $7
    3:
        sw $0,0x4($6)
        beqz $0, 4f     # ret0
        beqi $0,0x2,5f  # read32
        beqi $0,0x4,6f  # write32
        jsr $0
    4:
        sw $0,0x8($6)
        sw $sp,0x4($6)
        mov $sp, $7
        jmp $5
    5:
        lw $0,($1)
        bra 4b
    6:
        sw $2,($1)
        bra 4b
    7:
        bra 2b
# -- NSKCL, currently only pUSSM --
l_s2t1_nskcls:
l_s2t1_nskcl1:
    23:
        sw $3,0x8($6)           # not sure if req
        mov $6,$3
        mov $sp,$3
        lw $5,0x24($sp)
        bra 7b
#endif

#if defined(USSMFW360_370) || defined(USSMFW_ALL)
    .word 0xABCDEF22    # type 02 (prepp for 0xD0002 arg[0] = jmp pa)
    .word 0x03600000    # MINFW
    .word 0x03700000    # MAXFW
    .word 0x0080be96    # JMPBA
    .word 0x0080bd10    # PAIR0_START
    .word 0x0080bd20    # PAIR0_LAST
#endif

#if defined(USSMFW371_374) || defined(USSMFW_ALL)
    .word 0xABCDEF23    # type 03 (p4 plant jmpa with 0xD0002:1 then loadjump)
    .word 0x03710000
    .word 0x03740000
    .word 0x0080befc    # JMPBA
    .word 5414          # JMPOA
    .word 0x0080bd7c
    .word 0x0080bd7c
#endif

.word 0xABCDEF2F # ARR_END


    
    
