.section .text.skfchp

.global skfchp_arr
.type	skfchp_arr, @object
skfchp_arr:
.word 0xABCDEF10 # ARR_START
#if defined(SKFW360_374) || defined(SKFW_ALL)
    .word 0xABCDEF11    # skfchp ENTRY_START, type 01 (simple memcpy from here)
    .word 0x03600000    # MINFW
    .word 0x03740000    # MAXFW
# -- copy $6 to sp & run; replaces arm_panic, !func; $6=fcmd --
    .word 0x00800aa6    # DST
        mov $3,0x100    # SRC data
        mov $2,$6
        mov $1,$sp
        .short 0xb569   # bsr memcpy8 [0x00801016 - same for 3.60-3.74 but 8bit]
        lw $7,0x4($sp)
        bne $6,$7,1f
        jsr $sp
    1:
        jmp 0x00800e16
# -- ^
    .word 0xABCDEF1E    # type 0E (cont prev with new addr)
# -- if an unk fcmd is called - fall back to this; $6=fcmd --
    .word 0x00800d94
        and3 $1,$6,0x3
        beqz $1,+0x4    # make sure its not an invalid addr
        bra +0x30
        jmp 0x00800aa6  # ->our patched arm_panic
# -- ^
    .word 0xABCDEF1E
# -- alternative code exec path for !S; replaces stack cookie comp
    .word 0x00800ade
        movh $4,0x1f85
    .word 0xABCDEF1E
    .word 0x00800af2
        lw $5,($4)
        movh $3,0xE000
        lw $6,0x10($3)  # truncd movh,or,lw -> movh,lw(off)
        beq $6,$5,+0x30c
    .word 0xABCDEF1E
    .word 0x00800e06
        bra +0x10
        lw $3,0x8($4)
        add $4,0x4
        bne $4,$3,-0x30e
        mov $6,$4
        bra -0x12e      # we need to ack arm2cry0
# -- ^
#endif

.word 0xABCDEF1F # ARR_END
