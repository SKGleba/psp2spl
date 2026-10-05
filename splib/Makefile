TYPE?=lib
SILENT?=false

ARM_SRC?=arm
MEP_SRC?=mep
INC_DIR?=include
REF_DIR?=psp2ref
OUT_DIR?=output

ARM_BASE_OBJS=$(ARM_SRC)/libspl.o
ARM_LV0_OBJS=$(ARM_SRC)/splv0.o
ARM_TZS_OBJS=$(ARM_SRC)/tzs_offsets.o $(ARM_SRC)/spltz.o
ARM_CFK_OBJS=$(ARM_SRC)/splcfk.o

ifeq ($(SILENT),true)
	SILSUFF_LIBN=Silent
	SILSUFF_ARMD=-DSPLIB_NODEBUG
endif

ifeq ($(TYPE), lib)
	OUT_LIB=libspl$(SILSUFF_LIBN).a
	ARM_OBJS=$(ARM_BASE_OBJS) $(ARM_LV0_OBJS) $(ARM_TZS_OBJS)
	ARM_CDEFS=-I$(OUT_TDIR)/mep -DSPLT_LIB $(SILSUFF_ARMD)
	OUT_TDIR=$(OUT_DIR)/lib$(SILSUFF_LIBN)
else ifeq ($(TYPE), cfk)
	OUT_LIB=libsplCFK$(SILSUFF_LIBN).a
	ARM_OBJS=$(ARM_CFK_OBJS)
	ARM_CDEFS=-DSPLT_CFK $(SILSUFF_ARMD)
	OUT_TDIR=$(OUT_DIR)/cfk$(SILSUFF_LIBN)
endif

MEP_BINS=$(OUT_TDIR)/mep/lspl_lv0p.nmp $(OUT_TDIR)/mep/lspl_lv0p_noc.nmp $(OUT_TDIR)/mep/lspl_others.nmp
MEP_BINH=$(MEP_BINS:.nmp=.nmp.h)

MEP_PREFIX=mep-elf
ARM_PREFIX=arm-vita-eabi

MEP_CFLAGS=-I$(INC_DIR) -I$(REF_DIR) -fno-delete-null-pointer-checks -nostdlib -fno-optimize-sibling-calls -fno-jump-tables -Os -std=gnu99 -mc=far -mel -ml -Wno-multichar
ARM_CFLAGS=-I$(INC_DIR) -I$(REF_DIR) -mcpu=cortex-a9 -mthumb-interwork -Os -g0 -Wall -Wno-unused-const-variable -ffreestanding -fdata-sections -ffunction-sections -Wno-multichar $(ARM_CDEFS)

.PHONY: all arm mep clean cleanall install lib cfk actual

all: cleanall lib cfk
	$(MAKE) clean
	$(MAKE) install
actual: clean mep arm
lib:
	$(MAKE) actual TYPE=lib SILENT=false
	$(MAKE) actual TYPE=lib SILENT=true
cfk:
	$(MAKE) actual TYPE=cfk SILENT=false
	$(MAKE) actual TYPE=cfk SILENT=true

mep: $(MEP_BINH)

install:
	-cp $(OUT_DIR)/libspl.a $(VITASDK)/arm-vita-eabi/lib/libspl.a
	-cp $(OUT_DIR)/libsplSilent.a $(VITASDK)/arm-vita-eabi/lib/libsplSilent.a
	-cp $(OUT_DIR)/libsplCFK.a $(VITASDK)/arm-vita-eabi/lib/libsplCFK.a
	-cp $(OUT_DIR)/libsplCFKSilent.a $(VITASDK)/arm-vita-eabi/lib/libsplCFKSilent.a
	-rm -rf $(VITASDK)/arm-vita-eabi/include/libspl
	cp -r $(INC_DIR) $(VITASDK)/arm-vita-eabi/include/libspl
	@echo "Installed libs and headers to $(VITASDK)/arm-vita-eabi"

clean:
	-rm -f $(MEP_SRC)/*.o $(MEP_SRC)/*.ao $(MEP_SRC)/*.elf $(MEP_SRC)/*.nmp $(MEP_SRC)/*.map
	-rm -f $(ARM_SRC)/*.o

cleanall: clean
	-rm -rf $(OUT_DIR)

arm: mep $(OUT_LIB)
	-rm -f $(ARM_OBJS)
	-rm -f $(OUT_DIR)/$(OUT_LIB)
	mv $(OUT_LIB) $(OUT_DIR)/$(OUT_LIB)

$(OUT_LIB): $(MEP_BINH) $(ARM_OBJS)
	$(ARM_PREFIX)-ar rcs $@ $(ARM_OBJS)

$(ARM_SRC)/%.o: $(ARM_SRC)/%.c
	$(ARM_PREFIX)-gcc $(ARM_CFLAGS) -c $< -o $@
	-mkdir -p $(OUT_TDIR)/arm
	cp $@ $(OUT_TDIR)/arm/

$(OUT_TDIR)/mep/%.nmp.h: %.nmp
	-mkdir -p $(OUT_TDIR)/mep
	-rm -f $@
	xxd -i $< > $@
	mv $< $(OUT_TDIR)/mep/$<
	mv $(MEP_SRC)/$<.map $(OUT_TDIR)/mep/$<.map

$(MEP_SRC)/%.o: $(MEP_SRC)/%.c
	$(MEP_PREFIX)-gcc -c -o $@ $< $(MEP_CFLAGS)

$(MEP_SRC)/%.ao: $(MEP_SRC)/%.s
	$(MEP_PREFIX)-gcc -c -o $@ $< $(MEP_CFLAGS)

lspl_lv0p_noc.nmp: $(MEP_SRC)/lv0p.c
	$(MEP_PREFIX)-gcc -c -o $(MEP_SRC)/lv0p_noc.o $< $(MEP_CFLAGS) -DLV0P_NOCJPM
	$(MEP_PREFIX)-gcc -o $(MEP_SRC)/lv0p_noc.elf $(MEP_SRC)/lv0p_noc.o -nodefaultlibs -nostdlib -nostartfiles -ffreestanding -T$(MEP_SRC)/lv0p.x -Wl,-Map=$(MEP_SRC)/lspl_lv0p_noc.nmp.map
	$(MEP_PREFIX)-objcopy -O binary $(MEP_SRC)/lv0p_noc.elf lspl_lv0p_noc.nmp

lspl_lv0p.nmp: $(MEP_SRC)/lv0p.o
	$(MEP_PREFIX)-gcc -o $(MEP_SRC)/lv0p.elf $(MEP_SRC)/lv0p.o -nodefaultlibs -nostdlib -nostartfiles -ffreestanding -T$(MEP_SRC)/lv0p.x -Wl,-Map=$(MEP_SRC)/lspl_lv0p.nmp.map
	$(MEP_PREFIX)-objcopy -O binary $(MEP_SRC)/lv0p.elf lspl_lv0p.nmp

lspl_others.nmp: $(MEP_SRC)/skfchp.ao $(MEP_SRC)/stage2.ao
	$(MEP_PREFIX)-gcc -o $(MEP_SRC)/others.elf $(MEP_SRC)/skfchp.ao $(MEP_SRC)/stage2.ao -nodefaultlibs -nostdlib -nostartfiles -ffreestanding -T$(MEP_SRC)/others.x -Wl,-Map=$(MEP_SRC)/lspl_others.nmp.map
	$(MEP_PREFIX)-objcopy -O binary $(MEP_SRC)/others.elf lspl_others.nmp