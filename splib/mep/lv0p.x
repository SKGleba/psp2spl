SECTIONS
{
  . = 0x00000000;
  .text   : { *(.text.start) *(.text   .text.*   .gnu.linkonce.t.*) }
  .rodata : { *(.rodata .rodata.* .gnu.linkonce.r.*) }
  .data   : { *(.data   .data.* .far    .far.*  .gnu.linkonce.d.*)  *(.bss    .bss.*    .farbss .farbss.*   .gnu.linkonce.b.*) *(COMMON) }
}