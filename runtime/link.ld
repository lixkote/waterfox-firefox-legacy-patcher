SECTIONS {
  . = BASE;
  .blob : {
    *(.text.head)
    *(.text .text.*)
    *(.rodata .rodata.*)
    *(.data .data.*)
    *(.bss .bss.*)
    *(COMMON)
  }
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
