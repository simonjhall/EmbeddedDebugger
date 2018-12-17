ENTRY(_start)

SECTIONS
{
/* origins */
/*  . = 0x100100;*/
/* big daddy pro */
/*	. = 0x400100;*/
	. = 0x800100;
  .text : { *(.text*) }
  .rodata : { *(.rodata*) }
  
  .data : { *(.data) } 
  .bss : { *(.bss) }
}
