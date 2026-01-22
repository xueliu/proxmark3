INCLUDE sipeed_tang_nano_20k/software/include/generated/output_format.ld
ENTRY(_start)

__DYNAMIC = 0;

INCLUDE sipeed_tang_nano_20k/software/include/generated/regions.ld

SECTIONS
{
	.text :
	{
		_ftext = .;
		/* Make sure crt0 files come first, and they, and the isr */
		/* don't get disposed of by greedy optimisation */
		*crt0*(.text)
		KEEP(*crt0*(.text))
		KEEP(*(.text.isr))

		*(.text .stub .text.* .gnu.linkonce.t.*)
		*(.startos)
		_etext = .;
	} > main_ram

	.rodata :
	{
		. = ALIGN(8);
		_frodata = .;
		*(.rodata .rodata.* .gnu.linkonce.r.*)
		*(.rodata1)
		*(.got .got.*)
		*(.toc .toc.*)
		. = ALIGN(8);
		_erodata = .;
	} > main_ram

	.data :
	{
		. = ALIGN(8);
		_fdata = .;
		*(.data .data.* .gnu.linkonce.d.*)
		*(.data1)
		_gp = ALIGN(16);
		*(.sdata .sdata.* .gnu.linkonce.s.*)
		. = ALIGN(8);
		_edata = .;
	} > main_ram

	.bss :
	{
		. = ALIGN(8);
		_fbss = .;
		*(.dynsbss)
		*(.sbss .sbss.* .gnu.linkonce.sb.*)
		*(.scommon)
		*(.dynbss)
		*(.bss .bss.* .gnu.linkonce.b.*)
		*(COMMON)
		. = ALIGN(8);
		_ebss = .;
		_end = .;
	} > main_ram
}

commonareasize = 0x20;
PROVIDE(_fstack = ORIGIN(main_ram) + LENGTH(main_ram) - commonareasize);

SECTIONS
{
	.commonarea (_fstack) (NOLOAD) :
	{
		*(.commonarea)
	}
}

/* PM3 firmware expects these symbols for copying data from ROM to RAM, 
   but we are running entirely in RAM (loaded by debugger/serial), 
   so ROM addresses can just be the same as RAM addresses or ignored if not used by crt0. 
   However, common_arm/crt0 probably uses them. We need a RISC-V crt0. */
PROVIDE(_fdata_rom = LOADADDR(.data));
PROVIDE(_edata_rom = LOADADDR(.data) + SIZEOF(.data));

/* Aliases for start.c */
PROVIDE(__data_src_start__ = LOADADDR(.data));
PROVIDE(__data_start__ = _fdata);
PROVIDE(__data_end__ = _edata);
PROVIDE(__bss_start__ = _fbss);
PROVIDE(__bss_end__ = _ebss);

/* Aliases for legacy code */
PROVIDE(_stack_start = _ebss); /* Approx stack limit */
PROVIDE(_stack_end = _fstack);
PROVIDE(_flash_start = _ftext);
PROVIDE(_flash_end = _etext);
PROVIDE(_bootphase1_version_pointer = 0);


