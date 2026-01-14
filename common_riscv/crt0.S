

/*
 * RISC-V Startup Code (C Runtime Initialization 0)
 *
 * Even when running from RAM, this file is CRITICAL because:
 * 1. Stack Setup: The C compiler generates code assuming the Stack Pointer (sp) 
 *    points to valid memory. We must set this manually before calling any C function.
 * 2. Global Pointer: The compiler uses the Global Pointer (gp) for efficient 
 *    access to global variables. It must be initialized to the linker-defined value.
 * 3. BSS Clearing: The C standard requires uninitialized global variables (BSS) 
 *    to be zero. This code clears that memory region.
 * 4. Entry Point: It provides the standard `_start` symbol for the linker.
 */

.section .text          /* Define the following code as part of the text (code) section */
.global _start          /* specific symbol that linker looks for as entry point */
.global _fstack         /* Symbol defined in linker.ld pointing to top of stack */

_start:
    /* --------------------------------------------------------------------
     * 1. Set up Stack Pointer (sp)
     * -------------------------------------------------------------------- */
    la sp, _fstack      /* Load Address: Load the address of _fstack into sp register */
                        /* _fstack is defined in linker.ld as the end of internal RAM */

    /* --------------------------------------------------------------------
     * 2. Initialize Global Pointer (gp)
     * -------------------------------------------------------------------- */
    .option push        /* Save current assembler options */
    .option norelax     /* Disable linker relaxation for the next instruction to ensure */
                        /* the address calculation is accurate and not optimized away prematurely */
    la gp, _gp          /* Load the address of the global pointer */
                        /* _gp is a special symbol typically in the middle of .sdata/.sbss */
    .option pop         /* Restore assembler options */

    /* --------------------------------------------------------------------
     * 3. Clear BSS Section (Block Started by Symbol)
     * -------------------------------------------------------------------- */
    la t0, _fbss        /* Load start address of BSS section into temporary register t0 */
    la t1, _ebss        /* Load end address of BSS section into temporary register t1 */
    bge t0, t1, 2f      /* Branch to label '2' (forward) if start >= end (BSS is empty) */

1:                      /* Loop label '1' */
    sw zero, 0(t0)      /* Store Word: Write 0 (from zero register) to address in t0 */
    addi t0, t0, 4      /* Add Immediate: Increment t0 by 4 bytes */
    blt t0, t1, 1b      /* Branch to label '1' (backward) if t0 < t1 (continue loop) */
2:                      /* End of BSS loop label */

    /* --------------------------------------------------------------------
     * 4. Enter C Code
     * -------------------------------------------------------------------- */
    call Vector         /* Jump to the function named 'Vector' (entry point in C code) */
                        /* 'Vector' typically sets up the proxmark3 command loop */

    /* --------------------------------------------------------------------
     * 5. Catch Return (Safety Net)
     * -------------------------------------------------------------------- */
3:  j 3b                /* Infinite loop: Jump to label '3' (backward) -> itself. */
                        /* If main/Vector returns, we hang here to prevent undefined behavior. */

/* --------------------------------------------------------------------
 * Minimal Interrupt Vector Handler
 * -------------------------------------------------------------------- */
.section .text.isr      /* Place in a separate section for ISRs */
.global isr             /* Make the symbol visible globally */
.align 2                /* Align to 4-byte boundary (2^2) */
isr:
    mret                /* Machine Return: Return from interrupt context. */
                        /* Currently just a stub. Real handling would go here. */
