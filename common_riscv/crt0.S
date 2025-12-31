



.section .text
.global _start
.global _fstack

_start:
    /* Set up stack pointer */
    la sp, _fstack

    /* Initialize Global Pointer if needed */
    .option push
    .option norelax
    la gp, _gp
    .option pop

    /* Clear BSS */
    la t0, _fbss
    la t1, _ebss
    bge t0, t1, 2f
1:
    sw zero, 0(t0)
    addi t0, t0, 4
    blt t0, t1, 1b
2:

/*  
    Copy data from ROM to RAM if needed. 
    (Skipped for now as we assume loading into RAM directly or ROM=RAM in this setup)
*/

    /* Call Vector */
    call Vector

    /* Infinite loop if Vector returns */
3:  j 3b

/* Interrupt Vector Setup (Minimal) */
.section .text.isr
.global isr
.align 2
isr:
    /* Minimal ISR: Just return (mret) or loop */
    /* Only machine mode for now */
    mret
