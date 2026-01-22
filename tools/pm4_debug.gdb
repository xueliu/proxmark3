# Connect to OpenOCD (assuming running on localhost:3333)
target remote :3333

# Load symbol definitions (but do NOT load code, as it's loaded by BIOS)
file armsrc/obj/fullimage.stage1.elf
load


# Set a HARDWARE breakpoint at the entry point.
# CRITICAL: Must be a hardware breakpoint (hbreak) because:
# 1. The code hasn't been written to RAM yet (bios loading it).
# 2. Software breakpoints (writing 'ebreak' instruction) would get overwritten by the loader.
# hbreak *0x40000000
break Vector



# Continue execution and wait for the BIOS to jump to 0x40000000
continue
