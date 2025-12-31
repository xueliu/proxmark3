PACKAGES=libc libcompiler_rt libbase libfatfs liblitespi liblitedram libliteeth liblitesdcard liblitesata bios
PACKAGE_DIRS=/home/lx/spielplatz/litex/litex/litex/soc/software/libc /home/lx/spielplatz/litex/litex/litex/soc/software/libcompiler_rt /home/lx/spielplatz/litex/litex/litex/soc/software/libbase /home/lx/spielplatz/litex/litex/litex/soc/software/libfatfs /home/lx/spielplatz/litex/litex/litex/soc/software/liblitespi /home/lx/spielplatz/litex/litex/litex/soc/software/liblitedram /home/lx/spielplatz/litex/litex/litex/soc/software/libliteeth /home/lx/spielplatz/litex/litex/litex/soc/software/liblitesdcard /home/lx/spielplatz/litex/litex/litex/soc/software/liblitesata /home/lx/spielplatz/litex/litex/litex/soc/software/bios
LIBS=libc libcompiler_rt libbase libfatfs liblitespi liblitedram libliteeth liblitesdcard liblitesata
TRIPLE=riscv64-unknown-elf
CPU=vexriscv
CPUFAMILY=riscv
CPUFLAGS= -march=rv32i2p0_mac -mabi=ilp32 -D__vexriscv_smp__ -D__riscv_plic__
CPUENDIANNESS=little
CLANG=0
CPU_DIRECTORY=/home/lx/spielplatz/litex/litex/litex/soc/cores/cpu/vexriscv_smp
SOC_DIRECTORY=/home/lx/spielplatz/litex/litex/litex/soc
PICOLIBC_DIRECTORY=/home/lx/spielplatz/litex/pythondata-software-picolibc/pythondata_software_picolibc/data
PICOLIBC_FORMAT=integer
COMPILER_RT_DIRECTORY=/home/lx/spielplatz/litex/pythondata-software-compiler_rt/pythondata_software_compiler_rt/data
export BUILDINC_DIRECTORY
BUILDINC_DIRECTORY=/home/lx/spielplatz/litex/sipeed_tang_nano_20k/build/sipeed_tang_nano_20k/software/include
LIBC_DIRECTORY=/home/lx/spielplatz/litex/litex/litex/soc/software/libc
LIBCOMPILER_RT_DIRECTORY=/home/lx/spielplatz/litex/litex/litex/soc/software/libcompiler_rt
LIBBASE_DIRECTORY=/home/lx/spielplatz/litex/litex/litex/soc/software/libbase
LIBFATFS_DIRECTORY=/home/lx/spielplatz/litex/litex/litex/soc/software/libfatfs
LIBLITESPI_DIRECTORY=/home/lx/spielplatz/litex/litex/litex/soc/software/liblitespi
LIBLITEDRAM_DIRECTORY=/home/lx/spielplatz/litex/litex/litex/soc/software/liblitedram
LIBLITEETH_DIRECTORY=/home/lx/spielplatz/litex/litex/litex/soc/software/libliteeth
LIBLITESDCARD_DIRECTORY=/home/lx/spielplatz/litex/litex/litex/soc/software/liblitesdcard
LIBLITESATA_DIRECTORY=/home/lx/spielplatz/litex/litex/litex/soc/software/liblitesata
BIOS_DIRECTORY=/home/lx/spielplatz/litex/litex/litex/soc/software/bios
LTO=0
BIOS_CONSOLE_FULL=1