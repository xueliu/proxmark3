# Proxmark3 RISC-V Port Architecture

This document outlines the key architectural decisions and technical learnings from porting the Proxmark3 firmware to the RISC-V architecture (specifically LiteX/VexRiscv).

## 0. Build Instructions (Quick Start)

To build the firmware for the **PM4 (RISC-V)** platform:

```bash
# 1. Standard build (generates fullimage.elf and fullimage.bin)
make fullimage V=1

# 2. Parallel build with clean (Verified working)
# 2. Parallel build with clean (Verified working)
make clean && make -j fullimage

# 3. Debug Build (Enables -g -O0 and generated symbols)
make clean && make fullimage DEBUG=1
```
*Note*: The `bootrom` and `recovery` targets are automatically skipped for this platform.

## 1. Architectural Decisions

### 1.1 Target Architecture & Hardware
*   **Core**: `vexriscv_smp` (RISC-V 32-bit).
*   **Platform**: Sipeed Tang Nano 20k (FPGA).
*   **SoC Environment**: LiteX. The firmware relies heavily on LiteX-generated headers (`csr.h`, `soc.h`) for hardware description and peripheral access.

### 1.2 Execution Model
*   **RAM-based Execution**: Unlike the original firmware which potentially runs from Flash or a mix, this port is configured to run entirely from **RAM** (`main_ram` region @ `0x40000000`).
*   **Boot Process**: The firmware is loaded into RAM (e.g., via `serialboot` or JTAG) and executed. The startup code (`crt0.S`) initializes the C environment (stack, BSS) before jumping to `main`.

### 1.3 Hardware Abstraction Layer (HAL) Adaptations
*   **USB CDC Emulation**: The target FPGA core lacks a native hard USB PHY/Controller compatible with the original driver.
    *   **Decision**: Replace `usb_cdc.c` with a **UART-based emulation**.
    *   **Implementation**: `usb_write`, `usb_read`, and polling functions map directly to LiteX UART CSRs (`uart_rxtx`, `uart_txfull`, `uart_rxempty`). This allows standard firmware communication protocols into the UART console.
*   **Timing**:
    *   **Decision**: Use the RISC-V `rdcycle` instruction for high-precision timing instead of ARM/SAM7S specific hardware timers.
    *   **Implementation**: `ticks.c` was rewritten to read the cycle counter, scaled by `CONFIG_CLOCK_FREQUENCY` (defined in `soc.h`).
*   **Clock Management**:
    *   **Decision**: FPGA clocks are fixed by the bitstream.
    *   **Implementation**: `clocks.c` functions are stubbed out (no-ops).

### 1.4 Build System
*   **Toolchain**: `riscv64-unknown-elf-gcc`.
*   **Library Dependencies**: Uses `picolibc`, `libbase`, and `libcompiler_rt` provided by the LiteX software environment.
*   **Include Management**: 
    *   The build system uses `-isystem` to include external library headers without triggering strict warning checks.
    *   A custom `hw/common.h` and `system.h` were introduced to bridge the gap between LiteX generated headers and the compiler's expected environment.

## 2. Learnings from Debugging & Porting

### 2.1 Build System & Linker
*   **VPATH & Implicit Rules & ASMSRC**: The original Makefile structure mixed source directories in `VPATH`. `Makefile.common` defined an implicit rule for `.S` files (`$(ASMOBJ_S): $(OBJDIR)/%.o: %.S`). However, `armsrc/Makefile` unintentionally triggered this rule poorly when `ASMSRC` was not explicitly cleared or handled, leading to `crt0.S: No such file`. **Solution**: Explicitly set `ASMSRC =` (empty) in `armsrc/Makefile` to disable the conflicting implicit logic, and manually define `ASMOBJ = obj/crt0.o` with an explicit compilation rule.
*   **Symbol Mismatch**: Legacy code and linker scripts often use inconsistent symbol names (e.g., `_stack_start` vs `_fstack`). **Solution**: Creating aliases in the linker script (`PROVDIE(_stack_start = _ebss)`) allows legacy code to link without modification.
*   **Binary Generation**: The default build rules might produce S-Records (`.s19`) or ELF files. For loaders like `serialboot`, a raw binary (`.bin`) is often required. **Solution**: Explicit `objcopy -O binary` rules were added to `armsrc/Makefile`.
*   **Linker Script (`linker.ld`) Sections**:
    *   **.startos**: The `Vector` function uses `__attribute__((section(".startos")))`. This custom section was missing from the standard LiteX linker script. **Solution**: Added `*(.startos)` to the `.text` section in `common_riscv/linker.ld` to ensure the vector table/entry point is correctly linked.
    *   **.commonarea**: The Proxmark3 firmware relies on a shared memory region (`commonarea`) at the end of RAM to exchange flags (like `osimage_present`) between bootloader phases. **Solution**: Added a `.commonarea` section definition at the end of `main_ram` (explicitly calculating address via `_fstack`) to `common_riscv/linker.ld`.
    *   **Entry Point Verification**: Verified via `readelf` that the firmware entry point and `.text` section start at `0x40000000`, confirming correct linking for RAM execution.

### 2.2 Code Compatibility (ARM to RISC-V)
*   **Startup Verification (LEDs)**: When porting to a new architecture with uncertain UART reliability, visual indicators are redundant. **Technique**: Injected `leds_out_write(0)` (turn off all LEDs) at the very start of the `Vector` function in `armsrc/start.c`. This provides immediate visual confirmation that the CPU has jumped to the RAM entry point and executed the first instruction.
*   **crt0.S Necessity**: Even when running from RAM, a custom startup file (`crt0.S`) is **CRITICAL** for:
    1.  Initializing the Stack Pointer (`sp`) to the address defined in the linker script (`_fstack`).
    2.  Initializing the Global Pointer (`gp`) to `_gp`.
    3.  Clearing the BSS section to zero (RAM contents are undefined).
*   **Inline Assembly**: GCC's handling of `asm` vs `__asm__` keywords differs by strictness levels (e.g., `-std=c99`). **Solution**: Use `__asm__` for portability in headers and C files.
*   **Implicit Function Declarations**: Missing prototypes for functions (like `usb_read_ng`) can lead to link-time errors even if the compile phase passes. This is critical when replacing drivers—ensure *all* public API functions of the replaced driver are stubbed or implemented.
*   **Debug Symbols**: The final `armsrc/obj/fullimage.elf` is explicitly stripped of symbols to reduce size. When debugging, you **MUST** load symbols from the intermediate `armsrc/obj/fullimage.stage1.elf` file.

### 2.3 Dependency Management
*   **Header Hell**: Porting across architectures often reveals "hidden" dependencies on system headers. The LiteX `csr.h` depended on types and macros usually found in a `system.h` or `hw/common.h` which weren't in the standard include path. **Solution**: Mocking or adapting these "bridge" headers is a quick way to unblock compilation.
*   **Disabled Targets**: The `bootrom` and `recovery` targets are specific to the original AT91SAM7S architecture and its flashing mechanism. For the PM4 (FPGA), these are irrelevant (as we load directly to RAM) and cause build failures. 
    *   *Note*: The `recovery` target depends on `bootrom`. Attempting to run a parallel build (`make -j`) when only `bootrom` is disabled caused race conditions or dependency failures in `recovery`. **Solution**: Conditional logic `ifeq ($(PLATFORM),PM4)` was added to the root `Makefile` to explicitly skip **both** `bootrom` and `recovery` targets.


## 3. Project Goal
The objective is to port the Proxmark3 firmware (originally for AT91SAM7S - ARMv4T) to a LiteX-based SoC running on VexRiscv SMP (RISC-V 32-bit).
The target is **NOT** to emulate ARM instructions, but to **re-implement logic** using native RISC-V code and LiteX drivers.

Proxmark3的FPGA LF，HF部分也需要在Sipeed Tang Nano 20k (FPGA)中实现。因此需要定义一个新的接口用以连接LF，HF模块和CPU。

## 4. System Overview & Constraints

| Feature | Original (Proxmark3) | Target (LiteX/VexRiscv) | Action Required |
| :--- | :--- | :--- | :--- |
| **CPU** | AT91SAM7S512 (ARM) | VexRiscv SMP (ONLY 1 Core) | Rewrite Assembly to C. |
| **Clock** | 48 MHz (PLL) | [e.g., 50 MHz] | Recalculate timing-sensitive loops (FPGA protocols). |
| **Endianness** | Little Endian | Little Endian | Verify network/NFC byte order handling. |
| **Build System**| Makefile (ARM GCC) | CMake + LiteX Build Env | Use `riscv64-unknown-elf-gcc`. |

## 5. Hardware Abstraction Layer (HAL) Mapping
**CRITICAL:** The Agent must NOT use `AT91C_BASE_*` macros. Use LiteX CSR accessors defined in `#include <generated/csr.h>`.

### 3.1 Memory Map (Source of Truth: `regions.ld`)
The memory layout is defined by `common_riscv/sipeed_tang_nano_20k/software/include/generated/regions.ld`, generated by LiteX.

| Region Name | Origin | Length | Description |
| :--- | :--- | :--- | :--- |
| **rom** | `0x00000000` | 128 KB | **Boot ROM**. Contains the LiteX BIOS. CPU starts executing here on reset. |
| **spiflash**| `0x00800000` | 8 MB | **SPI Flash**. Memory-mapped access to the onboarding flash chip. |
| **sram** | `0x10000000` | 8 KB | **Internal SRAM**. Small, fast internal block RAM. Used for stack/data by BIOS. |
| **main_ram**| `0x40000000` | 8 MB | **Main RAM**. (HyperRAM/DRAM). Trace buffers, OS image, and heap live here. **Firmware Loaded Here.** |
| **clint** | `0xf0010000` | 64 KB | **CLINT**. RISC-V Core Local Interruptor (Timer, SW Interrupts). |
| **csr** | `0xf0000000` | 64 KB | **CSR configuration**. Memory-mapped IO for peripherals (UART, LEDs, etc). |
| **plic** | `0xf0c00000` | 4 MB | **PLIC**. Platform-Level Interrupt Controller. |

### 3.2 Peripheral Mapping Table (The "Translation Dictionary")

#### A. GPIO (Lights, Buttons, FPGA Control)
*Old Concept:* `AT91C_PIO_PAxx`
*New Concept:* LiteX GPIO Tristate or separate Out/In CSRs.

| Signal Name | PM3 Pin | LiteX CSR (Register) | Notes |
| :--- | :--- | :--- | :--- |
| LED_A (Red) | PA0 | `leds_out` (bit 0) | Use `leds_out_write(val)` |
| LED_B (Green)| PA1 | `leds_out` (bit 1) | |
| BUTTON | PAxx | `[buttons_in]` | Polling or Interrupt |

#### B. Communication (USB & UART)
* **UART:**
    * Old: `AT91C_BASE_US0`
    * New: `uart_rxtx` (LiteX UARTBone or simple UART).
    * *Strategy:* Redirect `printf` to LiteX UART.
* **USB (Critical):**
    * Old: AT91 UDP (Hardware specific)
    * New: 尝试使用 LiteX Serial Device 模拟USB CDC

### 3.3 Interrupts
* **Interrupt Controller:** Replaces AT91 AIC with **VexRiscv PLIC/CLINT**.

## 6. Code Standards for Porting
1.  **Driver Isolation:** All hardware access must go through `hal_litex.c`.
2.  **No Magic Numbers:** Replace address literals `0xFFFFF400` with named constants from `generated/csr.h`.
3.  **Timeouts:** Replace simple `for(i=0; i<1000; i++)` loops (CPU speed dependent) with `timer0_read()` delta checks.

## 7. Debugging Guide

To debug the firmware running from RAM (loaded via LiteX BIOS):

### 7.1 Prerequisites
*   **Hardware**: Sipeed Tang Nano 20k connected via USB.
*   **Software**: OpenOCD (configured for VexRiscv), GDB (`riscv64-unknown-elf-gdb`).

### 7.2 Procedure (Stop at Entry)
The goal is to catch the CPU exactly when it jumps to `0x40000000` after the BIOS loads the binary.

1.  **Start OpenOCD**:
    ```bash
    openocd -f interface/ftdi/sipeed-rv-debugger.cfg -t target/vexriscv.cfg
    ```
2.  **Start GDB (wait for load)**:
    Use the provided script `tools/pm4_debug.gdb`:
    ```bash
    riscv64-unknown-elf-gdb -x tools/pm4_debug.gdb
    ```
    *Note*: The script loads symbols from `armsrc/obj/fullimage.stage1.elf` (which contains debug info), NOT the stripped `fullimage.elf`.
    *GDB will connect, set a **Hardware Breakpoint** at `0x40000000` (and `Vector`), and wait (`continue`).*

3.  **Load Firmware (Serial Boot)**:
    In a separate terminal, send the firmware to the BIOS:
    ```bash
    litex_term --kernel armsrc/obj/fullimage.bin /dev/ttyUSB1
    ```

4.  **Debug**:
    Once the transfer finishes, the BIOS jumps to `0x40000000`. GDB will hit the hardware breakpoint.
    *   `list` : See source code at entry.
    *   `si` : Step instruction.
    *   `c` : Continue.

## 8. Bootrom Analysis (ARM Legacy)

The user requested an analysis of the original `bootrom` (AT91SAM7S) to fully understand what functionality might be missing or useful for the PM4 port.

### 8.1 Core Functionality
The ARM `bootrom` serves as a **Stage 1 Bootloader** and **Emergency Flasher**. Its lifecycle is:
1.  **Hardware Init**: Configures Clocks (PLL), GPIOs (LEDs, FPGA pins), and Watchdog. (*Porting Note: LiteX BIOS/Gateware handles most of this.*)
2.  **Decision Logic**: Decides whether to boot the Main Firmware (`osimage`) or enter Recovery Mode.
    *   **Checks**: Button press, `g_common_area` flags, or invalid OS image.
3.  **App Launch**: Jumps to the OS image entry point.
4.  **Recovery Loop**: If Recovery Mode is entered:
    *   Initializes USB CDC.
    *   Waits for commands from the client (Via `UsbPacketReceived`).
    *   Supports Flash Writing/Reading.

### 8.2 Key Functions & Porting Candidates

| Function / Logic | Description | Relevance to PM4 (RISC-V) |
| :--- | :--- | :--- |
| **`ConfigClocks`** | Sets up AT91 PMC (48MHz). | **No**. FPGA clocks are fixed by bitstream. |
| **`BootROM` (Entry)** | Clears BSS, Init IO, checks `g_common_area`. | **Partial**. `g_common_area` logic is useful for retaining state across soft-resets. |
| **`flash_mode`** | Main loop for the flasher. Polls USB. | **Yes**. A "Recovery Firmware" is needed to support updating via the standard client. |
| **`CMD_FINISH_WRITE`** | Writes data to internal Flush (EFC). | **Adapt**. Must be rewritten to write to **SPI Flash** (`spiflash` region) instead of AT91 EFC. |
| **`CMD_DEVICE_INFO`** | Reports capabilities to client. | **Yes**. Necessary for client handshake. |
| **`CMD_READ_MEM`** | Dumps memory/flash. | **Yes**. Useful for debugging/verification. |

### 8.3 Porting Strategy
*   **Immediate Term**: Discard `bootrom`. Use `litex_term` or JTAG to load `fullimage.bin` directly to RAM.
*   **Long Term (Recovery)**:
    *   Create a standalone "Recovery App" (small footprint) linked at a specific address (e.g., in SPI Flash).
    *   Implement the `CMD_*` protocol but map `FINISH_WRITE` to LiteX SPI Flash drivers.
    *   Retain `g_common_area` handshake to allow the main app to "Reboot to Recovery".