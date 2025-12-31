#ifndef __HW_COMMON_H
#define __HW_COMMON_H

#include <stdint.h>

static inline uint32_t csr_read_simple(unsigned long addr) {
    return *(volatile uint32_t *)addr;
}

static inline void csr_write_simple(uint32_t val, unsigned long addr) {
    *(volatile uint32_t *)addr = val;
}

static inline uint8_t readb(unsigned long addr) {
    return *(volatile uint8_t *)addr;
}

static inline void writeb(uint8_t val, unsigned long addr) {
    *(volatile uint8_t *)addr = val;
}

static inline uint32_t readl(unsigned long addr) {
    return *(volatile uint32_t *)addr;
}

static inline void writel(uint32_t val, unsigned long addr) {
    *(volatile uint32_t *)addr = val;
}

#endif
