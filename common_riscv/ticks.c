//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//-----------------------------------------------------------------------------
#include "ticks.h"
#include <generated/soc.h>
#include <generated/csr.h>

// Helper to read 64-bit cycle counter (or 32-bit low part)
static inline uint32_t get_cycles(void) {
    uint32_t c;
    __asm__ volatile("rdcycle %0" : "=r"(c));
    return c;
}

// Global variable to store system frequency if needed, 
// using macro from soc.h: CONFIG_CLOCK_FREQUENCY

void StartTickCount(void) {
    // No initialization needed for mcycle
}

uint32_t RAMFUNC GetTickCount(void) {
    // Return milliseconds
    // cycles / (freq / 1000) = cycles / (freq_in_khz)
    return get_cycles() / (CONFIG_CLOCK_FREQUENCY / 1000);
}

uint32_t RAMFUNC GetTickCountDelta(uint32_t start_ticks) {
    uint32_t now = GetTickCount();
    return now - start_ticks; // Arithmetic wrap-around handles uint32 overflow naturally
}

void SpinDelayUs(int us) {
    uint32_t start = get_cycles();
    uint32_t cycles_to_wait = us * (CONFIG_CLOCK_FREQUENCY / 1000000);
    while ((get_cycles() - start) < cycles_to_wait);
}

void SpinDelayUsPrecision(int us) {
    SpinDelayUs(us);
}

void SpinDelay(int ms) {
    SpinDelayUs(ms * 1000);
}

// Iso14443 timer stubs - not implemented for FPGA yet
void StartCountSspClk(void) {}
void ResetSspClk(void) {}
uint32_t RAMFUNC GetCountSspClk(void) { return 0; }
uint32_t RAMFUNC GetCountSspClkDelta(uint32_t start) { return 0; }
void WaitMS(uint32_t ms) { SpinDelay(ms); }

// Microsecond timer stubs
void StartCountUS(void) {}
uint32_t RAMFUNC GetCountUS(void) { 
    // Return microseconds
    return get_cycles() / (CONFIG_CLOCK_FREQUENCY / 1000000);
}

// Ticks timer stubs (originally used TC0/TC1)
// Ticks was used for "very precise timer", 1us = 1.5 ticks?
// Let's map GetTicks to cycles for now or microseconds?
// Original: 1us = 1.5 ticks => 1 tick = 0.666 us. (48MHz / 32 = 1.5MHz clock)
// So GetTicks returns 1.5MHz ticks.
void StartTicks(void) {}

uint32_t GetTicks(void) {
    // Simulate 1.5 MHz clock from CONFIG_CLOCK_FREQUENCY
    // cycles / (freq / 1500000)
    // or cycles * 1500000 / freq
    // To avoid overflow: (cycles / (freq/1000000)) * 1.5?
    
    // Simplest: just use cycles and adjust WaitTicks?
    // But caller expects GetTicks to be compatible with WaitUS implementation:
    // WaitUS(us) -> WaitTicks((us) * 1.5)
    
    // So if I return 1.5MHz ticks:
    return (uint32_t)((uint64_t)get_cycles() * 1500000 / CONFIG_CLOCK_FREQUENCY);
}

uint32_t RAMFUNC GetTicksDelta(uint32_t start) {
    return GetTicks() - start;
}

void WaitTicks(uint32_t ticks) {
    uint32_t start = GetTicks();
    while ((GetTicks() - start) < ticks);
}

void WaitUS(uint32_t us) {
    SpinDelayUs(us);
}

void StopTicks(void) {}
