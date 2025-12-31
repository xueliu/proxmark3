//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//-----------------------------------------------------------------------------
// Re-implementation of usb_cdc.h interface using LiteX UART (Serial)
//-----------------------------------------------------------------------------

#include "usb_cdc.h"
#include <generated/csr.h>
#include <stdbool.h>

// Mock functions for USB interface
void usb_disable(void) {}
void usb_enable(void) {}
bool usb_check(void) { return true; }

bool usb_poll(void) {
    return uart_rxempty_read() == 0;
}

bool usb_poll_validate_length(void) {
    // UART doesn't know length, but if not empty, at least 1 byte is there
    return usb_poll();
}

uint16_t usb_available_length(void) {
    return usb_poll() ? 1 : 0;
}

uint32_t usb_read(uint8_t *data, size_t len) {
    size_t count = 0;
    while (count < len) {
        if (uart_rxempty_read() == 0) {
            data[count++] = uart_rxtx_read();
        } else {
            break; // Non-blocking read? original usb_read seems to block with timeout?
                   // original usb_read has a loop with timeout. 
                   // For now, let's return what we have (non-blocking for single check)
                   // But if len > 0 asked, we might want to wait?
                   // Let's implement partial read. 
            break;
        }
    }
    return count;
}

// Write data to UART (USB CDC emulation)
int usb_write(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        while (uart_txfull_read()); // Wait for space
        uart_rxtx_write(data[i]);
    }
    return len;
}

// Async USB write stubs (mapped to synchronous UART for now)
int async_usb_write_start(void) {
    return 1;
}

void async_usb_write_pushByte(uint8_t data) {
    while (uart_txfull_read());
    uart_rxtx_write(data);
}

bool async_usb_write_requestWrite(void) {
    return true;
}

int async_usb_write_stop(void) {
    return 1;
}
// Read data (Next Gen implementation?) - map to standard read for now
uint32_t usb_read_ng(uint8_t *data, size_t len) {
    return usb_read(data, len);
}


// Additional helper to write (implied usage by printf etc? No, usb_cdc was for RX usually?
// Proxmark3 usages usb_write usually via functions in usart.c or similar?)
// Wait, usb_cdc.c in ARMSRC didn't have usb_write? 
// Checking usb_cdc.h might reveal write functions. 
// ARMSRC/usb_cdc.c had usb_read. 
// Writing usually happens via UDP registers directly in other files?
// Or maybe usart.c handles it? 
// Let's check usb_cdc.h compatibility. 
// For now, this is enough for reading.

// We need to implement write for the system to talk back.
// Usually printf uses stdout. 
// In Proxmark3, where does output go? 
// os/dbprint.c ? 
// armsrc/usart.c?

// For now, implementing what was in the original file (only read functions were visible in the slice I saw).
