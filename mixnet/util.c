/**
 * @file util.c
 * @brief Utility functions for Mixnet project
 * 
 * This module provides common utility functions used across the Mixnet project,
 * including time utilities and other shared functionality.
 * 
 * @author Carnegie Mellon University - 15-441/641
 * @date 2023
 */

#include "util.h"

#include <time.h>

uint64_t get_time_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
