/**
 * @file util.h
 * @brief Utility functions for Mixnet project
 * 
 * This module provides common utility functions used across the Mixnet project,
 * including time utilities and other shared functionality.
 * 
 * @author Carnegie Mellon University - 15-441/641
 * @date 2023
 */

#ifndef UTIL_H
#define UTIL_H

#include "packet.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get current time in milliseconds since epoch
 * 
 * Uses CLOCK_MONOTONIC for consistent timing across the system.
 * 
 * @return Current time in milliseconds, or 0 on error
 */
uint64_t get_time_ms(void);

/**
 * @brief Reverse an array of mixnet addresses
 * 
 * @param array The array to reverse
 * @param length The length of the array
 */
void reverse_route(mixnet_packet_routing_header *routing_header);

#ifdef __cplusplus
}
#endif

#endif // UTIL_H
