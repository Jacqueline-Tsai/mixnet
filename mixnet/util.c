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

void reverse_route(mixnet_packet_routing_header *routing_header) {
    for (uint16_t i = 0; i < routing_header->route_length / 2; i++) {
        mixnet_address temp = routing_header->route[i];
        routing_header->route[i] = routing_header->route[routing_header->route_length - i - 1];
        routing_header->route[routing_header->route_length - i - 1] = temp;
    }
}
