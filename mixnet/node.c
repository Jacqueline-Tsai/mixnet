/**
* Copyright (C) 2023 Carnegie Mellon University
*
* This file is part of the Mixnet course project developed for
* the Computer Networks course (15-441/641) taught at Carnegie
* Mellon University.
*
* No part of the Mixnet project may be copied and/or distributed
* without the express permission of the 15-441/641 course staff.
*/
#include "node.h"
#include "connection.h"
#include "packet.h"
#include "log.h"
#include "stp.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>

// STP functionality moved to stp.h and stp.c

// Forward declarations
static void process_flood_packet(mixnet_packet *packet, 
                            uint8_t port, const struct mixnet_node_config *config,
                            void *handle);

// Helper function to create and send STP packet
// STP functions moved to stp.c module
 
static void process_flood_packet(mixnet_packet *packet, 
                               uint8_t port, const struct mixnet_node_config *config,
                               void *handle) {
     // Check if port is blocked by STP
     if (packet->type != PACKET_TYPE_FLOOD || stp_is_port_blocked(port)) return;

     const stp_state_t *stp_state = stp_get_state();
     if (!stp_state) {
         LOG_ERROR("STP not initialized, dropping flood packet");
         return;
     }

     LOG_DEBUG("Processing FLOOD packet | from port %d | size %d | parent port %d", 
               port, packet->total_size, stp_state->parent_port);

     // Validate packet size for flood packets (should be just the header)
     if (packet->total_size != sizeof(mixnet_packet)) {
         LOG_ERROR("Invalid FLOOD packet size: %d (expected %zu)", 
              packet->total_size, sizeof(mixnet_packet));
         return;
     }
     
     // Forward flood packet to all other ports except the one we received it on
     // Flood packets should traverse the entire spanning tree, so we use STP port blocking
     for (uint8_t p = 0; p < config->num_neighbors; p++) {
        if (p == port || stp_is_port_blocked(p)) {
            continue;
        }
        // Create a copy of the packet to send
        mixnet_packet *fwd_packet = (mixnet_packet*)malloc(packet->total_size);
        if (!fwd_packet) {
            LOG_ERROR("Failed to allocate memory for FLOOD packet forward");
            continue;
        }
        
        // Copy the packet data
        memcpy(fwd_packet, packet, packet->total_size);
        
        LOG_DEBUG("Forwarding FLOOD packet | to port %d", p);
        int result = mixnet_send(handle, p, fwd_packet);
        if (result < 0) {
            LOG_ERROR("Failed to send FLOOD packet to port %d", p);
            free(fwd_packet);
        }
    }
    // if the port where the packet come from == number of neighbors, it means the packet is from the application layer
    if (port != config->num_neighbors) {
        mixnet_packet *app_packet = (mixnet_packet*)malloc(packet->total_size);
        if (app_packet) {
            memcpy(app_packet, packet, packet->total_size);
            mixnet_send(handle, config->num_neighbors, app_packet);
        }
    }
}

// Helper function to update port blocking state
// STP functions moved to stp.c module

void recv_packet(void *const handle, const struct mixnet_node_config *const config) {
    // Handle received packet
    uint8_t port;
    mixnet_packet *packet;
    
    // Try to receive packets
    int recv_count = mixnet_recv(handle, &port, &packet);
    if (recv_count > 0) {
        // Get STP state for logging
        const stp_state_t *stp_state = stp_get_state();
        if (stp_state) {
            char ports_block_state[256] = {0};
            int n = 0;
            for (uint8_t p = 0; p < config->num_neighbors; p++) {
                n += snprintf(ports_block_state + n, sizeof(ports_block_state) - n, 
                             "%d ", stp_is_port_blocked(p));
            }
            LOG_DEBUG("Received %d packets on port %d | type %d | packet size %d | block state %s", 
                     recv_count, port, packet->type, packet->total_size, ports_block_state);
        } else {
            LOG_DEBUG("Received %d packets on port %d | type %d | packet size %d", 
                     recv_count, port, packet->type, packet->total_size);
        }
        
        // Process STP packets
        if (packet->type == PACKET_TYPE_STP) {
            stp_process_packet(packet, port, config, handle);
        }

        // Process flood packets
        if (packet->type == PACKET_TYPE_FLOOD) {
            process_flood_packet(packet, port, config, handle);
        }
        
        // Free the packet after processing
        free(packet);
    }
}

void run_node(void *const handle,
            volatile bool *const keep_running,
            const struct mixnet_node_config c) {

    // Initialize logging system
    log_config_t log_config = log_get_default_config();
    log_config.enable_node_id = true;
    log_config.min_level = LOG_LEVEL_COUNT;
    if (log_init(&log_config) != 0) {
        fprintf(stderr, "Failed to initialize logging system\n");
        return;
    }

    log_set_node_id(c.node_addr);
    LOG_INFO("Running node | addr %d | num_neighbors %d", c.node_addr, c.num_neighbors);

    // Initialize STP
    stp_init(handle, &c);
    
    while(*keep_running) {
        // Check if STP has converged
        check_stp_converged();

        recv_packet(handle, &c);
        
        stp_send_periodic_hello(handle, &c);
        
        // Start reelection if we haven't heard from root
        stp_check_reelection(handle, &c);
    }
    
    // Cleanup STP and logging systems
    stp_cleanup();
    log_cleanup();
}