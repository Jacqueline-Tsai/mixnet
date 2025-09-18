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
#include "lsa.h"
#include "util.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>
 
static void process_flood_packet(mixnet_packet *packet, uint8_t port, 
    const struct mixnet_node_config *config, void *handle) {
     // Check if port is blocked by STP
     if (packet->type != PACKET_TYPE_FLOOD || stp_is_port_blocked(port)) return;

     LOG_DEBUG("Processing FLOOD packet | from port %d | size %d | parent port %d", 
               port, packet->total_size, stp_state.parent_port);

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


static void process_data_packet(mixnet_packet *packet , uint8_t port, 
    const struct mixnet_node_config *config , void *handle) {
    if (packet->type != PACKET_TYPE_DATA) return;

    mixnet_packet_routing_header *data_payload = (mixnet_packet_routing_header*)((char*)packet + sizeof(mixnet_packet));
    // mixnet_packet_routing_header *rh = (mixnet_packet_routing_header*)packet->payload();
    mixnet_address src_address = data_payload->src_address;
    mixnet_address dst_address = data_payload->dst_address;
    uint16_t route_length = data_payload->route_length;
    uint16_t hop_index = data_payload->hop_index;
    
    LOG_DEBUG("Processing DATA packet | from port %d | size %d | src_address %d | dst_address %d | route_length %d | hop_index %d", 
        port, packet->total_size, src_address, dst_address, route_length, hop_index);
    
    if (src_address == node_state.self_address) {
        // iter through lsa_state.routes
        for (uint16_t i = 0; i < lsa_state.num_routes; i++) {
            lsa_route *route = &lsa_state.routes[i];
            if (route->dst_addr != dst_address) {
                continue;
            }
            if (route->hop_count == 0) {
                LOG_DEBUG("Direct connection to %d", route->dst_addr);
            } else {
                LOG_DEBUG("Route to %d (%d hops): ", route->dst_addr, route->hop_count);
            }
        }
        return;
    }

    if (dst_address == node_state.self_address) {
        mixnet_packet *app_packet = (mixnet_packet*)malloc(packet->total_size);
        memcpy(app_packet, packet, packet->total_size);
        mixnet_send(handle, config->num_neighbors, app_packet);
        free(app_packet);
        return;
    }


    (void)handle;
    (void)config;
}

static void process_ping_packet(mixnet_packet *packet, uint8_t port, 
    const struct mixnet_node_config *config, void *handle) {
    if (packet->type != PACKET_TYPE_PING) return;

    LOG_DEBUG("Processing PING packet | from port %d | size %d", 
              port, packet->total_size);

    // Parse routing header
    if (packet->total_size < sizeof(mixnet_packet) + sizeof(mixnet_packet_routing_header) + sizeof(mixnet_packet_ping)) {
        LOG_ERROR("PING packet too small: %u", packet->total_size);
        return;
    }

    char *payload_base = (char*)packet + sizeof(mixnet_packet);
    mixnet_packet_routing_header *rh = (mixnet_packet_routing_header*)payload_base;
    mixnet_packet_ping *pp = (mixnet_packet_ping*)(payload_base + sizeof(mixnet_packet_routing_header) + (sizeof(mixnet_address) * rh->route_length));

    (void)handle;
    (void)config;
    (void)pp;
}

void recv_packet(void *const handle, const struct mixnet_node_config *const config) {
    // Handle received packet
    uint8_t port;
    mixnet_packet *packet;
    
    // Try to receive packets
    int recv_count = mixnet_recv(handle, &port, &packet);
    if (recv_count <= 0) {
        return;
    }

    switch (packet->type) {
        case PACKET_TYPE_STP:
            process_stp_packet(packet, port, config, handle);
            break;
        case PACKET_TYPE_FLOOD:
            process_flood_packet(packet, port, config, handle);
            break;
        case PACKET_TYPE_LSA:
            process_lsa_packet(packet, port, config, handle);
            break;
        case PACKET_TYPE_DATA:
            process_data_packet(packet, port, config, handle);
            break;
        case PACKET_TYPE_PING:
            process_ping_packet(packet, port, config, handle);
            break;
        default:
            LOG_ERROR("Unknown packet type %d received on port %d", packet->type, port);
            break;
    }
    
    // Free the packet after processing
    free(packet);
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

    // Initialize LSA
    // lsa_init(handle, &c);
    
    while(*keep_running) {
        // Check if STP has converged
        if(node_state.stage == 0 && check_converged()) {
            LOG_INFO("Node converged | root %d | path length %d | parent addr %d | parent port %d | is_root %d", 
                    stp_state.root_address, stp_state.path_length, node_state.neighbor_addrs[stp_state.parent_port], 
                    stp_state.parent_port, stp_state.is_root);
            // lsa_compute_routes();

            // lsa_print_graph();
            // lsa_print_routes();
        }

        // Receive and process packets, check if returned > 0
        recv_packet(handle, &c);
        
        stp_send_periodic_hello(handle, &c);
        
        // Start reelection if we haven't heard from root
        stp_check_reelection(handle, &c);
    }
    
    // Cleanup states and logging systems
    log_cleanup();
}

