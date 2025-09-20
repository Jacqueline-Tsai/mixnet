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
 
/**
 * @brief Process a FLOOD packet
 * 
 * @param packet The FLOOD packet
 * @param port The port the packet was received on
 * @param config The node configuration
 * @param handle The handle to the mixnet
 */
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
        memcpy(app_packet, packet, packet->total_size);
        int result = mixnet_send(handle, config->num_neighbors, app_packet);
        if (result < 0) {
            LOG_ERROR("Failed to send packet | result %d", result);
        }
    }
}

/**
 * @brief Process a DATA packet
 * 
 * @param packet The DATA packet
 * @param port The port the packet was received on
 * @param config The node configuration
 * @param handle The handle to the mixnet
 */
static void process_data_packet(mixnet_packet *packet, uint8_t port, 
        const struct mixnet_node_config *config, void *handle) {
    if (packet->type != PACKET_TYPE_DATA) return;
    
    mixnet_packet_routing_header *routing_header = (mixnet_packet_routing_header*)((char*)packet + sizeof(mixnet_packet));
    mixnet_address src_address = routing_header->src_address;
    mixnet_address dst_address = routing_header->dst_address;
    uint16_t route_length = routing_header->route_length;
    uint16_t hop_index = routing_header->hop_index;
    
    LOG_DEBUG("Processing DATA packet | from port %d | size %d | src_address %d | dst_address %d | route_length %d | hop_index %d", 
        port, packet->total_size, src_address, dst_address, route_length, hop_index);
    
    if (src_address == node_state.self_address) {
        if (config->do_random_routing) {
            generate_random_routes(dst_address);
        }
        uint8_t route_i = get_route_index(dst_address);
        
        uint16_t new_total_size = packet->total_size
                + (lsa_state.routes[route_i].hop_count - routing_header->route_length - 1) * sizeof(mixnet_address);
        mixnet_packet *new_packet = (mixnet_packet*)malloc(new_total_size);
        memcpy(new_packet, packet, sizeof(mixnet_packet));
        new_packet->total_size = new_total_size;

        mixnet_packet_routing_header *new_routing_header = (mixnet_packet_routing_header*)((char*)new_packet + sizeof(mixnet_packet));
        new_routing_header->src_address = routing_header->src_address;
        new_routing_header->dst_address = routing_header->dst_address;
        new_routing_header->route_length = lsa_state.routes[route_i].hop_count - 1;
        new_routing_header->hop_index = 0;
        memcpy(new_routing_header->route, lsa_state.routes[route_i].path, (lsa_state.routes[route_i].hop_count - 1) * sizeof(mixnet_address));

        // Copy the actual data payload
        char *old_data = (char*)packet + sizeof(mixnet_packet) + sizeof(mixnet_packet_routing_header) + (routing_header->route_length * sizeof(mixnet_address));
        char *new_data = (char*)new_packet + sizeof(mixnet_packet) + sizeof(mixnet_packet_routing_header) + (new_routing_header->route_length * sizeof(mixnet_address));
        size_t data_size = packet->total_size - sizeof(mixnet_packet) - sizeof(mixnet_packet_routing_header) - (routing_header->route_length * sizeof(mixnet_address));
        memcpy(new_data, old_data, data_size);
        
        uint8_t fwd_port = get_port(lsa_state.routes[route_i].path[new_routing_header->hop_index++]);
        LOG_DEBUG("Sending new DATA packet | port %d | total_size %d | route_length %d | hop_index %d", fwd_port, new_packet->total_size, new_routing_header->route_length, new_routing_header->hop_index);
        int result = mixnet_send(handle, fwd_port, new_packet);
        if (result < 0) {
            LOG_ERROR("Failed to send packet | result %d", result);
        }
        return;
    }
    
    if (dst_address == node_state.self_address) {
        mixnet_packet *app_packet = (mixnet_packet*)malloc(packet->total_size);
        memcpy(app_packet, packet, packet->total_size);
        LOG_DEBUG("Sending APP packet | port %d | total_size %d", config->num_neighbors, app_packet->total_size);
        int result = mixnet_send(handle, config->num_neighbors, app_packet);
        if (result < 0) {
            LOG_ERROR("Failed to send packet | result %d", result);
        }
        return;
    }

    routing_header->hop_index++;
    mixnet_packet *fwd_packet = (mixnet_packet*)malloc(packet->total_size);
    memcpy(fwd_packet, packet, packet->total_size);
    uint8_t fwd_port = routing_header->hop_index == routing_header->route_length + 1 ?
        get_port(routing_header->dst_address)
        : get_port(routing_header->route[routing_header->hop_index - 1]);
    LOG_DEBUG("Forwarding DATA packet | port %d | total_size %d | route_length %d | hop_index %d", fwd_port, packet->total_size, routing_header->route_length, routing_header->hop_index);
    mixnet_send(handle, fwd_port, fwd_packet);
}

/**
 * @brief Process a PING packet
 * 
 * @param packet The PING packet
 * @param port The port the packet was received on
 * @param config The node configuration
 * @param handle The handle to the mixnet
 */
static void process_ping_packet(mixnet_packet *packet, uint8_t port, 
    const struct mixnet_node_config *config, void *handle) {
    if (packet->type != PACKET_TYPE_PING) return;

    mixnet_packet_routing_header *routing_header = (mixnet_packet_routing_header*)((char*)packet + sizeof(mixnet_packet));
    mixnet_address src_address = routing_header->src_address;
    mixnet_address dst_address = routing_header->dst_address;
    uint16_t route_length = routing_header->route_length;
    uint16_t hop_index = routing_header->hop_index;

    uint16_t route_size = sizeof(mixnet_packet_routing_header) + sizeof(mixnet_address) * routing_header->route_length;
    mixnet_packet_ping *pp = (mixnet_packet_ping*)((char*)routing_header + route_size);
    LOG_DEBUG("Processing PING packet | from port %d | size %d | src_address %d | dst_address %d | route_length %d | hop_index %d | is_request %d | send_time %ld", 
            port, packet->total_size, src_address, dst_address, route_length, hop_index, pp->is_request, pp->send_time);

    if (src_address == node_state.self_address) {
        if (config->do_random_routing) {
            generate_random_routes(dst_address);
        }
        uint8_t route_i = get_route_index(dst_address);

        uint16_t new_total_size = packet->total_size + sizeof(mixnet_packet_ping)
                + (lsa_state.routes[route_i].hop_count - routing_header->route_length - 1) * sizeof(mixnet_address);

        mixnet_packet *new_packet = (mixnet_packet*)malloc(new_total_size);
        memcpy(new_packet, packet, sizeof(mixnet_packet));
        new_packet->total_size = new_total_size;
        
        mixnet_packet_routing_header *new_routing_header = (mixnet_packet_routing_header*)((char*)new_packet + sizeof(mixnet_packet));
        new_routing_header->src_address = routing_header->src_address;
        new_routing_header->dst_address = routing_header->dst_address;
        new_routing_header->route_length = lsa_state.routes[route_i].hop_count - 1;
        new_routing_header->hop_index = 0;
        
        uint16_t route_size = sizeof(mixnet_packet_routing_header) + sizeof(mixnet_address) * (lsa_state.routes[route_i].hop_count - 1);
        mixnet_address *route_ptr = (mixnet_address*)((char*)new_routing_header + sizeof(mixnet_packet_routing_header));
        memcpy(route_ptr, lsa_state.routes[route_i].path, route_size);

        mixnet_packet_ping *new_pp = (mixnet_packet_ping*)((char*)new_routing_header + route_size);
        new_pp->is_request = true;
        new_pp->_pad[0] = 0;
        new_pp->send_time = pp->send_time;

        uint8_t fwd_port = get_port(lsa_state.routes[route_i].path[new_routing_header->hop_index++]);
        LOG_DEBUG("Sending new PING packet | port %d | total_size %d | route_length %d | hop_index %d", fwd_port, new_packet->total_size, new_routing_header->route_length, new_routing_header->hop_index);
        int result = mixnet_send(handle, fwd_port, new_packet);
        if (result < 0) {
            LOG_ERROR("Failed to send packet | result %d", result);
        }
        return;
    }

    if (dst_address == node_state.self_address) {
        mixnet_packet *app_packet = (mixnet_packet*)malloc(packet->total_size);
        memcpy(app_packet, packet, packet->total_size);
        LOG_DEBUG("Sending APP packet | port %d | total_size %d", config->num_neighbors, app_packet->total_size);
        int result = mixnet_send(handle, config->num_neighbors, app_packet);
        if (result < 0) {
            LOG_ERROR("Failed to send APP packet | result %d", result);
        }
        if (pp->is_request) {
            LOG_INFO("Sending response PING packet");
            mixnet_packet *res_packet = (mixnet_packet*)malloc(packet->total_size);
            memcpy(res_packet, packet, packet->total_size);
            mixnet_packet_routing_header *res_routing_header = (mixnet_packet_routing_header*)((char*)res_packet + sizeof(mixnet_packet));
            res_routing_header->src_address = routing_header->dst_address;
            res_routing_header->dst_address = routing_header->src_address;
            res_routing_header->hop_index = 1;

            uint16_t route_size = sizeof(mixnet_packet_routing_header) + sizeof(mixnet_address) * routing_header->route_length;
            reverse_route(res_routing_header);

            mixnet_packet_ping *res_pp = (mixnet_packet_ping*)((char*)res_routing_header + route_size);
            res_pp->is_request = false;
            res_pp->_pad[0] = 0;
            res_pp->send_time = get_time_ms();
            uint8_t res_port = get_port(res_routing_header->route[0]);
            int result = mixnet_send(handle, res_port, res_packet);
            if (result < 0) {
                LOG_ERROR("Failed to send response packet | result %d", result);
            }
        }
        return;
    }

    routing_header->hop_index++;
    mixnet_packet *fwd_packet = (mixnet_packet*)malloc(packet->total_size);
    memcpy(fwd_packet, packet, packet->total_size);
    uint8_t fwd_port = routing_header->hop_index == routing_header->route_length + 1 ?
        get_port(routing_header->dst_address)
        : get_port(routing_header->route[routing_header->hop_index - 1]);
    LOG_DEBUG("Forwarding PING packet | port %d | total_size %d | route_length %d | hop_index %d", fwd_port, packet->total_size, routing_header->route_length, routing_header->hop_index);
    mixnet_send(handle, fwd_port, fwd_packet);
}

void process_packet(mixnet_packet *packet, uint8_t port, const struct mixnet_node_config *config, void *handle) {
    LOG_INFO("Processing packet | type %d | port %d | total size %d | mixing pipe cur_size %d", packet->type, port, packet->total_size, node_state.mixing_pipe->num_packets);
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
}

void recv_packet(void *const handle, const struct mixnet_node_config *const config) {
    // Handle received packet
    uint8_t port;
    mixnet_packet *packet;
    
    // Try to receive packets
    int recv_count = mixnet_recv(handle, &port, &packet);
    if (recv_count < 0) {
        LOG_ERROR("Failed to receive packet | recv_count %d", recv_count);
        return;
    }
    if (recv_count <= 0) {
        return;
    }
    LOG_INFO("Received packet | type %d | port %d | total size %d", packet->type, port, packet->total_size);

    if (packet->type != PACKET_TYPE_DATA && packet->type != PACKET_TYPE_PING) {
        process_packet(packet, port, config, handle);
        // Free the packet after processing
        free(packet);
        return;
    }

    LOG_INFO("Adding new packet to the mixing pipe... | cur_size %d/%d", node_state.mixing_pipe->last_packet_index, node_state.mixing_pipe->num_packets);
    uint8_t pkt_index = node_state.mixing_pipe->last_packet_index;
    node_state.mixing_pipe->packet[pkt_index] = (mixnet_packet*)malloc(packet->total_size);
    memcpy(node_state.mixing_pipe->packet[pkt_index], packet, packet->total_size);
    free(packet);

    // move index to the next packet
    node_state.mixing_pipe->last_packet_index = node_state.mixing_pipe->last_packet_index + 1;
    pkt_index = node_state.mixing_pipe->last_packet_index;
    if (pkt_index < node_state.mixing_pipe->num_packets) {
        return;
    }

    LOG_INFO("Processing all packets in the mixing pipe...");
    for (uint8_t i = 0; i < node_state.mixing_pipe->num_packets; i++) {
        LOG_INFO("Processing packet %d | total size %d", i, node_state.mixing_pipe->packet[i]->total_size);
        process_packet(node_state.mixing_pipe->packet[i], port, config, handle);
        // node_state.mixing_pipe->packet[i] = NULL;
    }
    node_state.mixing_pipe->last_packet_index = 0;
        // if (node_state.mixing_pipe->packet[pkt_index] == NULL) {
        //     // Wait until we receive enough packets in the mixing pipe
        //     LOG_INFO("Waiting for enough packets in the mixing pipe");
        //     return;
        // }
        // packet = (mixnet_packet*)malloc(node_state.mixing_pipe->packet[pkt_index]->total_size);
        // memcpy(packet, node_state.mixing_pipe->packet[pkt_index], node_state.mixing_pipe->packet[pkt_index]->total_size);
        // free(node_state.mixing_pipe->packet[pkt_index]);
        // node_state.mixing_pipe->packet[pkt_index] = NULL;

}

bool check_all_neighbors_addrs_known(void) {
    LOG_DEBUG("Checking if all neighbors addrs known");
    for (uint8_t p = 0; p < node_state.num_neighbors; p++) {
        if (node_state.neighbor_addrs[p] == INVALID_MIXADDR) {
            LOG_DEBUG("Neighbor addr %d not known", node_state.neighbor_addrs[p]);
            return false;
        }
    }
    LOG_INFO("All neighbors addrs known");
    return true;
}

void run_node(void *const handle,
            volatile bool *const keep_running,
            const struct mixnet_node_config c) {

    LOG_INFO("Running node | addr %d | num_neighbors %d", c.node_addr, c.num_neighbors);

    state_init(c.node_addr, c.num_neighbors, c.mixing_factor);

    // Initialize STP
    stp_init(handle, &c);

    // Initialize LSA
    lsa_init(&c);
    
    bool computed = false;
    while(*keep_running) {
        
        if (node_state.stage == 0 && get_time_ms() - node_state.init_time >= 100 && check_all_neighbors_addrs_known()) {
            node_state.stage++;
            LOG_INFO("Stage changed to %d", node_state.stage);
            lsa_send_init_packets(handle, &c);
        }

        if(node_state.stage == 1 && !computed && get_time_ms() - node_state.init_time >= 400) {
            lsa_print_graph();
            lsa_compute_routes();
            lsa_print_routes();
            computed = true;
        }

        // Check if STP has converged
        if (check_converged()) {
            LOG_INFO("Node converged | root %d | path length %d | parent addr %d | parent port %d | is_root %d", 
                stp_state.root_address, stp_state.path_length, node_state.neighbor_addrs[stp_state.parent_port], 
                stp_state.parent_port, stp_state.is_root);
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

