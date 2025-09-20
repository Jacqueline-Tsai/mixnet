/**
 * @file stp.c
 * @brief Spanning Tree Protocol (STP) implementation for Mixnet project
 * 
 * This module implements the Spanning Tree Protocol for creating a loop-free
 * topology in the network. It handles root election, path selection, and
 * port blocking to prevent loops.
 * 
 * @author Carnegie Mellon University - 15-441/641
 * @date 2023
 */

 #include "stp.h"
 #include "log.h"
 #include "connection.h"
 #include "util.h"
 
 #include <stdio.h>
 #include <stdint.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <pthread.h>
 
 
 // Internal function declarations
 static int send_stp_packet(void *handle, uint8_t port, mixnet_address root_addr, 
                         uint16_t path_len, mixnet_address node_addr);
 static void process_stp_hello_msg(mixnet_packet_stp *stp_payload, uint8_t port, 
                                 const struct mixnet_node_config *config, void *handle);
 
 // Helper function to create and send STP packet
 static int send_stp_packet(void *handle, uint8_t port, 
                         mixnet_address root_addr, uint16_t path_len, 
                         mixnet_address node_addr) {
     LOG_DEBUG("Sending STP packet to port %d: root=%d, path_length=%d", port, root_addr, path_len);
     // Allocate packet
     mixnet_packet *packet = (mixnet_packet*)malloc(sizeof(mixnet_packet) + sizeof(mixnet_packet_stp));
     if (!packet) return -1;
     
     // Set packet header
     packet->total_size = sizeof(mixnet_packet) + sizeof(mixnet_packet_stp);
     packet->type = PACKET_TYPE_STP;
     
     // Set STP payload
     mixnet_packet_stp *stp_payload = (mixnet_packet_stp*)((char*)packet + sizeof(mixnet_packet));
     stp_payload->root_address = root_addr;
     stp_payload->path_length = path_len;
     stp_payload->node_address = node_addr;
     
     // Send packet
     int result = mixnet_send(handle, port, packet);
     if (result < 0) {
         free(packet);
     }
     return result;
 }
 
 static void process_stp_hello_msg(mixnet_packet_stp *stp_payload, uint8_t port, 
                                 const struct mixnet_node_config *config, void *handle) {
    LOG_DEBUG("Processing STP hello message from port %d: root=%d, path_length=%d, sender=%d", 
              port, stp_payload->root_address, stp_payload->path_length, stp_payload->node_address);
     // Handle periodic hello messages
     if (stp_payload->root_address != stp_state.root_address || stp_payload->node_address != stp_state.root_address) {
        LOG_ERROR("Invalid hello message: expected root=%d, sender port=%d, got root=%d, sender=%d", 
                  stp_state.root_address, stp_state.parent_port, stp_payload->root_address, stp_payload->node_address);
         return;
     }
     if (stp_state.is_root) {
         LOG_ERROR("Root received its own hello message, ignoring");
         return;
     }
     
     stp_state.last_root_heard_time = get_time_ms();    
     for (uint8_t p = 0; p < config->num_neighbors; p++) {
         if (p == port || stp_state.ports_blocked[p]) {
             continue;
         }
         send_stp_packet(handle, p, stp_payload->root_address, stp_payload->path_length, stp_payload->node_address);
     }
 }
 
 void stp_init(void *handle, const struct mixnet_node_config *c) {
     uint64_t current_time = get_time_ms();
     stp_state.root_address = c->node_addr;  // Initially consider self as root
     stp_state.path_length = 0;
     stp_state.parent_port = -1;
     stp_state.is_root = true;
     stp_state.ports_blocked = (bool*)calloc(c->num_neighbors, sizeof(bool));
     stp_state.last_hello_time = current_time;
     stp_state.last_root_heard_time = UINT64_MAX;
 
     // Send initial STP packet
     for (uint8_t p = 0; p < c->num_neighbors; p++) {
         send_stp_packet(handle, p, stp_state.root_address, stp_state.path_length, c->node_addr);
     }
 }
 
 void process_stp_packet(mixnet_packet *packet, uint8_t port, 
                        const struct mixnet_node_config *config, void *handle) {
    if (packet->type != PACKET_TYPE_STP) return;
     
    mixnet_packet_stp *stp_payload = (mixnet_packet_stp*)((char*)packet + sizeof(mixnet_packet));
    mixnet_address sender_root = stp_payload->root_address;
    uint16_t sender_path_len = stp_payload->path_length;
    mixnet_address sender_addr = stp_payload->node_address;

    if (sender_path_len >= STP_HELLO_PATH_LEN_THRESHOLD) {
        process_stp_hello_msg(stp_payload, port, config, handle);
        return;
    }

    if (node_state.neighbor_addrs[port] == INVALID_MIXADDR) {
        LOG_INFO("Heard from addr %d, port %d", sender_addr, port);
        node_state.neighbor_addrs[port] = sender_addr;
    }
 
    LOG_DEBUG("Processing STP packet from port %d: sender=%d, root=%d, path_length=%d", 
              port, sender_addr, sender_root, sender_path_len);

     if (node_state.stage == 2) {
         LOG_DEBUG("Received STP election packet during convergence, restarting election");
         stp_init(handle, config);
         return;
     }
 
     // Open port for potential child
     if (sender_path_len == stp_state.path_length + 1 && sender_root == stp_state.root_address) {
         stp_state.ports_blocked[port] = false;
         return;
     }
 
     bool state_changed = false;
     
    // If we receive a better root (lower address)
    if (sender_root < stp_state.root_address) {
        LOG_DEBUG("Found better root: %d < %d, updating parent to %d via port %d", 
                  sender_root, stp_state.root_address, sender_addr, port);
        stp_state.root_address = sender_root;
        stp_state.path_length = sender_path_len + 1;
        stp_state.parent_port = port;
        stp_state.is_root = false;
        state_changed = true;
    }
    // If same root but better path (shorter path length)
    else if (sender_root == stp_state.root_address && 
            sender_path_len + 1 < stp_state.path_length) {
        LOG_DEBUG("Found shorter path to root: %d < %d, updating parent to %d via port %d", 
                  sender_path_len + 1, stp_state.path_length, sender_addr, port);
        stp_state.path_length = sender_path_len + 1;
        stp_state.parent_port = port;
        stp_state.is_root = false;
        state_changed = true;
    }
    // If same root and path length, tie-break by parent address
    else if (sender_root == stp_state.root_address && 
            sender_path_len + 1 == stp_state.path_length &&
            sender_addr < node_state.neighbor_addrs[stp_state.parent_port]) {
        LOG_DEBUG("Found better parent with same path length: %d < %d, updating parent to %d via port %d", 
                  sender_addr, node_state.neighbor_addrs[stp_state.parent_port], sender_addr, port);
        stp_state.parent_port = port;
        stp_state.is_root = false;
        state_changed = true;
    }
    else if (sender_root == stp_state.root_address && 
            sender_addr != node_state.neighbor_addrs[stp_state.parent_port]) {
        LOG_DEBUG("Blocking port %d due to inferior path to root", port);
        stp_state.ports_blocked[port] = true;
    }
 
     if (state_changed) {
         stp_update_port_blocking(config);
 
         for (uint8_t p = 0; p < config->num_neighbors; p++) {
             send_stp_packet(handle, p, stp_state.root_address, stp_state.path_length, config->node_addr);
         }
 
         char ports_block_state[256];  // Initialize to empty string
         int n = 0;
         for (uint8_t p = 0; p < config->num_neighbors; p++) {
             n += snprintf(ports_block_state + n, sizeof(ports_block_state) - n, "%d ", stp_state.ports_blocked[p]);
         }
        LOG_DEBUG("STP state updated: root=%d, path_length=%d, parent=%d, parent_port=%d, is_root=%d, blocked_ports=[%s]", 
         stp_state.root_address, stp_state.path_length, node_state.neighbor_addrs[stp_state.parent_port], stp_state.parent_port, stp_state.is_root, ports_block_state);
     }
 }
 
 void stp_send_periodic_hello(void *handle, const struct mixnet_node_config *config) {
    // Check if we need to send periodic hello messages
    uint64_t current_time = get_time_ms();
    if (node_state.stage != 2 || !stp_state.is_root || current_time < stp_state.last_hello_time ||
        current_time - stp_state.last_hello_time < config->root_hello_interval_ms) {
        return;
    }

     LOG_DEBUG("Sending periodic hello messages (is_root=%d)", stp_state.is_root);
     stp_state.last_hello_time = current_time;
     if (stp_state.is_root) {
         // Root sends hello to all ports
         for (uint8_t p = 0; p < config->num_neighbors; p++) {
             send_stp_packet(handle, p, stp_state.root_address, STP_HELLO_PATH_LEN_THRESHOLD, config->node_addr);
         }
     }
 }
 
 void stp_update_port_blocking(const struct mixnet_node_config *config) {
     // Reset all ports to unblocked first
     for (uint8_t p = 0; p < config->num_neighbors; p++) {
         stp_state.ports_blocked[p] = false;
     }
 
     // Block all ports except the one to parent (if not root)
     if (stp_state.is_root) {
         return;
     }
 
     for (uint8_t p = 0; p < config->num_neighbors; p++) {
         if (p != stp_state.parent_port) {
             stp_state.ports_blocked[p] = true;
         }
     }
 
     char ports_block_state[256];  // Initialize to empty string
     int n = 0;
     for (uint8_t p = 0; p < config->num_neighbors; p++) {
         n += snprintf(ports_block_state + n, sizeof(ports_block_state) - n, "%d ", stp_state.ports_blocked[p]);
     }
     LOG_DEBUG("Updated port blocking: parent_port=%d, blocked_ports=[%s]", stp_state.parent_port, ports_block_state);
 }

 
 bool stp_is_port_blocked(uint8_t port) {
     if (port >= 255) return true;
     return stp_state.ports_blocked[port];
}

 void stp_check_reelection(void *handle, const struct mixnet_node_config *config) {
    if (stp_state.is_root || node_state.stage != 2) {
        return;
    }
     
    uint64_t current_time = get_time_ms();
    if (current_time <= stp_state.last_root_heard_time || 
        current_time - stp_state.last_root_heard_time < config->reelection_interval_ms) {
        return;
    }

    LOG_INFO("Starting STP reelection: no root heard for %d ms (last_heard=%ld)", 
             config->reelection_interval_ms, stp_state.last_root_heard_time);
    stp_init(handle, config);
 }