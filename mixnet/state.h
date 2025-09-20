/**
 * @file state.h
 * @brief State structure definitions for Mixnet project
 * 
 * This module contains the state structure definitions used by both
 * STP (Spanning Tree Protocol) and LSA (Link State Advertisement) modules.
 * 
 * @author Carnegie Mellon University - 15-441/641
 * @date 2023
 */

#ifndef STATE_H
#define STATE_H

#include <stdint.h>
#include <stdbool.h>
#include "packet.h"
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t num_packets;
    uint8_t last_packet_index;
    mixnet_packet *packet[17];
} mixing_pipe_t;

// STP state structure
typedef struct {
    mixnet_address self_address;        // This node's address
    uint8_t stage;                      // Current STP stage. 0: initial, 1: addresss known, 2: converged
    uint64_t init_time;                 // Time when stp election started
    uint16_t num_neighbors;             // Number of neighbors
    mixnet_address *neighbor_addrs;     // Map port -> neighbor address (dynamic)
    mixing_pipe_t *mixing_pipe;         // The mixing pipe of the network
} node_state_t;

// STP specific fields
typedef struct {
    mixnet_address root_address;        // Current root address
    uint16_t path_length;               // Path length to root
    uint8_t parent_port;                // Port to parent
    bool is_root;                       // Whether this node is the root
    bool *ports_blocked;                // Blocked state for each port (dynamic)
    uint64_t last_hello_time;           // Last time we sent a hello
    uint64_t last_root_heard_time;      // Last time we started reelection
} stp_state_t;

// LSA structures
typedef struct {
    mixnet_address from_addr;
    mixnet_address to_addr;
    uint16_t cost;
} adjacency_edge_t;

// The graph of the network
typedef struct {
    uint16_t num_edges;
    adjacency_edge_t adjacency_list[256]; // an array of a adjacency edge
} lsa_graph_t;

typedef struct {
    mixnet_address dst_addr;    // destination address
    uint16_t hop_count;         // number of hops
    uint16_t cost;              // cost of the route
    mixnet_address* path;       // sequence of node addrs (excl. src/dst if that's your spec)
} lsa_route_t;

// LSA state structure
typedef struct {
    uint16_t forwarding_table_size;             // Current size of forwarding table
    uint64_t last_lsa_time;                     // Last time we sent an LSA

    uint16_t num_nodes;                         // Number of nodes in the network
    mixnet_address addrs_heard_from[256];       // Track which addresses we've heard from (dynamic)

    lsa_graph_t *graph;                         // The graph of the network
    lsa_route_t *routes;                        // The routes of the network
} lsa_state_t;

extern node_state_t node_state;
extern stp_state_t stp_state;
extern lsa_state_t lsa_state;

extern uint32_t convergence_time_ms;

/**
* @brief Check if the nodes should converge
* 
* @return true if the node just converged
*/
bool check_converged(void);

/**
* @brief Initialize the state of the node
* 
* @param num_neighbors Number of neighbors
*/
void state_init(mixnet_address self_address, uint16_t num_neighbors, uint16_t mixing_factor);

/**
* @brief Cleanup the state of the node
*/
void cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // STATE_H
