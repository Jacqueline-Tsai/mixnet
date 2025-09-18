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

// STP state structure
typedef struct {
    mixnet_address self_address;        // This node's address
    uint8_t stage;                      // Current STP stage. 0: initial, 1: converged
    uint64_t init_time;                 // Time when stp election started
    mixnet_address *neighbor_addrs;     // Map port -> neighbor address (dynamic)
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
} adjacency_edge;

// The graph of the network
typedef struct {
    uint16_t num_edges;
    adjacency_edge adjacency_list[256]; // an array of a adjacency edge
} lsa_graph;

typedef struct {
    mixnet_address dst_addr;    // destination address
    uint16_t hop_count;         // number of hops
    mixnet_address* path;       // sequence of node addrs (excl. src/dst if that's your spec)
} lsa_route;

// LSA state structure
typedef struct {
    uint16_t forwarding_table_size;        // Current size of forwarding table
    uint16_t max_forwarding_table_size;    // Maximum size of forwarding table
    mixnet_lsa_link_params *neighbor_links; // Direct neighbor links (dynamic)
    uint16_t neighbor_count;               // Number of direct neighbors
    uint64_t last_lsa_time;                // Last time we sent an LSA
    bool *neighbor_heard_from;             // Track which neighbors we've heard from (dynamic)
    lsa_graph *graph;                       // The graph of the network
    int num_routes;                         // Number of routes
    lsa_route *routes;                      // The routes of the network
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
void state_init(uint16_t num_neighbors);

/**
* @brief Cleanup the state of the node
*/
void cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // STATE_H
