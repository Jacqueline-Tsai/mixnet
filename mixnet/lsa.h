/**
 * @file lsa.h
 * @brief Link State Advertisement (LSA) implementation for Mixnet project
 * 
 * This module implements the Link State Advertisement protocol for creating
 * forwarding tables based on link state information. It handles neighbor
 * discovery, LSA flooding, and shortest path computation.
 * 
 * @author Carnegie Mellon University - 15-441/641
 * @date 2023
 */

#ifndef LSA_H
#define LSA_H

#include <stdint.h>
#include <stdbool.h>
#include "packet.h"
#include "config.h"
#include "state.h"

#ifdef __cplusplus
extern "C" {
#endif

// LSA constants
#define LSA_INFINITY 0xFFFF
#define LSA_MAX_DESTINATIONS 256


/**
 * @brief Initialize LSA state for a node
 * 
 * @param handle Network handle
 * @param config Node configuration
 */
void lsa_init(const struct mixnet_node_config *config);

/**
 * @brief Send initial LSA packets to all neighbors
 * 
 * @param handle Network handle
 * @param config Node configuration
 */
void lsa_send_init_packets(void *handle, const struct mixnet_node_config *config);

/**
 * @brief Process received LSA packet
 * 
 * @param packet Received packet
 * @param port Port where packet was received
 * @param config Node configuration
 * @param handle Network handle
 */
void process_lsa_packet(mixnet_packet *packet, uint8_t port, 
                       const struct mixnet_node_config *config, void *handle);

/**
 * @brief Update forwarding table based on received LSA
 * 
 * @param lsa_payload LSA packet payload
 * @param sender_addr Address of the sender
 * @param config Node configuration
 */
void lsa_update_forwarding_table(mixnet_packet_lsa *lsa_payload, 
                                mixnet_address sender_addr,
                                const struct mixnet_node_config *config);

/**
 * @brief Add or update forwarding table entry
 * 
 * @param destination Destination address
 * @param next_hop Next hop address
 * @param cost Cost to destination
 */
void lsa_add_forwarding_entry(mixnet_address destination, mixnet_address next_hop, uint16_t cost);

/**
 * @brief Remove forwarding table entry
 * 
 * @param destination Destination address to remove
 */
void lsa_remove_forwarding_entry(mixnet_address destination);

/**
 * @brief Get next hop for a destination
 * 
 * @param destination Destination address
 * @return Next hop address, or INVALID_MIXADDR if not found
 */
mixnet_address lsa_get_next_hop(mixnet_address destination);

/**
 * @brief Get cost to a destination
 * 
 * @param destination Destination address
 * @return Cost to destination, or LSA_INFINITY if not reachable
 */
uint16_t lsa_get_cost(mixnet_address destination);


/**
 * @brief Handle link failure by applying bad news rule
 * 
 * @param failed_neighbor Address of the neighbor whose link failed
 */
void lsa_handle_link_failure(mixnet_address failed_neighbor);

/**
 * @brief Compute routes from current node to all nodes in the LSA graph
 * 
 * This function implements Dijkstra's shortest path algorithm to find routes
 * from the current node (state.self.addr) to all nodes observed in the 
 * lsa_graph_t's adjacency_list.
 * 
 * @return 0 on success, -1 on failure
 */
void lsa_compute_routes(void);

/**
 * @brief Print the LSA graph adjacency list
 * 
 * This function prints all edges in the LSA graph with their costs.
 */
void lsa_print_graph(void);

/**
 * @brief Print all computed routes
 * 
 * This function prints all routes computed by lsa_compute_routes().
 */
void lsa_print_routes(void);

/**
 * @brief Get port number for a given neighbor address
 * 
 * @param neighbor_addr Neighbor address to look up
 * @return Port number if found, -1 if not found
 */
uint8_t get_port(mixnet_address neighbor_addr);

/**
 * @brief Get the index of the route for a given destination address
 * 
 * @param dst_addr Destination address
 * @return Index of the route if found, -1 if not found
 */
uint8_t get_route_index(mixnet_address dst_addr);

/**
 * @brief Generate random routes
 * 
 * @param target_node Target node
 */
void generate_random_routes(mixnet_address target_node);

#ifdef __cplusplus
}
#endif

#endif // LSA_H
