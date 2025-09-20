/**
 * @file lsa.c
 * @brief Link State Advertisement (LSA) implementation for Mixnet project
 * 
 * This module implements the Link State Advertisement protocol for creating
 * forwarding tables based on link state information. It handles neighbor
 * discovery, LSA flooding, and shortest path computation.
 * 
 * @author Carnegie Mellon University - 15-441/641
 * @date 2023
 */

#include "lsa.h"
#include "log.h"
#include "connection.h"
 #include "util.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


// Internal function declarations
static int lsa_send_init_packet(void *handle, uint8_t port, const struct mixnet_node_config *config);

// Helper function to create and send LSA packet
static int lsa_send_init_packet(void *handle, uint8_t port, const struct mixnet_node_config *config) {
    LOG_DEBUG("Sending LSA packet to port %d", port);
    
    // Calculate packet size
    uint16_t payload_size = sizeof(mixnet_packet_lsa) + 
                           (config->num_neighbors * sizeof(mixnet_lsa_link_params));
    // Allocate packet
    mixnet_packet *packet = (mixnet_packet*)malloc(sizeof(mixnet_packet) + payload_size);
    if (!packet) return -1;
    
    // Set packet header
    packet->total_size = sizeof(mixnet_packet) + payload_size;
    packet->type = PACKET_TYPE_LSA;
    
    // Set LSA payload
    mixnet_packet_lsa *lsa_payload = (mixnet_packet_lsa*)((char*)packet + sizeof(mixnet_packet));
    lsa_payload->node_address = node_state.self_address;
    lsa_payload->neighbor_count = config->num_neighbors;
    
    // Pack neighbor links
    for (uint16_t i = 0; i < config->num_neighbors; i++) {
        lsa_payload->links[i].neighbor_mixaddr = node_state.neighbor_addrs[i];
        lsa_payload->links[i].cost = config->link_costs[i];
    }
    
    // Send packet
    int result = mixnet_send(handle, port, packet);
    if (result < 0) {
        free(packet);
    }
    return result;
}


// // Apply good news rule: better route found
// static void apply_good_news_rule(mixnet_address destination, mixnet_address next_hop, 
//                                 uint16_t cost, mixnet_address sender_addr) {
//     (void)sender_addr; // Suppress unused parameter warning
//     int idx = find_forwarding_entry(destination);
    
//     if (idx == -1) {
//         // New destination - add entry
//         expand_forwarding_table_if_needed();
//         if (lsa_state.forwarding_table_size < lsa_state.max_forwarding_table_size) {
//             idx = lsa_state.forwarding_table_size++;
//             lsa_state.forwarding_table[idx].destination = destination;
//             lsa_state.forwarding_table[idx].next_hop = next_hop;
//             lsa_state.forwarding_table[idx].cost = cost;
//             lsa_state.forwarding_table[idx].valid = true;
//             LOG_DEBUG("Added new destination %d via %d with cost %d", 
//                      destination, next_hop, cost);
//         }
//     } else {
//         // Existing destination - update if better
//         if (cost < lsa_state.forwarding_table[idx].cost) {
//             lsa_state.forwarding_table[idx].next_hop = next_hop;
//             lsa_state.forwarding_table[idx].cost = cost;
//             lsa_state.forwarding_table[idx].valid = true;
//             LOG_DEBUG("Updated destination %d via %d with cost %d", 
//                      destination, next_hop, cost);
//         }
//     }
// }

// // Apply bad news rule: route is no longer available
// static void apply_bad_news_rule(mixnet_address destination, mixnet_address sender_addr) {
//     int idx = find_forwarding_entry(destination);
    
//     if (idx != -1 && lsa_state.forwarding_table[idx].next_hop == sender_addr) {
//         // Mark route as invalid (cost = infinity)
//         lsa_state.forwarding_table[idx].cost = LSA_INFINITY;
//         lsa_state.forwarding_table[idx].valid = false;
//         LOG_DEBUG("Marked destination %d as unreachable via %d", destination, sender_addr);
//     }
// }

// Process received LSA packet
void process_lsa_packet(mixnet_packet *packet, uint8_t port, 
                        const struct mixnet_node_config *config, void *handle) {
    if (packet->type != PACKET_TYPE_LSA) return;
    assert(port < config->num_neighbors);

    mixnet_packet_lsa *lsa_payload = (mixnet_packet_lsa*)((char*)packet + sizeof(mixnet_packet));
    mixnet_address sender_addr = lsa_payload->node_address;

    LOG_DEBUG("Processing LSA packet on port %d (from %d), sender %d, size %d, with %d neighbors", port, node_state.neighbor_addrs[port], lsa_payload->node_address, packet->total_size, lsa_payload->neighbor_count);
    
    // Check if this is our own LSA (ignore)
    if (sender_addr == node_state.self_address) {
        LOG_INFO("Ignoring LSA packet | sender_addr (%d) == node_state.self_address (%d)", sender_addr, node_state.self_address);
        return;
    }
    
    for (uint16_t i = 0; i < lsa_state.num_nodes; i++) {
        if (lsa_state.addrs_heard_from[i] == sender_addr) {
            LOG_INFO("Ignoring LSA packet | sender_addr (%d) already heard from", sender_addr);
            return;
        }
    }

    lsa_state.addrs_heard_from[lsa_state.num_nodes++] = sender_addr;
    // Process each neighbor link in the LSA
    for (uint16_t i = 0; i < lsa_payload->neighbor_count; i++) {
        mixnet_lsa_link_params *link = &lsa_payload->links[i];
        lsa_state.graph->adjacency_list[lsa_state.graph->num_edges].from_addr = sender_addr;
        lsa_state.graph->adjacency_list[lsa_state.graph->num_edges].to_addr = link->neighbor_mixaddr;
        lsa_state.graph->adjacency_list[lsa_state.graph->num_edges].cost = link->cost;
        lsa_state.graph->num_edges++;
    }
    LOG_DEBUG("LSA graph updated with %d edges", lsa_state.graph->num_edges);
    // Forward LSA to other neighbors
    for (uint8_t p = 0; p < config->num_neighbors; p++) {
        if (p == port) {
            continue;
        }
        // forward LSA to other neighbors, not send a new one. refer to stp forwarding
        // use memcpy and mixnet_send
        LOG_INFO("Forwarding LSA to port %d (addr %d)\n", p, node_state.neighbor_addrs[p]);
        mixnet_packet *fwd_packet = (mixnet_packet*)malloc(packet->total_size);
        memcpy(fwd_packet, packet, packet->total_size);
        mixnet_send(handle, p, fwd_packet);
    }
}

void lsa_send_init_packets(void *handle, const struct mixnet_node_config *config) {
    LOG_INFO("Sending initial LSA packets");

    // Put each neighbor link in the LSA graph
    for (uint16_t i = 0; i < node_state.num_neighbors; i++) {        
        lsa_state.graph->adjacency_list[i].from_addr = node_state.self_address;
        lsa_state.graph->adjacency_list[i].to_addr = node_state.neighbor_addrs[i];
        lsa_state.graph->adjacency_list[i].cost = config->link_costs[i];
    }

    // Send initial LSA to all neighbors
    for (uint8_t p = 0; p < config->num_neighbors; p++) {
        lsa_send_init_packet(handle, p, config);
    }
}

void lsa_init(const struct mixnet_node_config *config) {
    LOG_INFO("Initializing LSA");

    uint64_t current_time = get_time_ms();
    
    // Initialize state
    lsa_state.last_lsa_time = current_time;
    
    // Allocate neighbor heard from tracking
    lsa_state.num_nodes = 1;
    lsa_state.addrs_heard_from[0] = node_state.self_address;
    
    lsa_state.graph = (lsa_graph_t*)calloc(1, sizeof(lsa_graph_t));
    lsa_state.graph->num_edges = node_state.num_neighbors;
    
    LOG_INFO("LSA initialized for node %d with %d neighbors", 
             config->node_addr, config->num_neighbors);
}


/**
 * @brief Handle link failure by applying bad news rule
 * 
 * @param failed_neighbor Address of the neighbor whose link failed
 */
 void lsa_handle_link_failure(mixnet_address failed_neighbor) { 
    LOG_DEBUG("Handling link failure to neighbor %d", failed_neighbor);
}

int get_neighbors(mixnet_address node, mixnet_address *neighbors) {
    uint8_t num_neighbors = 0;
    for (uint16_t i = 0; i < lsa_state.graph->num_edges; i++) {
        if (node !=lsa_state.graph->adjacency_list[i].from_addr) {
            continue;
        }
        neighbors[num_neighbors++] = lsa_state.graph->adjacency_list[i].to_addr;
    }
    return num_neighbors;
}

int get_cost(mixnet_address node_1, mixnet_address node_2) {
    for (uint16_t i = 0; i < lsa_state.graph->num_edges; i++) {
        if (lsa_state.graph->adjacency_list[i].from_addr == node_1 && lsa_state.graph->adjacency_list[i].to_addr == node_2) {
            return lsa_state.graph->adjacency_list[i].cost;
        }
    }
    return LSA_INFINITY;
}

uint8_t get_index(mixnet_address node) {
    for (uint16_t i = 0; i < lsa_state.num_nodes; i++) {
        if (lsa_state.addrs_heard_from[i] == node) {
            return i;
        }
    }
    LOG_ERROR("get_index | node %d not found", node);
    return -1;
}

/**
 * @brief Get port number for a given neighbor address
 * 
 * @param neighbor_addr Neighbor address to look up
 * @return Port number if found, -1 if not found
 */
uint8_t get_port(mixnet_address neighbor_addr) {
    for (uint8_t p = 0; p < node_state.num_neighbors; p++) {
        if (node_state.neighbor_addrs[p] == neighbor_addr) {
            return p;
        }
    }
    LOG_ERROR("get_port | neighbor %d not found", neighbor_addr);
    return -1;
}

/**
 * @brief Get the index of the route for a given destination address
 * 
 * @param dst_addr Destination address
 * @return Index of the route if found, -1 if not found
 */
uint8_t get_route_index(mixnet_address dst_addr) {
    for (uint8_t i = 0; i < lsa_state.num_nodes; i++) {
        if (lsa_state.routes[i].dst_addr == dst_addr) {
            return i;
        }
    }
    LOG_ERROR("get_route_index | dst_addr %d not found", dst_addr);
    return -1;
}

/**
 * @brief Dijkstra's algorithm to find the shortest path
 * 
 * @param current_node Current node
 * @param total_costs Total cost
 * @param hop_count Hop count
 * @param paths Paths
 * @param random_routing Whether to use random routing
 */
void dijkstra(mixnet_address current_node, uint16_t total_costs, uint16_t hop_count, mixnet_address *paths) {
    LOG_DEBUG("Dijkstra | current_node %d | total_costs %d | hop_count %d", current_node, total_costs, hop_count);
    uint8_t index = get_index(current_node);
    if (lsa_state.routes[index].cost <= total_costs) {
        return;
    }
    lsa_state.routes[index].cost = total_costs;
    lsa_state.routes[index].hop_count = hop_count;
    lsa_state.routes[index].path = (mixnet_address*)calloc(hop_count, sizeof(mixnet_address));
    memcpy(lsa_state.routes[index].path, paths, hop_count * sizeof(mixnet_address));
    
    mixnet_address neighbors[256];
    uint8_t num_neighbors = get_neighbors(current_node, neighbors);
    for (uint8_t i = 0; i < num_neighbors; i++) {
        uint16_t cost = get_cost(current_node, neighbors[i]);
        mixnet_address *new_paths = (mixnet_address*)calloc(hop_count + 1, sizeof(mixnet_address));
        memcpy(new_paths, paths, hop_count * sizeof(mixnet_address));
        new_paths[hop_count] = neighbors[i];

        dijkstra(neighbors[i], cost + total_costs, hop_count + 1, new_paths);
        free(new_paths);
    }
}

/**
 * @brief Compute routes from current node to all nodes in the LSA graph
 * 
 * This function implements Dijkstra's shortest path algorithm to find routes
 * from the current node (state.self.addr) to all nodes observed in the 
 * lsa_graph_t's adjacency_list.
 * 
 * @return 0 on success, -1 on failure
 */
void lsa_compute_routes(void) {
    LOG_INFO("Computing routes...");
    if (!lsa_state.graph) {
        LOG_ERROR("LSA graph not initialized");
    }
    
    lsa_state.routes = (lsa_route_t*)calloc(lsa_state.num_nodes, sizeof(lsa_route_t));
    for (uint16_t i = 0; i < lsa_state.num_nodes; i++) {
        lsa_state.routes[i].dst_addr = lsa_state.addrs_heard_from[i];
        lsa_state.routes[i].cost = LSA_INFINITY;
        lsa_state.routes[i].path = NULL;
        lsa_state.routes[i].hop_count = 0;
    }
    dijkstra(node_state.self_address, 0, 0, NULL);
}

void random_shuffle(mixnet_address *array, uint8_t size) {
    LOG_DEBUG("Random shuffle | size %d", size);
    for (uint8_t i = 0; i < size; i++) {
        uint8_t j = rand() % size;
        if (i == j) {
            continue;
        }
        LOG_DEBUG("Swaping i %d | j %d | array[i] %d | array[j] %d", i, j, array[i], array[j]);
        mixnet_address temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
}

/**
 * @brief Random DFS to find a path to the target node
 * 
 * @param current_node Current node
 * @param total_costs Total cost
 * @param hop_count Hop count
 * @param path Path
 * @param target_node Target node
 */
bool random_dfs(mixnet_address current_node, uint16_t total_costs, uint16_t hop_count, mixnet_address *path, mixnet_address target_node) {
    LOG_DEBUG("Random DFS | current_node %d | total_costs %d | hop_count %d | target_node %d", current_node, total_costs, hop_count, target_node);
    path[hop_count] = current_node;
    if (current_node == target_node) {
        uint8_t node_i = get_index(current_node);
        lsa_state.routes[node_i].cost = total_costs;
        lsa_state.routes[node_i].hop_count = hop_count;
        lsa_state.routes[node_i].path = (mixnet_address*)calloc(hop_count, sizeof(mixnet_address));
        memcpy(lsa_state.routes[node_i].path, path + 1, hop_count * sizeof(mixnet_address));
        LOG_DEBUG("Found target_node %d", current_node);
        return true;
    }
    for (uint8_t i = 0; i < hop_count; i++) {
        if (path[i] == current_node) {
            LOG_DEBUG("Current_node %d already in path", current_node);
            return false;
        }
    }

    mixnet_address neighbors[256];
    uint8_t num_neighbors = get_neighbors(current_node, neighbors);
    LOG_DEBUG("Found num_neighbors %d for node %d", num_neighbors, current_node);
    random_shuffle(neighbors, num_neighbors);
    for (uint8_t i = 0; i < num_neighbors; i++) {
        uint16_t cost = get_cost(current_node, neighbors[i]);
        if (random_dfs(neighbors[i], total_costs + cost, hop_count + 1, path, target_node)) {
            return true;
        }
    }
    return false;
}

void generate_random_routes(mixnet_address target_node) {
    LOG_INFO("Generating random routes...");
    mixnet_address *paths = (mixnet_address*)calloc(lsa_state.num_nodes, sizeof(mixnet_address));
    random_dfs(node_state.self_address, 0, 0, paths, target_node);
    free(paths);

    char buf[256];
    int n = 0;
    n += snprintf(buf + n, sizeof(buf) - n, "Random routes generated for node %d to %d | path length %d", node_state.self_address, target_node, lsa_state.routes[get_index(target_node)].hop_count - 1);
    for (uint16_t i = 0; i < lsa_state.num_nodes; i++) {
        if (lsa_state.routes[i].dst_addr != target_node) {
            continue;
        }
        n += snprintf(buf + n, sizeof(buf) - n, "  Route to %d (%d hops, %d cost): ", lsa_state.routes[i].dst_addr, lsa_state.routes[i].hop_count, lsa_state.routes[i].cost);
        for (uint16_t j = 0; j < lsa_state.routes[i].hop_count; j++) {
            n += snprintf(buf + n, sizeof(buf) - n, "%d -> ", lsa_state.routes[i].path[j]);
        }
        n += snprintf(buf + n, sizeof(buf) - n, "End\n");
    }
    LOG_DEBUG("%s", buf);

}

/**
 * @brief Print the LSA graph adjacency list
 * 
 * This function prints all edges in the LSA graph with their costs.
 */
void lsa_print_graph(void) {
    if (!lsa_state.graph) {
        LOG_ERROR("LSA graph not initialized");
        return;
    }
    char buf[1024];
    size_t n = 0;

    n += snprintf(buf + n, sizeof(buf) - n, "Printing LSA graph...");
    n += snprintf(buf + n, sizeof(buf) - n, "LSA Graph (from node %d)\n", node_state.self_address);

    // Edge count
    n += snprintf(buf + n, sizeof(buf) - n, "Number of edges: %d\n",
                    lsa_state.graph->num_edges);

    if (lsa_state.graph->num_edges == 0) {
        // No edges to print
        n += snprintf(buf + n, sizeof(buf) - n,
                        "  No edges in graph\n");
        LOG_DEBUG("%s", buf);
        return;
    }

    // Append each edge, guarding against buffer overflow
    for (uint16_t i = 0; i < lsa_state.graph->num_edges; i++) {
        if (n >= sizeof(buf)) { break; }
        adjacency_edge_t *edge = &lsa_state.graph->adjacency_list[i];
        n += snprintf(buf + n, sizeof(buf) - n,
                        "  Edge %d: %d -> %d (cost: %d)\n",
                        i, edge->from_addr, edge->to_addr, edge->cost);
    }
    LOG_DEBUG("%s", buf);
}

/**
 * @brief Print all computed routes
 * 
 * This function prints all routes computed by lsa_compute_routes().
 */
void lsa_print_routes(void) {
    if (!lsa_state.routes || lsa_state.num_nodes == 0) {
        LOG_ERROR("LSA routes not initialized | lsa_state.num_nodes %d | !lsa_state.routes %d", lsa_state.num_nodes, !lsa_state.routes);
        return;
    }
    
    char buf[1024];
    size_t n = 0;
    n += snprintf(buf + n, sizeof(buf) - n, "Printing LSA routes...\n");
    n += snprintf(buf + n, sizeof(buf) - n, "LSA Routes (from node %d):", node_state.self_address);
    
    bool has_routes = false;
    for (int i = 0; i < lsa_state.num_nodes; i++) {
        lsa_route_t *route = &lsa_state.routes[i];
        
        n += snprintf(buf + n, sizeof(buf) - n, "  Route to %d (%d hops, %d cost): ", route->dst_addr, route->hop_count, route->cost);
        
        n += snprintf(buf + n, sizeof(buf) - n, "Start -> ");
        for (uint16_t j = 0; j < route->hop_count; j++) {
            n += snprintf(buf + n, sizeof(buf) - n, "%d -> ", route->path[j]);
        }
        n += snprintf(buf + n, sizeof(buf) - n, "End\n");
    }
    LOG_DEBUG(buf);
    
    if (!has_routes) {
        LOG_DEBUG("No routes computed");
    }
}
