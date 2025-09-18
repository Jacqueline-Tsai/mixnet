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
static int send_lsa_packet(void *handle, uint8_t port, const struct mixnet_node_config *config);

// Helper function to create and send LSA packet
static int send_lsa_packet(void *handle, uint8_t port, const struct mixnet_node_config *config) {
    (void)config; // Suppress unused parameter warning
    LOG_DEBUG("Sending LSA packet to port %d", port);
    
    // Calculate packet size
    uint16_t payload_size = sizeof(mixnet_packet_lsa) + 
                           (lsa_state.neighbor_count * sizeof(mixnet_lsa_link_params));
    
    // Allocate packet
    mixnet_packet *packet = (mixnet_packet*)malloc(sizeof(mixnet_packet) + payload_size);
    if (!packet) return -1;
    
    // Set packet header
    packet->total_size = sizeof(mixnet_packet) + payload_size;
    packet->type = PACKET_TYPE_LSA;
    
    // Set LSA payload
    mixnet_packet_lsa *lsa_payload = (mixnet_packet_lsa*)((char*)packet + sizeof(mixnet_packet));
    lsa_payload->node_address = node_state.self_address;
    lsa_payload->neighbor_count = lsa_state.neighbor_count;
    
    // Copy neighbor links
    memcpy(lsa_payload->links, lsa_state.neighbor_links, 
           lsa_state.neighbor_count * sizeof(mixnet_lsa_link_params));
    
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

    LOG_DEBUG("Processing LSA packet on port %d (from %d), sender %d, with %d neighbors", port, node_state.neighbor_addrs[port], lsa_payload->node_address, lsa_payload->neighbor_count);
    
    // Check if this is our own LSA (ignore)
    if (sender_addr == node_state.self_address || lsa_state.neighbor_heard_from[port]) {
        return;
    }
    lsa_state.neighbor_heard_from[port] = true;
    
    // Process each neighbor link in the LSA
    for (uint16_t i = 0; i < lsa_payload->neighbor_count; i++) {
        mixnet_lsa_link_params *link = &lsa_payload->links[i];
        mixnet_address destination = link->neighbor_mixaddr;
        
        uint16_t edge_idx = lsa_state.graph->num_edges;
        lsa_state.graph->adjacency_list[edge_idx].from_addr = sender_addr;
        lsa_state.graph->adjacency_list[edge_idx].to_addr = destination;
        lsa_state.graph->adjacency_list[edge_idx].cost = link->cost;
        lsa_state.graph->num_edges++;
    }
    
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
        free(fwd_packet);
    }
}

void lsa_init(void *handle, const struct mixnet_node_config *config) {
    LOG_INFO("Initializing LSA");
    // Wait for all neighbors addresses to be known
    while (true) {
        bool heard_from_all_neighbors = true;
        for (uint8_t p = 0; p < config->num_neighbors; p++) {
            if (node_state.neighbor_addrs[p] == INVALID_MIXADDR) {
                heard_from_all_neighbors = false;
                break;
            }
        }
        if (heard_from_all_neighbors) {
            break;
        }
        sleep(1);
    }
    LOG_DEBUG("All neighbors addresses known. Starting LSA initialization");
    uint64_t current_time = get_time_ms();
    
    // Initialize state
    node_state.self_address = config->node_addr;
    node_state.stage = 0;
    node_state.init_time = current_time;
    lsa_state.neighbor_count = config->num_neighbors;
    lsa_state.last_lsa_time = current_time;
    
    // Allocate neighbor links
    lsa_state.neighbor_links = (mixnet_lsa_link_params*)calloc(config->num_neighbors, sizeof(mixnet_lsa_link_params));
    
    // Initialize neighbor links with direct neighbors
    for (uint16_t i = 0; i < config->num_neighbors; i++) {
        lsa_state.neighbor_links[i].neighbor_mixaddr = i; // Assuming neighbor addresses are 0, 1, 2, ...
        lsa_state.neighbor_links[i].cost = config->link_costs ? config->link_costs[i] : 1;
    }
    
    // Allocate neighbor heard from tracking
    lsa_state.neighbor_heard_from = (bool*)calloc(config->num_neighbors, sizeof(bool));
    
    lsa_state.graph = (lsa_graph*)calloc(1, sizeof(lsa_graph));
    lsa_state.graph->num_edges = 0;
    
    // Allocate routes array
    lsa_state.routes = (lsa_route*)calloc(LSA_MAX_DESTINATIONS, sizeof(lsa_route));
    
    // Send initial LSA to all neighbors
    lsa_send_init_packet(handle, config);
    
    LOG_INFO("LSA initialized for node %d with %d neighbors", 
             config->node_addr, config->num_neighbors);
}


void lsa_send_init_packet(void *handle, const struct mixnet_node_config *config) {
    lsa_state.last_lsa_time = get_time_ms();
    
    LOG_DEBUG("Sending LSA to all neighbors");
    
    for (uint8_t p = 0; p < config->num_neighbors; p++) {
        send_lsa_packet(handle, p, config);
    }
}


/**
 * @brief Handle link failure by applying bad news rule
 * 
 * @param failed_neighbor Address of the neighbor whose link failed
 */
void lsa_handle_link_failure(mixnet_address failed_neighbor) { 
    LOG_DEBUG("Handling link failure to neighbor %d", failed_neighbor);
}

/**
 * @brief Compute routes from current node to all nodes in the LSA graph
 * 
 * This function implements Dijkstra's shortest path algorithm to find routes
 * from the current node (state.self.addr) to all nodes observed in the 
 * lsa_graph's adjacency_list.
 * 
 * @return 0 on success, -1 on failure
 */
int lsa_compute_routes(void) {
    if (!lsa_state.graph || !lsa_state.routes) {
        LOG_ERROR("LSA graph or routes not initialized");
        return -1;
    }
    
    mixnet_address source = node_state.self_address;
    uint16_t num_edges = lsa_state.graph->num_edges;
    
    // Find all unique nodes in the graph
    mixnet_address nodes[256];
    uint16_t num_nodes = 0;
    bool node_exists[256] = {false};
    
    // Add source node
    nodes[num_nodes++] = source;
    node_exists[source] = true;
    
    // Add all nodes from adjacency list
    for (uint16_t i = 0; i < num_edges; i++) {
        mixnet_address from = lsa_state.graph->adjacency_list[i].from_addr;
        mixnet_address to = lsa_state.graph->adjacency_list[i].to_addr;
        
        if (!node_exists[from]) {
            nodes[num_nodes++] = from;
            node_exists[from] = true;
        }
        if (!node_exists[to]) {
            nodes[num_nodes++] = to;
            node_exists[to] = true;
        }
    }
    
    // Initialize distances and previous nodes
    uint16_t distances[256];
    mixnet_address previous[256];
    bool visited[256] = {false};
    
    for (uint16_t i = 0; i < num_nodes; i++) {
        distances[nodes[i]] = LSA_INFINITY;
        previous[nodes[i]] = INVALID_MIXADDR;
    }
    distances[source] = 0;
    
    // Dijkstra's algorithm
    for (uint16_t i = 0; i < num_nodes; i++) {
        // Find unvisited node with minimum distance
        mixnet_address current = INVALID_MIXADDR;
        uint16_t min_dist = LSA_INFINITY;
        
        for (uint16_t j = 0; j < num_nodes; j++) {
            mixnet_address node = nodes[j];
            if (!visited[node] && distances[node] < min_dist) {
                min_dist = distances[node];
                current = node;
            }
        }
        
        if (current == INVALID_MIXADDR) break;
        visited[current] = true;
        
        // Update distances to neighbors
        for (uint16_t j = 0; j < num_edges; j++) {
            adjacency_edge *edge = &lsa_state.graph->adjacency_list[j];
            if (edge->from_addr == current) {
                mixnet_address neighbor = edge->to_addr;
                uint16_t new_dist = distances[current] + edge->cost;
                
                if (new_dist < distances[neighbor]) {
                    distances[neighbor] = new_dist;
                    previous[neighbor] = current;
                }
            }
        }
    }
    
    // Build routes
    uint16_t route_count = 0;
    for (uint16_t i = 0; i < num_nodes; i++) {
        mixnet_address dest = nodes[i];
        if (dest == source) continue; // Skip self
        
        if (distances[dest] < LSA_INFINITY) {
            // Count hops in path
            uint16_t hop_count = 0;
            mixnet_address path[256];
            mixnet_address current = dest;
            
            while (current != source && current != INVALID_MIXADDR) {
                path[hop_count++] = current;
                current = previous[current];
            }
            
            if (current == source) {
                // Allocate memory for path
                lsa_state.routes[route_count].dst_addr = dest;
                lsa_state.routes[route_count].hop_count = hop_count;
                lsa_state.routes[route_count].path = (mixnet_address*)malloc(hop_count * sizeof(mixnet_address));
                
                if (lsa_state.routes[route_count].path) {
                    // Copy path in reverse order (from source to destination)
                    for (uint16_t j = 0; j < hop_count; j++) {
                        lsa_state.routes[route_count].path[j] = path[hop_count - 1 - j];
                    }
                    route_count++;
                } else {
                    LOG_ERROR("Failed to allocate memory for route path");
                }
            }
        }
    }
    lsa_state.num_routes = route_count;
    if (lsa_state.num_routes == 0) {
        LOG_ERROR("No routes computed from node %d", source);
    }
    LOG_DEBUG("Computed %d routes from node %d", route_count, source);
    return 0;
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

    // Header
    n += snprintf(buf + n, sizeof(buf) - n,
                    "LSA Graph (from node %d)\n",
                    node_state.self_address);

    // Edge count
    n += snprintf(buf + n, sizeof(buf) - n,
                    "Number of edges: %d\n",
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
        adjacency_edge *edge = &lsa_state.graph->adjacency_list[i];
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
    if (!lsa_state.routes || lsa_state.num_routes == 0) {
        LOG_ERROR("LSA routes not initialized | lsa_state.num_routes %d | !lsa_state.routes %d", lsa_state.num_routes, !lsa_state.routes);
        return;
    }
    
    char buf[1024];
    sprintf(buf, "LSA Routes (from node %d):", node_state.self_address);
    
    bool has_routes = false;
    for (int i = 0; i < lsa_state.num_routes; i++) {
        lsa_route *route = &lsa_state.routes[i];
        
        // Check if this route is valid (has a destination and path)
        if (route->dst_addr != INVALID_MIXADDR && route->path != NULL) {
            has_routes = true;
            sprintf(buf, "  Route to %d (%d hops): ", route->dst_addr, route->hop_count);
            
            // Print the path
            if (route->hop_count == 0) {
                sprintf(buf, "    Direct connection");
            } else {
                sprintf(buf, "    %d", node_state.self_address);
                for (uint16_t j = 0; j < route->hop_count; j++) {
                    sprintf(buf, " -> %d", route->path[j]);
                }
                printf("\n");
            }
        }
    }
    LOG_DEBUG(buf);
    
    if (!has_routes) {
        LOG_DEBUG("No routes computed");
    }
}
