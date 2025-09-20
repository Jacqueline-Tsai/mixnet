#include <time.h>
#include <stdlib.h>
#include "state.h"
#include "log.h"
#include "util.h"

node_state_t node_state;
stp_state_t stp_state;
lsa_state_t lsa_state;

uint32_t convergence_time_ms = 500;

bool check_converged(void) {
    if (node_state.stage != 1) {
        return false;
    }
 
    if (get_time_ms() - node_state.init_time >= convergence_time_ms) {
        node_state.stage++;
        LOG_INFO("Stage changed to %d", node_state.stage);
        return true;
    }
    return false;
 }

void state_init(mixnet_address self_address, uint16_t num_neighbors, uint16_t mixing_factor) {
    // Initialize random seed
    srand(time(NULL));

    // Initialize logging system
    log_config_t log_config = log_get_default_config();
    log_config.enable_node_id = true;
    log_config.min_level = LOG_LEVEL_COUNT;
    if (log_init(&log_config) != 0) {
        LOG_ERROR("Failed to initialize logging system");
        return;
    }
    log_set_node_id(self_address);

    node_state.self_address = self_address;
    node_state.stage = 0;
    node_state.init_time = get_time_ms();
    node_state.num_neighbors = num_neighbors;
    node_state.neighbor_addrs = (mixnet_address*)calloc(num_neighbors, sizeof(mixnet_address));
    for (uint16_t i = 0; i < num_neighbors; i++) {
        node_state.neighbor_addrs[i] = INVALID_MIXADDR;
    }

    node_state.mixing_pipe = (mixing_pipe_t*)calloc(1, sizeof(mixing_pipe_t));
    node_state.mixing_pipe->num_packets = mixing_factor;
    node_state.mixing_pipe->last_packet_index = 0;
    for (uint8_t i = 0; i < node_state.mixing_pipe->num_packets; i++) {
        node_state.mixing_pipe->packet[i] = NULL;
    }
}

void cleanup() {
    free(node_state.neighbor_addrs);

    free(stp_state.ports_blocked);

    free(lsa_state.graph);
    // Free individual route paths
    for (int i = 0; i < lsa_state.num_nodes; i++) {
        free(lsa_state.routes[i].path);
    }
    free(lsa_state.routes);
}