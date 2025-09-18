#include "state.h"
#include "log.h"
#include "util.h"

node_state_t node_state;
stp_state_t stp_state;
lsa_state_t lsa_state;

uint32_t convergence_time_ms = 5000;

bool check_converged(void) {
    if (node_state.stage == 1) {
        return false;
    }
 
    if (get_time_ms() - node_state.init_time >= convergence_time_ms) {
        node_state.stage = 1;
        return true;
    }
    return false;
 }

void state_init(uint16_t num_neighbors) {
    node_state.stage = 0;
    node_state.init_time = get_time_ms();
    node_state.neighbor_addrs = (mixnet_address*)calloc(num_neighbors, sizeof(mixnet_address));
    for (uint16_t i = 0; i < num_neighbors; i++) {
        node_state.neighbor_addrs[i] = INVALID_MIXADDR;
    }
}

void cleanup() {
    free(node_state.neighbor_addrs);

    free(stp_state.ports_blocked);

    free(lsa_state.neighbor_links);
    free(lsa_state.neighbor_heard_from);
    free(lsa_state.graph);
    // Free individual route paths
    for (int i = 0; i < lsa_state.num_routes; i++) {
        free(lsa_state.routes[i].path);
    }
    free(lsa_state.routes);
}