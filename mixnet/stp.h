/**
 * @file stp.h
 * @brief Spanning Tree Protocol (STP) implementation for Mixnet project
 * 
 * This module implements the Spanning Tree Protocol for creating a loop-free
 * topology in the network. It handles root election, path selection, and
 * port blocking to prevent loops.
 * 
 * @author Carnegie Mellon University - 15-441/641
 * @date 2023
 */

 #ifndef STP_H
 #define STP_H
 
 #include <stdint.h>
 #include <stdbool.h>
 #include "packet.h"
 #include "config.h"
 
 #ifdef __cplusplus
 extern "C" {
 #endif
 
 // STP constants
 #define STP_HELLO_PATH_LEN_THRESHOLD 0x8000
 
 // STP state structure
 typedef struct {
     mixnet_address self_address;        // This node's address
     uint8_t stage;                      // Current STP stage. 0: initial, 1: converged
     uint64_t init_time;                 // Time when stp election started
     mixnet_address root_address;        // Current root address
     uint16_t path_length;               // Path length to root
     mixnet_address parent_address;      // Parent node address
     uint8_t parent_port;                // Port to parent
     bool is_root;                       // Whether this node is the root
     bool *ports_blocked;                // Blocked state for each port (dynamic)
     mixnet_address *neighbor_addrs;     // Map port -> neighbor address (dynamic)
     uint64_t last_hello_time;           // Last time we sent a hello
     uint64_t last_root_heard_time;      // Last time we started reelection
 } stp_state_t;
 
 // Global STP configuration
 extern uint32_t stp_convergence_time_ms_;
 
 /**
  * @brief Initialize STP state for a node
  * 
  * @param handle Network handle
  * @param config Node configuration
  */
 void stp_init(void *handle, const struct mixnet_node_config *config);
 
 /**
  * @brief Process received STP packet
  * 
  * @param packet Received packet
  * @param port Port where packet was received
  * @param config Node configuration
  * @param handle Network handle
  */
 void stp_process_packet(mixnet_packet *packet, uint8_t port, 
                        const struct mixnet_node_config *config, void *handle);
 
 /**
  * @brief Send periodic hello messages (root only)
  * 
  * @param handle Network handle
  * @param config Node configuration
  */
 void stp_send_periodic_hello(void *handle, const struct mixnet_node_config *config);
 
 /**
  * @brief Update port blocking state based on current STP state
  * 
  * @param config Node configuration
  */
 void stp_update_port_blocking(const struct mixnet_node_config *config);
 
 /**
  * @brief Check if STP has converged
  * 
  * @return true if STP is converged, false otherwise
  */
 void check_stp_converged(void);
 
 /**
  * @brief Check if a port is blocked
  * 
  * @param port Port number to check
  * @return true if port is blocked, false otherwise
  */
 bool stp_is_port_blocked(uint8_t port);
 
 /**
  * @brief Get current STP state
  * 
  * @return Pointer to current STP state
  */
 stp_state_t* stp_get_state(void);
 
 /**
  * @brief Cleanup STP resources
  */
 void stp_cleanup(void);
 
 /**
  * @brief Start STP reelection process
  * 
  * @param handle Network handle
  * @param config Node configuration
  */
 void stp_check_reelection(void *handle, const struct mixnet_node_config *config);
 
 #ifdef __cplusplus
 }
 #endif
 
 #endif // STP_H