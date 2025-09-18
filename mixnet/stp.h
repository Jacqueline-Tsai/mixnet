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
#include "state.h"
 
 #ifdef __cplusplus
 extern "C" {
 #endif
 
 // STP constants
 #define STP_HELLO_PATH_LEN_THRESHOLD 0x8000
 
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
 void process_stp_packet(mixnet_packet *packet, uint8_t port, 
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
  * @brief Check if a port is blocked
  * 
  * @param port Port number to check
  * @return true if port is blocked, false otherwise
  */
 bool stp_is_port_blocked(uint8_t port);
 
 
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