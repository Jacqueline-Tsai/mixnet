/**
 * @file log.h
 * @brief Professional logging system for Mixnet project
 * 
 * This module provides a thread-safe, configurable logging system with
 * different log levels, timestamps, and optional node identification.
 * 
 * @author Carnegie Mellon University - 15-441/641
 * @date 2023
 */

#ifndef LOG_H
#define LOG_H

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Log levels in order of severity
 */
typedef enum {
    LOG_LEVEL_DEBUG = 0,    ///< Debug information (most verbose)
    LOG_LEVEL_INFO,         ///< General information
    LOG_LEVEL_WARN,         ///< Warning messages
    LOG_LEVEL_ERROR,        ///< Error messages
    LOG_LEVEL_FATAL,        ///< Fatal errors (least verbose)
    LOG_LEVEL_COUNT         ///< Total number of log levels
} log_level_t;

/**
 * @brief Logging configuration structure
 */
typedef struct {
    log_level_t min_level;      ///< Minimum log level to output
    bool enable_timestamp;      ///< Include timestamp in log output
    bool enable_node_id;        ///< Include node ID in log output
    bool enable_colors;         ///< Enable colored output (if supported)
    bool enable_thread_id;      ///< Include thread ID in log output
    const char *log_file;       ///< Optional log file path (NULL for stdout)
} log_config_t;

/**
 * @brief Initialize the logging system
 * 
 * @param config Logging configuration (can be NULL for defaults)
 * @return 0 on success, -1 on failure
 */
int log_init(const log_config_t *config);

/**
 * @brief Cleanup the logging system
 * 
 * Should be called before program termination to ensure
 * all log messages are flushed and resources are freed.
 */
void log_cleanup(void);

/**
 * @brief Set the node ID for log messages
 * 
 * @param node_id Node identifier to include in log messages
 */
void log_set_node_id(uint32_t node_id);

/**
 * @brief Set the minimum log level
 * 
 * @param level Minimum log level to output
 */
void log_set_level(log_level_t level);

/**
 * @brief Check if a log level would be output
 * 
 * @param level Log level to check
 * @return true if the level would be output, false otherwise
 */
bool log_is_enabled(log_level_t level);

/**
 * @brief Core logging function
 * 
 * @param level Log level
 * @param file Source file name (use __FILE__)
 * @param line Source line number (use __LINE__)
 * @param func Source function name (use __func__)
 * @param fmt printf-style format string
 * @param ... Format arguments
 */
void log_message(log_level_t level, const char *file, int line, const char *func,
                 const char *fmt, ...);

/**
 * @brief Core logging function with va_list
 * 
 * @param level Log level
 * @param file Source file name
 * @param line Source line number
 * @param func Source function name
 * @param fmt printf-style format string
 * @param args va_list of format arguments
 */
void log_message_v(log_level_t level, const char *file, int line, const char *func,
                   const char *fmt, va_list args);

/**
 * @brief Flush any pending log output
 */
void log_flush(void);

/**
 * @brief Get current time in milliseconds since epoch
 * 
 * @return Current time in milliseconds
 */
uint64_t log_get_time_ms(void);

/**
 * @brief Get string representation of log level
 * 
 * @param level Log level
 * @return String representation of the log level
 */
const char *log_level_to_string(log_level_t level);

/**
 * @brief Get default logging configuration
 * 
 * @return Default logging configuration
 */
log_config_t log_get_default_config(void);

// Convenience macros for easier logging
#define LOG_DEBUG(fmt, ...) \
    log_message(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

#define LOG_INFO(fmt, ...) \
    log_message(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) \
    log_message(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...) \
    log_message(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

#define LOG_FATAL(fmt, ...) \
    log_message(LOG_LEVEL_FATAL, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

// Legacy compatibility macro (for existing code)
#define LOGF(fmt, ...) LOG_DEBUG(fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // LOG_H
