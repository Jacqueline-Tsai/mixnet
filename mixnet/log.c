/**
 * @file log.c
 * @brief Professional logging system implementation for Mixnet project
 * 
 * This module provides a thread-safe, configurable logging system with
 * different log levels, timestamps, and optional node identification.
 * 
 * @author Carnegie Mellon University - 15-441/641
 * @date 2023
 */

#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/time.h>

// ANSI color codes for terminal output
#define ANSI_COLOR_RESET   "\033[0m"
#define ANSI_COLOR_RED     "\033[31m"
#define ANSI_COLOR_YELLOW  "\033[33m"
#define ANSI_COLOR_BLUE    "\033[34m"
#define ANSI_COLOR_GREEN   "\033[32m"
#define ANSI_COLOR_CYAN    "\033[36m"
#define ANSI_COLOR_MAGENTA "\033[35m"

// Log level colors
static const char *level_colors[LOG_LEVEL_COUNT] = {
    [LOG_LEVEL_DEBUG] = ANSI_COLOR_CYAN,
    [LOG_LEVEL_INFO]  = ANSI_COLOR_GREEN,
    [LOG_LEVEL_WARN]  = ANSI_COLOR_YELLOW,
    [LOG_LEVEL_ERROR] = ANSI_COLOR_RED,
    [LOG_LEVEL_FATAL] = ANSI_COLOR_MAGENTA
};

// Log level names
static const char *level_names[LOG_LEVEL_COUNT] = {
    [LOG_LEVEL_DEBUG] = "DEBUG",
    [LOG_LEVEL_INFO]  = "INFO ",
    [LOG_LEVEL_WARN]  = "WARN ",
    [LOG_LEVEL_ERROR] = "ERROR",
    [LOG_LEVEL_FATAL] = "FATAL"
};

// Global logging state
static struct {
    log_config_t config;
    bool initialized;
    uint32_t node_id;
    FILE *log_file;
    pthread_mutex_t mutex;
    pthread_t thread_id;
} g_log_state = {
    .config = {LOG_LEVEL_DEBUG, false, false, false, false, NULL},
    .initialized = false,
    .node_id = 0,
    .log_file = NULL,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .thread_id = 0
};

// Internal function declarations
static void log_output_message(log_level_t level, const char *file, int line, 
                              const char *func, const char *message);
static void log_format_timestamp(char *buffer, size_t buffer_size);
static const char *log_get_filename(const char *filepath);
static void log_setup_colors(void);

int log_init(const log_config_t *config) {
    if (g_log_state.initialized) {
        return 0; // Already initialized
    }

    // Set default configuration
    g_log_state.config = log_get_default_config();
    
    // Override with provided configuration
    if (config != NULL) {
        g_log_state.config = *config;
    }

    // Initialize thread ID
    g_log_state.thread_id = pthread_self();

    // Setup log file if specified
    if (g_log_state.config.log_file != NULL) {
        g_log_state.log_file = fopen(g_log_state.config.log_file, "a");
        if (g_log_state.log_file == NULL) {
            fprintf(stderr, "Failed to open log file '%s': %s\n", 
                    g_log_state.config.log_file, strerror(errno));
            return -1;
        }
    }

    // Setup colors if enabled and outputting to terminal
    if (g_log_state.config.enable_colors && g_log_state.log_file == NULL) {
        log_setup_colors();
    }

    g_log_state.initialized = true;
    return 0;
}

void log_cleanup(void) {
    if (!g_log_state.initialized) {
        return;
    }

    pthread_mutex_lock(&g_log_state.mutex);
    
    // Flush any pending output
    if (g_log_state.log_file != NULL) {
        fflush(g_log_state.log_file);
        fclose(g_log_state.log_file);
        g_log_state.log_file = NULL;
    } else {
        fflush(stdout);
    }

    g_log_state.initialized = false;
    pthread_mutex_unlock(&g_log_state.mutex);
}

void log_set_node_id(uint32_t node_id) {
    pthread_mutex_lock(&g_log_state.mutex);
    g_log_state.node_id = node_id;
    pthread_mutex_unlock(&g_log_state.mutex);
}

void log_set_level(log_level_t level) {
    if (level >= LOG_LEVEL_COUNT) {
        return;
    }
    
    pthread_mutex_lock(&g_log_state.mutex);
    g_log_state.config.min_level = level;
    pthread_mutex_unlock(&g_log_state.mutex);
}

bool log_is_enabled(log_level_t level) {
    if (!g_log_state.initialized || level >= LOG_LEVEL_COUNT) {
        return false;
    }
    
    pthread_mutex_lock(&g_log_state.mutex);
    bool enabled = (level >= g_log_state.config.min_level);
    pthread_mutex_unlock(&g_log_state.mutex);
    
    return enabled;
}

void log_message(log_level_t level, const char *file, int line, const char *func,
                 const char *fmt, ...) {
    if (!log_is_enabled(level)) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    log_message_v(level, file, line, func, fmt, args);
    va_end(args);
}

void log_message_v(log_level_t level, const char *file, int line, const char *func,
                   const char *fmt, va_list args) {
    if (!g_log_state.initialized || !log_is_enabled(level)) {
        return;
    }

    // Format the message
    char message[1024];
    int ret = vsnprintf(message, sizeof(message), fmt, args);
    if (ret < 0) {
        return; // Formatting error
    }
    if (ret >= (int)sizeof(message)) {
        // Message was truncated, add indicator
        strcpy(message + sizeof(message) - 4, "...");
    }

    log_output_message(level, file, line, func, message);
}

void log_flush(void) {
    if (!g_log_state.initialized) {
        return;
    }

    pthread_mutex_lock(&g_log_state.mutex);
    
    if (g_log_state.log_file != NULL) {
        fflush(g_log_state.log_file);
    } else {
        fflush(stdout);
    }
    
    pthread_mutex_unlock(&g_log_state.mutex);
}

uint64_t log_get_time_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

const char *log_level_to_string(log_level_t level) {
    if (level >= LOG_LEVEL_COUNT) {
        return "UNKNOWN";
    }
    return level_names[level];
}

log_config_t log_get_default_config(void) {
    log_config_t config = {
        .min_level = LOG_LEVEL_DEBUG,
        .enable_timestamp = true,
        .enable_node_id = true,
        .enable_colors = true,
        .enable_thread_id = false,
        .log_file = NULL
    };
    return config;
}

// Internal functions

static void log_output_message(log_level_t level, const char *file, int line, 
                              const char *func, const char *message) {
    pthread_mutex_lock(&g_log_state.mutex);

    FILE *output = (g_log_state.log_file != NULL) ? g_log_state.log_file : stdout;
    
    // Start with color if enabled
    if (g_log_state.config.enable_colors && g_log_state.log_file == NULL) {
        fprintf(output, "%s", level_colors[level]);
    }

    // Timestamp
    if (g_log_state.config.enable_timestamp) {
        char timestamp[32];
        log_format_timestamp(timestamp, sizeof(timestamp));
        fprintf(output, "[%s] ", timestamp);
    }

    // Log level
    fprintf(output, "[%s] ", level_names[level]);

    // Node ID
    if (g_log_state.config.enable_node_id) {
        fprintf(output, "[%u] ", g_log_state.node_id);
    }

    // Thread ID
    if (g_log_state.config.enable_thread_id) {
        fprintf(output, "[%lu] ", (unsigned long)g_log_state.thread_id);
    }

    // Location (file:line:function)
    const char *filename = log_get_filename(file);
    fprintf(output, "[%s:%d:%s] ", filename, line, func);

    // Message
    fprintf(output, "%s", message);

    // Reset color if enabled
    if (g_log_state.config.enable_colors && g_log_state.log_file == NULL) {
        fprintf(output, "%s", ANSI_COLOR_RESET);
    }

    // Ensure newline
    if (message[strlen(message) - 1] != '\n') {
        fprintf(output, "\n");
    }

    pthread_mutex_unlock(&g_log_state.mutex);
}

static void log_format_timestamp(char *buffer, size_t buffer_size) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    struct tm *tm_info = localtime(&tv.tv_sec);
    if (tm_info == NULL) {
        snprintf(buffer, buffer_size, "00:00:00.000");
        return;
    }
    
    snprintf(buffer, buffer_size, "%02d:%02d:%02d.%03ld",
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
             (long)(tv.tv_usec / 1000));
}

static const char *log_get_filename(const char *filepath) {
    if (filepath == NULL) {
        return "unknown";
    }
    
    const char *filename = strrchr(filepath, '/');
    if (filename == NULL) {
        filename = strrchr(filepath, '\\');
    }
    
    return (filename != NULL) ? filename + 1 : filepath;
}

static void log_setup_colors(void) {
    // Check if we're outputting to a terminal
    if (isatty(fileno(stdout))) {
        // Colors are already enabled in the configuration
        return;
    } else {
        // Disable colors if not outputting to a terminal
        g_log_state.config.enable_colors = false;
    }
}
