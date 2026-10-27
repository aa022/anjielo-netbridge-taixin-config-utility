#ifndef AHNB_TAIXINNET_H
#define AHNB_TAIXINNET_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define AHNB_API __declspec(dllexport)
#else
#define AHNB_API __attribute__((visibility("default")))
#endif

#define AHNB_ABI_VERSION 0x00020200u
#define AHNB_MAX_CHANNELS 16u
#define AHNB_CHANNEL_MIN_KHZ 700000u
#define AHNB_CHANNEL_MAX_KHZ 1000000u
#define AHNB_RAW_COMMAND_MAX 1024u
#define AHNB_STRUCT_SIZE_COUNT 6u

enum ahnb_status {
    AHNB_OK = 0,
    AHNB_INVALID_ARGUMENT = 1,
    AHNB_SYSTEM_ERROR = 2,
    AHNB_TIMEOUT = 3,
    AHNB_PROTOCOL_ERROR = 4,
    AHNB_NOT_FOUND = 5,
    AHNB_UNSUPPORTED = 6,
    AHNB_VERIFY_FAILED = 7,
    AHNB_PARTIAL = 8,
    AHNB_BUFFER_TOO_SMALL = 9
};

enum ahnb_capability_flags {
    AHNB_CAP_CORE = 1u << 0,
    AHNB_CAP_CREDENTIALS = 1u << 1,
    AHNB_CAP_RADIO = 1u << 2,
    AHNB_CAP_CONNECTION_STATE = 1u << 8,
    AHNB_CAP_STORED_TX_POWER = 1u << 9 /* reserved: no longer reported by ahnb_probe */
};

enum ahnb_field_masks {
    AHNB_FIELD_SSID = 1u << 0,
    AHNB_FIELD_PSK = 1u << 1,
    AHNB_FIELD_ENCRYPTION = 1u << 2,
    AHNB_FIELD_CHANNELS = 1u << 3,
    AHNB_FIELD_BANDWIDTH = 1u << 4,
    AHNB_FIELD_TX_POWER = 1u << 5,
    AHNB_FIELD_ALL = 0x3fu
};

typedef struct ahnb_endpoint {
    char interface_name[64];
    char ipv4_address[16];
    char broadcast_address[16];
} ahnb_endpoint;

typedef struct ahnb_target {
    uint8_t mac[6];
    uint8_t reserved[2];
    char response_address[16];
} ahnb_target;

typedef struct ahnb_capabilities {
    uint32_t flags;
    char role[32];
    char connection_state[32];
} ahnb_capabilities;

typedef struct ahnb_managed_config {
    uint8_t mac[6];
    uint8_t reserved[2];
    char role[32];
    char connection_state[32];
    char ssid[129];
    char psk[65];
    char encryption[32];
    uint32_t channels_khz[AHNB_MAX_CHANNELS];
    uint32_t channel_count;
    uint32_t bandwidth_mhz;
    int32_t stored_tx_power_dbm;
    int32_t runtime_tx_power_dbm;
    uint32_t present_mask;
} ahnb_managed_config;

typedef struct ahnb_radio_config {
    uint32_t channels_khz[AHNB_MAX_CHANNELS];
    uint32_t channel_count;
    uint32_t bandwidth_mhz;
    int32_t tx_power_dbm;
} ahnb_radio_config;

typedef struct ahnb_operation_result {
    int32_t status;
    uint32_t failed_stage;
    uint32_t failed_field;
    uint32_t applied_mask;
    uint32_t verified_mask;
    char message[192];
} ahnb_operation_result;

typedef struct ahnb_handle ahnb_handle;

#ifdef __cplusplus
extern "C" {
#endif

AHNB_API uint32_t ahnb_abi_version(void);
/* os_errno may be NULL; on AHNB_SYSTEM_ERROR it receives the OS errno. */
AHNB_API int ahnb_open(const ahnb_endpoint *endpoint, const ahnb_target *target,
                       ahnb_handle **handle, int *os_errno);
AHNB_API void ahnb_close(ahnb_handle *handle);
AHNB_API int ahnb_probe(ahnb_handle *handle, ahnb_capabilities *capabilities);
AHNB_API int ahnb_read_psk(ahnb_handle *handle, char psk[65]);
AHNB_API int ahnb_read_managed_config(ahnb_handle *handle,
                                      ahnb_managed_config *config);
/* Same as ahnb_read_managed_config but never queries the PSK or the WNBCFG dump
   (which carries it): stored_tx_power_dbm equals runtime_tx_power_dbm. */
AHNB_API int ahnb_read_status(ahnb_handle *handle, ahnb_managed_config *config);
/* Sends one printable-ASCII command verbatim and collects the reply until a
   status line, idle_ms of silence after the first packet (0 disables), or
   timeout_ms (must be >= 1). OK when any bytes arrived, TIMEOUT when none. */
AHNB_API int ahnb_raw_query(ahnb_handle *handle, const char *command,
                            uint32_t timeout_ms, uint32_t idle_ms,
                            char *response, size_t capacity, size_t *length);
AHNB_API int ahnb_apply_credentials(ahnb_handle *handle, const char *ssid,
                                    const char *psk,
                                    ahnb_operation_result *result);
AHNB_API int ahnb_apply_ssid(ahnb_handle *handle, const char *ssid,
                            ahnb_operation_result *result);
AHNB_API int ahnb_apply_psk(ahnb_handle *handle, const char *psk,
                           ahnb_operation_result *result);
AHNB_API int ahnb_apply_radio(ahnb_handle *handle,
                              const ahnb_radio_config *config,
                              ahnb_operation_result *result);
AHNB_API int ahnb_restore_managed_config(ahnb_handle *handle,
                                         const ahnb_managed_config *config,
                                         ahnb_operation_result *result);
AHNB_API const char *ahnb_status_string(int status);
/* endpoint, target, capabilities, managed_config, radio_config, operation_result */
AHNB_API void ahnb_struct_sizes(uint32_t sizes[AHNB_STRUCT_SIZE_COUNT]);

#ifdef __cplusplus
}
#endif
#endif
