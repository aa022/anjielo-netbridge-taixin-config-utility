#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "taixinnet.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#ifndef __APPLE__
#include <sys/random.h>
#endif

#define NETAT_PORT 56789
#define HEADER_SIZE 15u
#define RESPONSE_MAX 8192u
#define VALUE_MAX 512u
#define COMMAND_MAX AHNB_RAW_COMMAND_MAX
#define QUERY_TIMEOUT_MS 1000u
#define SUMMARY_TIMEOUT_MS 3000u
#define SUMMARY_IDLE_MS 200u
#define POLL_SLICE_MAX_MS 1000u
#define RECEIVE_ITERATIONS_MAX 100000u
#define PSK_QUERY_ATTEMPTS 3u
#define PSK_HEX_LENGTH 64u
#define SSID_MAX_LENGTH 32u
#define CHANNEL_STEP_KHZ 100u
#define CHANNEL_UNIT_LIMIT 100000u
#define CHANNEL_DIGITS_MAX 7u
#define CHANNEL_TEXT_MAX 256u
#define NUMBER_TEXT_MAX 32u
#define TX_POWER_MIN_DBM 6 /* wnb firmware v1.6 AT+TXPOWER= accepts 6..20 */
#define TX_POWER_MAX_DBM 20
#define ENCRYPTION_WPA_PSK "WPA-PSK"
#define SUMMARY_QUERY "AT+WNBCFG"

enum netat_command { AT_REQUEST = 3, AT_RESPONSE = 4 };

enum receive_code { RECV_ERROR = -1, RECV_TIMEOUT = 0, RECV_PACKET = 1, RECV_IGNORED = 2 };

enum reply_end_flags {
    END_ON_TERMINATOR = 1u << 0,
    END_ON_FIRST_PACKET = 1u << 1,
    END_ON_IDLE = 1u << 2
};

enum reply_end_reason {
    ENDED_DEADLINE = 0,
    ENDED_TERMINATOR = 1,
    ENDED_FIRST_PACKET = 2,
    ENDED_IDLE = 3,
    ENDED_OVERFLOW = 4,
    ENDED_ERROR = 5
};

/* Ordered by precedence: a reply's kind is the highest kind of any line. */
enum line_kind {
    LINE_BLANK = 0,
    LINE_VALUE = 1,
    LINE_OK = 2,
    LINE_ERROR = 3,
    LINE_UNSUPPORTED = 4
};

enum result_stage { STAGE_VALIDATE = 0, STAGE_PROBE = 2, STAGE_WRITE = 3, STAGE_VERIFY = 4 };

struct response_target {
    uint8_t mac[6];
    struct in_addr address;
};

struct reply_plan {
    unsigned flags;
    unsigned timeout_ms;
    unsigned idle_ms;
};

struct field_write {
    const char *field;
    const char *value;
    uint32_t mask;
};

struct radio_values {
    char bandwidth[NUMBER_TEXT_MAX];
    char channels[CHANNEL_TEXT_MAX];
    char power[NUMBER_TEXT_MAX];
};

struct ahnb_handle {
    int fd;
    unsigned ifindex;
    struct in_addr address;
    char interface_name[64];
    int (*transport_send)(struct ahnb_handle *, const uint8_t *, size_t, struct in_addr);
    int (*transport_receive)(struct ahnb_handle *, uint8_t *, size_t, size_t *,
                             struct sockaddr_in *, unsigned);
    uint64_t (*transport_clock)(struct ahnb_handle *);
    void *transport_context;
    struct response_target target;
};

static void secure_zero(void *data, size_t size) {
    volatile unsigned char *cursor = data;
    while (size) {
        *cursor = 0;
        cursor++;
        size--;
    }
}

static void copy_text(char *dest, size_t size, const char *source) {
    if (!size) return;
    snprintf(dest, size, "%s", source ? source : "");
}

static void result_init(ahnb_operation_result *result) {
    memset(result, 0, sizeof(*result));
}

/* Any failure after an acknowledged write is PARTIAL, whatever the cause. */
static int result_fail(ahnb_operation_result *result, int status,
                       uint32_t stage, uint32_t field, const char *message) {
    result->status = status;
    result->failed_stage = stage;
    result->failed_field = field;
    if (!result->applied_mask) {
        copy_text(result->message, sizeof(result->message), message);
        return status;
    }
    result->status = AHNB_PARTIAL;
    snprintf(result->message, sizeof(result->message),
             "%s Settings were partially written (applied mask 0x%02x).",
             message, (unsigned)result->applied_mask);
    return AHNB_PARTIAL;
}

static void result_succeed(ahnb_operation_result *result, const char *message) {
    result->status = AHNB_OK;
    result->failed_stage = 0;
    result->failed_field = 0;
    copy_text(result->message, sizeof(result->message), message);
}

static int random_cookie(uint8_t cookie[6]) {
#ifdef __APPLE__
    arc4random_buf(cookie, 6);
    return AHNB_OK;
#else
    size_t offset = 0;
    while (offset < 6) {
        ssize_t count = getrandom(cookie + offset, 6 - offset, 0);
        if (count > 0) { offset += (size_t)count; continue; }
        if (count < 0 && errno == EINTR) continue;
        return AHNB_SYSTEM_ERROR;
    }
    return AHNB_OK;
#endif
}

static uint64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static uint64_t handle_now_ms(ahnb_handle *handle) {
    if (handle->transport_clock) return handle->transport_clock(handle);
    return monotonic_ms();
}

static uint16_t read_u16(const uint8_t bytes[2]) {
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static void write_header(uint8_t header[HEADER_SIZE], uint8_t command,
                         uint16_t length, const uint8_t destination[6],
                         const uint8_t source[6]) {
    memset(header, 0, HEADER_SIZE);
    header[0] = command;
    header[1] = (uint8_t)(length >> 8);
    header[2] = (uint8_t)(length & 0xff);
    memcpy(header + 3, destination, 6);
    memcpy(header + 9, source, 6);
}

static int packet_valid(const uint8_t *packet, size_t size, uint8_t command,
                        const uint8_t destination[6], const uint8_t source[6]) {
    if (!packet || size < HEADER_SIZE || packet[0] != command) return 0;
    if (read_u16(packet + 1) != size - HEADER_SIZE) return 0;
    if (destination && memcmp(packet + 3, destination, 6)) return 0;
    if (source && memcmp(packet + 9, source, 6)) return 0;
    return 1;
}

static int send_packet(ahnb_handle *handle, const uint8_t *data, size_t size,
                       struct in_addr address) {
    if (handle->transport_send)
        return handle->transport_send(handle, data, size, address);
    struct sockaddr_in destination;
    memset(&destination, 0, sizeof(destination));
    destination.sin_family = AF_INET;
    destination.sin_port = htons(NETAT_PORT);
    destination.sin_addr = address;
#ifdef __APPLE__
    ssize_t sent = sendto(handle->fd, data, size, 0,
                          (struct sockaddr *)&destination, sizeof(destination));
#else
    struct iovec iov = {(void *)data, size};
    char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    memset(control, 0, sizeof(control));
    message.msg_name = &destination;
    message.msg_namelen = sizeof(destination);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    struct in_pktinfo *info = (struct in_pktinfo *)CMSG_DATA(cmsg);
    memset(info, 0, sizeof(*info));
    info->ipi_ifindex = (int)handle->ifindex;
    info->ipi_spec_dst = handle->address;
    ssize_t sent = sendmsg(handle->fd, &message, 0);
#endif
    return sent == (ssize_t)size ? AHNB_OK : AHNB_SYSTEM_ERROR;
}

/* Returns a RECV_* code; a zero-length datagram is a packet, not a timeout. */
static int receive_packet(ahnb_handle *handle, uint8_t *data, size_t size,
                          size_t *received, struct sockaddr_in *source,
                          unsigned timeout_ms) {
    *received = 0;
    if (handle->transport_receive)
        return handle->transport_receive(handle, data, size, received, source, timeout_ms);
    struct pollfd entry;
    entry.fd = handle->fd;
    entry.events = POLLIN;
    entry.revents = 0;
    int ready = poll(&entry, 1, (int)timeout_ms);
    if (ready < 0) return errno == EINTR ? RECV_IGNORED : RECV_ERROR;
    if (ready == 0) return RECV_TIMEOUT;
#ifdef __APPLE__
    socklen_t length = sizeof(*source);
    ssize_t count = recvfrom(handle->fd, data, size, 0, (struct sockaddr *)source, &length);
    if (count < 0) return errno == EINTR || errno == EAGAIN ? RECV_IGNORED : RECV_ERROR;
    *received = (size_t)count;
    return RECV_PACKET;
#else
    struct iovec iov = {data, size};
    char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_name = source;
    message.msg_namelen = sizeof(*source);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    ssize_t count = recvmsg(handle->fd, &message, 0);
    if (count < 0) return errno == EINTR || errno == EAGAIN ? RECV_IGNORED : RECV_ERROR;
    int matching_interface = 0;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg;
         cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo *info = (struct in_pktinfo *)CMSG_DATA(cmsg);
            matching_interface = info->ipi_ifindex == (int)handle->ifindex;
        }
    }
    if (!matching_interface) return RECV_IGNORED;
    *received = (size_t)count;
    return RECV_PACKET;
#endif
}

uint32_t ahnb_abi_version(void) { return AHNB_ABI_VERSION; }

void ahnb_struct_sizes(uint32_t sizes[AHNB_STRUCT_SIZE_COUNT]) {
    if (!sizes) return;
    sizes[0] = (uint32_t)sizeof(ahnb_endpoint);
    sizes[1] = (uint32_t)sizeof(ahnb_target);
    sizes[2] = (uint32_t)sizeof(ahnb_capabilities);
    sizes[3] = (uint32_t)sizeof(ahnb_managed_config);
    sizes[4] = (uint32_t)sizeof(ahnb_radio_config);
    sizes[5] = (uint32_t)sizeof(ahnb_operation_result);
}

static int fixed_text_terminated(const char *text, size_t capacity) {
    return text && memchr(text, '\0', capacity) != NULL;
}

static int open_failed(ahnb_handle *handle, int *os_errno) {
    int saved = errno;
    if (os_errno) *os_errno = saved;
    ahnb_close(handle);
    return AHNB_SYSTEM_ERROR;
}

int ahnb_open(const ahnb_endpoint *endpoint, const ahnb_target *target,
              ahnb_handle **output, int *os_errno) {
    if (os_errno) *os_errno = 0;
    if (output) *output = NULL;
    if (!endpoint || !target || !output ||
        !fixed_text_terminated(endpoint->interface_name,
                               sizeof(endpoint->interface_name)) ||
        !fixed_text_terminated(endpoint->ipv4_address,
                               sizeof(endpoint->ipv4_address)) ||
        !fixed_text_terminated(endpoint->broadcast_address,
                               sizeof(endpoint->broadcast_address)) ||
        !fixed_text_terminated(target->response_address,
                               sizeof(target->response_address)) ||
        !endpoint->interface_name[0] || !endpoint->ipv4_address[0] ||
        !endpoint->broadcast_address[0] || !target->response_address[0] ||
        (target->mac[0] & 1) ||
        !memcmp(target->mac, "\0\0\0\0\0\0", 6))
        return AHNB_INVALID_ARGUMENT;
    unsigned index = if_nametoindex(endpoint->interface_name);
    if (!index) return AHNB_NOT_FOUND;
    struct in_addr address = {0}, broadcast = {0};
    struct in_addr response_address = {0};
    /* The broadcast address is validated for ABI compatibility only: requests
       always go to the limited broadcast address. */
    if (inet_pton(AF_INET, endpoint->ipv4_address, &address) != 1 ||
        inet_pton(AF_INET, endpoint->broadcast_address, &broadcast) != 1 ||
        inet_pton(AF_INET, target->response_address, &response_address) != 1)
        return AHNB_INVALID_ARGUMENT;
    ahnb_handle *handle = calloc(1, sizeof(*handle));
    if (!handle) return open_failed(NULL, os_errno);
    handle->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (handle->fd < 0) return open_failed(handle, os_errno);
    handle->ifindex = index;
    handle->address = address;
    copy_text(handle->interface_name, sizeof(handle->interface_name),
              endpoint->interface_name);
    memcpy(handle->target.mac, target->mac, sizeof(handle->target.mac));
    handle->target.address = response_address;
    int enabled = 1;
    if (setsockopt(handle->fd, SOL_SOCKET, SO_BROADCAST, &enabled, sizeof(enabled)) < 0 ||
        setsockopt(handle->fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) < 0)
        return open_failed(handle, os_errno);
#ifdef SO_REUSEPORT
    if (setsockopt(handle->fd, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled)) < 0)
        return open_failed(handle, os_errno);
#endif
#ifdef __APPLE__
    if (setsockopt(handle->fd, IPPROTO_IP, IP_BOUND_IF, &index, sizeof(index)) < 0)
        return open_failed(handle, os_errno);
#else
    if (setsockopt(handle->fd, IPPROTO_IP, IP_PKTINFO, &enabled, sizeof(enabled)) < 0)
        return open_failed(handle, os_errno);
#endif
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(NETAT_PORT);
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(handle->fd, (struct sockaddr *)&local, sizeof(local)) < 0)
        return open_failed(handle, os_errno);
    *output = handle;
    return AHNB_OK;
}

void ahnb_close(ahnb_handle *handle) {
    if (!handle) return;
    if (handle->fd >= 0) close(handle->fd);
    secure_zero(handle, sizeof(*handle));
    free(handle);
}

static int ascii_equal_ci(const char *left, const char *right) {
    while (*left && *right) {
        if (tolower((unsigned char)*left) != tolower((unsigned char)*right))
            return 0;
        left++; right++;
    }
    return *left == '\0' && *right == '\0';
}

static int ascii_prefix_ci(const char *text, size_t length, const char *word) {
    size_t word_length = strlen(word);
    if (length < word_length) return 0;
    for (size_t index = 0; index < word_length; index++) {
        if (tolower((unsigned char)text[index]) != tolower((unsigned char)word[index]))
            return 0;
    }
    return 1;
}

static const char *find_ascii_ci(const char *text, const char *needle) {
    size_t length = strlen(needle);
    if (!length) return text;
    for (; *text; text++) {
        if (ascii_prefix_ci(text, strlen(text), needle)) return text;
    }
    return NULL;
}

/* A keyword line is the keyword alone or followed by ':' or a space. */
static int keyword_line(const char *line, size_t length, const char *keyword) {
    size_t keyword_length = strlen(keyword);
    if (!ascii_prefix_ci(line, length, keyword)) return 0;
    if (length == keyword_length) return 1;
    return line[keyword_length] == ':' || line[keyword_length] == ' ';
}

/* Status lines are whole lines; value lines always carry a prefix. */
static int classify_line(const char *line, size_t length) {
    while (length && isspace((unsigned char)line[0])) { line++; length--; }
    while (length && isspace((unsigned char)line[length - 1])) length--;
    if (!length) return LINE_BLANK;
    if (length == 2 && ascii_prefix_ci(line, length, "OK")) return LINE_OK;
    if (keyword_line(line, length, "ERROR")) return LINE_ERROR;
    if (keyword_line(line, length, "UNSUPPORT") ||
        keyword_line(line, length, "UNSUPPORTED") ||
        keyword_line(line, length, "UNKNOWN") ||
        ascii_prefix_ci(line, length, "valid cmds:"))
        return LINE_UNSUPPORTED;
    return LINE_VALUE;
}

static int reply_kind(const char *text) {
    int kind = LINE_BLANK;
    const char *line = text;
    for (;;) {
        size_t length = strcspn(line, "\r\n");
        int line_kind = classify_line(line, length);
        if (line_kind > kind) kind = line_kind;
        if (!line[length]) break;
        line += length + 1;
    }
    return kind;
}

/* Complete lines are classified normally. The unfinished last line ends the
   reply only as an exact "OK"/"ERROR" (the firmware's final "\r\nOK" packet),
   so a fragment such as "    ok" + "_retry:3" never ends a dump early. */
static int reply_terminated(const char *text) {
    const char *line = text;
    for (;;) {
        size_t length = strcspn(line, "\r\n");
        if (!line[length])
            return !strcmp(line, "OK") || !strcmp(line, "ERROR");
        if (classify_line(line, length) >= LINE_OK) return 1;
        line += length + 1;
    }
}

static int reply_is_failure(int kind) {
    return kind == LINE_ERROR || kind == LINE_UNSUPPORTED;
}

static int query_has_single_packet_reply(const char *query) {
    return !strcmp(query, "AT+MAC_ADDR=?") ||
           !strcmp(query, "AT+CONN_STATE") ||
           !strcmp(query, "AT+CCMP_SUPPORT=?");
}

static int reply_from_target(const uint8_t *packet, size_t size,
                             const struct sockaddr_in *source,
                             const struct response_target *target,
                             const uint8_t cookie[6]) {
    if (source->sin_port != htons(NETAT_PORT)) return 0;
    if (source->sin_addr.s_addr != target->address.s_addr) return 0;
    return packet_valid(packet, size, AT_RESPONSE, cookie, target->mac);
}

static int send_request(ahnb_handle *handle, const struct response_target *target,
                        const char *command, const uint8_t cookie[6]) {
    uint8_t packet[HEADER_SIZE + COMMAND_MAX];
    size_t length = strlen(command);
    if (!length || length > COMMAND_MAX) return AHNB_INVALID_ARGUMENT;
    write_header(packet, AT_REQUEST, (uint16_t)length, target->mac, cookie);
    memcpy(packet + HEADER_SIZE, command, length);
    /* NetAT is an L2-selection protocol carried over UDP broadcast: retain the
       proven broadcast transport and select solely with the exact header MAC. */
    struct in_addr limited_broadcast;
    limited_broadcast.s_addr = htonl(INADDR_BROADCAST);
    int status = send_packet(handle, packet, HEADER_SIZE + length, limited_broadcast);
    secure_zero(packet, sizeof(packet));
    return status;
}

/* The single receive loop shared by managed and raw queries. */
static int collect_reply(ahnb_handle *handle, const struct response_target *target,
                         const uint8_t cookie[6], const struct reply_plan *plan,
                         char *output, size_t capacity, size_t *length, int *reason) {
    uint8_t packet[RESPONSE_MAX];
    struct sockaddr_in source;
    size_t used = 0;
    size_t received = 0;
    unsigned matched = 0;
    int status = AHNB_OK;
    uint64_t now = handle_now_ms(handle);
    uint64_t deadline = now + plan->timeout_ms;
    uint64_t last_packet = now;
    output[0] = '\0';
    *reason = ENDED_DEADLINE;
    for (unsigned iteration = 0; iteration < RECEIVE_ITERATIONS_MAX; iteration++) {
        now = handle_now_ms(handle);
        if (now >= deadline) break;
        uint64_t wait = deadline - now;
        if ((plan->flags & END_ON_IDLE) && matched) {
            uint64_t idle_deadline = last_packet + plan->idle_ms;
            if (now >= idle_deadline) { *reason = ENDED_IDLE; break; }
            if (idle_deadline - now < wait) wait = idle_deadline - now;
        }
        if (wait > POLL_SLICE_MAX_MS) wait = POLL_SLICE_MAX_MS;
        memset(&source, 0, sizeof(source));
        int code = receive_packet(handle, packet, sizeof(packet), &received, &source,
                                  (unsigned)wait);
        if (code == RECV_ERROR) { status = AHNB_SYSTEM_ERROR; *reason = ENDED_ERROR; break; }
        if (code != RECV_PACKET) continue;
        if (!reply_from_target(packet, received, &source, target, cookie)) continue;
        matched++;
        last_packet = handle_now_ms(handle);
        size_t payload = received - HEADER_SIZE;
        size_t room = capacity - 1 - used;
        if (payload > room) {
            memcpy(output + used, packet + HEADER_SIZE, room);
            used += room;
            output[used] = '\0';
            status = AHNB_BUFFER_TOO_SMALL;
            *reason = ENDED_OVERFLOW;
            break;
        }
        memcpy(output + used, packet + HEADER_SIZE, payload);
        used += payload;
        output[used] = '\0';
        if (plan->flags & END_ON_FIRST_PACKET) { *reason = ENDED_FIRST_PACKET; break; }
        if ((plan->flags & END_ON_TERMINATOR) && reply_terminated(output)) {
            *reason = ENDED_TERMINATOR;
            break;
        }
    }
    secure_zero(packet, sizeof(packet));
    *length = used;
    return status;
}

static int exchange(ahnb_handle *handle, const struct response_target *target,
                    const char *command, const struct reply_plan *plan,
                    char *output, size_t capacity, size_t *length, int *reason) {
    uint8_t cookie[6];
    output[0] = '\0';
    *length = 0;
    *reason = ENDED_ERROR;
    if (random_cookie(cookie) != AHNB_OK) return AHNB_SYSTEM_ERROR;
    int status = send_request(handle, target, command, cookie);
    if (status != AHNB_OK) return status;
    return collect_reply(handle, target, cookie, plan, output, capacity, length, reason);
}

static void plan_for_query(const char *query, struct reply_plan *plan) {
    plan->flags = END_ON_TERMINATOR;
    plan->timeout_ms = QUERY_TIMEOUT_MS;
    plan->idle_ms = 0;
    if (query_has_single_packet_reply(query)) {
        plan->flags = END_ON_FIRST_PACKET;
        return;
    }
    /* The summary has no terminator: it ends after an idle gap. */
    if (!strcmp(query, SUMMARY_QUERY)) {
        plan->flags = END_ON_TERMINATOR | END_ON_IDLE;
        plan->timeout_ms = SUMMARY_TIMEOUT_MS;
        plan->idle_ms = SUMMARY_IDLE_MS;
    }
}

static int private_query(ahnb_handle *handle, const struct response_target *target,
                         const char *query, char *output, size_t capacity) {
    struct reply_plan plan;
    size_t length = 0;
    int reason = ENDED_ERROR;
    if (!capacity) return AHNB_INVALID_ARGUMENT;
    plan_for_query(query, &plan);
    int status = exchange(handle, target, query, &plan, output, capacity, &length, &reason);
    if (status != AHNB_OK) return status;
    /* An idle-terminated reply that is still streaming at the deadline is kept. */
    if (reason == ENDED_DEADLINE && !((plan.flags & END_ON_IDLE) && length))
        return AHNB_TIMEOUT;
    return AHNB_OK;
}

/* Separator is whichever of ':' or '=' comes first; the value is kept
   verbatim. Prefix-less lines ("+CONNECTED", "aes ccmp enabled") are trimmed. */
static char *trim_spaces(char *text) {
    while (*text && isspace((unsigned char)*text)) text++;
    char *end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) {
        end--;
        *end = '\0';
    }
    return text;
}

static char *value_start(char *line) {
    char *colon = strchr(line, ':');
    char *equals = strchr(line, '=');
    char *separator = colon;
    if (!separator || (equals && equals < separator)) separator = equals;
    if (separator) return separator + 1;
    return trim_spaces(line);
}

static int extract_value(char *response, char *value, size_t size, int allow_empty) {
    if (reply_is_failure(reply_kind(response))) return AHNB_UNSUPPORTED;
    char *line = response;
    for (;;) {
        size_t length = strcspn(line, "\r\n");
        int has_next = line[length] != '\0';
        if (classify_line(line, length) == LINE_VALUE) {
            line[length] = '\0';
            char *start = value_start(line);
            size_t value_length = strlen(start);
            if ((!allow_empty && !value_length) || value_length >= size)
                return AHNB_PROTOCOL_ERROR;
            memcpy(value, start, value_length + 1);
            return AHNB_OK;
        }
        if (!has_next) return AHNB_PROTOCOL_ERROR;
        line += length + 1;
    }
}

static int query_text_common(ahnb_handle *handle, const struct response_target *target,
                             const char *query, char *value, size_t size,
                             int allow_empty) {
    char response[RESPONSE_MAX];
    int status = private_query(handle, target, query, response, sizeof(response));
    if (status == AHNB_OK) status = extract_value(response, value, size, allow_empty);
    secure_zero(response, sizeof(response));
    return status;
}

static int query_text(ahnb_handle *handle, const struct response_target *target,
                      const char *query, char *value, size_t size) {
    return query_text_common(handle, target, query, value, size, 0);
}

static int query_text_allow_empty(ahnb_handle *handle,
                                  const struct response_target *target,
                                  const char *query, char *value, size_t size) {
    return query_text_common(handle, target, query, value, size, 1);
}

static int parse_int_value(const char *text, int *value) {
    char *end = NULL; errno = 0;
    long parsed = strtol(text, &end, 10);
    while (end && isspace((unsigned char)*end)) end++;
    int known_unit = end && (*end == '\0' || ascii_equal_ci(end, "MHz") ||
                             ascii_equal_ci(end, "dbm"));
    if (errno || end == text || !known_unit || parsed < -2147483647L || parsed > 2147483647L)
        return AHNB_PROTOCOL_ERROR;
    *value = (int)parsed; return AHNB_OK;
}

static int summary_char_starts_field(char previous) {
    return isspace((unsigned char)previous) || previous == ',' || previous == ';';
}

/* Finds "field:" or "field=" at a word boundary and parses its number. */
static int summary_int_value(const char *summary, const char *field, int *value) {
    size_t field_length = strlen(field);
    const char *cursor = summary;
    for (;;) {
        const char *location = find_ascii_ci(cursor, field);
        if (!location) return AHNB_NOT_FOUND;
        const char *after = location + field_length;
        int starts = location == summary || summary_char_starts_field(location[-1]);
        if (starts && (*after == ':' || *after == '=')) {
            char number[NUMBER_TEXT_MAX];
            size_t length = strcspn(after + 1, "\r\n,;");
            if (length >= sizeof(number)) return AHNB_PROTOCOL_ERROR;
            memcpy(number, after + 1, length);
            number[length] = '\0';
            return parse_int_value(number, value);
        }
        cursor = location + 1;
    }
}

static int valid_channel_khz(uint64_t khz) {
    return khz >= AHNB_CHANNEL_MIN_KHZ && khz <= AHNB_CHANNEL_MAX_KHZ &&
           khz % CHANNEL_STEP_KHZ == 0;
}

static int is_decimal_digit(char character) {
    return character >= '0' && character <= '9';
}

/* "8635" (100 kHz units), "863.5" (MHz, one decimal) or "863500" (kHz). */
static int parse_channel_token(const char *token, size_t length, uint32_t *khz) {
    uint64_t whole = 0;
    uint64_t value = 0;
    size_t index = 0;
    while (index < length && is_decimal_digit(token[index])) {
        if (index == CHANNEL_DIGITS_MAX) return AHNB_PROTOCOL_ERROR;
        whole = whole * 10u + (uint64_t)(token[index] - '0');
        index++;
    }
    if (!index) return AHNB_PROTOCOL_ERROR;
    if (index == length) {
        value = whole < CHANNEL_UNIT_LIMIT ? whole * CHANNEL_STEP_KHZ : whole;
    } else {
        if (token[index] != '.' || index + 2 != length || !is_decimal_digit(token[index + 1]))
            return AHNB_PROTOCOL_ERROR;
        value = whole * 1000u + (uint64_t)(token[index + 1] - '0') * CHANNEL_STEP_KHZ;
    }
    if (!valid_channel_khz(value)) return AHNB_PROTOCOL_ERROR;
    *khz = (uint32_t)value;
    return AHNB_OK;
}

static int is_channel_separator(char character) {
    return character == ',' || character == ' ' || character == '\t';
}

static int parse_channels(const char *text, uint32_t channels[AHNB_MAX_CHANNELS],
                          uint32_t *count) {
    uint32_t parsed[AHNB_MAX_CHANNELS];
    uint32_t used = 0;
    size_t index = 0;
    if (!text) return AHNB_PROTOCOL_ERROR;
    for (;;) {
        while (is_channel_separator(text[index])) index++;
        if (!text[index]) break;
        size_t start = index;
        while (text[index] && !is_channel_separator(text[index])) index++;
        if (used == AHNB_MAX_CHANNELS) return AHNB_PROTOCOL_ERROR;
        if (parse_channel_token(text + start, index - start, &parsed[used]) != AHNB_OK)
            return AHNB_PROTOCOL_ERROR;
        used++;
    }
    if (!used) return AHNB_PROTOCOL_ERROR;
    memcpy(channels, parsed, used * sizeof(parsed[0]));
    *count = used;
    return AHNB_OK;
}

static int parse_mac_text(const char *text, uint8_t mac[6]) {
    char normalized[64];
    if (!text || strlen(text) >= sizeof(normalized)) return AHNB_PROTOCOL_ERROR;
    copy_text(normalized, sizeof(normalized), text);
    for (char *cursor = normalized; *cursor; cursor++)
        if (*cursor == '-') *cursor = ':';
    unsigned values[6]; char extra;
    if (sscanf(normalized, "%2x:%2x:%2x:%2x:%2x:%2x%c", &values[0], &values[1],
               &values[2], &values[3], &values[4], &values[5], &extra) != 6)
        return AHNB_PROTOCOL_ERROR;
    for (size_t i = 0; i < 6; i++) mac[i] = (uint8_t)values[i];
    return AHNB_OK;
}

/* AES-CCMP must be reported as enabled; nothing here ever sets it. */
static int ccmp_reported_enabled(const char *value) {
    char trimmed[VALUE_MAX];
    copy_text(trimmed, sizeof(trimmed), value);
    char *start = trim_spaces(trimmed);
    if (!strcmp(start, "1")) return 1;
    if (find_ascii_ci(start, "disable") || find_ascii_ci(start, "not ")) return 0;
    return find_ascii_ci(start, "ccmp") != NULL && find_ascii_ci(start, "enable") != NULL;
}

static int valid_psk(const char *psk) {
    if (!psk || strlen(psk) != PSK_HEX_LENGTH) return 0;
    for (size_t i = 0; i < PSK_HEX_LENGTH; i++)
        if (!isxdigit((unsigned char)psk[i])) return 0;
    return 1;
}

static int valid_snapshot_psk(const char *psk) {
    return psk && (!*psk || valid_psk(psk));
}

static int valid_encryption(const char *encryption) {
    if (!encryption || !*encryption || strlen(encryption) >= 32) return 0;
    for (const unsigned char *cursor = (const unsigned char *)encryption; *cursor; cursor++)
        if (!isalnum(*cursor) && *cursor != '-' && *cursor != '_') return 0;
    return 1;
}

static int valid_ssid(const char *ssid) {
    if (!ssid) return 0;
    size_t size = strlen(ssid);
    return size >= 1 && size <= SSID_MAX_LENGTH && !strchr(ssid, '\r') && !strchr(ssid, '\n');
}

static int valid_radio(const ahnb_radio_config *config) {
    if (!config || !config->channel_count || config->channel_count > AHNB_MAX_CHANNELS)
        return 0;
    if (!(config->bandwidth_mhz == 1 || config->bandwidth_mhz == 2 ||
          config->bandwidth_mhz == 4 || config->bandwidth_mhz == 8))
        return 0;
    if (config->tx_power_dbm < TX_POWER_MIN_DBM || config->tx_power_dbm > TX_POWER_MAX_DBM)
        return 0;
    for (uint32_t i = 0; i < config->channel_count; i++)
        if (!valid_channel_khz(config->channels_khz[i])) return 0;
    return 1;
}

static int query_valid_psk(ahnb_handle *handle,
                           const struct response_target *target,
                           char psk[PSK_HEX_LENGTH + 1]) {
    int last_status = AHNB_PROTOCOL_ERROR;
    for (unsigned attempt = 0; attempt < PSK_QUERY_ATTEMPTS; attempt++) {
        secure_zero(psk, PSK_HEX_LENGTH + 1);
        int status = query_text(handle, target, "AT+PSK?", psk, PSK_HEX_LENGTH + 1);
        if (status == AHNB_OK && valid_psk(psk)) return AHNB_OK;
        secure_zero(psk, PSK_HEX_LENGTH + 1);
        last_status = status == AHNB_OK ? AHNB_PROTOCOL_ERROR : status;
        if (last_status != AHNB_TIMEOUT && last_status != AHNB_PROTOCOL_ERROR)
            break;
    }
    return last_status;
}

static int probe_identity(ahnb_handle *handle, const struct response_target *target,
                          ahnb_capabilities *capabilities) {
    char value[VALUE_MAX];
    uint8_t reported_mac[6];
    if (query_text(handle, target, "AT+MODE?", value, sizeof(value)) != AHNB_OK)
        return AHNB_UNSUPPORTED;
    if (capabilities) copy_text(capabilities->role, sizeof(capabilities->role), value);
    if (query_text(handle, target, "AT+MAC_ADDR=?", value, sizeof(value)) != AHNB_OK ||
        parse_mac_text(value, reported_mac) != AHNB_OK || memcmp(reported_mac, target->mac, 6))
        return AHNB_UNSUPPORTED;
    return AHNB_OK;
}

static int probe_credentials(ahnb_handle *handle, const struct response_target *target) {
    char value[VALUE_MAX];
    if (query_text(handle, target, "AT+SSID?", value, sizeof(value)) != AHNB_OK) return 0;
    if (query_text(handle, target, "AT+KEYMGMT?", value, sizeof(value)) != AHNB_OK) return 0;
    if (query_text(handle, target, "AT+CCMP_SUPPORT=?", value, sizeof(value)) != AHNB_OK)
        return 0;
    return 1;
}

static int read_radio_target(ahnb_handle *handle, const struct response_target *target,
                             ahnb_managed_config *config) {
    char value[VALUE_MAX];
    int number = 0;
    int status = query_text(handle, target, "AT+CHAN_LIST?", value, sizeof(value));
    if (status != AHNB_OK) return status;
    status = parse_channels(value, config->channels_khz, &config->channel_count);
    if (status != AHNB_OK) return status;
    config->present_mask |= AHNB_FIELD_CHANNELS;
    status = query_text(handle, target, "AT+BSS_BW?", value, sizeof(value));
    if (status != AHNB_OK) return status;
    status = parse_int_value(value, &number);
    if (status != AHNB_OK) return status;
    config->bandwidth_mhz = (uint32_t)number;
    config->present_mask |= AHNB_FIELD_BANDWIDTH;
    status = query_text(handle, target, "AT+TXPOWER?", value, sizeof(value));
    if (status != AHNB_OK) return status;
    status = parse_int_value(value, &number);
    if (status != AHNB_OK) return status;
    config->runtime_tx_power_dbm = number;
    return AHNB_OK;
}

static int probe_radio(ahnb_handle *handle, const struct response_target *target) {
    ahnb_managed_config radio;
    memset(&radio, 0, sizeof(radio));
    return read_radio_target(handle, target, &radio) == AHNB_OK;
}

/* The full summary (idle-gap terminated) carries the saved TX power setting. The dump
   also carries the PSK, so only the parsed number leaves this function. */
static int read_summary_tx_power(ahnb_handle *handle, const struct response_target *target,
                                 int *power) {
    char summary[RESPONSE_MAX];
    int status = private_query(handle, target, SUMMARY_QUERY, summary, sizeof(summary));
    if (status == AHNB_OK && reply_is_failure(reply_kind(summary))) status = AHNB_UNSUPPORTED;
    if (status == AHNB_OK) {
        status = summary_int_value(summary, "tx_power", power);
        if (status != AHNB_OK) status = summary_int_value(summary, "TXPOWER", power);
    }
    secure_zero(summary, sizeof(summary));
    return status;
}

/* The probe never reads AT+WNBCFG: that dump carries the PSK. */
static int probe_target(ahnb_handle *handle, const struct response_target *target,
                        ahnb_capabilities *capabilities) {
    memset(capabilities, 0, sizeof(*capabilities));
    char value[VALUE_MAX];
    if (probe_identity(handle, target, capabilities) != AHNB_OK) return AHNB_UNSUPPORTED;
    capabilities->flags |= AHNB_CAP_CORE;
    if (query_text(handle, target, "AT+CONN_STATE", value, sizeof(value)) == AHNB_OK) {
        copy_text(capabilities->connection_state, sizeof(capabilities->connection_state),
                  value);
        capabilities->flags |= AHNB_CAP_CONNECTION_STATE;
    }
    if (probe_credentials(handle, target)) capabilities->flags |= AHNB_CAP_CREDENTIALS;
    if (probe_radio(handle, target)) capabilities->flags |= AHNB_CAP_RADIO;
    return AHNB_OK;
}

int ahnb_probe(ahnb_handle *handle, ahnb_capabilities *capabilities) {
    if (!handle || !capabilities) return AHNB_INVALID_ARGUMENT;
    return probe_target(handle, &handle->target, capabilities);
}

static int read_failure(ahnb_managed_config *config, int status) {
    secure_zero(config->psk, sizeof(config->psk));
    if (status == AHNB_TIMEOUT || status == AHNB_SYSTEM_ERROR) return status;
    return AHNB_UNSUPPORTED;
}

static int read_config_target(ahnb_handle *handle, const struct response_target *target,
                              int include_psk, ahnb_managed_config *config) {
    memset(config, 0, sizeof(*config));
    memcpy(config->mac, target->mac, 6);
    config->stored_tx_power_dbm = -1;
    config->runtime_tx_power_dbm = -1;
    int status = query_text(handle, target, "AT+MODE?", config->role, sizeof(config->role));
    if (status != AHNB_OK) return read_failure(config, status);
    status = query_text(handle, target, "AT+SSID?", config->ssid, sizeof(config->ssid));
    if (status != AHNB_OK) return read_failure(config, status);
    status = query_text(handle, target, "AT+KEYMGMT?", config->encryption,
                        sizeof(config->encryption));
    if (status != AHNB_OK) return read_failure(config, status);
    config->present_mask |= AHNB_FIELD_SSID | AHNB_FIELD_ENCRYPTION;
    if (include_psk) {
        /* A WPA unit must report a full PSK; an empty answer is retried. */
        if (!strcmp(config->encryption, ENCRYPTION_WPA_PSK))
            status = query_valid_psk(handle, target, config->psk);
        else
            status = query_text_allow_empty(handle, target, "AT+PSK?", config->psk,
                                            sizeof(config->psk));
        if (status == AHNB_OK && !valid_snapshot_psk(config->psk)) status = AHNB_PROTOCOL_ERROR;
        if (status != AHNB_OK) return read_failure(config, status);
        config->present_mask |= AHNB_FIELD_PSK;
    }
    if (query_text(handle, target, "AT+CONN_STATE", config->connection_state,
                   sizeof(config->connection_state)) != AHNB_OK)
        config->connection_state[0] = '\0';
    status = read_radio_target(handle, target, config);
    if (status != AHNB_OK) return read_failure(config, status);
    /* AT+TXPOWER= sets the saved value; AT+TXPOWER? reports the live power, which the
       firmware's PA power control can move (one unit runs 1 dB above its setting). */
    int stored_power = 0;
    config->stored_tx_power_dbm = config->runtime_tx_power_dbm;
    if (read_summary_tx_power(handle, target, &stored_power) == AHNB_OK)
        config->stored_tx_power_dbm = stored_power;
    config->present_mask |= AHNB_FIELD_TX_POWER;
    return AHNB_OK;
}

int ahnb_read_managed_config(ahnb_handle *handle, ahnb_managed_config *config) {
    if (!handle || !config) return AHNB_INVALID_ARGUMENT;
    return read_config_target(handle, &handle->target, 1, config);
}

int ahnb_read_status(ahnb_handle *handle, ahnb_managed_config *config) {
    if (!handle || !config) return AHNB_INVALID_ARGUMENT;
    return read_config_target(handle, &handle->target, 0, config);
}

int ahnb_read_psk(ahnb_handle *handle, char psk[65]) {
    if (!handle || !psk) return AHNB_INVALID_ARGUMENT;
    secure_zero(psk, PSK_HEX_LENGTH + 1);
    const struct response_target *target = &handle->target;
    if (probe_identity(handle, target, NULL) != AHNB_OK || !probe_credentials(handle, target))
        return AHNB_UNSUPPORTED;
    return query_valid_psk(handle, target, psk);
}

static int valid_raw_command(const char *command) {
    size_t length = 0;
    if (!command) return 0;
    while (command[length]) {
        unsigned char character = (unsigned char)command[length];
        if (character < 0x20 || character > 0x7e) return 0;
        length++;
        if (length > AHNB_RAW_COMMAND_MAX) return 0;
    }
    return length >= 1;
}

int ahnb_raw_query(ahnb_handle *handle, const char *command, uint32_t timeout_ms,
                   uint32_t idle_ms, char *response, size_t capacity, size_t *length) {
    struct reply_plan plan;
    size_t used = 0;
    int reason = ENDED_ERROR;
    if (length) *length = 0;
    if (!handle || !response || !capacity || !timeout_ms || !valid_raw_command(command))
        return AHNB_INVALID_ARGUMENT;
    plan.flags = END_ON_TERMINATOR;
    plan.timeout_ms = timeout_ms;
    plan.idle_ms = idle_ms;
    if (idle_ms) plan.flags |= END_ON_IDLE;
    int status = exchange(handle, &handle->target, command, &plan, response, capacity,
                          &used, &reason);
    if (length) *length = used;
    if (status != AHNB_OK) return status;
    return used ? AHNB_OK : AHNB_TIMEOUT;
}

static int set_value(ahnb_handle *handle, const struct response_target *target,
                     const char *field, const char *value) {
    char command[COMMAND_MAX + 1];
    char response[RESPONSE_MAX];
    int status = AHNB_INVALID_ARGUMENT;
    int written = snprintf(command, sizeof(command), "AT+%s=%s", field, value);
    if (written >= 0 && (size_t)written < sizeof(command))
        status = private_query(handle, target, command, response, sizeof(response));
    if (status == AHNB_OK) {
        int kind = reply_kind(response);
        if (kind == LINE_ERROR) status = AHNB_PROTOCOL_ERROR;
        if (kind == LINE_UNSUPPORTED) status = AHNB_UNSUPPORTED;
    }
    secure_zero(command, sizeof(command));
    secure_zero(response, sizeof(response));
    return status;
}

static int apply_field_sequence(ahnb_handle *handle, const struct response_target *target,
                                const struct field_write *writes, size_t count,
                                ahnb_operation_result *result) {
    char message[96];
    for (size_t index = 0; index < count; index++) {
        int status = set_value(handle, target, writes[index].field, writes[index].value);
        if (status != AHNB_OK) {
            snprintf(message, sizeof(message), "Device did not acknowledge the %s write.",
                     writes[index].field);
            return result_fail(result, status, STAGE_WRITE, writes[index].mask, message);
        }
        result->applied_mask |= writes[index].mask;
    }
    return AHNB_OK;
}

/* Mutation entry points probe exactly once; internal helpers never re-probe. */
static int probe_for_mutation(ahnb_handle *handle, uint32_t capability,
                              ahnb_operation_result *result) {
    ahnb_capabilities capabilities;
    uint32_t required = AHNB_CAP_CORE | capability;
    int status = probe_target(handle, &handle->target, &capabilities);
    if (status != AHNB_OK || (capabilities.flags & required) != required)
        return result_fail(result, AHNB_UNSUPPORTED, STAGE_PROBE, 0,
                           "Required compatibility probe failed; no settings were written.");
    return AHNB_OK;
}

static int verify_psk(ahnb_handle *handle, const struct response_target *target,
                      const char *psk) {
    char value[VALUE_MAX];
    int status;
    if (psk[0])
        status = query_valid_psk(handle, target, value);
    else
        status = query_text_allow_empty(handle, target, "AT+PSK?", value, sizeof(value));
    /* Hex is case-free: firmware may echo an uppercase key in lowercase. */
    int matches = status == AHNB_OK && ascii_equal_ci(value, psk);
    secure_zero(value, sizeof(value));
    return matches;
}

static int verify_credentials(ahnb_handle *handle, const struct response_target *target,
                              const char *encryption, const char *psk, const char *ssid,
                              ahnb_operation_result *result) {
    char value[VALUE_MAX];
    int status = query_text(handle, target, "AT+SSID?", value, sizeof(value));
    if (status != AHNB_OK || strcmp(value, ssid))
        return result_fail(result, AHNB_VERIFY_FAILED, STAGE_VERIFY, AHNB_FIELD_SSID,
                           "SSID read-back did not match.");
    result->verified_mask |= AHNB_FIELD_SSID;
    if (!verify_psk(handle, target, psk))
        return result_fail(result, AHNB_VERIFY_FAILED, STAGE_VERIFY, AHNB_FIELD_PSK,
                           "Protected PSK read-back did not match.");
    result->verified_mask |= AHNB_FIELD_PSK;
    status = query_text(handle, target, "AT+KEYMGMT?", value, sizeof(value));
    if (status != AHNB_OK || strcmp(value, encryption))
        return result_fail(result, AHNB_VERIFY_FAILED, STAGE_VERIFY, AHNB_FIELD_ENCRYPTION,
                           "Encryption mode read-back did not match.");
    if (!strcmp(encryption, ENCRYPTION_WPA_PSK) && psk[0]) {
        status = query_text(handle, target, "AT+CCMP_SUPPORT=?", value, sizeof(value));
        if (status != AHNB_OK || !ccmp_reported_enabled(value))
            return result_fail(result, AHNB_VERIFY_FAILED, STAGE_VERIFY,
                               AHNB_FIELD_ENCRYPTION,
                               "AES-CCMP was not reported as enabled.");
    }
    result->verified_mask |= AHNB_FIELD_ENCRYPTION;
    result_succeed(result, "Credentials applied and privately verified.");
    return AHNB_OK;
}

/* These firmwares accept credential changes reliably only as the proven
   KEYMGMT -> PSK -> SSID transaction. */
static int write_credentials_unprobed(ahnb_handle *handle,
                                      const struct response_target *target,
                                      const char *encryption, const char *psk,
                                      const char *ssid, ahnb_operation_result *result) {
    struct field_write writes[3] = {
        {"KEYMGMT", encryption, AHNB_FIELD_ENCRYPTION},
        {"PSK", psk, AHNB_FIELD_PSK},
        {"SSID", ssid, AHNB_FIELD_SSID},
    };
    int status = apply_field_sequence(handle, target, writes, 3, result);
    if (status != AHNB_OK) return status;
    return verify_credentials(handle, target, encryption, psk, ssid, result);
}

static int format_channels(const ahnb_radio_config *config, char *output, size_t size) {
    size_t used = 0;
    if (!size) return AHNB_BUFFER_TOO_SMALL;
    output[0] = '\0';
    for (uint32_t i = 0; i < config->channel_count; i++) {
        int count = snprintf(output + used, size - used, "%s%u", i ? "," : "",
                             (unsigned)(config->channels_khz[i] / CHANNEL_STEP_KHZ));
        if (count < 0 || (size_t)count >= size - used) {
            output[0] = '\0';
            return AHNB_BUFFER_TOO_SMALL;
        }
        used += (size_t)count;
    }
    return AHNB_OK;
}

static int prepare_radio_values(const ahnb_radio_config *config, struct radio_values *values) {
    snprintf(values->bandwidth, sizeof(values->bandwidth), "%u",
             (unsigned)config->bandwidth_mhz);
    snprintf(values->power, sizeof(values->power), "%d", (int)config->tx_power_dbm);
    return format_channels(config, values->channels, sizeof(values->channels));
}

static int radio_field_matches(const ahnb_radio_config *expected,
                               const ahnb_managed_config *actual, uint32_t field) {
    if (field == AHNB_FIELD_BANDWIDTH) return expected->bandwidth_mhz == actual->bandwidth_mhz;
    if (field == AHNB_FIELD_TX_POWER)
        return expected->tx_power_dbm == actual->stored_tx_power_dbm;
    if (field == AHNB_FIELD_CHANNELS)
        return expected->channel_count == actual->channel_count &&
               !memcmp(expected->channels_khz, actual->channels_khz,
                       expected->channel_count * sizeof(uint32_t));
    return 0;
}

static int write_radio_unprobed(ahnb_handle *handle, const struct response_target *target,
                                const ahnb_radio_config *config,
                                const struct radio_values *values,
                                ahnb_operation_result *result) {
    struct field_write writes[3] = {
        {"BSS_BW", values->bandwidth, AHNB_FIELD_BANDWIDTH},
        {"CHAN_LIST", values->channels, AHNB_FIELD_CHANNELS},
        {"TXPOWER", values->power, AHNB_FIELD_TX_POWER},
    };
    int status = apply_field_sequence(handle, target, writes, 3, result);
    if (status != AHNB_OK) return status;
    ahnb_managed_config actual;
    memset(&actual, 0, sizeof(actual));
    status = read_radio_target(handle, target, &actual);
    if (status != AHNB_OK)
        return result_fail(result, AHNB_VERIFY_FAILED, STAGE_VERIFY, 0,
                           "Radio read-back failed.");
    /* Verify the saved setting; fall back to the live value only without the dump. */
    int saved_power = 0;
    actual.stored_tx_power_dbm = actual.runtime_tx_power_dbm;
    if (read_summary_tx_power(handle, target, &saved_power) == AHNB_OK)
        actual.stored_tx_power_dbm = saved_power;
    for (size_t index = 0; index < 3; index++) {
        if (!radio_field_matches(config, &actual, writes[index].mask))
            return result_fail(result, AHNB_VERIFY_FAILED, STAGE_VERIFY, writes[index].mask,
                               "Radio read-back did not match.");
        result->verified_mask |= writes[index].mask;
    }
    result_succeed(result, "Radio settings applied and verified.");
    return AHNB_OK;
}

int ahnb_apply_credentials(ahnb_handle *handle, const char *ssid,
                           const char *psk, ahnb_operation_result *result) {
    ahnb_operation_result scratch;
    if (!result) result = &scratch;
    result_init(result);
    if (!handle || !valid_ssid(ssid) || !valid_psk(psk))
        return result_fail(result, AHNB_INVALID_ARGUMENT, STAGE_VALIDATE, 0,
                           "Invalid credential settings.");
    int status = probe_for_mutation(handle, AHNB_CAP_CREDENTIALS, result);
    if (status != AHNB_OK) return status;
    return write_credentials_unprobed(handle, &handle->target, ENCRYPTION_WPA_PSK, psk, ssid,
                                      result);
}

int ahnb_apply_ssid(ahnb_handle *handle, const char *ssid,
                    ahnb_operation_result *result) {
    ahnb_operation_result scratch;
    char previous_psk[PSK_HEX_LENGTH + 1];
    if (!result) result = &scratch;
    result_init(result);
    if (!handle || !valid_ssid(ssid))
        return result_fail(result, AHNB_INVALID_ARGUMENT, STAGE_VALIDATE, AHNB_FIELD_SSID,
                           "Invalid SSID setting.");
    int status = probe_for_mutation(handle, AHNB_CAP_CREDENTIALS, result);
    if (status != AHNB_OK) return status;
    status = query_valid_psk(handle, &handle->target, previous_psk);
    if (status != AHNB_OK) {
        secure_zero(previous_psk, sizeof(previous_psk));
        return result_fail(result, AHNB_UNSUPPORTED, STAGE_PROBE, AHNB_FIELD_PSK,
                           "Protected PSK could not be snapshotted; no settings were written.");
    }
    /* Reapply the protected existing PSK so only the SSID changes. */
    status = write_credentials_unprobed(handle, &handle->target, ENCRYPTION_WPA_PSK,
                                        previous_psk, ssid, result);
    secure_zero(previous_psk, sizeof(previous_psk));
    if (status == AHNB_OK)
        result_succeed(result, "SSID applied through the verified credential transaction; "
                               "protected PSK was preserved.");
    return status;
}

int ahnb_apply_psk(ahnb_handle *handle, const char *psk,
                   ahnb_operation_result *result) {
    ahnb_operation_result scratch;
    char previous_ssid[VALUE_MAX];
    if (!result) result = &scratch;
    result_init(result);
    if (!handle || !valid_psk(psk))
        return result_fail(result, AHNB_INVALID_ARGUMENT, STAGE_VALIDATE, AHNB_FIELD_PSK,
                           "Invalid PSK setting.");
    int status = probe_for_mutation(handle, AHNB_CAP_CREDENTIALS, result);
    if (status != AHNB_OK) return status;
    status = query_text(handle, &handle->target, "AT+SSID?", previous_ssid,
                        sizeof(previous_ssid));
    if (status != AHNB_OK || !valid_ssid(previous_ssid))
        return result_fail(result, AHNB_UNSUPPORTED, STAGE_PROBE, AHNB_FIELD_SSID,
                           "SSID could not be snapshotted; no settings were written.");
    status = write_credentials_unprobed(handle, &handle->target, ENCRYPTION_WPA_PSK, psk,
                                        previous_ssid, result);
    if (status == AHNB_OK)
        result_succeed(result, "Protected PSK applied through the verified credential "
                               "transaction; SSID was preserved.");
    return status;
}

int ahnb_apply_radio(ahnb_handle *handle,
                     const ahnb_radio_config *config, ahnb_operation_result *result) {
    ahnb_operation_result scratch;
    struct radio_values values;
    if (!result) result = &scratch;
    result_init(result);
    if (!handle || !valid_radio(config))
        return result_fail(result, AHNB_INVALID_ARGUMENT, STAGE_VALIDATE, 0,
                           "Invalid radio settings.");
    if (prepare_radio_values(config, &values) != AHNB_OK)
        return result_fail(result, AHNB_INVALID_ARGUMENT, STAGE_VALIDATE, AHNB_FIELD_CHANNELS,
                           "Channel list could not be encoded; no settings were written.");
    int status = probe_for_mutation(handle, AHNB_CAP_RADIO, result);
    if (status != AHNB_OK) return status;
    return write_radio_unprobed(handle, &handle->target, config, &values, result);
}

int ahnb_restore_managed_config(ahnb_handle *handle,
                                const ahnb_managed_config *config,
                                ahnb_operation_result *result) {
    ahnb_operation_result scratch;
    ahnb_radio_config radio;
    struct radio_values values;
    if (!result) result = &scratch;
    result_init(result);
    if (!handle || !config || memcmp(handle->target.mac, config->mac, 6) ||
        config->present_mask != AHNB_FIELD_ALL ||
        !fixed_text_terminated(config->ssid, sizeof(config->ssid)) ||
        !fixed_text_terminated(config->psk, sizeof(config->psk)) ||
        !fixed_text_terminated(config->encryption, sizeof(config->encryption)) ||
        !valid_ssid(config->ssid) || !valid_snapshot_psk(config->psk) ||
        !valid_encryption(config->encryption))
        return result_fail(result, AHNB_INVALID_ARGUMENT, STAGE_VALIDATE, 0,
                           "Snapshot is incomplete or unsafe to restore.");
    memset(&radio, 0, sizeof(radio));
    radio.channel_count = config->channel_count;
    memcpy(radio.channels_khz, config->channels_khz, sizeof(radio.channels_khz));
    radio.bandwidth_mhz = config->bandwidth_mhz;
    /* Restore the saved setting: writing the live value would ratchet it upwards. */
    radio.tx_power_dbm = config->stored_tx_power_dbm;
    if (!valid_radio(&radio) || prepare_radio_values(&radio, &values) != AHNB_OK)
        return result_fail(result, AHNB_INVALID_ARGUMENT, STAGE_VALIDATE, 0,
                           "Snapshot radio settings are invalid.");
    int status = probe_for_mutation(handle, AHNB_CAP_CREDENTIALS | AHNB_CAP_RADIO, result);
    if (status != AHNB_OK) return status;
    status = write_credentials_unprobed(handle, &handle->target, config->encryption,
                                        config->psk, config->ssid, result);
    if (status != AHNB_OK) return status;
    status = write_radio_unprobed(handle, &handle->target, &radio, &values, result);
    if (status != AHNB_OK) return status;
    result_succeed(result, "Snapshot restored and every managed field verified.");
    return AHNB_OK;
}

const char *ahnb_status_string(int status) {
    switch (status) {
    case AHNB_OK: return "success";
    case AHNB_INVALID_ARGUMENT: return "invalid argument";
    case AHNB_SYSTEM_ERROR: return "system error";
    case AHNB_TIMEOUT: return "timeout";
    case AHNB_PROTOCOL_ERROR: return "protocol error";
    case AHNB_NOT_FOUND: return "not found";
    case AHNB_UNSUPPORTED: return "unsupported";
    case AHNB_VERIFY_FAILED: return "verification failed";
    case AHNB_PARTIAL: return "partial operation";
    case AHNB_BUFFER_TOO_SMALL: return "buffer too small";
    default: return "unknown status";
    }
}
