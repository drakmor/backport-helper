#include "hooks.h"

#include <common_dialog.h>
#include <libhttp.h>
#include <libhttp2.h>
#include <libnetctl.h>
#include <net.h>
#include <np/np_auth.h>
#include <np/np_bandwidth_test.h>
#include <np/np_common.h>
#include <np/np_commerce.h>
#include <np/np_entitlement_access.h>
#include <np/np_error.h>
#include <np/np_game_intent.h>
#include <np/np_session_signaling.h>
#include <np/np_webapi2.h>
#include <np_commerce_dialog.h>
#include <signin_dialog.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <system_service.h>
#include <user_service/user_service_api.h>
#include <user_service/user_service_error.h>

#include <atomic>
#include <type_traits>

#ifndef SCE_OK
#define SCE_OK 0
#endif

#ifndef SCE_NP_SESSION_SIGNALING_MAX_CONNECTION_NUM
#define SCE_NP_SESSION_SIGNALING_MAX_CONNECTION_NUM 64
#endif

#ifndef SCE_NP_SESSION_SIGNALING_NETINFO_STUN_STATUS_OK
#define SCE_NP_SESSION_SIGNALING_NETINFO_STUN_STATUS_OK 2
#endif

#ifndef SCE_SYSTEM_SERVICE_ERROR_PARAMETER
#define SCE_SYSTEM_SERVICE_ERROR_PARAMETER -2136932349
#endif

#ifndef SCE_SYSTEM_SERVICE_ERROR_NO_EVENT
#define SCE_SYSTEM_SERVICE_ERROR_NO_EVENT -2136932348
#endif

extern "C" int sceKernelDebugOutText(int channel, const char* text);

namespace {

constexpr const char* kOnlineId = "Happy";
constexpr const char* kFakeEmail = "happy@example.invalid";
constexpr const char* kFakeAccessToken = "HAPPY_ACCESS_TOKEN";
constexpr const char* kFakeRefreshToken = "HAPPY_REFRESH_TOKEN";
constexpr const char* kFakeAuthCode = "HAPPY_AUTH_CODE";
constexpr const char* kFakeAuthorizedAppCode = "HAPPY_APP_CODE";
constexpr const char* kFakeEntitlementTransactionPrefix = "HAPPY";
constexpr char kNpAuthClientId[] = "6f38fd3e-2d7f-41f2-9b03-813355e88e25";
constexpr char kFakeDuid[] =
    "0000000800070000000000000000000000000000000000000000000000000000";
static_assert(sizeof(kFakeDuid) == 65);
constexpr const char* kFakeIdToken =
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
    "eyJ2ZXIiOiIxLjAiLCJpc3MiOiJodHRwczovL2F1dGguYXBpLm5wLmFjLnBsYXlzdGF0aW9uLm5ldC8y"
    "LjAvb2F1dGgvdG9rZW4iLCJlbnZfaXNzX2lkIjoiMjU2IiwiYXVkIjpbIjZmMzhmZDNlLTJkN2YtNDFm"
    "Mi05YjAzLTgxMzM1NWU4OGUyNSJdLCJpYXQiOjE3MDQwNjcyMDAsImV4cCI6NDEwMjQ0NDgwMCwic3Vi"
    "IjoiMSIsImxlZ2FsX2NvdW50cnkiOiJVUyIsImxvY2FsZSI6ImVuLVVTIiwibm9uY2UiOiIiLCJhdF9oYXNo"
    "IjoiIiwiYWdlIjozMCwiZGV2aWNlX3R5cGUiOiJQUzUiLCJvbmxpbmVfaWQiOiJIYXBweSIsImR1aWQiOiIw"
    "MDAwMDAwODAwMDcwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw"
    "IiwiYmlydGhkYXRlIjoiMTk4MC0wMS0wMSIsImVtYWlsIjoiaGFwcHlAZXhhbXBsZS5pbnZhbGlkIn0.";
constexpr SceUserServiceUserId kFakeUserId = 1;
constexpr SceNpAccountId kFakeAccountId = 1;
constexpr int32_t kFakeCallbackId = 1;
constexpr double kFakeBandwidthBps = 1000000.0;
constexpr size_t kMaxWebApiRequestStates = 64;
constexpr size_t kMaxWebApiResponseBody = 2048;
constexpr size_t kMaxAuthRequestStates = SCE_NP_AUTH_MAX_REQUEST_NUM;
constexpr int32_t kAuthPollsBeforeFinish = 0;
constexpr int kSessionSignalingPeerNatStatusInfoCode = 8;
constexpr uintptr_t kGt7EbootBase = 0x400000;
constexpr uintptr_t kGt7AdhocThrowRuntimeAddress = kGt7EbootBase + 0xDAB20;
constexpr uintptr_t kGt7AdhocReporterRuntimeAddress = kGt7EbootBase + 0x1AC54A0;
constexpr uintptr_t kGt7JwtParseRuntimeAddress = kGt7EbootBase + 0xF03DF0;
constexpr uintptr_t kGt7NpAuthTokenWrapperRuntimeAddress = kGt7EbootBase + 0xD95C80;
constexpr uintptr_t kGt7AuthTokenWorkerRuntimeAddress = kGt7EbootBase + 0xD95D60;
constexpr uintptr_t kGt7AuthTokenWorkerEndRuntimeAddress = kGt7EbootBase + 0xD96200;
constexpr uintptr_t kGt7AsyncQueuePushRuntimeAddress = kGt7EbootBase + 0xA76740;
constexpr uint64_t kGt7AdhocStringHeapCapacity = 0x10;

typedef float Gt7AdhocVector __attribute__((vector_size(16)));
using Gt7AdhocThrowFn = int64_t (*)(const char*, const char*, unsigned int, void*, Gt7AdhocVector);
using Gt7AdhocReporterFn = int64_t (*)(const char*, const char*, const char*, Gt7AdhocVector);
using Gt7JwtParseFn = int64_t (*)(void*, const char*, Gt7AdhocVector);
using Gt7NpAuthTokenWrapperFn =
    int64_t (*)(void*, void*, const char*, const char*, const char*, Gt7AdhocVector);
using Gt7AsyncQueuePushFn = int64_t (*)(void*, void*);

std::atomic<int32_t> g_npRequestId{1};
std::atomic<int32_t> g_authRequestId{1};
std::atomic<int32_t> g_webApiLibCtxId{1};
std::atomic<int32_t> g_webApiUserCtxId{1};
std::atomic<int32_t> g_webApiRequestId{1};
std::atomic<int32_t> g_pushHandleId{1};
std::atomic<int32_t> g_pushFilterId{1};
std::atomic<int32_t> g_pushCallbackId{1};
std::atomic<int32_t> g_npCallbackId{1};
std::atomic<int32_t> g_bandwidthContextId{1};
std::atomic<int32_t> g_entitlementRequestId{1};
std::atomic<int32_t> g_sessionSignalingContextId{1};
std::atomic<int32_t> g_sessionSignalingRequestId{1};
std::atomic<int32_t> g_sessionSignalingGroupId{1};
std::atomic<int32_t> g_sessionSignalingConnectionId{1};
std::atomic<int32_t> g_netCtlCallbackId{1};
std::atomic<int32_t> g_netCtlCallbackV6Id{1};
std::atomic<uintptr_t> g_netCtlCallback{0};
std::atomic<void*> g_netCtlCallbackArg{nullptr};
std::atomic<bool> g_netCtlCallbackPending{false};
std::atomic<uintptr_t> g_netCtlCallbackV6{0};
std::atomic<void*> g_netCtlCallbackV6Arg{nullptr};
std::atomic<bool> g_netCtlCallbackV6Pending{false};
std::atomic<size_t> g_webApiPoolSize{0};
std::atomic<bool> g_gameIntentInitialized{false};
std::atomic<SceCommonDialogStatus> g_commerceDialogStatus{SCE_COMMON_DIALOG_STATUS_NONE};
std::atomic<SceSigninDialogStatus> g_signinDialogStatus{SCE_SIGNIN_DIALOG_STATUS_NONE};
std::atomic<void*> g_commerceDialogUserData{nullptr};
std::atomic<int32_t> g_npCheckCallbackLogCount{0};
std::atomic<int32_t> g_userServiceGetEventLogCount{0};
std::atomic<int32_t> g_systemServiceStatusLogCount{0};
std::atomic<int32_t> g_systemServiceReceiveLogCount{0};
std::atomic<bool> g_userServiceLoginEventPending{true};
std::atomic<bool> g_userServiceLoginEventDelivered{false};
std::atomic<uintptr_t> g_npStateCallback{0};
std::atomic<void*> g_npStateCallbackUserData{nullptr};
std::atomic<int32_t> g_npStateCallbackId{0};
std::atomic<bool> g_npStateCallbackPending{false};
std::atomic<bool> g_npStateCallbackDelivered{false};
std::atomic<uintptr_t> g_npReachabilityCallback{0};
std::atomic<void*> g_npReachabilityCallbackUserData{nullptr};
std::atomic<bool> g_npReachabilityCallbackPending{false};
std::atomic<bool> g_npReachabilityCallbackDelivered{false};
std::atomic<uintptr_t> g_npPremiumCallback{0};
std::atomic<void*> g_npPremiumCallbackUserData{nullptr};
std::atomic<bool> g_gt7AdhocDiagnosticsInstallAttempted{false};
Gt7AdhocThrowFn g_originalGt7AdhocThrow = nullptr;
Gt7AdhocReporterFn g_originalGt7AdhocReporter = nullptr;
Gt7JwtParseFn g_originalGt7JwtParse = nullptr;
Gt7NpAuthTokenWrapperFn g_originalGt7NpAuthTokenWrapper = nullptr;
Gt7AsyncQueuePushFn g_originalGt7AsyncQueuePush = nullptr;

struct SceNpAuthGetAuthorizedAppCodeParameter;
struct SceNpCommereDialogParam2;
struct SceNpSessionSignalingCreateContext2Param;

struct SceNetInAddrCompat {
    uint32_t s_addr;
};

struct SceNpSessionSignalingNetInfoSdk10Compat {
    SceNetInAddr localAddr;
    SceNetInAddr mappedAddr;
    int natStatus;
    int stunStatus;
};

struct SceNpSessionSignalingConnectionListCompat {
    uint32_t connId[64];
    size_t connIdNum;
};

struct SceNpCommerceDialogParam2Compat {
    SceCommonDialogBaseParam baseParam;
    int32_t size;
    SceUserServiceUserId userId;
    SceNpCommerceDialogMode mode;
    SceNpServiceLabel serviceLabel;
    int32_t serviceName;
    const char* const* targets;
    uint32_t numTargets;
    int32_t padding;
    uint64_t features;
    void* userData;
    uint8_t reserved[32];
};

struct WebApiRequestState {
    int64_t requestId;
    size_t bodySize;
    size_t readOffset;
    int32_t httpStatus;
    char body[kMaxWebApiResponseBody];
};

enum class AuthRequestKind : uint8_t {
    None,
    AuthorizationCode,
    AuthorizedAppCode,
    IdToken,
};

struct AuthRequestState {
    int32_t requestId;
    AuthRequestKind kind;
    int32_t pollsRemaining;
    int32_t result;
};

WebApiRequestState g_webApiRequests[kMaxWebApiRequestStates] = {};
AuthRequestState g_authRequests[kMaxAuthRequestStates] = {};

void online_klog(const char* fmt, ...) {
    char line[256];
    int offset = snprintf(line, sizeof(line), "[backport-helper][online] ");
    if (offset < 0 || static_cast<size_t>(offset) >= sizeof(line)) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    vsnprintf(line + offset, sizeof(line) - static_cast<size_t>(offset), fmt, args);
    va_end(args);

    const size_t len = strlen(line);
    if (len + 1 < sizeof(line) && (len == 0 || line[len - 1] != '\n')) {
        line[len] = '\n';
        line[len + 1] = '\0';
    }
    (void)sceKernelDebugOutText(0, line);
}

bool should_log_noisy(std::atomic<int32_t>& counter) {
    const int32_t value = counter.fetch_add(1, std::memory_order_relaxed);
    return value < 16 || (value & 0xff) == 0;
}

void queue_user_service_login_event_once() {
    if (!g_userServiceLoginEventDelivered.load(std::memory_order_relaxed)) {
        g_userServiceLoginEventPending.store(true, std::memory_order_relaxed);
    }
}

void queue_np_online_callbacks() {
    if (g_npStateCallback.load(std::memory_order_relaxed) != 0 &&
        !g_npStateCallbackDelivered.load(std::memory_order_relaxed)) {
        g_npStateCallbackPending.store(true, std::memory_order_relaxed);
    }
    if (g_npReachabilityCallback.load(std::memory_order_relaxed) != 0 &&
        !g_npReachabilityCallbackDelivered.load(std::memory_order_relaxed)) {
        g_npReachabilityCallbackPending.store(true, std::memory_order_relaxed);
    }
}

int32_t next_id(std::atomic<int32_t>& counter) {
    return counter.fetch_add(1, std::memory_order_relaxed);
}

const char* auth_request_kind_name(AuthRequestKind kind) {
    switch (kind) {
    case AuthRequestKind::AuthorizationCode:
        return "authorization_code";
    case AuthRequestKind::AuthorizedAppCode:
        return "authorized_app_code";
    case AuthRequestKind::IdToken:
        return "id_token";
    case AuthRequestKind::None:
    default:
        return "none";
    }
}

AuthRequestState* find_auth_request(int32_t requestId) {
    for (size_t i = 0; i < kMaxAuthRequestStates; ++i) {
        if (g_authRequests[i].requestId == requestId) {
            return &g_authRequests[i];
        }
    }
    return nullptr;
}

AuthRequestState* allocate_auth_request(int32_t requestId) {
    AuthRequestState* freeSlot = nullptr;
    for (size_t i = 0; i < kMaxAuthRequestStates; ++i) {
        if (g_authRequests[i].requestId == requestId) {
            freeSlot = &g_authRequests[i];
            break;
        }
        if (!freeSlot && g_authRequests[i].requestId == 0) {
            freeSlot = &g_authRequests[i];
        }
    }
    if (!freeSlot) {
        freeSlot = &g_authRequests[static_cast<size_t>(requestId) % kMaxAuthRequestStates];
    }
    memset(freeSlot, 0, sizeof(*freeSlot));
    freeSlot->requestId = requestId;
    freeSlot->kind = AuthRequestKind::None;
    freeSlot->result = SCE_OK;
    return freeSlot;
}

void clear_auth_request(int32_t requestId) {
    AuthRequestState* state = find_auth_request(requestId);
    if (state) {
        memset(state, 0, sizeof(*state));
    }
}

void mark_auth_request_pending(int32_t requestId, AuthRequestKind kind) {
    AuthRequestState* state = find_auth_request(requestId);
    if (!state) {
        state = allocate_auth_request(requestId);
    }
    state->kind = kind;
    state->pollsRemaining = kAuthPollsBeforeFinish;
    state->result = SCE_OK;
}

template <typename Fn>
Fn original_late(const char* symbol) {
    return reinterpret_cast<Fn>(hookGetOriginalLateDlsymFunction(symbol));
}

uint16_t bswap16(uint16_t value) {
    return static_cast<uint16_t>((value >> 8) | (value << 8));
}

void format_net_in_addr(SceNetInAddr addr, char* dst, size_t dstSize) {
    if (!dst || dstSize == 0) {
        return;
    }
    const uint32_t value = addr.s_addr;
    snprintf(dst,
             dstSize,
             "%u.%u.%u.%u",
             static_cast<unsigned>(value & 0xffu),
             static_cast<unsigned>((value >> 8) & 0xffu),
             static_cast<unsigned>((value >> 16) & 0xffu),
             static_cast<unsigned>((value >> 24) & 0xffu));
}

void describe_net_sockaddr(const SceNetSockaddr* addr, char* dst, size_t dstSize) {
    if (!dst || dstSize == 0) {
        return;
    }
    if (!addr) {
        snprintf(dst, dstSize, "<null>");
        return;
    }
    if (addr->sa_family == SCE_NET_AF_INET && addr->sa_len >= sizeof(SceNetSockaddrIn)) {
        const auto* in = reinterpret_cast<const SceNetSockaddrIn*>(addr);
        char ip[32];
        format_net_in_addr(in->sin_addr, ip, sizeof(ip));
        snprintf(dst, dstSize, "%s:%u", ip, static_cast<unsigned>(bswap16(in->sin_port)));
        return;
    }
    snprintf(dst,
             dstSize,
             "family=%u len=%u",
             static_cast<unsigned>(addr->sa_family),
             static_cast<unsigned>(addr->sa_len));
}

void copy_cstr(char* dst, size_t dstSize, const char* src) {
    if (!dst || dstSize == 0) {
        return;
    }
    if (!src) {
        src = "";
    }
    strncpy(dst, src, dstSize - 1);
    dst[dstSize - 1] = '\0';
}

void copy_printable_cstr(char* dst, size_t dstSize, const char* src) {
    if (!dst || dstSize == 0) {
        return;
    }
    if (!src) {
        copy_cstr(dst, dstSize, "<null>");
        return;
    }

    size_t out = 0;
    while (out + 1 < dstSize && src[out] != '\0') {
        const unsigned char value = static_cast<unsigned char>(src[out]);
        dst[out] = value >= 0x20 && value < 0x7f ? static_cast<char>(value) : '.';
        ++out;
    }
    dst[out] = '\0';
}

const char* safe_cstr(const char* value) {
    return value ? value : "<null>";
}

const char* gt7_adhoc_string_data(const void* stringObj) {
    if (!stringObj) {
        return nullptr;
    }

    const auto* bytes = static_cast<const uint8_t*>(stringObj);
    const uint64_t capacity = *reinterpret_cast<const uint64_t*>(bytes + 0x20);
    if (capacity >= kGt7AdhocStringHeapCapacity) {
        return *reinterpret_cast<const char* const*>(bytes + 0x08);
    }
    return reinterpret_cast<const char*>(bytes + 0x08);
}

void log_long_cstr(const char* label, const char* text) {
    if (!text) {
        online_klog("%s=<null>", label ? label : "text");
        return;
    }

    constexpr size_t kChunkSize = 150;
    constexpr int kMaxChunks = 6;
    for (int chunk = 0; chunk < kMaxChunks && *text; ++chunk) {
        char buf[kChunkSize + 1];
        size_t len = 0;
        while (len < kChunkSize && text[len] != '\0') {
            const unsigned char value = static_cast<unsigned char>(text[len]);
            buf[len] = value >= 0x20 && value < 0x7f ? static_cast<char>(value) : '.';
            ++len;
        }
        buf[len] = '\0';
        online_klog("%s[%d]=%s", label ? label : "text", chunk, buf);
        text += len;
    }
    if (*text) {
        online_klog("%s=truncated", label ? label : "text");
    }
}

int64_t gt7_adhoc_reporter_hook(const char* type, const char* message, const char* trace, Gt7AdhocVector xmm0) {
    (void)xmm0;
    online_klog("GT7 AdhocReporter skipped type=%s", safe_cstr(type));
    log_long_cstr("GT7 AdhocReporter msg", message);
    log_long_cstr("GT7 AdhocReporter trace", trace);
    return 0;
}

int64_t gt7_adhoc_throw_hook(const char* type,
                             const char* sourcePath,
                             unsigned int sourceLine,
                             void* message,
                             Gt7AdhocVector xmm0) {
    char messageBuf[160];
    copy_printable_cstr(messageBuf, sizeof(messageBuf), gt7_adhoc_string_data(message));

    online_klog("GT7 AdhocError type=%s line=%u", safe_cstr(type), sourceLine);
    online_klog("GT7 AdhocError path=%s", safe_cstr(sourcePath));
    online_klog("GT7 AdhocError msg=%s", messageBuf);

    if (g_originalGt7AdhocThrow) {
        return g_originalGt7AdhocThrow(type, sourcePath, sourceLine, message, xmm0);
    }
    return 0;
}

int64_t gt7_jwt_parse_hook(void* parsedObject, const char* token, Gt7AdhocVector xmm0) {
    const int64_t result = g_originalGt7JwtParse
        ? g_originalGt7JwtParse(parsedObject, token, xmm0)
        : 0;

    size_t tokenLength = 0;
    int periodCount = 0;
    if (token) {
        tokenLength = strlen(token);
        for (const char* cursor = token; *cursor; ++cursor) {
            if (*cursor == '.') {
                ++periodCount;
            }
        }
    }

    int envIssuerId = 0;
    int age = 0;
    unsigned int deviceType = 0;
    char onlineId[48] = "<null>";
    char duid[80] = "<null>";
    if (parsedObject) {
        const auto* bytes = static_cast<const uint8_t*>(parsedObject);
        envIssuerId = *reinterpret_cast<const int*>(bytes + 80);
        age = *reinterpret_cast<const int*>(bytes + 360);
        deviceType = bytes[364];
        copy_printable_cstr(onlineId,
                            sizeof(onlineId),
                            gt7_adhoc_string_data(bytes + 368));
        copy_printable_cstr(duid,
                            sizeof(duid),
                            gt7_adhoc_string_data(bytes + 408));
    }

    online_klog("GT7 JWT parsed=%d len=%zu periods=%d env=%d age=%d device=%u",
                result != 0 ? 1 : 0,
                tokenLength,
                periodCount,
                envIssuerId,
                age,
                deviceType);
    online_klog("GT7 JWT onlineId=%s duid=%s", onlineId, duid);
    return result;
}

int64_t gt7_np_auth_token_wrapper_hook(void* outString,
                                       void* paramBlock,
                                       const char* clientId,
                                       const char* clientSecret,
                                       const char* scope,
                                       Gt7AdhocVector xmm0) {
    const int64_t result = g_originalGt7NpAuthTokenWrapper
        ? g_originalGt7NpAuthTokenWrapper(outString,
                                          paramBlock,
                                          clientId,
                                          clientSecret,
                                          scope,
                                          xmm0)
        : 0;

    const char* token = gt7_adhoc_string_data(outString);
    size_t tokenLength = 0;
    int periodCount = 0;
    if (token) {
        tokenLength = strlen(token);
        for (const char* cursor = token; *cursor; ++cursor) {
            if (*cursor == '.') {
                ++periodCount;
            }
        }
    }

    char clientBuf[48];
    char scopeBuf[128];
    copy_printable_cstr(clientBuf, sizeof(clientBuf), clientId);
    copy_printable_cstr(scopeBuf, sizeof(scopeBuf), scope);
    const bool clientMatches = clientId && strcmp(clientId, kNpAuthClientId) == 0;
    int userId = 0;
    if (paramBlock) {
        userId = *reinterpret_cast<const int*>(static_cast<const uint8_t*>(paramBlock) + 4);
    }
    online_klog("GT7 NpAuthTokenWrapper len=%zu periods=%d user=%d client=%s match=%d secret=%s",
                tokenLength,
                periodCount,
                userId,
                clientBuf,
                clientMatches ? 1 : 0,
                clientSecret ? "set" : "<null>");
    online_klog("GT7 NpAuthTokenWrapper scope=%s", scopeBuf);
    log_long_cstr("GT7 NpAuthTokenWrapper token", token);
    return result;
}

int64_t gt7_async_queue_push_hook(void* queue, void* item) {
    const uintptr_t caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    const bool fromAuthTokenWorker = caller >= kGt7AuthTokenWorkerRuntimeAddress &&
                                     caller < kGt7AuthTokenWorkerEndRuntimeAddress;
    int64_t first = 0;
    int64_t second = 0;
    if (fromAuthTokenWorker && item) {
        const auto* values = static_cast<const int64_t*>(item);
        first = values[0];
        second = values[1];
    }

    const int64_t result = g_originalGt7AsyncQueuePush
        ? g_originalGt7AsyncQueuePush(queue, item)
        : 0;

    if (fromAuthTokenWorker) {
        online_klog("GT7 AsyncQueuePush auth-token caller=%p queue=%p item=%p pair=(%p,%p) -> 0x%llx",
                    reinterpret_cast<void*>(caller),
                    queue,
                    item,
                    reinterpret_cast<void*>(first),
                    reinterpret_cast<void*>(second),
                    static_cast<unsigned long long>(result));
    }
    return result;
}

void install_gt7_adhoc_diagnostics_once(void) {
    bool expected = false;
    if (!g_gt7AdhocDiagnosticsInstallAttempted.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }

    void* original = nullptr;
    const int rc = hookInstallAbsolute(reinterpret_cast<void*>(kGt7AdhocThrowRuntimeAddress),
                                       reinterpret_cast<void*>(&gt7_adhoc_throw_hook),
                                       &original);
    g_originalGt7AdhocThrow = reinterpret_cast<Gt7AdhocThrowFn>(original);
    online_klog("GT7 Adhoc diagnostics throw target=%p rc=0x%x original=%p",
                reinterpret_cast<void*>(kGt7AdhocThrowRuntimeAddress),
                static_cast<unsigned int>(rc),
                original);

    original = nullptr;
    const int reporterRc = hookInstallAbsolute(reinterpret_cast<void*>(kGt7AdhocReporterRuntimeAddress),
                                               reinterpret_cast<void*>(&gt7_adhoc_reporter_hook),
                                               &original);
    g_originalGt7AdhocReporter = reinterpret_cast<Gt7AdhocReporterFn>(original);
    online_klog("GT7 Adhoc diagnostics reporter target=%p rc=0x%x original=%p",
                reinterpret_cast<void*>(kGt7AdhocReporterRuntimeAddress),
                static_cast<unsigned int>(reporterRc),
                original);

    original = nullptr;
    const int jwtRc = hookInstallAbsolute(reinterpret_cast<void*>(kGt7JwtParseRuntimeAddress),
                                          reinterpret_cast<void*>(&gt7_jwt_parse_hook),
                                          &original);
    g_originalGt7JwtParse = reinterpret_cast<Gt7JwtParseFn>(original);
    online_klog("GT7 JWT diagnostics target=%p rc=0x%x original=%p",
                reinterpret_cast<void*>(kGt7JwtParseRuntimeAddress),
                static_cast<unsigned int>(jwtRc),
                original);

    original = nullptr;
    const int tokenWrapperRc =
        hookInstallAbsolute(reinterpret_cast<void*>(kGt7NpAuthTokenWrapperRuntimeAddress),
                            reinterpret_cast<void*>(&gt7_np_auth_token_wrapper_hook),
                            &original);
    g_originalGt7NpAuthTokenWrapper = reinterpret_cast<Gt7NpAuthTokenWrapperFn>(original);
    online_klog("GT7 NpAuthTokenWrapper diagnostics target=%p rc=0x%x original=%p",
                reinterpret_cast<void*>(kGt7NpAuthTokenWrapperRuntimeAddress),
                static_cast<unsigned int>(tokenWrapperRc),
                original);

    original = nullptr;
    const int asyncQueueRc =
        hookInstallAbsolute(reinterpret_cast<void*>(kGt7AsyncQueuePushRuntimeAddress),
                            reinterpret_cast<void*>(&gt7_async_queue_push_hook),
                            &original);
    g_originalGt7AsyncQueuePush = reinterpret_cast<Gt7AsyncQueuePushFn>(original);
    online_klog("GT7 AsyncQueue diagnostics target=%p rc=0x%x original=%p",
                reinterpret_cast<void*>(kGt7AsyncQueuePushRuntimeAddress),
                static_cast<unsigned int>(asyncQueueRc),
                original);
}

bool streq(const char* lhs, const char* rhs) {
    return lhs && rhs && strcmp(lhs, rhs) == 0;
}

bool contains(const char* text, const char* needle) {
    return text && needle && strstr(text, needle) != nullptr;
}

bool starts_with(const char* text, const char* prefix) {
    return text && prefix && strncmp(text, prefix, strlen(prefix)) == 0;
}

bool equals_ignore_case(const char* lhs, const char* rhs) {
    if (!lhs || !rhs) {
        return false;
    }
    while (*lhs && *rhs) {
        char a = *lhs++;
        char b = *rhs++;
        if (a >= 'A' && a <= 'Z') {
            a = static_cast<char>(a + ('a' - 'A'));
        }
        if (b >= 'A' && b <= 'Z') {
            b = static_cast<char>(b + ('a' - 'A'));
        }
        if (a != b) {
            return false;
        }
    }
    return *lhs == '\0' && *rhs == '\0';
}

const char* get_webapi_response_header_value(const WebApiRequestState* state, const char* fieldName) {
    if (!fieldName) {
        return nullptr;
    }
    if (equals_ignore_case(fieldName, "Content-Type")) {
        return SCE_NP_WEBAPI2_CONTENT_TYPE_APPLICATION_JSON_UTF8;
    }
    if (equals_ignore_case(fieldName, "Content-Length")) {
        static thread_local char lengthBuf[32];
        snprintf(lengthBuf, sizeof(lengthBuf), "%zu", state ? state->bodySize : 0);
        return lengthBuf;
    }
    return "";
}

bool fill_dynamic_webapi_response_body(WebApiRequestState* state, const char* path) {
    if (!state || !path) {
        return false;
    }
    if (contains(path, "update_psn_token") || contains(path, "/get_token")) {
        snprintf(state->body,
                 sizeof(state->body),
                 "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600,"
                 "\"refresh_token\":\"%s\",\"refresh_token_expires_in\":2592000,"
                 "\"id_token\":\"%s\"}",
                 kFakeAccessToken,
                 kFakeRefreshToken,
                 kFakeIdToken);
        return true;
    }
    if (streq(path, "/login") || streq(path, "/auth") || streq(path, "/prot") ||
        streq(path, "/v2")) {
        snprintf(state->body,
                 sizeof(state->body),
                 "{\"result\":{},\"status\":\"ok\",\"access_token\":\"%s\","
                 "\"online_id\":\"%s\",\"account_id\":\"%llu\",\"email\":\"%s\"}",
                 kFakeAccessToken,
                 kOnlineId,
                 static_cast<unsigned long long>(kFakeAccountId),
                 kFakeEmail);
        return true;
    }
    return false;
}

const char* choose_webapi_response_body(const char* method, const char* apiGroup, const char* path) {
    if (contains(path, "update_psn_token") || contains(path, "/get_token")) {
        return "";
    }
    if (contains(path, "/v5/container")) {
        return "{\"children\":[],\"children_\":[],\"containers\":[],\"containers_\":[],"
               "\"totalItemCount\":0,\"totalItemCount_\":0}";
    }
    if (contains(path, "/get_reward_list")) {
        return "{\"result\":{\"rewards\":[],\"rewards_\":[]},\"result_\":{\"rewards\":[],\"rewards_\":[]},"
               "\"rewards\":[],\"rewards_\":[]}";
    }
    if (contains(path, "/get_reward_item") || contains(path, "/get_reward")) {
        return "{\"result\":{},\"item\":{},\"items\":[]}";
    }
    if (contains(path, "/get_friend") || contains(path, "/get_list_friend") ||
        contains(path, "/get_acted_friends") || contains(path, "/check_friend") ||
        contains(path, "/update_friend")) {
        return "{\"friends\":[],\"users\":[],\"hasFriend\":false,\"totalItemCount\":0}";
    }
    if (contains(path, "/get_sport_profile") || contains(path, "/update_sport_profile")) {
        return "{\"profile\":{},\"sportProfile\":{},\"result\":{}}";
    }
    if (contains(path, "/get_user_profile") || contains(path, "/search_user_profile")) {
        return "{\"profile\":{},\"profiles\":[],\"users\":[],\"totalItemCount\":0}";
    }
    if (contains(path, "/search_session_log")) {
        return "{\"logs\":[],\"sessionLogs\":[],\"session_logs\":[],\"totalItemCount\":0}";
    }
    if (contains(path, "/search_session") || contains(path, "/create_session") ||
        contains(path, "/send_room_log")) {
        return "{\"sessions\":[],\"rooms\":[],\"logs\":[],\"totalItemCount\":0}";
    }
    if (contains(path, "/replays/available_space")) {
        return "{\"availableSpace\":1073741824,\"available_space\":1073741824,"
               "\"totalSize\":0,\"total_size\":0}";
    }
    if (contains(path, "/replay/upload")) {
        return "{\"result\":{},\"status\":\"ok\",\"uploadId\":\"\",\"upload_id\":\"\",\"items\":[]}";
    }
    if (contains(path, "/news_feed")) {
        return "{\"newsFeed\":[],\"news_feed\":[],\"notices\":[],\"items\":[],\"totalItemCount\":0}";
    }
    if (contains(path, "/get_prize_result")) {
        return "{\"result\":{},\"prizeResult\":{},\"prize_result\":{},\"prizes\":[],\"items\":[]}";
    }
    if (contains(path, "/get_upload_url")) {
        return "{\"url\":\"\",\"uploadUrl\":\"\",\"upload_url\":\"\",\"headers\":[]}";
    }
    if (contains(path, "/get_extended_user_info") || contains(path, "/get_user_info")) {
        return "{\"user\":{},\"users\":[],\"profile\":{},\"profiles\":[],\"totalItemCount\":0}";
    }
    if (contains(path, "/get_sport_users") || contains(path, "/search_user") ||
        contains(path, "/get_hot_users") || contains(path, "/get_shared_users") ||
        contains(path, "/get_liked_users") || contains(path, "/get_following") ||
        contains(path, "/get_follower")) {
        return "{\"users\":[],\"profiles\":[],\"totalItemCount\":0}";
    }
    if (contains(path, "/get_blocking") || contains(path, "/update_blocking") ||
        contains(path, "/update_block_list") || contains(path, "/v1/users/me/blocks")) {
        return "{\"blocks\":[],\"blockedUsers\":[],\"users\":[],\"totalItemCount\":0}";
    }
    if (contains(path, "/v2/profanity/filter")) {
        return "{\"result\":{},\"text\":\"\",\"filteredText\":\"\",\"isProfanity\":false}";
    }
    if (contains(path, "/search_place") || contains(path, "/search_ugc") ||
        contains(path, "/search_replay") || contains(path, "/search_net_replay")) {
        return "{\"items\":[],\"places\":[],\"ugcs\":[],\"replays\":[],\"totalItemCount\":0}";
    }
    if (starts_with(path, "/search")) {
        return "{\"items\":[],\"courses\":[],\"cars\":[],\"areas\":[],\"totalItemCount\":0}";
    }
    if (contains(path, "/get_net_replay")) {
        return "{\"result\":{},\"replays\":[],\"items\":[],\"totalItemCount\":0}";
    }
    if (contains(path, "/get_members")) {
        return "{\"members\":[],\"players\":[],\"users\":[],\"totalItemCount\":0}";
    }
    if (contains(path, "/get_my_record") || contains(path, "/get_my_rank") ||
        contains(path, "/get_user_rank_list") ||
        contains(path, "/get_time_trial_result") || contains(path, "/get_entry_status") ||
        contains(path, "/get_league_entry") || contains(path, "/get_registration_info") ||
        contains(path, "/get_sport_race")) {
        return "{\"result\":{},\"records\":[],\"entries\":[],\"rankings\":[],\"totalItemCount\":0}";
    }
    if (contains(path, "/get_mps_config") || contains(path, "/get_mps_instance") ||
        contains(path, "/get_mrtt_instance") || contains(path, "/get_mrtt_instance_list") ||
        contains(path, "/get_calendar_list") || contains(path, "/get_history") ||
        contains(path, "/get_season_list") ||
        contains(path, "/get_selection") || contains(path, "/get_detail") ||
        contains(path, "/get_folder") || contains(path, "/get_place_folders")) {
        return "{\"result\":{},\"items\":[],\"folders\":[],\"configs\":[],\"totalItemCount\":0}";
    }
    if (contains(path, "/get_consumable_list") || contains(path, "/get_list") ||
        contains(path, "/get_id_list") || contains(path, "/get_list_by_ids") ||
        contains(path, "/get_item") || contains(path, "/get_comment_list") ||
        contains(path, "/get_record_count") || contains(path, "/get_save_history")) {
        return "{\"result\":{},\"items\":[],\"comments\":[],\"history\":[],"
               "\"count\":0,\"totalItemCount\":0}";
    }
    if (contains(path, "/race/game_parameter") || contains(path, "/race/settings")) {
        return "{\"result\":{},\"gameParameter\":{},\"game_parameter\":{},\"parameters\":[]}";
    }
    if (contains(path, "/race/") || streq(path, "/race") || contains(path, "/replay") ||
        contains(path, "/replays")) {
        return "{\"result\":{},\"status\":\"ok\",\"items\":[],\"logs\":[]}";
    }
    if (contains(path, "/v1/users/") && contains(path, "/friends")) {
        return "{\"friends\":[],\"totalItemCount\":0}";
    }
    if (contains(path, "/v1/users/") &&
        (contains(path, "basicPresences") || contains(path, "presences"))) {
        return "{\"basicPresences\":[]}";
    }
    if (contains(path, "/v1/users/") && contains(path, "profiles")) {
        return "{\"profiles\":[]}";
    }
    if (contains(path, "/v1/gameSessions") || contains(path, "/v1/playerSessions") ||
        contains(path, "/v1/matches") || contains(path, "/v1/users/")) {
        return "{\"result\":{},\"sessions\":[],\"members\":[],\"players\":[],\"matches\":[],"
               "\"users\":[],\"totalItemCount\":0}";
    }
    if (streq(path, "/login") || streq(path, "/auth") || streq(path, "/prot") ||
        streq(path, "/v2")) {
        return "";
    }
    if (contains(path, "/v3/users/me/communication/restriction/status")) {
        return "{\"restricted\":false,\"isRestricted\":false,\"status\":\"ok\"}";
    }
    if (streq(path, "/logout") || contains(path, "/logout")) {
        return "{\"result\":{},\"status\":\"ok\"}";
    }
    if (starts_with(path, "/create_match") || starts_with(path, "/create_team_match") ||
        contains(path, "/create_session") || contains(path, "/update_") ||
        contains(path, "/send_") || streq(path, "/create") || streq(path, "/update") ||
        streq(path, "/send")) {
        return "{\"result\":{},\"status\":\"ok\",\"items\":[]}";
    }
    if (contains(path, "ranking")) {
        return "{\"rankings\":[],\"friendRankings\":[],\"entries\":[],"
               "\"totalItemCount\":0,\"totalEntryCount\":0}";
    }
    if (!streq(method, SCE_NP_WEBAPI2_HTTP_METHOD_GET)) {
        return "";
    }
    if (contains(path, "publicProfiles") || contains(path, "profiles")) {
        return "{\"profiles\":[]}";
    }
    if (contains(path, "friends")) {
        return "{\"friends\":[],\"totalItemCount\":0}";
    }
    if (contains(path, "basicPresences") || contains(path, "presences")) {
        return "{\"basicPresences\":[]}";
    }
    if (contains(path, "blocks") || contains(path, "blocking")) {
        return "{\"blocks\":[],\"totalItemCount\":0}";
    }
    if (contains(path, "entitlement") || contains(apiGroup, "entitlement")) {
        return "{\"entitlements\":[]}";
    }
    if (contains(path, "communication") || contains(apiGroup, "communication")) {
        return "{\"restricted\":false}";
    }
    if (contains(path, "activities") || contains(apiGroup, "activities")) {
        return "{\"users\":[]}";
    }
    if (contains(path, "leaderboard") || contains(apiGroup, "leaderboard")) {
        return "{\"entries\":[],\"totalEntryCount\":0}";
    }
    if (contains(path, "sessions") || contains(path, "matches") || contains(apiGroup, "session") ||
        contains(apiGroup, "match")) {
        return "{\"sessions\":[],\"matches\":[],\"members\":[],\"players\":[]}";
    }
    return "{}";
}

WebApiRequestState* find_webapi_request(int64_t requestId) {
    for (size_t i = 0; i < kMaxWebApiRequestStates; ++i) {
        if (g_webApiRequests[i].requestId == requestId) {
            return &g_webApiRequests[i];
        }
    }
    return nullptr;
}

WebApiRequestState* allocate_webapi_request(int64_t requestId) {
    WebApiRequestState* freeSlot = nullptr;
    for (size_t i = 0; i < kMaxWebApiRequestStates; ++i) {
        if (g_webApiRequests[i].requestId == requestId) {
            return &g_webApiRequests[i];
        }
        if (!freeSlot && g_webApiRequests[i].requestId == 0) {
            freeSlot = &g_webApiRequests[i];
        }
    }
    if (!freeSlot) {
        freeSlot = &g_webApiRequests[static_cast<size_t>(requestId) % kMaxWebApiRequestStates];
    }
    memset(freeSlot, 0, sizeof(*freeSlot));
    freeSlot->requestId = requestId;
    return freeSlot;
}

void release_webapi_request(int64_t requestId) {
    WebApiRequestState* state = find_webapi_request(requestId);
    if (state) {
        memset(state, 0, sizeof(*state));
    }
}

void fill_peer_address(SceNpPeerAddressA* peerAddr) {
    if (!peerAddr) {
        return;
    }
    memset(peerAddr, 0, sizeof(*peerAddr));
    peerAddr->accountId = kFakeAccountId;
    peerAddr->platform = SCE_NP_PLATFORM_TYPE_PS5;
}

void fill_loopback_addr(SceNetInAddr* addr) {
    if (addr) {
        addr->s_addr = SCE_NET_INADDR_LOOPBACK;
    }
}

void fill_empty_connection_stats(SceNpSessionSignalingConnectionStatistics* stats) {
    if (!stats) {
        return;
    }
    memset(stats, 0, sizeof(*stats));
    stats->maxConnection = SCE_NP_SESSION_SIGNALING_MAX_CONNECTION_NUM;
}

void fill_memory_info(SceNpSessionSignalingMemoryInfo* memInfo) {
    if (memInfo) {
        memset(memInfo, 0, sizeof(*memInfo));
    }
}

int32_t sceCommonDialogInitialize_hook(void) {
    install_gt7_adhoc_diagnostics_once();
    online_klog("sceCommonDialogInitialize -> OK");
    return SCE_OK;
}

bool sceCommonDialogIsUsed_hook(void) {
    const bool isUsed =
        g_commerceDialogStatus.load(std::memory_order_relaxed) == SCE_COMMON_DIALOG_STATUS_RUNNING;
    online_klog("sceCommonDialogIsUsed -> %d", isUsed ? 1 : 0);
    return isUsed;
}

int32_t sceUserServiceInitialize_hook(const SceUserServiceInitializeParams* initParams) {
    (void)initParams;
    install_gt7_adhoc_diagnostics_once();
    queue_user_service_login_event_once();
    queue_np_online_callbacks();
    online_klog("sceUserServiceInitialize -> OK");
    return SCE_OK;
}

int32_t sceUserServiceInitialize2_hook(int threadPriority, SceKernelCpumask cpuAffinityMask) {
    (void)threadPriority;
    (void)cpuAffinityMask;
    install_gt7_adhoc_diagnostics_once();
    queue_user_service_login_event_once();
    queue_np_online_callbacks();
    online_klog("sceUserServiceInitialize2 -> OK");
    return SCE_OK;
}

int32_t sceUserServiceTerminate_hook(void) {
    online_klog("sceUserServiceTerminate -> OK");
    return SCE_OK;
}

int32_t sceUserServiceGetLoginUserIdList_hook(SceUserServiceLoginUserIdList* userIdList) {
    install_gt7_adhoc_diagnostics_once();
    if (!userIdList) {
        online_klog("sceUserServiceGetLoginUserIdList -> invalid_argument");
        return SCE_USER_SERVICE_ERROR_INVALID_ARGUMENT;
    }
    for (int i = 0; i < SCE_USER_SERVICE_MAX_LOGIN_USERS; ++i) {
        userIdList->userId[i] = SCE_USER_SERVICE_USER_ID_INVALID;
    }
    userIdList->userId[0] = kFakeUserId;
    queue_user_service_login_event_once();
    queue_np_online_callbacks();
    online_klog("sceUserServiceGetLoginUserIdList -> [%d] pending=%d delivered=%d",
                kFakeUserId,
                g_userServiceLoginEventPending.load(std::memory_order_relaxed) ? 1 : 0,
                g_userServiceLoginEventDelivered.load(std::memory_order_relaxed) ? 1 : 0);
    return SCE_OK;
}

int32_t sceUserServiceGetEvent_hook(SceUserServiceEvent* event) {
    install_gt7_adhoc_diagnostics_once();
    if (!event) {
        online_klog("sceUserServiceGetEvent -> invalid_argument");
        return SCE_USER_SERVICE_ERROR_INVALID_ARGUMENT;
    }
    memset(event, 0, sizeof(*event));
    if (g_userServiceLoginEventPending.exchange(false, std::memory_order_relaxed)) {
        event->eventType = SCE_USER_SERVICE_EVENT_TYPE_LOGIN;
        event->userId = kFakeUserId;
        g_userServiceLoginEventDelivered.store(true, std::memory_order_relaxed);
        online_klog("sceUserServiceGetEvent -> login user=%d", kFakeUserId);
        return SCE_OK;
    }
    if (should_log_noisy(g_userServiceGetEventLogCount)) {
        online_klog("sceUserServiceGetEvent -> no_event pending=0 delivered=%d",
                    g_userServiceLoginEventDelivered.load(std::memory_order_relaxed) ? 1 : 0);
    }
    return SCE_USER_SERVICE_ERROR_NO_EVENT;
}

int32_t sceUserServiceGetInitialUser_hook(SceUserServiceUserId* userId) {
    install_gt7_adhoc_diagnostics_once();
    if (!userId) {
        online_klog("sceUserServiceGetInitialUser -> invalid_argument");
        return SCE_USER_SERVICE_ERROR_INVALID_ARGUMENT;
    }
    *userId = kFakeUserId;
    online_klog("sceUserServiceGetInitialUser -> %d", kFakeUserId);
    return SCE_OK;
}

int32_t sceUserServiceGetUserName_hook(SceUserServiceUserId userId, char* userName, size_t size) {
    install_gt7_adhoc_diagnostics_once();
    if (!userName || size == 0) {
        online_klog("sceUserServiceGetUserName user=%d size=%zu -> invalid_argument", userId, size);
        return SCE_USER_SERVICE_ERROR_INVALID_ARGUMENT;
    }
    if (size <= strlen(kOnlineId)) {
        online_klog("sceUserServiceGetUserName user=%d size=%zu -> buffer_too_short", userId, size);
        return SCE_USER_SERVICE_ERROR_BUFFER_TOO_SHORT;
    }
    copy_cstr(userName, size, kOnlineId);
    online_klog("sceUserServiceGetUserName user=%d -> %s", userId, kOnlineId);
    return SCE_OK;
}

int32_t sceUserServiceGetUserNumber_hook(SceUserServiceUserId userId, int32_t* number) {
    install_gt7_adhoc_diagnostics_once();
    if (!number) {
        online_klog("sceUserServiceGetUserNumber user=%d -> invalid_argument", userId);
        return SCE_USER_SERVICE_ERROR_INVALID_ARGUMENT;
    }
    *number = 0;
    online_klog("sceUserServiceGetUserNumber user=%d -> 0", userId);
    return SCE_OK;
}

int32_t sceUserServiceGetGamePresets_hook(SceUserServiceUserId userId, SceUserServiceGamePresets* presets) {
    install_gt7_adhoc_diagnostics_once();
    if (!presets) {
        online_klog("sceUserServiceGetGamePresets user=%d -> invalid_argument", userId);
        return SCE_USER_SERVICE_ERROR_INVALID_ARGUMENT;
    }
    sceUserServiceGamePresetsInitialize(presets);
    presets->difficulty = SCE_USER_SERVICE_GAME_PRESETS_DIFFICULTY_DEFAULT;
    presets->priority = SCE_USER_SERVICE_GAME_PRESETS_PRIORITY_PERFORMANCE;
    presets->invertVerticalViewFor1stPersonView = SCE_USER_SERVICE_GAME_PRESETS_INVERT_OFF;
    presets->invertHorizontalViewFor1stPersonView = SCE_USER_SERVICE_GAME_PRESETS_INVERT_OFF;
    presets->invertVerticalViewFor3rdPersonView = SCE_USER_SERVICE_GAME_PRESETS_INVERT_OFF;
    presets->invertHorizontalViewFor3rdPersonView = SCE_USER_SERVICE_GAME_PRESETS_INVERT_OFF;
    presets->displaySubTitles = SCE_USER_SERVICE_GAME_PRESETS_DISPLAY_SUBTITLES_OFF;
    presets->audioLanguage = SCE_USER_SERVICE_GAME_PRESETS_AUDIO_LANGUAGE_SAME_AS_SYSTEM;
    online_klog("sceUserServiceGetGamePresets user=%d -> default", userId);
    return SCE_OK;
}

int32_t sceUserServiceGetAgeLevel_hook(SceUserServiceUserId userId, uint32_t* ageLevel) {
    install_gt7_adhoc_diagnostics_once();
    if (!ageLevel) {
        online_klog("sceUserServiceGetAgeLevel user=%d -> invalid_argument", userId);
        return SCE_USER_SERVICE_ERROR_INVALID_ARGUMENT;
    }
    *ageLevel = SCE_USER_SERVICE_AGE_LEVEL_ANY;
    online_klog("sceUserServiceGetAgeLevel user=%d -> any", userId);
    return SCE_OK;
}

int32_t sceUserServiceGetAccessibilityChatTranscription_hook(SceUserServiceUserId userId, int32_t* value) {
    if (!value) {
        online_klog("sceUserServiceGetAccessibilityChatTranscription user=%d -> invalid_argument", userId);
        return SCE_USER_SERVICE_ERROR_INVALID_ARGUMENT;
    }
    *value = 0;
    online_klog("sceUserServiceGetAccessibilityChatTranscription user=%d -> 0", userId);
    return SCE_OK;
}

int32_t sceUserServiceGetAccessibilityPressAndHoldDelay_hook(SceUserServiceUserId userId, int32_t* value) {
    if (!value) {
        online_klog("sceUserServiceGetAccessibilityPressAndHoldDelay user=%d -> invalid_argument", userId);
        return SCE_USER_SERVICE_ERROR_INVALID_ARGUMENT;
    }
    *value = 0;
    online_klog("sceUserServiceGetAccessibilityPressAndHoldDelay user=%d -> 0", userId);
    return SCE_OK;
}

int32_t sceUserServiceGetAccessibilityTriggerEffect_hook(SceUserServiceUserId userId, int32_t* value) {
    if (!value) {
        online_klog("sceUserServiceGetAccessibilityTriggerEffect user=%d -> invalid_argument", userId);
        return SCE_USER_SERVICE_ERROR_INVALID_ARGUMENT;
    }
    *value = 1;
    online_klog("sceUserServiceGetAccessibilityTriggerEffect user=%d -> 1", userId);
    return SCE_OK;
}

int32_t sceSystemServiceReceiveEvent_hook(SceSystemServiceEvent* event) {
    install_gt7_adhoc_diagnostics_once();
    if (!event) {
        online_klog("sceSystemServiceReceiveEvent -> invalid_argument");
        return SCE_SYSTEM_SERVICE_ERROR_PARAMETER;
    }
    memset(event, 0, sizeof(*event));
    event->eventType = SCE_SYSTEM_SERVICE_EVENT_INVALID;
    if (should_log_noisy(g_systemServiceReceiveLogCount)) {
        online_klog("sceSystemServiceReceiveEvent -> no_event");
    }
    return SCE_SYSTEM_SERVICE_ERROR_NO_EVENT;
}

int32_t sceSystemServiceGetStatus_hook(SceSystemServiceStatus* status) {
    install_gt7_adhoc_diagnostics_once();
    if (!status) {
        online_klog("sceSystemServiceGetStatus -> invalid_argument");
        return SCE_SYSTEM_SERVICE_ERROR_PARAMETER;
    }
    memset(status, 0, sizeof(*status));
    status->eventNum = 0;
    if (should_log_noisy(g_systemServiceStatusLogCount)) {
        online_klog("sceSystemServiceGetStatus -> events=0");
    }
    return SCE_OK;
}

int sceNpSetNpTitleId_hook(const SceNpTitleId* titleId, const SceNpTitleSecret* titleSecret) {
    (void)titleId;
    (void)titleSecret;
    online_klog("sceNpSetNpTitleId -> OK");
    return SCE_OK;
}

int sceNpSetAdditionalScope_hook(const char* scope) {
    online_klog("sceNpSetAdditionalScope scope=%s -> OK", scope ? scope : "<null>");
    return SCE_OK;
}

int sceNpCheckCallback_hook(void) {
    bool dispatched = false;

    const uintptr_t stateCallbackValue = g_npStateCallback.load(std::memory_order_relaxed);
    if (stateCallbackValue != 0 &&
        g_npStateCallbackPending.exchange(false, std::memory_order_relaxed)) {
        auto callback = reinterpret_cast<SceNpStateCallbackA>(stateCallbackValue);
        void* userdata = g_npStateCallbackUserData.load(std::memory_order_relaxed);
        online_klog("sceNpCheckCallback -> state SIGNED_IN user=%d", kFakeUserId);
        g_npStateCallbackDelivered.store(true, std::memory_order_relaxed);
        callback(kFakeUserId, SCE_NP_STATE_SIGNED_IN, userdata);
        dispatched = true;
    }

    const uintptr_t reachabilityCallbackValue =
        g_npReachabilityCallback.load(std::memory_order_relaxed);
    if (reachabilityCallbackValue != 0 &&
        g_npReachabilityCallbackPending.exchange(false, std::memory_order_relaxed)) {
        auto callback = reinterpret_cast<SceNpReachabilityStateCallback>(reachabilityCallbackValue);
        void* userdata = g_npReachabilityCallbackUserData.load(std::memory_order_relaxed);
        online_klog("sceNpCheckCallback -> reachability REACHABLE user=%d", kFakeUserId);
        g_npReachabilityCallbackDelivered.store(true, std::memory_order_relaxed);
        callback(kFakeUserId, SCE_NP_REACHABILITY_STATE_REACHABLE, userdata);
        dispatched = true;
    }

    if (!dispatched && should_log_noisy(g_npCheckCallbackLogCount)) {
        online_klog("sceNpCheckCallback -> OK");
    }
    return SCE_OK;
}

int sceNpGetState_hook(SceUserServiceUserId userId, SceNpState* state) {
    (void)userId;
    if (!state) {
        online_klog("sceNpGetState user=%d -> invalid_argument", userId);
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    *state = SCE_NP_STATE_SIGNED_IN;
    queue_np_online_callbacks();
    online_klog("sceNpGetState user=%d -> SIGNED_IN", userId);
    return SCE_OK;
}

int sceNpRegisterStateCallbackA_hook(SceNpStateCallbackA callback, void* userdata) {
    if (!callback) {
        online_klog("sceNpRegisterStateCallbackA callback=<null> -> invalid_argument");
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    const int id = next_id(g_npCallbackId);
    g_npStateCallback.store(reinterpret_cast<uintptr_t>(callback), std::memory_order_relaxed);
    g_npStateCallbackUserData.store(userdata, std::memory_order_relaxed);
    g_npStateCallbackId.store(id, std::memory_order_relaxed);
    g_npStateCallbackDelivered.store(false, std::memory_order_relaxed);
    g_npStateCallbackPending.store(true, std::memory_order_relaxed);
    online_klog("sceNpRegisterStateCallbackA callback=%p -> id=%d",
                reinterpret_cast<void*>(callback),
                id);
    return id;
}

int sceNpUnregisterStateCallbackA_hook(int callbackId) {
    if (callbackId == g_npStateCallbackId.load(std::memory_order_relaxed)) {
        g_npStateCallback.store(0, std::memory_order_relaxed);
        g_npStateCallbackUserData.store(nullptr, std::memory_order_relaxed);
        g_npStateCallbackId.store(0, std::memory_order_relaxed);
        g_npStateCallbackPending.store(false, std::memory_order_relaxed);
        g_npStateCallbackDelivered.store(false, std::memory_order_relaxed);
    }
    online_klog("sceNpUnregisterStateCallbackA id=%d -> OK", callbackId);
    return SCE_OK;
}

int sceNpGetNpReachabilityState_hook(SceUserServiceUserId userId, SceNpReachabilityState* state) {
    (void)userId;
    if (!state) {
        online_klog("sceNpGetNpReachabilityState user=%d -> invalid_argument", userId);
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    *state = SCE_NP_REACHABILITY_STATE_REACHABLE;
    online_klog("sceNpGetNpReachabilityState user=%d -> REACHABLE", userId);
    return SCE_OK;
}

int sceNpRegisterNpReachabilityStateCallback_hook(SceNpReachabilityStateCallback callback,
                                                  void* userdata) {
    if (!callback) {
        online_klog("sceNpRegisterNpReachabilityStateCallback callback=<null> -> invalid_argument");
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    g_npReachabilityCallback.store(reinterpret_cast<uintptr_t>(callback),
                                   std::memory_order_relaxed);
    g_npReachabilityCallbackUserData.store(userdata, std::memory_order_relaxed);
    g_npReachabilityCallbackDelivered.store(false, std::memory_order_relaxed);
    g_npReachabilityCallbackPending.store(true, std::memory_order_relaxed);
    online_klog("sceNpRegisterNpReachabilityStateCallback callback=%p -> id=%d",
                reinterpret_cast<void*>(callback),
                kFakeCallbackId);
    return kFakeCallbackId;
}

int sceNpUnregisterNpReachabilityStateCallback_hook(void) {
    g_npReachabilityCallback.store(0, std::memory_order_relaxed);
    g_npReachabilityCallbackUserData.store(nullptr, std::memory_order_relaxed);
    g_npReachabilityCallbackPending.store(false, std::memory_order_relaxed);
    g_npReachabilityCallbackDelivered.store(false, std::memory_order_relaxed);
    online_klog("sceNpUnregisterNpReachabilityStateCallback -> OK");
    return SCE_OK;
}

int sceNpHasSignedUp_hook(SceUserServiceUserId userId, bool* hasSignedUp) {
    (void)userId;
    if (!hasSignedUp) {
        online_klog("sceNpHasSignedUp user=%d -> invalid_argument", userId);
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    *hasSignedUp = true;
    online_klog("sceNpHasSignedUp user=%d -> true", userId);
    return SCE_OK;
}

int sceNpGetAccountIdA_hook(SceUserServiceUserId userId, SceNpAccountId* accountId) {
    (void)userId;
    if (!accountId) {
        online_klog("sceNpGetAccountIdA user=%d -> invalid_argument", userId);
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    *accountId = kFakeAccountId;
    online_klog("sceNpGetAccountIdA user=%d -> account=%llu",
                userId,
                static_cast<unsigned long long>(kFakeAccountId));
    return SCE_OK;
}

int sceNpGetUserIdByAccountId_hook(SceNpAccountId accountId, SceUserServiceUserId* userId) {
    if (!userId) {
        online_klog("sceNpGetUserIdByAccountId account=%llu -> invalid_argument",
                    static_cast<unsigned long long>(accountId));
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    *userId = kFakeUserId;
    online_klog("sceNpGetUserIdByAccountId account=%llu -> user=%d",
                static_cast<unsigned long long>(accountId),
                kFakeUserId);
    return SCE_OK;
}

int sceNpGetOnlineId_hook(SceUserServiceUserId userId, SceNpOnlineId* onlineId) {
    (void)userId;
    if (!onlineId) {
        online_klog("sceNpGetOnlineId user=%d -> invalid_argument", userId);
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    memset(onlineId, 0, sizeof(*onlineId));
    copy_cstr(onlineId->data, sizeof(onlineId->data), kOnlineId);
    onlineId->term = '\0';
    online_klog("sceNpGetOnlineId user=%d -> %s", userId, kOnlineId);
    return SCE_OK;
}

int sceNpGetAccountCountryA_hook(SceUserServiceUserId userId, SceNpCountryCode* countryCode) {
    (void)userId;
    if (!countryCode) {
        online_klog("sceNpGetAccountCountryA user=%d -> invalid_argument", userId);
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    memset(countryCode, 0, sizeof(*countryCode));
    countryCode->data[0] = 'U';
    countryCode->data[1] = 'S';
    countryCode->term = '\0';
    online_klog("sceNpGetAccountCountryA user=%d -> US", userId);
    return SCE_OK;
}

int sceNpNotifyPremiumFeature_hook(const SceNpNotifyPremiumFeatureParameter* param) {
    (void)param;
    online_klog("sceNpNotifyPremiumFeature -> OK");
    return SCE_OK;
}

int sceNpRegisterPremiumEventCallback_hook(SceNpPremiumEventCallback callback, void* userdata) {
    if (!callback) {
        online_klog("sceNpRegisterPremiumEventCallback callback=<null> -> invalid_argument");
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    g_npPremiumCallback.store(reinterpret_cast<uintptr_t>(callback), std::memory_order_relaxed);
    g_npPremiumCallbackUserData.store(userdata, std::memory_order_relaxed);
    online_klog("sceNpRegisterPremiumEventCallback callback=%p -> id=%d",
                reinterpret_cast<void*>(callback),
                kFakeCallbackId);
    return kFakeCallbackId;
}

int sceNpUnregisterPremiumEventCallback_hook(void) {
    g_npPremiumCallback.store(0, std::memory_order_relaxed);
    g_npPremiumCallbackUserData.store(nullptr, std::memory_order_relaxed);
    online_klog("sceNpUnregisterPremiumEventCallback -> OK");
    return SCE_OK;
}

int sceNpCreateRequest_hook(void) {
    const int id = next_id(g_npRequestId);
    online_klog("sceNpCreateRequest -> id=%d", id);
    return id;
}

int sceNpCreateAsyncRequest_hook(const SceNpCreateAsyncRequestParameter* param) {
    (void)param;
    const int id = next_id(g_npRequestId);
    online_klog("sceNpCreateAsyncRequest -> id=%d", id);
    return id;
}

int sceNpDeleteRequest_hook(int reqId) {
    online_klog("sceNpDeleteRequest id=%d -> OK", reqId);
    return SCE_OK;
}

int sceNpAbortRequest_hook(int reqId) {
    online_klog("sceNpAbortRequest id=%d -> OK", reqId);
    return SCE_OK;
}

int sceNpSetTimeout_hook(int reqId,
                         int32_t resolveRetry,
                         uint32_t resolveTimeout,
                         uint32_t connTimeout,
                         uint32_t sendTimeout,
                         uint32_t recvTimeout) {
    (void)reqId;
    (void)resolveRetry;
    (void)resolveTimeout;
    (void)connTimeout;
    (void)sendTimeout;
    (void)recvTimeout;
    return SCE_OK;
}

int sceNpWaitAsync_hook(int reqId, int* result) {
    (void)reqId;
    if (!result) {
        online_klog("sceNpWaitAsync id=%d -> invalid_argument", reqId);
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    *result = SCE_OK;
    online_klog("sceNpWaitAsync id=%d -> result=OK", reqId);
    return SCE_OK;
}

int sceNpPollAsync_hook(int reqId, int* result) {
    (void)reqId;
    if (!result) {
        online_klog("sceNpPollAsync id=%d -> invalid_argument", reqId);
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    *result = SCE_OK;
    online_klog("sceNpPollAsync id=%d -> finished result=OK", reqId);
    return SCE_NP_POLL_ASYNC_RET_FINISHED;
}

int sceNpGetAccountLanguage2_hook(int reqId,
                                  SceUserServiceUserId userId,
                                  SceNpLanguageCode2* languageCode2) {
    (void)reqId;
    (void)userId;
    if (!languageCode2) {
        online_klog("sceNpGetAccountLanguage2 req=%d user=%d -> invalid_argument", reqId, userId);
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    memset(languageCode2, 0, sizeof(*languageCode2));
    copy_cstr(languageCode2->code, sizeof(languageCode2->code), "en-US");
    online_klog("sceNpGetAccountLanguage2 req=%d user=%d -> en-US", reqId, userId);
    return SCE_OK;
}

int sceNpGetAccountAge_hook(int reqId, SceUserServiceUserId userId, uint8_t* age) {
    (void)reqId;
    (void)userId;
    if (!age) {
        online_klog("sceNpGetAccountAge req=%d user=%d -> invalid_argument", reqId, userId);
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    *age = 30;
    online_klog("sceNpGetAccountAge req=%d user=%d -> 30", reqId, userId);
    return SCE_OK;
}

int sceNpCheckNpReachability_hook(int reqId, SceUserServiceUserId userId) {
    online_klog("sceNpCheckNpReachability req=%d user=%d -> OK", reqId, userId);
    return SCE_OK;
}

int sceNpCheckPremium_hook(int reqId,
                           const SceNpCheckPremiumParameter* param,
                           SceNpCheckPremiumResult* result) {
    (void)reqId;
    (void)param;
    if (!result) {
        online_klog("sceNpCheckPremium req=%d -> invalid_argument", reqId);
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    memset(result, 0, sizeof(*result));
    result->authorized = true;
    online_klog("sceNpCheckPremium req=%d -> authorized=true", reqId);
    return SCE_OK;
}

int sceNpAuthCreateRequest_hook(void) {
    const int id = next_id(g_authRequestId);
    allocate_auth_request(id);
    online_klog("sceNpAuthCreateRequest -> id=%d", id);
    return id;
}

int sceNpAuthCreateAsyncRequest_hook(const SceNpAuthCreateAsyncRequestParameter* param) {
    (void)param;
    const int id = next_id(g_authRequestId);
    allocate_auth_request(id);
    online_klog("sceNpAuthCreateAsyncRequest -> id=%d", id);
    return id;
}

int sceNpAuthDeleteRequest_hook(int reqId) {
    AuthRequestState* state = find_auth_request(reqId);
    online_klog("sceNpAuthDeleteRequest id=%d kind=%s -> OK",
                reqId,
                state ? auth_request_kind_name(state->kind) : "unknown");
    clear_auth_request(reqId);
    return SCE_OK;
}

int sceNpAuthAbortRequest_hook(int reqId) {
    AuthRequestState* state = find_auth_request(reqId);
    online_klog("sceNpAuthAbortRequest id=%d kind=%s -> OK",
                reqId,
                state ? auth_request_kind_name(state->kind) : "unknown");
    clear_auth_request(reqId);
    return SCE_OK;
}

int sceNpAuthSetTimeout_hook(int reqId,
                             int32_t resolveRetry,
                             uint32_t resolveTimeout,
                             uint32_t connTimeout,
                             uint32_t sendTimeout,
                             uint32_t recvTimeout) {
    (void)reqId;
    (void)resolveRetry;
    (void)resolveTimeout;
    (void)connTimeout;
    (void)sendTimeout;
    (void)recvTimeout;
    return SCE_OK;
}

int sceNpAuthWaitAsync_hook(int reqId, int* result) {
    (void)reqId;
    if (!result) {
        online_klog("sceNpAuthWaitAsync id=%d -> invalid_argument", reqId);
        return SCE_NP_AUTH_ERROR_INVALID_ARGUMENT;
    }
    AuthRequestState* state = find_auth_request(reqId);
    *result = state ? state->result : SCE_OK;
    if (state) {
        state->pollsRemaining = 0;
    }
    online_klog("sceNpAuthWaitAsync id=%d kind=%s -> result=0x%x",
                reqId,
                state ? auth_request_kind_name(state->kind) : "unknown",
                *result);
    return SCE_OK;
}

int sceNpAuthPollAsync_hook(int reqId, int* result) {
    (void)reqId;
    if (!result) {
        online_klog("sceNpAuthPollAsync id=%d -> invalid_argument", reqId);
        return SCE_NP_AUTH_ERROR_INVALID_ARGUMENT;
    }
    AuthRequestState* state = find_auth_request(reqId);
    if (state && state->pollsRemaining > 0) {
        --state->pollsRemaining;
        *result = SCE_OK;
        online_klog("sceNpAuthPollAsync id=%d kind=%s -> running remaining=%d",
                    reqId,
                    auth_request_kind_name(state->kind),
                    state->pollsRemaining);
        return SCE_NP_AUTH_POLL_ASYNC_RET_RUNNING;
    }
    *result = state ? state->result : SCE_OK;
    online_klog("sceNpAuthPollAsync id=%d kind=%s -> finished result=0x%x",
                reqId,
                state ? auth_request_kind_name(state->kind) : "unknown",
                *result);
    return SCE_NP_AUTH_POLL_ASYNC_RET_FINISHED;
}

int sceNpAuthGetAuthorizationCodeV3_hook(int reqId,
                                         const SceNpAuthGetAuthorizationCodeParameterV3* param,
                                         SceNpAuthorizationCode* authCode,
                                         int* issuerId) {
    (void)reqId;
    (void)param;
    if (!authCode || !issuerId) {
        online_klog("sceNpAuthGetAuthorizationCodeV3 req=%d -> invalid_argument", reqId);
        return SCE_NP_AUTH_ERROR_INVALID_ARGUMENT;
    }
    memset(authCode, 0, sizeof(*authCode));
    copy_cstr(authCode->code, sizeof(authCode->code), kFakeAuthCode);
    *issuerId = 0x100;
    mark_auth_request_pending(reqId, AuthRequestKind::AuthorizationCode);
    online_klog("sceNpAuthGetAuthorizationCodeV3 req=%d -> issuer=0x%x", reqId, *issuerId);
    return SCE_OK;
}

int sceNpAuthGetAuthorizedAppCode_hook(int reqId,
                                       const SceNpAuthGetAuthorizedAppCodeParameter* param,
                                       SceNpAuthorizationCode* authCode,
                                       int* issuerId,
                                       bool* consentRequiredError) {
    (void)reqId;
    (void)param;
    if (!authCode || !issuerId || !consentRequiredError) {
        online_klog("sceNpAuthGetAuthorizedAppCode req=%d -> invalid_argument", reqId);
        return SCE_NP_AUTH_ERROR_INVALID_ARGUMENT;
    }
    memset(authCode, 0, sizeof(*authCode));
    copy_cstr(authCode->code, sizeof(authCode->code), kFakeAuthorizedAppCode);
    *issuerId = 0x100;
    *consentRequiredError = false;
    mark_auth_request_pending(reqId, AuthRequestKind::AuthorizedAppCode);
    online_klog("sceNpAuthGetAuthorizedAppCode req=%d -> issuer=0x%x consent=false",
                reqId,
                *issuerId);
    return SCE_OK;
}

int sceNpAuthGetIdTokenV3_hook(int reqId,
                               const SceNpAuthGetIdTokenParameterV3* param,
                               SceNpIdToken* idToken) {
    if (!param || !idToken) {
        online_klog("sceNpAuthGetIdTokenV3 req=%d -> invalid_argument", reqId);
        return SCE_NP_AUTH_ERROR_INVALID_ARGUMENT;
    }
    memset(idToken, 0, sizeof(*idToken));
    copy_cstr(idToken->token, sizeof(idToken->token), kFakeIdToken);
    mark_auth_request_pending(reqId, AuthRequestKind::IdToken);
    online_klog("sceNpAuthGetIdTokenV3 req=%d user=%d client=%s match=%d scope=%s -> fake_unsigned_id_token len=%zu",
                reqId,
                param->userId,
                param->clientId ? param->clientId->id : "<null>",
                param->clientId && streq(param->clientId->id, kNpAuthClientId) ? 1 : 0,
                param->scope ? param->scope : "<null>",
                strlen(idToken->token));
    return SCE_OK;
}

int32_t sceSigninDialogInitialize_hook(void) {
    g_signinDialogStatus.store(SCE_SIGNIN_DIALOG_STATUS_INITIALIZED, std::memory_order_relaxed);
    online_klog("sceSigninDialogInitialize -> INITIALIZED");
    return SCE_OK;
}

int32_t sceSigninDialogTerminate_hook(void) {
    g_signinDialogStatus.store(SCE_SIGNIN_DIALOG_STATUS_NONE, std::memory_order_relaxed);
    online_klog("sceSigninDialogTerminate -> NONE");
    return SCE_OK;
}

int32_t sceSigninDialogOpen_hook(const SceSigninDialogParam* param) {
    if (!param) {
        online_klog("sceSigninDialogOpen param=<null> -> invalid_argument");
        return SCE_SIGNIN_DIALOG_ERROR_PARAM_INVALID;
    }
    g_signinDialogStatus.store(SCE_SIGNIN_DIALOG_STATUS_FINISHED, std::memory_order_relaxed);
    online_klog("sceSigninDialogOpen user=%d -> FINISHED", param->userId);
    return SCE_OK;
}

int32_t sceSigninDialogClose_hook(void) {
    g_signinDialogStatus.store(SCE_SIGNIN_DIALOG_STATUS_FINISHED, std::memory_order_relaxed);
    online_klog("sceSigninDialogClose -> FINISHED");
    return SCE_OK;
}

SceSigninDialogStatus sceSigninDialogUpdateStatus_hook(void) {
    const SceSigninDialogStatus status = g_signinDialogStatus.load(std::memory_order_relaxed);
    online_klog("sceSigninDialogUpdateStatus -> %d", static_cast<int>(status));
    return status;
}

SceSigninDialogStatus sceSigninDialogGetStatus_hook(void) {
    const SceSigninDialogStatus status = g_signinDialogStatus.load(std::memory_order_relaxed);
    online_klog("sceSigninDialogGetStatus -> %d", static_cast<int>(status));
    return status;
}

int32_t sceSigninDialogGetResult_hook(SceSigninDialogResult* result) {
    if (!result) {
        online_klog("sceSigninDialogGetResult result=<null> -> invalid_argument");
        return SCE_SIGNIN_DIALOG_ERROR_PARAM_INVALID;
    }
    memset(result, 0, sizeof(*result));
    result->result = SCE_SIGNIN_DIALOG_RESULT_OK;
    g_signinDialogStatus.store(SCE_SIGNIN_DIALOG_STATUS_FINISHED, std::memory_order_relaxed);
    online_klog("sceSigninDialogGetResult -> OK");
    return SCE_OK;
}
int32_t sceNpCommerceDialogInitialize_hook(void) {
    g_commerceDialogUserData.store(nullptr, std::memory_order_relaxed);
    g_commerceDialogStatus.store(SCE_COMMON_DIALOG_STATUS_INITIALIZED, std::memory_order_relaxed);
    online_klog("sceNpCommerceDialogInitialize -> INITIALIZED");
    return SCE_OK;
}

void sceNpCommerceDialogParamInitialize_hook(SceNpCommerceDialogParam* param) {
    if (!param) {
        online_klog("sceNpCommerceDialogParamInitialize param=<null>");
        return;
    }
    memset(param, 0, sizeof(*param));
    _sceCommonDialogBaseParamInit(&param->baseParam);
    param->size = sizeof(*param);
    online_klog("sceNpCommerceDialogParamInitialize -> size=%zu", sizeof(*param));
}

void sceNpCommerceDialogParamInitialize2_hook(SceNpCommereDialogParam2* param) {
    if (!param) {
        online_klog("sceNpCommerceDialogParamInitialize2 param=<null>");
        return;
    }
    auto* compat = reinterpret_cast<SceNpCommerceDialogParam2Compat*>(param);
    memset(compat, 0, sizeof(*compat));
    _sceCommonDialogBaseParamInit(&compat->baseParam);
    compat->size = sizeof(*compat);
    online_klog("sceNpCommerceDialogParamInitialize2 -> size=%zu", sizeof(*compat));
}

int32_t sceNpCommerceDialogOpen_hook(const SceNpCommerceDialogParam* param) {
    if (!param) {
        online_klog("sceNpCommerceDialogOpen param=<null> -> invalid_argument");
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    g_commerceDialogUserData.store(param->userData, std::memory_order_relaxed);
    g_commerceDialogStatus.store(SCE_COMMON_DIALOG_STATUS_FINISHED, std::memory_order_relaxed);
    online_klog("sceNpCommerceDialogOpen user=%d mode=%d -> FINISHED",
                param->userId,
                static_cast<int>(param->mode));
    return SCE_OK;
}

int32_t sceNpCommerceDialogOpen2_hook(const SceNpCommereDialogParam2* param) {
    if (!param) {
        online_klog("sceNpCommerceDialogOpen2 param=<null> -> invalid_argument");
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    const auto* compat = reinterpret_cast<const SceNpCommerceDialogParam2Compat*>(param);
    g_commerceDialogUserData.store(compat->userData, std::memory_order_relaxed);
    g_commerceDialogStatus.store(SCE_COMMON_DIALOG_STATUS_FINISHED, std::memory_order_relaxed);
    online_klog("sceNpCommerceDialogOpen2 user=%d mode=%d targets=%u -> FINISHED",
                compat->userId,
                static_cast<int>(compat->mode),
                compat->numTargets);
    return SCE_OK;
}

SceCommonDialogStatus sceNpCommerceDialogUpdateStatus_hook(void) {
    const SceCommonDialogStatus status = g_commerceDialogStatus.load(std::memory_order_relaxed);
    online_klog("sceNpCommerceDialogUpdateStatus -> %d", static_cast<int>(status));
    return status;
}

SceCommonDialogStatus sceNpCommerceDialogGetStatus_hook(void) {
    const SceCommonDialogStatus status = g_commerceDialogStatus.load(std::memory_order_relaxed);
    online_klog("sceNpCommerceDialogGetStatus -> %d", static_cast<int>(status));
    return status;
}

int32_t sceNpCommerceDialogGetResult_hook(SceNpCommerceDialogResult* result) {
    if (!result) {
        online_klog("sceNpCommerceDialogGetResult result=<null> -> invalid_argument");
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    memset(result, 0, sizeof(*result));
    result->result = SCE_NP_COMMERCE_DIALOG_RESULT_PURCHASED;
    result->authorized = true;
    result->userData = g_commerceDialogUserData.load(std::memory_order_relaxed);
    online_klog("sceNpCommerceDialogGetResult -> PURCHASED authorized=true");
    return SCE_OK;
}

int32_t sceNpCommerceDialogClose_hook(void) {
    g_commerceDialogStatus.store(SCE_COMMON_DIALOG_STATUS_FINISHED, std::memory_order_relaxed);
    online_klog("sceNpCommerceDialogClose -> FINISHED");
    return SCE_OK;
}

int32_t sceNpCommerceDialogTerminate_hook(void) {
    g_commerceDialogUserData.store(nullptr, std::memory_order_relaxed);
    g_commerceDialogStatus.store(SCE_COMMON_DIALOG_STATUS_NONE, std::memory_order_relaxed);
    online_klog("sceNpCommerceDialogTerminate -> NONE");
    return SCE_OK;
}

int32_t sceNpCommerceShowPsStoreIcon_hook(SceNpCommercePsStoreIconPos pos) {
    online_klog("sceNpCommerceShowPsStoreIcon pos=%d -> OK", static_cast<int>(pos));
    return SCE_OK;
}

int32_t sceNpCommerceHidePsStoreIcon_hook(void) {
    online_klog("sceNpCommerceHidePsStoreIcon -> OK");
    return SCE_OK;
}

int32_t sceNpCommerceSetPsStoreIconLayout_hook(SceNpCommercePsStoreIconLayout layout) {
    online_klog("sceNpCommerceSetPsStoreIconLayout layout=%d -> OK", static_cast<int>(layout));
    return SCE_OK;
}

int32_t sceNpEntitlementAccessGetGameTrialsFlag_hook(uint32_t* gameTrialsFlag) {
    if (!gameTrialsFlag) {
        online_klog("sceNpEntitlementAccessGetGameTrialsFlag -> parameter_error");
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    *gameTrialsFlag = 0;
    online_klog("sceNpEntitlementAccessGetGameTrialsFlag -> 0");
    return SCE_OK;
}

int32_t sceNpEntitlementAccessInitialize_hook(const SceNpEntitlementAccessInitParam* initParam,
                                              SceNpEntitlementAccessBootParam* bootParam) {
    (void)initParam;
    if (bootParam) {
        memset(bootParam, 0, sizeof(*bootParam));
    }
    online_klog("sceNpEntitlementAccessInitialize bootParam=%p -> OK",
                static_cast<void*>(bootParam));
    return SCE_OK;
}

int32_t sceNpEntitlementAccessGetSkuFlag_hook(SceNpEntitlementAccessSkuFlag* skuFlag) {
    if (!skuFlag) {
        online_klog("sceNpEntitlementAccessGetSkuFlag -> parameter_error");
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    *skuFlag = SCE_NP_ENTITLEMENT_ACCESS_SKU_FLAG_FULL;
    online_klog("sceNpEntitlementAccessGetSkuFlag -> FULL");
    return SCE_OK;
}

int32_t sceNpEntitlementAccessGetAddcontEntitlementInfoList_hook(
    SceNpServiceLabel serviceLabel,
    SceNpEntitlementAccessAddcontEntitlementInfo* list,
    uint32_t listNum,
    uint32_t* hitNum) {
    (void)serviceLabel;
    if (!hitNum) {
        online_klog("sceNpEntitlementAccessGetAddcontEntitlementInfoList label=%u -> parameter_error",
                    serviceLabel);
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    if (!list && listNum != 0) {
        online_klog("sceNpEntitlementAccessGetAddcontEntitlementInfoList label=%u listNum=%u -> parameter_error",
                    serviceLabel,
                    listNum);
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    if (list && listNum != 0) {
        memset(list, 0, sizeof(*list) * listNum);
    }
    *hitNum = 0;
    online_klog("sceNpEntitlementAccessGetAddcontEntitlementInfoList label=%u listNum=%u -> hit=0",
                serviceLabel,
                listNum);
    return SCE_OK;
}

int32_t sceNpEntitlementAccessGetAddcontEntitlementInfo_hook(
    SceNpServiceLabel serviceLabel,
    const SceNpUnifiedEntitlementLabel* entitlementLabel,
    SceNpEntitlementAccessAddcontEntitlementInfo* info) {
    (void)serviceLabel;
    if (!entitlementLabel || !info) {
        online_klog("sceNpEntitlementAccessGetAddcontEntitlementInfo label=%u -> parameter_error",
                    serviceLabel);
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    memset(info, 0, sizeof(*info));
    online_klog("sceNpEntitlementAccessGetAddcontEntitlementInfo label=%u -> entitlement_not_found",
                serviceLabel);
    return SCE_NP_ENTITLEMENT_ACCESS_SERVER_ERROR_ENTITLEMENT_NOT_FOUND;
}

int32_t sceNpEntitlementAccessGetEntitlementKey_hook(
    SceNpServiceLabel serviceLabel,
    const SceNpUnifiedEntitlementLabel* entitlementLabel,
    SceNpEntitlementAccessEntitlementKey* key) {
    (void)serviceLabel;
    if (!entitlementLabel || !key) {
        online_klog("sceNpEntitlementAccessGetEntitlementKey label=%u -> parameter_error",
                    serviceLabel);
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    memset(key, 0, sizeof(*key));
    online_klog("sceNpEntitlementAccessGetEntitlementKey label=%u -> entitlement_not_found",
                serviceLabel);
    return SCE_NP_ENTITLEMENT_ACCESS_SERVER_ERROR_ENTITLEMENT_NOT_FOUND;
}

int32_t sceNpEntitlementAccessGenerateTransactionId_hook(
    SceNpEntitlementAccessTransactionId* transactionId) {
    if (!transactionId) {
        online_klog("sceNpEntitlementAccessGenerateTransactionId -> parameter_error");
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    memset(transactionId, 0, sizeof(*transactionId));
    snprintf(transactionId->transactionId,
             sizeof(transactionId->transactionId),
             "%s-%08x",
             kFakeEntitlementTransactionPrefix,
             static_cast<unsigned>(next_id(g_entitlementRequestId)));
    online_klog("sceNpEntitlementAccessGenerateTransactionId -> %s",
                transactionId->transactionId);
    return SCE_OK;
}

int32_t sceNpEntitlementAccessRequestConsumeUnifiedEntitlement_hook(
    SceUserServiceUserId userId,
    SceNpServiceLabel serviceLabel,
    const SceNpUnifiedEntitlementLabel* entitlementLabel,
    const SceNpEntitlementAccessTransactionId* transactionId,
    int32_t useCount,
    int64_t* requestId) {
    (void)userId;
    (void)serviceLabel;
    (void)transactionId;
    (void)useCount;
    if (!entitlementLabel || !requestId) {
        online_klog("sceNpEntitlementAccessRequestConsumeUnifiedEntitlement user=%d label=%u -> parameter_error",
                    userId,
                    serviceLabel);
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    *requestId = next_id(g_entitlementRequestId);
    online_klog("sceNpEntitlementAccessRequestConsumeUnifiedEntitlement user=%d label=%u use=%d -> req=%lld",
                userId,
                serviceLabel,
                useCount,
                static_cast<long long>(*requestId));
    return SCE_OK;
}

int32_t sceNpEntitlementAccessRequestConsumeServiceEntitlement_hook(
    SceUserServiceUserId userId,
    SceNpServiceLabel serviceLabel,
    const SceNpServiceEntitlementLabel* entitlementLabel,
    const SceNpEntitlementAccessTransactionId* transactionId,
    int32_t useCount,
    int64_t* requestId) {
    (void)userId;
    (void)serviceLabel;
    (void)transactionId;
    (void)useCount;
    if (!entitlementLabel || !requestId) {
        online_klog("sceNpEntitlementAccessRequestConsumeServiceEntitlement user=%d label=%u -> parameter_error",
                    userId,
                    serviceLabel);
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    *requestId = next_id(g_entitlementRequestId);
    online_klog("sceNpEntitlementAccessRequestConsumeServiceEntitlement user=%d label=%u use=%d -> req=%lld",
                userId,
                serviceLabel,
                useCount,
                static_cast<long long>(*requestId));
    return SCE_OK;
}

int32_t sceNpEntitlementAccessPollConsumeEntitlement_hook(int64_t requestId,
                                                          int32_t* pResult,
                                                          int32_t* useLimit) {
    if (!pResult || !useLimit) {
        online_klog("sceNpEntitlementAccessPollConsumeEntitlement req=%lld -> parameter_error",
                    static_cast<long long>(requestId));
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    *pResult = SCE_NP_ENTITLEMENT_ACCESS_SERVER_ERROR_ENTITLEMENT_NOT_FOUND;
    *useLimit = 0;
    online_klog("sceNpEntitlementAccessPollConsumeEntitlement req=%lld -> entitlement_not_found",
                static_cast<long long>(requestId));
    return SCE_NP_ENTITLEMENT_ACCESS_POLL_RET_FINISHED;
}

int32_t sceNpEntitlementAccessRequestUnifiedEntitlementInfo_hook(
    SceUserServiceUserId userId,
    SceNpServiceLabel serviceLabel,
    const SceNpUnifiedEntitlementLabel* entitlementLabel,
    int64_t* requestId) {
    (void)userId;
    (void)serviceLabel;
    if (!entitlementLabel || !requestId) {
        online_klog("sceNpEntitlementAccessRequestUnifiedEntitlementInfo user=%d label=%u -> parameter_error",
                    userId,
                    serviceLabel);
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    *requestId = next_id(g_entitlementRequestId);
    online_klog("sceNpEntitlementAccessRequestUnifiedEntitlementInfo user=%d label=%u -> req=%lld",
                userId,
                serviceLabel,
                static_cast<long long>(*requestId));
    return SCE_OK;
}

int32_t sceNpEntitlementAccessPollUnifiedEntitlementInfo_hook(
    int64_t requestId,
    int32_t* pResult,
    SceNpEntitlementAccessUnifiedEntitlementInfo* info) {
    if (!pResult || !info) {
        online_klog("sceNpEntitlementAccessPollUnifiedEntitlementInfo req=%lld -> parameter_error",
                    static_cast<long long>(requestId));
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    memset(info, 0, sizeof(*info));
    *pResult = SCE_NP_ENTITLEMENT_ACCESS_SERVER_ERROR_ENTITLEMENT_NOT_FOUND;
    online_klog("sceNpEntitlementAccessPollUnifiedEntitlementInfo req=%lld -> entitlement_not_found",
                static_cast<long long>(requestId));
    return SCE_NP_ENTITLEMENT_ACCESS_POLL_RET_FINISHED;
}

int32_t sceNpEntitlementAccessRequestUnifiedEntitlementInfoList_hook(
    SceUserServiceUserId userId,
    SceNpServiceLabel serviceLabel,
    const SceNpUnifiedEntitlementLabel* list,
    uint32_t listNum,
    const SceNpEntitlementAccessRequestEntitlementInfoListParam* param,
    int64_t* requestId) {
    (void)userId;
    (void)serviceLabel;
    (void)param;
    if (!requestId || (!list && listNum != 0)) {
        online_klog("sceNpEntitlementAccessRequestUnifiedEntitlementInfoList user=%d label=%u listNum=%u -> parameter_error",
                    userId,
                    serviceLabel,
                    listNum);
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    *requestId = next_id(g_entitlementRequestId);
    online_klog("sceNpEntitlementAccessRequestUnifiedEntitlementInfoList user=%d label=%u listNum=%u -> req=%lld",
                userId,
                serviceLabel,
                listNum,
                static_cast<long long>(*requestId));
    return SCE_OK;
}

int32_t sceNpEntitlementAccessPollUnifiedEntitlementInfoList_hook(
    int64_t requestId,
    int32_t* pResult,
    SceNpEntitlementAccessUnifiedEntitlementInfo* list,
    uint32_t listNum,
    uint32_t* hitNum,
    int32_t* nextOffset,
    int32_t* previousOffset) {
    if (!pResult || !hitNum || !nextOffset || !previousOffset || (!list && listNum != 0)) {
        online_klog("sceNpEntitlementAccessPollUnifiedEntitlementInfoList req=%lld listNum=%u -> parameter_error",
                    static_cast<long long>(requestId),
                    listNum);
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    if (list && listNum != 0) {
        memset(list, 0, sizeof(*list) * listNum);
    }
    *pResult = SCE_OK;
    *hitNum = 0;
    *nextOffset = SCE_NP_ENTITLEMENT_ACCESS_INVALID_OFFSET;
    *previousOffset = SCE_NP_ENTITLEMENT_ACCESS_INVALID_OFFSET;
    online_klog("sceNpEntitlementAccessPollUnifiedEntitlementInfoList req=%lld listNum=%u -> hit=0",
                static_cast<long long>(requestId),
                listNum);
    return SCE_NP_ENTITLEMENT_ACCESS_POLL_RET_FINISHED;
}

int32_t sceNpEntitlementAccessRequestServiceEntitlementInfo_hook(
    SceUserServiceUserId userId,
    SceNpServiceLabel serviceLabel,
    const SceNpServiceEntitlementLabel* entitlementLabel,
    int64_t* requestId) {
    (void)userId;
    (void)serviceLabel;
    if (!entitlementLabel || !requestId) {
        online_klog("sceNpEntitlementAccessRequestServiceEntitlementInfo user=%d label=%u -> parameter_error",
                    userId,
                    serviceLabel);
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    *requestId = next_id(g_entitlementRequestId);
    online_klog("sceNpEntitlementAccessRequestServiceEntitlementInfo user=%d label=%u -> req=%lld",
                userId,
                serviceLabel,
                static_cast<long long>(*requestId));
    return SCE_OK;
}

int32_t sceNpEntitlementAccessPollServiceEntitlementInfo_hook(
    int64_t requestId,
    int32_t* pResult,
    SceNpEntitlementAccessServiceEntitlementInfo* info) {
    if (!pResult || !info) {
        online_klog("sceNpEntitlementAccessPollServiceEntitlementInfo req=%lld -> parameter_error",
                    static_cast<long long>(requestId));
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    memset(info, 0, sizeof(*info));
    *pResult = SCE_NP_ENTITLEMENT_ACCESS_SERVER_ERROR_ENTITLEMENT_NOT_FOUND;
    online_klog("sceNpEntitlementAccessPollServiceEntitlementInfo req=%lld -> entitlement_not_found",
                static_cast<long long>(requestId));
    return SCE_NP_ENTITLEMENT_ACCESS_POLL_RET_FINISHED;
}

int32_t sceNpEntitlementAccessRequestServiceEntitlementInfoList_hook(
    SceUserServiceUserId userId,
    SceNpServiceLabel serviceLabel,
    const SceNpServiceEntitlementLabel* list,
    uint32_t listNum,
    const SceNpEntitlementAccessRequestEntitlementInfoListParam* param,
    int64_t* requestId) {
    (void)userId;
    (void)serviceLabel;
    (void)param;
    if (!requestId || (!list && listNum != 0)) {
        online_klog("sceNpEntitlementAccessRequestServiceEntitlementInfoList user=%d label=%u listNum=%u -> parameter_error",
                    userId,
                    serviceLabel,
                    listNum);
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    *requestId = next_id(g_entitlementRequestId);
    online_klog("sceNpEntitlementAccessRequestServiceEntitlementInfoList user=%d label=%u listNum=%u -> req=%lld",
                userId,
                serviceLabel,
                listNum,
                static_cast<long long>(*requestId));
    return SCE_OK;
}

int32_t sceNpEntitlementAccessPollServiceEntitlementInfoList_hook(
    int64_t requestId,
    int32_t* pResult,
    SceNpEntitlementAccessServiceEntitlementInfo* list,
    uint32_t listNum,
    uint32_t* hitNum,
    int32_t* nextOffset,
    int32_t* previousOffset) {
    if (!pResult || !hitNum || !nextOffset || !previousOffset || (!list && listNum != 0)) {
        online_klog("sceNpEntitlementAccessPollServiceEntitlementInfoList req=%lld listNum=%u -> parameter_error",
                    static_cast<long long>(requestId),
                    listNum);
        return SCE_NP_ENTITLEMENT_ACCESS_ERROR_PARAMETER;
    }
    if (list && listNum != 0) {
        memset(list, 0, sizeof(*list) * listNum);
    }
    *pResult = SCE_OK;
    *hitNum = 0;
    *nextOffset = SCE_NP_ENTITLEMENT_ACCESS_INVALID_OFFSET;
    *previousOffset = SCE_NP_ENTITLEMENT_ACCESS_INVALID_OFFSET;
    online_klog("sceNpEntitlementAccessPollServiceEntitlementInfoList req=%lld listNum=%u -> hit=0",
                static_cast<long long>(requestId),
                listNum);
    return SCE_NP_ENTITLEMENT_ACCESS_POLL_RET_FINISHED;
}

int32_t sceNpEntitlementAccessDeleteRequest_hook(int64_t requestId) {
    online_klog("sceNpEntitlementAccessDeleteRequest req=%lld -> OK",
                static_cast<long long>(requestId));
    return SCE_OK;
}

int32_t sceNpEntitlementAccessAbortRequest_hook(int64_t requestId) {
    online_klog("sceNpEntitlementAccessAbortRequest req=%lld -> OK",
                static_cast<long long>(requestId));
    return SCE_OK;
}

int32_t sceNpGameIntentInitialize_hook(const SceNpGameIntentInitParam* initParam) {
    if (!initParam || initParam->size != sizeof(SceNpGameIntentInitParam)) {
        online_klog("sceNpGameIntentInitialize size=%zu -> invalid_argument",
                    initParam ? initParam->size : 0);
        return SCE_NP_GAME_INTENT_ERROR_INVALID_ARGUMENT;
    }
    bool expected = false;
    if (!g_gameIntentInitialized.compare_exchange_strong(expected, true, std::memory_order_relaxed)) {
        online_klog("sceNpGameIntentInitialize -> already_initialized");
        return SCE_NP_GAME_INTENT_ERROR_ALREADY_INITIALIZED;
    }
    online_klog("sceNpGameIntentInitialize size=%zu -> OK", initParam->size);
    return SCE_OK;
}

int32_t sceNpGameIntentTerminate_hook(void) {
    if (!g_gameIntentInitialized.exchange(false, std::memory_order_relaxed)) {
        online_klog("sceNpGameIntentTerminate -> not_initialized");
        return SCE_NP_GAME_INTENT_ERROR_NOT_INITIALIZED;
    }
    online_klog("sceNpGameIntentTerminate -> OK");
    return SCE_OK;
}

int32_t sceNpGameIntentReceiveIntent_hook(SceNpGameIntentInfo* intentInfo) {
    if (!intentInfo) {
        online_klog("sceNpGameIntentReceiveIntent -> invalid_argument");
        return SCE_NP_GAME_INTENT_ERROR_INVALID_ARGUMENT;
    }
    if (!g_gameIntentInitialized.load(std::memory_order_relaxed)) {
        online_klog("sceNpGameIntentReceiveIntent -> not_initialized");
        return SCE_NP_GAME_INTENT_ERROR_NOT_INITIALIZED;
    }
    memset(intentInfo, 0, sizeof(*intentInfo));
    intentInfo->size = sizeof(*intentInfo);
    intentInfo->userId = SCE_USER_SERVICE_USER_ID_INVALID;
    online_klog("sceNpGameIntentReceiveIntent -> intent_not_found");
    return SCE_NP_GAME_INTENT_ERROR_INTENT_NOT_FOUND;
}

int32_t sceNpGameIntentGetPropertyValueString_hook(const SceNpGameIntentData* intentData,
                                                   const char* key,
                                                   char* valueBuf,
                                                   size_t bufSize) {
    (void)intentData;
    if (!key || !valueBuf || bufSize == 0) {
        online_klog("sceNpGameIntentGetPropertyValueString key=%s -> invalid_argument",
                    key ? key : "<null>");
        return SCE_NP_GAME_INTENT_ERROR_INVALID_ARGUMENT;
    }
    if (!g_gameIntentInitialized.load(std::memory_order_relaxed)) {
        valueBuf[0] = '\0';
        online_klog("sceNpGameIntentGetPropertyValueString key=%s -> not_initialized", key);
        return SCE_NP_GAME_INTENT_ERROR_NOT_INITIALIZED;
    }
    valueBuf[0] = '\0';
    online_klog("sceNpGameIntentGetPropertyValueString key=%s -> value_not_found", key);
    return SCE_NP_GAME_INTENT_ERROR_VALUE_NOT_FOUND;
}

int sceNpBandwidthTestInitStartUpload_hook(const SceNpBandwidthTestInitParam* param,
                                           uint32_t timeOutInUsec) {
    (void)param;
    const int id = next_id(g_bandwidthContextId);
    online_klog("sceNpBandwidthTestInitStartUpload timeout=%u -> ctx=%d", timeOutInUsec, id);
    return id;
}

int sceNpBandwidthTestInitStartDownload_hook(const SceNpBandwidthTestInitParam* param,
                                             uint32_t timeOutInUsec) {
    (void)param;
    const int id = next_id(g_bandwidthContextId);
    online_klog("sceNpBandwidthTestInitStartDownload timeout=%u -> ctx=%d", timeOutInUsec, id);
    return id;
}

int sceNpBandwidthTestGetStatus_hook(int contextId, int* status) {
    if (!status) {
        online_klog("sceNpBandwidthTestGetStatus ctx=%d -> invalid_argument", contextId);
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    *status = SCE_NP_BANDWIDTH_TEST_STATUS_FINISHED;
    online_klog("sceNpBandwidthTestGetStatus ctx=%d -> FINISHED", contextId);
    return SCE_OK;
}

int sceNpBandwidthTestShutdown_hook(int contextId, SceNpBandwidthTestResult* result) {
    if (!result) {
        online_klog("sceNpBandwidthTestShutdown ctx=%d -> invalid_argument", contextId);
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    memset(result, 0, sizeof(*result));
    result->uploadBps = kFakeBandwidthBps;
    result->downloadBps = kFakeBandwidthBps;
    result->result = SCE_OK;
    online_klog("sceNpBandwidthTestShutdown ctx=%d -> upload=%.0f download=%.0f",
                contextId,
                kFakeBandwidthBps,
                kFakeBandwidthBps);
    return SCE_OK;
}

int sceNpBandwidthTestAbort_hook(int contextId) {
    online_klog("sceNpBandwidthTestAbort ctx=%d -> OK", contextId);
    return SCE_OK;
}

int sceNpSessionSignalingInitialize_hook(const SceNpSessionSignalingInitParam* param) {
    (void)param;
    online_klog("sceNpSessionSignalingInitialize -> OK");
    return SCE_OK;
}

int sceNpSessionSignalingTerminate_hook(void) {
    online_klog("sceNpSessionSignalingTerminate -> OK");
    return SCE_OK;
}

int sceNpSessionSignalingCreateContext_hook(const SceNpSessionSignalingCreateContextParam* param,
                                            SceNpSessionSignalingContextId* ctxId) {
    (void)param;
    if (!ctxId) {
        online_klog("sceNpSessionSignalingCreateContext -> invalid_argument");
        return SCE_NP_SESSION_SIGNALING_ERROR_INVALID_ARGUMENT;
    }
    *ctxId = static_cast<SceNpSessionSignalingContextId>(next_id(g_sessionSignalingContextId));
    online_klog("sceNpSessionSignalingCreateContext -> ctx=%d", static_cast<int>(*ctxId));
    return SCE_OK;
}

int sceNpSessionSignalingCreateContext2_hook(const SceNpSessionSignalingCreateContext2Param* param,
                                             uint32_t* ctxId) {
    (void)param;
    if (!ctxId) {
        online_klog("sceNpSessionSignalingCreateContext2 -> invalid_argument");
        return SCE_NP_SESSION_SIGNALING_ERROR_INVALID_ARGUMENT;
    }
    *ctxId = static_cast<uint32_t>(next_id(g_sessionSignalingContextId));
    online_klog("sceNpSessionSignalingCreateContext2 -> ctx=%u", *ctxId);
    return SCE_OK;
}

int sceNpSessionSignalingRequestPrepare_hook(SceNpSessionSignalingContextId ctxId,
                                             SceNpSessionSignalingRequestId* reqId) {
    if (!reqId) {
        online_klog("sceNpSessionSignalingRequestPrepare ctx=%d -> invalid_argument",
                    static_cast<int>(ctxId));
        return SCE_NP_SESSION_SIGNALING_ERROR_INVALID_ARGUMENT;
    }
    *reqId = static_cast<SceNpSessionSignalingRequestId>(next_id(g_sessionSignalingRequestId));
    online_klog("sceNpSessionSignalingRequestPrepare ctx=%d -> req=%d",
                static_cast<int>(ctxId),
                static_cast<int>(*reqId));
    return SCE_OK;
}

int sceNpSessionSignalingDestroyContext_hook(SceNpSessionSignalingContextId ctxId) {
    online_klog("sceNpSessionSignalingDestroyContext ctx=%d -> OK", static_cast<int>(ctxId));
    return SCE_OK;
}

int sceNpSessionSignalingActivateUser_hook(SceNpSessionSignalingContextId ctxId,
                                           const SceNpPeerAddressA* peerAddrA,
                                           SceNpSessionSignalingGroupId* grpId) {
    (void)peerAddrA;
    if (!grpId) {
        online_klog("sceNpSessionSignalingActivateUser ctx=%d -> invalid_argument",
                    static_cast<int>(ctxId));
        return SCE_NP_SESSION_SIGNALING_ERROR_INVALID_ARGUMENT;
    }
    *grpId = static_cast<SceNpSessionSignalingGroupId>(next_id(g_sessionSignalingGroupId));
    online_klog("sceNpSessionSignalingActivateUser ctx=%d peer=%p -> group=%d",
                static_cast<int>(ctxId),
                static_cast<const void*>(peerAddrA),
                static_cast<int>(*grpId));
    return SCE_OK;
}

int sceNpSessionSignalingActivateSession_hook(SceNpSessionSignalingContextId ctxId,
                                              const char* sessionId,
                                              SceNpSessionSignalingSessionType sessionType,
                                              const SceNpSessionSignalingSessionOptParam* optParam,
                                              SceNpSessionSignalingGroupId* grpId) {
    (void)sessionType;
    (void)optParam;
    if (!sessionId || !grpId) {
        online_klog("sceNpSessionSignalingActivateSession ctx=%d session=%s -> invalid_argument",
                    static_cast<int>(ctxId),
                    sessionId ? sessionId : "<null>");
        return SCE_NP_SESSION_SIGNALING_ERROR_INVALID_ARGUMENT;
    }
    *grpId = static_cast<SceNpSessionSignalingGroupId>(next_id(g_sessionSignalingGroupId));
    online_klog("sceNpSessionSignalingActivateSession ctx=%d session=%s type=%d -> group=%d",
                static_cast<int>(ctxId),
                sessionId,
                static_cast<int>(sessionType),
                static_cast<int>(*grpId));
    return SCE_OK;
}

int sceNpSessionSignalingDeactivate_hook(SceNpSessionSignalingContextId ctxId,
                                         SceNpSessionSignalingGroupId grpId) {
    online_klog("sceNpSessionSignalingDeactivate ctx=%d group=%d -> OK",
                static_cast<int>(ctxId),
                static_cast<int>(grpId));
    return SCE_OK;
}

int sceNpSessionSignalingGetGroupInfo_hook(uint32_t ctxId,
                                           uint32_t grpId,
                                           SceNpSessionSignalingConnectionListCompat* connList) {
    if (connList) {
        memset(connList, 0, sizeof(*connList));
    }
    online_klog("sceNpSessionSignalingGetGroupInfo ctx=%u group=%u -> conn=0", ctxId, grpId);
    return SCE_OK;
}

int sceNpSessionSignalingGetConnectionInfo_hook(SceNpSessionSignalingContextId ctxId,
                                                SceNpSessionSignalingConnectionId connId,
                                                SceNpSessionSignalingConnectionInfoCode code,
                                                SceNpSessionSignalingConnectionInfo* info) {
    if (!info) {
        online_klog("sceNpSessionSignalingGetConnectionInfo ctx=%d conn=%d code=%d -> invalid_argument",
                    static_cast<int>(ctxId),
                    static_cast<int>(connId),
                    static_cast<int>(code));
        return SCE_NP_SESSION_SIGNALING_ERROR_INVALID_ARGUMENT;
    }
    memset(info, 0, sizeof(*info));
    switch (static_cast<int>(code)) {
        case SCE_NP_SESSION_SIGNALING_CONNECTION_INFO_RTT:
            info->rtt = 1;
            break;
        case SCE_NP_SESSION_SIGNALING_CONNECTION_INFO_NET_ADDRESS:
        case SCE_NP_SESSION_SIGNALING_CONNECTION_INFO_MAPPED_ADDRESS:
            fill_loopback_addr(&info->address.addr);
            info->address.port = 0;
            break;
        case SCE_NP_SESSION_SIGNALING_CONNECTION_INFO_PACKET_LOSS:
            info->packetLoss = 0;
            break;
        case SCE_NP_SESSION_SIGNALING_CONNECTION_INFO_PEER_ADDRESS:
            fill_peer_address(&info->peerAddrA);
            break;
        case kSessionSignalingPeerNatStatusInfoCode:
            *reinterpret_cast<int*>(info) = SCE_NP_SESSION_SIGNALING_NETINFO_NAT_STATUS_TYPE2;
            break;
        default:
            online_klog("sceNpSessionSignalingGetConnectionInfo ctx=%d conn=%d code=%d -> invalid_code",
                        static_cast<int>(ctxId),
                        static_cast<int>(connId),
                        static_cast<int>(code));
            return SCE_NP_SESSION_SIGNALING_ERROR_INVALID_ARGUMENT;
    }
    online_klog("sceNpSessionSignalingGetConnectionInfo ctx=%d conn=%d code=%d -> OK",
                static_cast<int>(ctxId),
                static_cast<int>(connId),
                static_cast<int>(code));
    return SCE_OK;
}

int sceNpSessionSignalingGetConnectionStatus_hook(SceNpSessionSignalingContextId ctxId,
                                                  SceNpSessionSignalingConnectionId connId,
                                                  SceNpSessionSignalingConnectionStatus* connectionStatus,
                                                  SceNetInAddr* peerAddr,
                                                  SceNetInPort_t* peerPort) {
    if (!connectionStatus || !peerAddr || !peerPort) {
        online_klog("sceNpSessionSignalingGetConnectionStatus ctx=%d conn=%d -> invalid_argument",
                    static_cast<int>(ctxId),
                    static_cast<int>(connId));
        return SCE_NP_SESSION_SIGNALING_ERROR_INVALID_ARGUMENT;
    }
    *connectionStatus = SCE_NP_SESSION_SIGNALING_CONNECTION_STATUS_ACTIVE;
    fill_loopback_addr(peerAddr);
    *peerPort = 0;
    online_klog("sceNpSessionSignalingGetConnectionStatus ctx=%d conn=%d -> ACTIVE",
                static_cast<int>(ctxId),
                static_cast<int>(connId));
    return SCE_OK;
}

int sceNpSessionSignalingGetConnectionFromPeerAddress_hook(
    SceNpSessionSignalingContextId ctxId,
    const SceNpPeerAddressA* peerAddrA,
    SceNpSessionSignalingConnectionId* connId) {
    (void)peerAddrA;
    if (!connId) {
        online_klog("sceNpSessionSignalingGetConnectionFromPeerAddress ctx=%d -> invalid_argument",
                    static_cast<int>(ctxId));
        return SCE_NP_SESSION_SIGNALING_ERROR_INVALID_ARGUMENT;
    }
    *connId = static_cast<SceNpSessionSignalingConnectionId>(
        next_id(g_sessionSignalingConnectionId));
    online_klog("sceNpSessionSignalingGetConnectionFromPeerAddress ctx=%d peer=%p -> conn=%d",
                static_cast<int>(ctxId),
                static_cast<const void*>(peerAddrA),
                static_cast<int>(*connId));
    return SCE_OK;
}

int sceNpSessionSignalingGetConnectionFromNetAddress_hook(SceNpSessionSignalingContextId ctxId,
                                                          SceNetInAddr peerAddr,
                                                          SceNetInPort_t peerPort,
                                                          SceNpSessionSignalingConnectionId* connId) {
    (void)peerAddr;
    if (!connId) {
        online_klog("sceNpSessionSignalingGetConnectionFromNetAddress ctx=%d port=%u -> invalid_argument",
                    static_cast<int>(ctxId),
                    static_cast<unsigned>(peerPort));
        return SCE_NP_SESSION_SIGNALING_ERROR_INVALID_ARGUMENT;
    }
    *connId = static_cast<SceNpSessionSignalingConnectionId>(
        next_id(g_sessionSignalingConnectionId));
    online_klog("sceNpSessionSignalingGetConnectionFromNetAddress ctx=%d port=%u -> conn=%d",
                static_cast<int>(ctxId),
                static_cast<unsigned>(peerPort),
                static_cast<int>(*connId));
    return SCE_OK;
}

int sceNpSessionSignalingGetConnectionFromPeerAddress2_hook(uint32_t ctxId,
                                                            uint32_t grpId,
                                                            const SceNpPeerAddressA* peerAddrA,
                                                            uint32_t* connId) {
    (void)ctxId;
    (void)grpId;
    (void)peerAddrA;
    if (!connId) {
        online_klog("sceNpSessionSignalingGetConnectionFromPeerAddress2 ctx=%u group=%u -> invalid_argument",
                    ctxId,
                    grpId);
        return SCE_NP_SESSION_SIGNALING_ERROR_INVALID_ARGUMENT;
    }
    *connId = static_cast<uint32_t>(next_id(g_sessionSignalingConnectionId));
    online_klog("sceNpSessionSignalingGetConnectionFromPeerAddress2 ctx=%u group=%u peer=%p -> conn=%u",
                ctxId,
                grpId,
                static_cast<const void*>(peerAddrA),
                *connId);
    return SCE_OK;
}

int sceNpSessionSignalingGetConnectionFromNetAddress2_hook(
    uint32_t ctxId,
    uint32_t grpId,
    SceNetInAddrCompat peerAddr,
    uint16_t peerPort,
    SceNpSessionSignalingConnectionListCompat* connList) {
    (void)ctxId;
    (void)grpId;
    (void)peerAddr;
    (void)peerPort;
    if (connList) {
        memset(connList, 0, sizeof(*connList));
    }
    online_klog("sceNpSessionSignalingGetConnectionFromNetAddress2 ctx=%u group=%u port=%u -> conn=0",
                ctxId,
                grpId,
                static_cast<unsigned>(peerPort));
    return SCE_OK;
}

int sceNpSessionSignalingGetGroupFromPeerAddress_hook(uint32_t ctxId,
                                                      const SceNpPeerAddressA* peerAddrA,
                                                      uint32_t* grpId) {
    (void)ctxId;
    (void)peerAddrA;
    if (!grpId) {
        online_klog("sceNpSessionSignalingGetGroupFromPeerAddress ctx=%u -> invalid_argument", ctxId);
        return SCE_NP_ERROR_INVALID_ARGUMENT;
    }
    *grpId = static_cast<uint32_t>(next_id(g_sessionSignalingGroupId));
    online_klog("sceNpSessionSignalingGetGroupFromPeerAddress ctx=%u peer=%p -> group=%u",
                ctxId,
                static_cast<const void*>(peerAddrA),
                *grpId);
    return SCE_OK;
}

int sceNpSessionSignalingGetGroupFromSessionId_hook(uint32_t ctxId,
                                                    const char* sessionId,
                                                    uint32_t* grpId) {
    if (!grpId) {
        online_klog("sceNpSessionSignalingGetGroupFromSessionId ctx=%u session=%s -> invalid_argument",
                    ctxId,
                    sessionId ? sessionId : "<null>");
        return SCE_NP_SESSION_SIGNALING_ERROR_INVALID_ARGUMENT;
    }
    *grpId = static_cast<uint32_t>(next_id(g_sessionSignalingGroupId));
    online_klog("sceNpSessionSignalingGetGroupFromSessionId ctx=%u session=%s -> group=%u",
                ctxId,
                sessionId ? sessionId : "<null>",
                *grpId);
    return SCE_OK;
}

int sceNpSessionSignalingGetLocalNetInfo_hook(SceNpSessionSignalingContextId ctxId,
                                              SceNpSessionSignalingNetInfo* info) {
    if (!info) {
        online_klog("sceNpSessionSignalingGetLocalNetInfo ctx=%d -> invalid_argument",
                    static_cast<int>(ctxId));
        return SCE_NP_SESSION_SIGNALING_ERROR_INVALID_ARGUMENT;
    }
    memset(info, 0, sizeof(*info));
    fill_loopback_addr(&info->localAddr);
    fill_loopback_addr(&info->mappedAddr);
    info->natStatus = SCE_NP_SESSION_SIGNALING_NETINFO_NAT_STATUS_TYPE2;
#if BACKPORT_SDK >= 10
    reinterpret_cast<SceNpSessionSignalingNetInfoSdk10Compat*>(info)->stunStatus =
        SCE_NP_SESSION_SIGNALING_NETINFO_STUN_STATUS_OK;
#endif
    online_klog("sceNpSessionSignalingGetLocalNetInfo ctx=%d -> NAT_TYPE2 STUN_OK",
                static_cast<int>(ctxId));
    return SCE_OK;
}

int sceNpSessionSignalingGetConnectionStatistics_hook(
    SceNpSessionSignalingConnectionStatistics* stats) {
    if (!stats) {
        online_klog("sceNpSessionSignalingGetConnectionStatistics -> invalid_argument");
        return SCE_NP_SESSION_SIGNALING_ERROR_INVALID_ARGUMENT;
    }
    fill_empty_connection_stats(stats);
    online_klog("sceNpSessionSignalingGetConnectionStatistics -> max=%u",
                SCE_NP_SESSION_SIGNALING_MAX_CONNECTION_NUM);
    return SCE_OK;
}

int sceNpSessionSignalingGetMemoryInfo_hook(SceNpSessionSignalingMemoryInfo* memInfo) {
    if (!memInfo) {
        online_klog("sceNpSessionSignalingGetMemoryInfo -> invalid_argument");
        return SCE_NP_SESSION_SIGNALING_ERROR_INVALID_ARGUMENT;
    }
    fill_memory_info(memInfo);
    online_klog("sceNpSessionSignalingGetMemoryInfo -> OK");
    return SCE_OK;
}

int32_t sceNpWebApi2Initialize_hook(int libHttp2CtxId, size_t poolSize) {
    g_webApiPoolSize.store(poolSize, std::memory_order_relaxed);
    const int32_t id = next_id(g_webApiLibCtxId);
    online_klog("sceNpWebApi2Initialize httpCtx=%d pool=%zu -> libCtx=%d",
                libHttp2CtxId,
                poolSize,
                id);
    return id;
}

int32_t sceNpWebApi2Terminate_hook(int32_t libCtxId) {
    g_webApiPoolSize.store(0, std::memory_order_relaxed);
    online_klog("sceNpWebApi2Terminate libCtx=%d -> OK", libCtxId);
    return SCE_OK;
}

int32_t sceNpWebApi2CreateUserContext_hook(int32_t libCtxId, SceUserServiceUserId userId) {
    const int32_t id = next_id(g_webApiUserCtxId);
    online_klog("sceNpWebApi2CreateUserContext libCtx=%d user=%d -> userCtx=%d",
                libCtxId,
                userId,
                id);
    return id;
}

int32_t sceNpWebApi2DeleteUserContext_hook(int32_t userCtxId) {
    online_klog("sceNpWebApi2DeleteUserContext userCtx=%d -> OK", userCtxId);
    return SCE_OK;
}

int32_t sceNpWebApi2CreateRequest_hook(int32_t userCtxId,
                                       const char* pApiGroup,
                                       const char* pPath,
                                       SceNpWebApi2HttpMethod method,
                                       const SceNpWebApi2ContentParameter* pContentParameter,
                                       int64_t* pRequestId) {
    (void)userCtxId;
    (void)pContentParameter;
    if (!pApiGroup || !pPath || !method || !pRequestId) {
        online_klog("sceNpWebApi2CreateRequest userCtx=%d group=%s path=%s method=%s -> invalid_argument",
                    userCtxId,
                    pApiGroup ? pApiGroup : "<null>",
                    pPath ? pPath : "<null>",
                    method ? method : "<null>");
        return SCE_NP_WEBAPI2_ERROR_INVALID_ARGUMENT;
    }
    const int64_t requestId = next_id(g_webApiRequestId);
    WebApiRequestState* state = allocate_webapi_request(requestId);
    if (!fill_dynamic_webapi_response_body(state, pPath)) {
        const char* body = choose_webapi_response_body(method, pApiGroup, pPath);
        copy_cstr(state->body, sizeof(state->body), body);
    } else {
        state->body[sizeof(state->body) - 1] = '\0';
    }
    state->bodySize = strlen(state->body);
    state->readOffset = 0;
    state->httpStatus = state->bodySize == 0 ? 204 : 200;
    *pRequestId = requestId;
    online_klog("sceNpWebApi2CreateRequest userCtx=%d method=%s group=%s path=%s -> req=%lld status=%d body=%zu",
                userCtxId,
                method,
                pApiGroup,
                pPath,
                static_cast<long long>(requestId),
                state->httpStatus,
                state->bodySize);
    return SCE_OK;
}

int32_t sceNpWebApi2DeleteRequest_hook(int64_t requestId) {
    release_webapi_request(requestId);
    online_klog("sceNpWebApi2DeleteRequest req=%lld -> OK", static_cast<long long>(requestId));
    return SCE_OK;
}

int32_t sceNpWebApi2AbortRequest_hook(int64_t requestId) {
    release_webapi_request(requestId);
    online_klog("sceNpWebApi2AbortRequest req=%lld -> OK", static_cast<long long>(requestId));
    return SCE_OK;
}

int32_t sceNpWebApi2SendRequest_hook(int64_t requestId,
                                     const void* pData,
                                     size_t dataSize,
                                     SceNpWebApi2ResponseInformationOption* pRespInfoOption) {
    if (!pData && dataSize != 0) {
        online_klog("sceNpWebApi2SendRequest req=%lld dataSize=%zu -> invalid_argument",
                    static_cast<long long>(requestId),
                    dataSize);
        return SCE_NP_WEBAPI2_ERROR_INVALID_ARGUMENT;
    }
    WebApiRequestState* state = find_webapi_request(requestId);
    if (pRespInfoOption) {
        pRespInfoOption->httpStatus = state ? state->httpStatus : 204;
        pRespInfoOption->responseDataSize = state ? state->bodySize : 0;
        if (pRespInfoOption->pErrorObject && pRespInfoOption->errorObjectSize > 0) {
            pRespInfoOption->pErrorObject[0] = '\0';
        }
    }
    online_klog("sceNpWebApi2SendRequest req=%lld dataSize=%zu -> status=%d body=%zu respInfo=%p",
                static_cast<long long>(requestId),
                dataSize,
                state ? state->httpStatus : 204,
                state ? state->bodySize : 0,
                static_cast<void*>(pRespInfoOption));
    return SCE_OK;
}

int32_t sceNpWebApi2ReadData_hook(int64_t requestId, void* pData, size_t size) {
    if (!pData && size != 0) {
        online_klog("sceNpWebApi2ReadData req=%lld size=%zu -> invalid_argument",
                    static_cast<long long>(requestId),
                    size);
        return SCE_NP_WEBAPI2_ERROR_INVALID_ARGUMENT;
    }
    WebApiRequestState* state = find_webapi_request(requestId);
    if (!state || !pData || size == 0 || state->readOffset >= state->bodySize) {
        online_klog("sceNpWebApi2ReadData req=%lld size=%zu -> 0",
                    static_cast<long long>(requestId),
                    size);
        return 0;
    }
    const size_t remaining = state->bodySize - state->readOffset;
    const size_t toCopy = remaining < size ? remaining : size;
    memcpy(pData, state->body + state->readOffset, toCopy);
    state->readOffset += toCopy;
    if (toCopy > static_cast<size_t>(INT32_MAX)) {
        online_klog("sceNpWebApi2ReadData req=%lld size=%zu -> INT32_MAX",
                    static_cast<long long>(requestId),
                    size);
        return INT32_MAX;
    }
    online_klog("sceNpWebApi2ReadData req=%lld size=%zu -> copied=%zu offset=%zu/%zu",
                static_cast<long long>(requestId),
                size,
                toCopy,
                state->readOffset,
                state->bodySize);
    return static_cast<int32_t>(toCopy);
}

int32_t sceNpWebApi2AddHttpRequestHeader_hook(int64_t requestId,
                                              const char* pFieldName,
                                              const char* pValue) {
    if (!pFieldName || !pValue) {
        online_klog("sceNpWebApi2AddHttpRequestHeader req=%lld field=%s -> invalid_argument",
                    static_cast<long long>(requestId),
                    pFieldName ? pFieldName : "<null>");
        return SCE_NP_WEBAPI2_ERROR_INVALID_ARGUMENT;
    }
    online_klog("sceNpWebApi2AddHttpRequestHeader req=%lld %s=%s -> OK",
                static_cast<long long>(requestId),
                pFieldName,
                pValue);
    return SCE_OK;
}

int32_t sceNpWebApi2GetHttpResponseHeaderValueLength_hook(int64_t requestId,
                                                          const char* pFieldName,
                                                          size_t* pValueLength) {
    if (!pFieldName || !pValueLength) {
        online_klog("sceNpWebApi2GetHttpResponseHeaderValueLength req=%lld field=%s -> invalid_argument",
                    static_cast<long long>(requestId),
                    pFieldName ? pFieldName : "<null>");
        return SCE_NP_WEBAPI2_ERROR_INVALID_ARGUMENT;
    }
    const WebApiRequestState* state = find_webapi_request(requestId);
    const char* value = get_webapi_response_header_value(state, pFieldName);
    *pValueLength = value ? strlen(value) + 1 : 0;
    online_klog("sceNpWebApi2GetHttpResponseHeaderValueLength req=%lld field=%s -> %zu",
                static_cast<long long>(requestId),
                pFieldName,
                *pValueLength);
    return SCE_OK;
}

int32_t sceNpWebApi2GetHttpResponseHeaderValue_hook(int64_t requestId,
                                                    const char* pFieldName,
                                                    char* pValue,
                                                    size_t valueSize) {
    if (!pFieldName) {
        online_klog("sceNpWebApi2GetHttpResponseHeaderValue req=%lld field=<null> -> invalid_argument",
                    static_cast<long long>(requestId));
        return SCE_NP_WEBAPI2_ERROR_INVALID_ARGUMENT;
    }
    if (!pValue || valueSize == 0) {
        online_klog("sceNpWebApi2GetHttpResponseHeaderValue req=%lld field=%s size=%zu -> invalid_argument",
                    static_cast<long long>(requestId),
                    pFieldName,
                    valueSize);
        return SCE_NP_WEBAPI2_ERROR_INVALID_ARGUMENT;
    }
    const WebApiRequestState* state = find_webapi_request(requestId);
    const char* value = get_webapi_response_header_value(state, pFieldName);
    if (value && strlen(value) + 1 > valueSize) {
        pValue[0] = '\0';
        online_klog("sceNpWebApi2GetHttpResponseHeaderValue req=%lld field=%s size=%zu need=%zu -> invalid_argument",
                    static_cast<long long>(requestId),
                    pFieldName,
                    valueSize,
                    strlen(value) + 1);
        return SCE_NP_WEBAPI2_ERROR_INVALID_ARGUMENT;
    }
    copy_cstr(pValue, valueSize, value);
    online_klog("sceNpWebApi2GetHttpResponseHeaderValue req=%lld field=%s -> %s",
                static_cast<long long>(requestId),
                pFieldName,
                value ? value : "<null>");
    return SCE_OK;
}

int32_t sceNpWebApi2GetMemoryPoolStats_hook(int32_t libCtxId,
                                            SceNpWebApi2MemoryPoolStats* pCurrentStat) {
    (void)libCtxId;
    if (!pCurrentStat) {
        online_klog("sceNpWebApi2GetMemoryPoolStats libCtx=%d -> invalid_argument", libCtxId);
        return SCE_NP_WEBAPI2_ERROR_INVALID_ARGUMENT;
    }
    memset(pCurrentStat, 0, sizeof(*pCurrentStat));
    pCurrentStat->poolSize = g_webApiPoolSize.load(std::memory_order_relaxed);
    online_klog("sceNpWebApi2GetMemoryPoolStats libCtx=%d -> pool=%zu",
                libCtxId,
                pCurrentStat->poolSize);
    return SCE_OK;
}

int32_t sceNpWebApi2SetRequestTimeout_hook(int64_t requestId, uint32_t timeout) {
    online_klog("sceNpWebApi2SetRequestTimeout req=%lld timeout=%u -> OK",
                static_cast<long long>(requestId),
                timeout);
    return SCE_OK;
}

void sceNpWebApi2CheckTimeout_hook(void) {
}

int32_t sceNpWebApi2AddWebTraceTag_hook(int64_t requestId, const char* pValue) {
    if (!pValue) {
        online_klog("sceNpWebApi2AddWebTraceTag req=%lld value=<null> -> invalid_argument",
                    static_cast<long long>(requestId));
        return SCE_NP_WEBAPI2_ERROR_INVALID_ARGUMENT;
    }
    online_klog("sceNpWebApi2AddWebTraceTag req=%lld value=%s -> OK",
                static_cast<long long>(requestId),
                pValue);
    return SCE_OK;
}

int32_t sceNpWebApi2PushEventCreateHandle_hook(int32_t libCtxId) {
    const int32_t id = next_id(g_pushHandleId);
    online_klog("sceNpWebApi2PushEventCreateHandle libCtx=%d -> handle=%d", libCtxId, id);
    return id;
}

int32_t sceNpWebApi2PushEventDeleteHandle_hook(int32_t libCtxId, int32_t handleId) {
    online_klog("sceNpWebApi2PushEventDeleteHandle libCtx=%d handle=%d -> OK",
                libCtxId,
                handleId);
    return SCE_OK;
}

int32_t sceNpWebApi2PushEventAbortHandle_hook(int32_t libCtxId, int32_t handleId) {
    online_klog("sceNpWebApi2PushEventAbortHandle libCtx=%d handle=%d -> OK",
                libCtxId,
                handleId);
    return SCE_OK;
}

int32_t sceNpWebApi2PushEventSetHandleTimeout_hook(int32_t libCtxId,
                                                   int32_t handleId,
                                                   uint32_t timeout) {
    online_klog("sceNpWebApi2PushEventSetHandleTimeout libCtx=%d handle=%d timeout=%u -> OK",
                libCtxId,
                handleId,
                timeout);
    return SCE_OK;
}

int32_t sceNpWebApi2PushEventCreateFilter_hook(
    int32_t libCtxId,
    int32_t handleId,
    const char* pNpServiceName,
    SceNpServiceLabel npServiceLabel,
    const SceNpWebApi2PushEventFilterParameter* pFilterParam,
    size_t filterParamNum) {
    (void)libCtxId;
    (void)handleId;
    (void)pFilterParam;
    const int32_t id = next_id(g_pushFilterId);
    online_klog("sceNpWebApi2PushEventCreateFilter libCtx=%d handle=%d service=%s label=%u params=%zu -> filter=%d",
                libCtxId,
                handleId,
                pNpServiceName ? pNpServiceName : "<null>",
                npServiceLabel,
                filterParamNum,
                id);
    return id;
}

int32_t sceNpWebApi2PushEventDeleteFilter_hook(int32_t libCtxId, int32_t filterId) {
    online_klog("sceNpWebApi2PushEventDeleteFilter libCtx=%d filter=%d -> OK",
                libCtxId,
                filterId);
    return SCE_OK;
}

int32_t sceNpWebApi2PushEventRegisterCallback_hook(int32_t userCtxId,
                                                   int32_t filterId,
                                                   SceNpWebApi2PushEventCallback cbFunc,
                                                   void* pUserArg) {
    (void)userCtxId;
    (void)filterId;
    (void)pUserArg;
    if (!cbFunc) {
        online_klog("sceNpWebApi2PushEventRegisterCallback userCtx=%d filter=%d cb=<null> -> invalid_argument",
                    userCtxId,
                    filterId);
        return SCE_NP_WEBAPI2_ERROR_INVALID_ARGUMENT;
    }
    const int32_t id = next_id(g_pushCallbackId);
    online_klog("sceNpWebApi2PushEventRegisterCallback userCtx=%d filter=%d cb=%p -> callback=%d",
                userCtxId,
                filterId,
                reinterpret_cast<void*>(cbFunc),
                id);
    return id;
}

int32_t sceNpWebApi2PushEventUnregisterCallback_hook(int32_t userCtxId, int32_t callbackId) {
    online_klog("sceNpWebApi2PushEventUnregisterCallback userCtx=%d callback=%d -> OK",
                userCtxId,
                callbackId);
    return SCE_OK;
}

int32_t sceNpWebApi2PushEventRegisterPushContextCallback_hook(
    int32_t userCtxId,
    int32_t filterId,
    SceNpWebApi2PushEventPushContextCallback cbFunc,
    void* pUserArg) {
    (void)userCtxId;
    (void)filterId;
    (void)pUserArg;
    if (!cbFunc) {
        online_klog("sceNpWebApi2PushEventRegisterPushContextCallback userCtx=%d filter=%d cb=<null> -> invalid_argument",
                    userCtxId,
                    filterId);
        return SCE_NP_WEBAPI2_ERROR_INVALID_ARGUMENT;
    }
    const int32_t id = next_id(g_pushCallbackId);
    online_klog("sceNpWebApi2PushEventRegisterPushContextCallback userCtx=%d filter=%d cb=%p -> callback=%d",
                userCtxId,
                filterId,
                reinterpret_cast<void*>(cbFunc),
                id);
    return id;
}

int32_t sceNpWebApi2PushEventUnregisterPushContextCallback_hook(int32_t userCtxId,
                                                                int32_t callbackId) {
    online_klog("sceNpWebApi2PushEventUnregisterPushContextCallback userCtx=%d callback=%d -> OK",
                userCtxId,
                callbackId);
    return SCE_OK;
}

int32_t sceNpWebApi2PushEventCreatePushContext_hook(
    int32_t userCtxId,
    SceNpWebApi2PushEventPushContextId* pPushCtxId) {
    const int32_t id = next_id(g_pushCallbackId);
    (void)userCtxId;
    if (!pPushCtxId) {
        online_klog("sceNpWebApi2PushEventCreatePushContext userCtx=%d -> invalid_argument",
                    userCtxId);
        return SCE_NP_WEBAPI2_ERROR_INVALID_ARGUMENT;
    }
    snprintf(pPushCtxId->uuid,
             sizeof(pPushCtxId->uuid),
             "00000000-0000-4000-8000-%012x",
             static_cast<unsigned>(id));
    online_klog("sceNpWebApi2PushEventCreatePushContext userCtx=%d -> %s",
                userCtxId,
                pPushCtxId->uuid);
    return SCE_OK;
}

int32_t sceNpWebApi2PushEventDeletePushContext_hook(
    int32_t userCtxId,
    const SceNpWebApi2PushEventPushContextId* pPushCtxId) {
    (void)userCtxId;
    if (!pPushCtxId) {
        online_klog("sceNpWebApi2PushEventDeletePushContext userCtx=%d -> invalid_argument",
                    userCtxId);
        return SCE_NP_WEBAPI2_ERROR_INVALID_ARGUMENT;
    }
    online_klog("sceNpWebApi2PushEventDeletePushContext userCtx=%d uuid=%s -> OK",
                userCtxId,
                pPushCtxId->uuid);
    return SCE_OK;
}

int32_t sceNpWebApi2PushEventStartPushContextCallback_hook(
    int32_t userCtxId,
    const SceNpWebApi2PushEventPushContextId* pPushCtxId) {
    (void)userCtxId;
    if (!pPushCtxId) {
        online_klog("sceNpWebApi2PushEventStartPushContextCallback userCtx=%d -> invalid_argument",
                    userCtxId);
        return SCE_NP_WEBAPI2_ERROR_INVALID_ARGUMENT;
    }
    online_klog("sceNpWebApi2PushEventStartPushContextCallback userCtx=%d uuid=%s -> OK",
                userCtxId,
                pPushCtxId->uuid);
    return SCE_OK;
}

int sceHttpInit_hook(int libnetMemId, int libsslCtxId, size_t poolSize) {
    auto original = original_late<decltype(&::sceHttpInit)>("sceHttpInit");
    const int ret = original ? original(libnetMemId, libsslCtxId, poolSize) : -1;
    online_klog("sceHttpInit libnet=%d ssl=%d pool=%zu -> %d",
                libnetMemId,
                libsslCtxId,
                poolSize,
                ret);
    return ret;
}

int sceHttpTerm_hook(int libhttpCtxId) {
    auto original = original_late<decltype(&::sceHttpTerm)>("sceHttpTerm");
    const int ret = original ? original(libhttpCtxId) : -1;
    online_klog("sceHttpTerm ctx=%d -> %d", libhttpCtxId, ret);
    return ret;
}

int sceHttpCreateTemplate_hook(int libhttpCtxId,
                               const char* userAgent,
                               int httpVer,
                               int isAutoProxyConf) {
    auto original = original_late<decltype(&::sceHttpCreateTemplate)>("sceHttpCreateTemplate");
    const int ret = original ? original(libhttpCtxId, userAgent, httpVer, isAutoProxyConf) : -1;
    online_klog("sceHttpCreateTemplate ctx=%d ua=%s ver=%d proxy=%d -> %d",
                libhttpCtxId,
                userAgent ? userAgent : "<null>",
                httpVer,
                isAutoProxyConf,
                ret);
    return ret;
}

int sceHttpCreateConnection_hook(int tmplId,
                                 const char* serverName,
                                 const char* scheme,
                                 uint16_t port,
                                 int isEnableKeepalive) {
    auto original = original_late<decltype(&::sceHttpCreateConnection)>("sceHttpCreateConnection");
    const int ret =
        original ? original(tmplId, serverName, scheme, port, isEnableKeepalive) : -1;
    online_klog("sceHttpCreateConnection tmpl=%d scheme=%s server=%s port=%u keepalive=%d -> %d",
                tmplId,
                scheme ? scheme : "<null>",
                serverName ? serverName : "<null>",
                static_cast<unsigned>(port),
                isEnableKeepalive,
                ret);
    return ret;
}

int sceHttpCreateConnectionWithURL_hook(int tmplId, const char* url, int isEnableKeepalive) {
    auto original =
        original_late<decltype(&::sceHttpCreateConnectionWithURL)>("sceHttpCreateConnectionWithURL");
    const int ret = original ? original(tmplId, url, isEnableKeepalive) : -1;
    online_klog("sceHttpCreateConnectionWithURL tmpl=%d url=%s keepalive=%d -> %d",
                tmplId,
                url ? url : "<null>",
                isEnableKeepalive,
                ret);
    return ret;
}

int sceHttpCreateRequest_hook(int connId, int method, const char* path, uint64_t contentLength) {
    auto original = original_late<decltype(&::sceHttpCreateRequest)>("sceHttpCreateRequest");
    const int ret = original ? original(connId, method, path, contentLength) : -1;
    online_klog("sceHttpCreateRequest conn=%d method=%d path=%s len=%llu -> %d",
                connId,
                method,
                path ? path : "<null>",
                static_cast<unsigned long long>(contentLength),
                ret);
    return ret;
}

int sceHttpCreateRequest2_hook(int connId,
                               const char* method,
                               const char* path,
                               uint64_t contentLength) {
    auto original = original_late<decltype(&::sceHttpCreateRequest2)>("sceHttpCreateRequest2");
    const int ret = original ? original(connId, method, path, contentLength) : -1;
    online_klog("sceHttpCreateRequest2 conn=%d method=%s path=%s len=%llu -> %d",
                connId,
                method ? method : "<null>",
                path ? path : "<null>",
                static_cast<unsigned long long>(contentLength),
                ret);
    return ret;
}

int sceHttpCreateRequestWithURL_hook(int connId,
                                     int method,
                                     const char* url,
                                     uint64_t contentLength) {
    auto original =
        original_late<decltype(&::sceHttpCreateRequestWithURL)>("sceHttpCreateRequestWithURL");
    const int ret = original ? original(connId, method, url, contentLength) : -1;
    online_klog("sceHttpCreateRequestWithURL conn=%d method=%d url=%s len=%llu -> %d",
                connId,
                method,
                url ? url : "<null>",
                static_cast<unsigned long long>(contentLength),
                ret);
    return ret;
}

int sceHttpCreateRequestWithURL2_hook(int connId,
                                      const char* method,
                                      const char* url,
                                      uint64_t contentLength) {
    auto original =
        original_late<decltype(&::sceHttpCreateRequestWithURL2)>("sceHttpCreateRequestWithURL2");
    const int ret = original ? original(connId, method, url, contentLength) : -1;
    online_klog("sceHttpCreateRequestWithURL2 conn=%d method=%s url=%s len=%llu -> %d",
                connId,
                method ? method : "<null>",
                url ? url : "<null>",
                static_cast<unsigned long long>(contentLength),
                ret);
    return ret;
}

int sceHttpAddRequestHeader_hook(int id, const char* name, const char* value, uint32_t mode) {
    auto original = original_late<decltype(&::sceHttpAddRequestHeader)>("sceHttpAddRequestHeader");
    const int ret = original ? original(id, name, value, mode) : -1;
    const bool redact = contains(name, "Authorization") || contains(name, "Cookie");
    online_klog("sceHttpAddRequestHeader id=%d %s=%s mode=%u -> %d",
                id,
                name ? name : "<null>",
                redact ? "<redacted>" : (value ? value : "<null>"),
                mode,
                ret);
    return ret;
}

int sceHttpSendRequest_hook(int reqId, const void* postData, size_t size) {
    auto original = original_late<decltype(&::sceHttpSendRequest)>("sceHttpSendRequest");
    const int ret = original ? original(reqId, postData, size) : -1;
    online_klog("sceHttpSendRequest req=%d post=%p size=%zu -> %d",
                reqId,
                postData,
                size,
                ret);
    return ret;
}

int sceHttpGetStatusCode_hook(int reqId, int* statusCode) {
    auto original = original_late<decltype(&::sceHttpGetStatusCode)>("sceHttpGetStatusCode");
    const int ret = original ? original(reqId, statusCode) : -1;
    online_klog("sceHttpGetStatusCode req=%d -> ret=%d status=%d",
                reqId,
                ret,
                statusCode ? *statusCode : 0);
    return ret;
}

int sceHttpGetLastErrno_hook(int reqId, int* errNum) {
    auto original = original_late<decltype(&::sceHttpGetLastErrno)>("sceHttpGetLastErrno");
    const int ret = original ? original(reqId, errNum) : -1;
    online_klog("sceHttpGetLastErrno req=%d -> ret=%d errno=%d",
                reqId,
                ret,
                errNum ? *errNum : 0);
    return ret;
}

int sceHttpReadData_hook(int reqId, void* data, size_t size) {
    auto original = original_late<decltype(&::sceHttpReadData)>("sceHttpReadData");
    const int ret = original ? original(reqId, data, size) : -1;
    online_klog("sceHttpReadData req=%d size=%zu -> %d", reqId, size, ret);
    return ret;
}

int sceHttp2Init_hook(int libnetMemId,
                      int libsslCtxId,
                      size_t poolSize,
                      int maxConcurrentRequest) {
    auto original = original_late<decltype(&::sceHttp2Init)>("sceHttp2Init");
    const int ret = original
        ? original(libnetMemId, libsslCtxId, poolSize, maxConcurrentRequest)
        : -1;
    online_klog("sceHttp2Init libnet=%d ssl=%d pool=%zu max=%d -> %d",
                libnetMemId,
                libsslCtxId,
                poolSize,
                maxConcurrentRequest,
                ret);
    return ret;
}

int sceHttp2Term_hook(int libhttpCtxId) {
    auto original = original_late<decltype(&::sceHttp2Term)>("sceHttp2Term");
    const int ret = original ? original(libhttpCtxId) : -1;
    online_klog("sceHttp2Term ctx=%d -> %d", libhttpCtxId, ret);
    return ret;
}

int sceHttp2CreateTemplate_hook(int libhttpCtxId,
                                const char* userAgent,
                                int httpVer,
                                int isAutoProxyConf) {
    auto original = original_late<decltype(&::sceHttp2CreateTemplate)>("sceHttp2CreateTemplate");
    const int ret = original
        ? original(libhttpCtxId, userAgent, httpVer, isAutoProxyConf)
        : -1;
    online_klog("sceHttp2CreateTemplate ctx=%d ua=%s ver=%d proxy=%d -> %d",
                libhttpCtxId,
                userAgent ? userAgent : "<null>",
                httpVer,
                isAutoProxyConf,
                ret);
    return ret;
}

int sceHttp2DeleteTemplate_hook(int tmplId) {
    auto original = original_late<decltype(&::sceHttp2DeleteTemplate)>("sceHttp2DeleteTemplate");
    const int ret = original ? original(tmplId) : -1;
    online_klog("sceHttp2DeleteTemplate tmpl=%d -> %d", tmplId, ret);
    return ret;
}

int sceHttp2GetMemoryPoolStats_hook(int libhttp2CtxId, SceHttp2MemoryPoolStats* currentStat) {
    auto original =
        original_late<decltype(&::sceHttp2GetMemoryPoolStats)>("sceHttp2GetMemoryPoolStats");
    const int ret = original ? original(libhttp2CtxId, currentStat) : -1;
    online_klog("sceHttp2GetMemoryPoolStats ctx=%d stats=%p -> %d",
                libhttp2CtxId,
                static_cast<void*>(currentStat),
                ret);
    return ret;
}

int sceHttp2CreateRequestWithURL_hook(int tmplId,
                                      const char* method,
                                      const char* url,
                                      uint64_t contentLength) {
    auto original = original_late<decltype(&::sceHttp2CreateRequestWithURL)>(
        "sceHttp2CreateRequestWithURL");
    const int ret = original ? original(tmplId, method, url, contentLength) : -1;
    online_klog("sceHttp2CreateRequestWithURL tmpl=%d method=%s url=%s len=%llu -> %d",
                tmplId,
                method ? method : "<null>",
                url ? url : "<null>",
                static_cast<unsigned long long>(contentLength),
                ret);
    return ret;
}

int sceHttp2DeleteRequest_hook(int reqId) {
    auto original = original_late<decltype(&::sceHttp2DeleteRequest)>("sceHttp2DeleteRequest");
    const int ret = original ? original(reqId) : -1;
    online_klog("sceHttp2DeleteRequest req=%d -> %d", reqId, ret);
    return ret;
}

int sceHttp2SslEnableOption_hook(int templateOrReqId, uint32_t sslFlags) {
    auto original = original_late<decltype(&::sceHttp2SslEnableOption)>("sceHttp2SslEnableOption");
    const int ret = original ? original(templateOrReqId, sslFlags) : -1;
    online_klog("sceHttp2SslEnableOption id=%d flags=0x%x -> %d",
                templateOrReqId,
                sslFlags,
                ret);
    return ret;
}

int sceHttp2SslDisableOption_hook(int templateOrReqId, uint32_t sslFlags) {
    auto original =
        original_late<decltype(&::sceHttp2SslDisableOption)>("sceHttp2SslDisableOption");
    const int ret = original ? original(templateOrReqId, sslFlags) : -1;
    online_klog("sceHttp2SslDisableOption id=%d flags=0x%x -> %d",
                templateOrReqId,
                sslFlags,
                ret);
    return ret;
}

int sceHttp2SetMinSslVersion_hook(int tmplId, SceSslVersion version) {
    using Fn = int (*)(int, SceSslVersion);
    auto original = original_late<Fn>("sceHttp2SetMinSslVersion");
    const int ret = original ? original(tmplId, version) : -1;
    online_klog("sceHttp2SetMinSslVersion tmpl=%d version=%d -> %d",
                tmplId,
                static_cast<int>(version),
                ret);
    return ret;
}

int sceHttp2SetSslCallback_hook(int templateOrReqId,
                                SceHttp2SslCallback cbfunc,
                                void* userArg) {
    auto original = original_late<decltype(&::sceHttp2SetSslCallback)>("sceHttp2SetSslCallback");
    const int ret = original ? original(templateOrReqId, cbfunc, userArg) : -1;
    online_klog("sceHttp2SetSslCallback id=%d cb=%p user=%p -> %d",
                templateOrReqId,
                reinterpret_cast<void*>(cbfunc),
                userArg,
                ret);
    return ret;
}

int sceHttp2AddRequestHeader_hook(int id,
                                  const char* name,
                                  const char* value,
                                  uint32_t mode) {
    auto original = original_late<decltype(&::sceHttp2AddRequestHeader)>(
        "sceHttp2AddRequestHeader");
    const int ret = original ? original(id, name, value, mode) : -1;
    const bool redact = contains(name, "Authorization") || contains(name, "Cookie");
    online_klog("sceHttp2AddRequestHeader id=%d %s=%s mode=%u -> %d",
                id,
                name ? name : "<null>",
                redact ? "<redacted>" : (value ? value : "<null>"),
                mode,
                ret);
    return ret;
}

int sceHttp2RemoveRequestHeader_hook(int templateOrReqId, const char* name) {
    auto original =
        original_late<decltype(&::sceHttp2RemoveRequestHeader)>("sceHttp2RemoveRequestHeader");
    const int ret = original ? original(templateOrReqId, name) : -1;
    online_klog("sceHttp2RemoveRequestHeader id=%d name=%s -> %d",
                templateOrReqId,
                name ? name : "<null>",
                ret);
    return ret;
}

int sceHttp2SetRequestContentLength_hook(int reqId, uint64_t contentLength) {
    auto original =
        original_late<decltype(&::sceHttp2SetRequestContentLength)>("sceHttp2SetRequestContentLength");
    const int ret = original ? original(reqId, contentLength) : -1;
    online_klog("sceHttp2SetRequestContentLength req=%d len=%llu -> %d",
                reqId,
                static_cast<unsigned long long>(contentLength),
                ret);
    return ret;
}

int sceHttp2SetRequestNoContentLength_hook(int reqId) {
    using Fn = int (*)(int);
    auto original = original_late<Fn>("sceHttp2SetRequestNoContentLength");
    const int ret = original ? original(reqId) : -1;
    online_klog("sceHttp2SetRequestNoContentLength req=%d -> %d", reqId, ret);
    return ret;
}

int sceHttp2SetRequestServerName_hook(int reqId, const char* serverName) {
    using Fn = int (*)(int, const char*);
    auto original = original_late<Fn>("sceHttp2SetRequestServerName");
    const int ret = original ? original(reqId, serverName) : -1;
    online_klog("sceHttp2SetRequestServerName req=%d server=%s -> %d",
                reqId,
                serverName ? serverName : "<null>",
                ret);
    return ret;
}

int sceHttp2SetInflateGZIPEnabled_hook(int templateOrReqId, int isEnable) {
    auto original =
        original_late<decltype(&::sceHttp2SetInflateGZIPEnabled)>("sceHttp2SetInflateGZIPEnabled");
    const int ret = original ? original(templateOrReqId, isEnable) : -1;
    online_klog("sceHttp2SetInflateGZIPEnabled id=%d enable=%d -> %d",
                templateOrReqId,
                isEnable,
                ret);
    return ret;
}

int sceHttp2SendRequest_hook(int reqId, const void* postData, size_t size) {
    auto original = original_late<decltype(&::sceHttp2SendRequest)>("sceHttp2SendRequest");
    const int ret = original ? original(reqId, postData, size) : -1;
    online_klog("sceHttp2SendRequest req=%d post=%p size=%zu -> %d",
                reqId,
                postData,
                size,
                ret);
    return ret;
}

int sceHttp2SendRequestAsync_hook(int reqId,
                                  const void* postData,
                                  size_t size,
                                  SceHttp2TriggerUserEventArgs* kqueueOption,
                                  void* option) {
    auto original = original_late<decltype(&::sceHttp2SendRequestAsync)>(
        "sceHttp2SendRequestAsync");
    const int ret = original ? original(reqId, postData, size, kqueueOption, option) : -1;
    online_klog("sceHttp2SendRequestAsync req=%d post=%p size=%zu event=%p -> %d",
                reqId,
                postData,
                size,
                static_cast<void*>(kqueueOption),
                ret);
    return ret;
}

int sceHttp2GetResponseContentLength_hook(int reqId, int* result, uint64_t* contentLength) {
    auto original =
        original_late<decltype(&::sceHttp2GetResponseContentLength)>("sceHttp2GetResponseContentLength");
    const int ret = original ? original(reqId, result, contentLength) : -1;
    online_klog("sceHttp2GetResponseContentLength req=%d -> ret=%d result=%d len=%llu",
                reqId,
                ret,
                result ? *result : -1,
                contentLength ? static_cast<unsigned long long>(*contentLength) : 0ULL);
    return ret;
}

int sceHttp2GetStatusCode_hook(int reqId, int* statusCode) {
    auto original = original_late<decltype(&::sceHttp2GetStatusCode)>("sceHttp2GetStatusCode");
    const int ret = original ? original(reqId, statusCode) : -1;
    online_klog("sceHttp2GetStatusCode req=%d -> ret=%d status=%d",
                reqId,
                ret,
                statusCode ? *statusCode : -1);
    return ret;
}

int sceHttp2GetAllResponseHeaders_hook(int reqId, char** header, size_t* headerSize) {
    auto original =
        original_late<decltype(&::sceHttp2GetAllResponseHeaders)>("sceHttp2GetAllResponseHeaders");
    const int ret = original ? original(reqId, header, headerSize) : -1;
    online_klog("sceHttp2GetAllResponseHeaders req=%d -> ret=%d header=%p size=%zu",
                reqId,
                ret,
                header ? static_cast<void*>(*header) : nullptr,
                headerSize ? *headerSize : 0);
    return ret;
}

int sceHttp2GetAllTrailingHeaders_hook(int reqId, char** header, size_t* headerSize) {
    using Fn = int (*)(int, char**, size_t*);
    auto original = original_late<Fn>("sceHttp2GetAllTrailingHeaders");
    const int ret = original ? original(reqId, header, headerSize) : -1;
    online_klog("sceHttp2GetAllTrailingHeaders req=%d -> ret=%d header=%p size=%zu",
                reqId,
                ret,
                header ? static_cast<void*>(*header) : nullptr,
                headerSize ? *headerSize : 0);
    return ret;
}

int sceHttp2ReadData_hook(int reqId, void* data, size_t size) {
    auto original = original_late<decltype(&::sceHttp2ReadData)>("sceHttp2ReadData");
    const int ret = original ? original(reqId, data, size) : -1;
    online_klog("sceHttp2ReadData req=%d size=%zu -> %d", reqId, size, ret);
    return ret;
}

int sceHttp2ReadDataAsync_hook(int reqId,
                               void* data,
                               size_t size,
                               SceHttp2TriggerUserEventArgs* kqueueOption,
                               void* option) {
    auto original = original_late<decltype(&::sceHttp2ReadDataAsync)>("sceHttp2ReadDataAsync");
    const int ret = original ? original(reqId, data, size, kqueueOption, option) : -1;
    online_klog("sceHttp2ReadDataAsync req=%d size=%zu event=%p -> %d",
                reqId,
                size,
                static_cast<void*>(kqueueOption),
                ret);
    return ret;
}

int sceHttp2WaitAsync_hook(int reqId,
                           SceHttp2AsyncResult* result,
                           SceKernelUseconds* timeout,
                           void* option) {
    auto original = original_late<decltype(&::sceHttp2WaitAsync)>("sceHttp2WaitAsync");
    const int ret = original ? original(reqId, result, timeout, option) : -1;
    online_klog("sceHttp2WaitAsync req=%d -> ret=%d event=%d result=%d",
                reqId,
                ret,
                result ? static_cast<int>(result->eventType) : -1,
                result ? result->result : -1);
    return ret;
}

int sceHttp2SetAuthInfoCallback_hook(int templateOrReqId,
                                     SceHttp2AuthInfoCallback cbfunc,
                                     void* userArg) {
    auto original =
        original_late<decltype(&::sceHttp2SetAuthInfoCallback)>("sceHttp2SetAuthInfoCallback");
    const int ret = original ? original(templateOrReqId, cbfunc, userArg) : -1;
    online_klog("sceHttp2SetAuthInfoCallback id=%d cb=%p user=%p -> %d",
                templateOrReqId,
                reinterpret_cast<void*>(cbfunc),
                userArg,
                ret);
    return ret;
}

int sceHttp2SetAuthEnabled_hook(int templateOrReqId, int isEnable) {
    auto original = original_late<decltype(&::sceHttp2SetAuthEnabled)>("sceHttp2SetAuthEnabled");
    const int ret = original ? original(templateOrReqId, isEnable) : -1;
    online_klog("sceHttp2SetAuthEnabled id=%d enable=%d -> %d",
                templateOrReqId,
                isEnable,
                ret);
    return ret;
}

int sceHttp2GetAuthEnabled_hook(int templateOrReqId, int* isEnable) {
    auto original = original_late<decltype(&::sceHttp2GetAuthEnabled)>("sceHttp2GetAuthEnabled");
    const int ret = original ? original(templateOrReqId, isEnable) : -1;
    online_klog("sceHttp2GetAuthEnabled id=%d -> ret=%d enable=%d",
                templateOrReqId,
                ret,
                isEnable ? *isEnable : -1);
    return ret;
}

int sceHttp2AuthCacheFlush_hook(int libhttpCtxId) {
    auto original = original_late<decltype(&::sceHttp2AuthCacheFlush)>("sceHttp2AuthCacheFlush");
    const int ret = original ? original(libhttpCtxId) : -1;
    online_klog("sceHttp2AuthCacheFlush ctx=%d -> %d", libhttpCtxId, ret);
    return ret;
}

int sceHttp2SetRedirectCallback_hook(int templateOrReqId,
                                     SceHttp2RedirectCallback cbfunc,
                                     void* userArg) {
    auto original =
        original_late<decltype(&::sceHttp2SetRedirectCallback)>("sceHttp2SetRedirectCallback");
    const int ret = original ? original(templateOrReqId, cbfunc, userArg) : -1;
    online_klog("sceHttp2SetRedirectCallback id=%d cb=%p user=%p -> %d",
                templateOrReqId,
                reinterpret_cast<void*>(cbfunc),
                userArg,
                ret);
    return ret;
}

int sceHttp2SetAutoRedirect_hook(int templateOrReqId, int isEnable) {
    auto original = original_late<decltype(&::sceHttp2SetAutoRedirect)>("sceHttp2SetAutoRedirect");
    const int ret = original ? original(templateOrReqId, isEnable) : -1;
    online_klog("sceHttp2SetAutoRedirect id=%d enable=%d -> %d",
                templateOrReqId,
                isEnable,
                ret);
    return ret;
}

int sceHttp2GetAutoRedirect_hook(int templateOrReqId, int* isEnable) {
    auto original = original_late<decltype(&::sceHttp2GetAutoRedirect)>("sceHttp2GetAutoRedirect");
    const int ret = original ? original(templateOrReqId, isEnable) : -1;
    online_klog("sceHttp2GetAutoRedirect id=%d -> ret=%d enable=%d",
                templateOrReqId,
                ret,
                isEnable ? *isEnable : -1);
    return ret;
}

int sceHttp2RedirectCacheFlush_hook(int libhttpCtxId) {
    auto original =
        original_late<decltype(&::sceHttp2RedirectCacheFlush)>("sceHttp2RedirectCacheFlush");
    const int ret = original ? original(libhttpCtxId) : -1;
    online_klog("sceHttp2RedirectCacheFlush ctx=%d -> %d", libhttpCtxId, ret);
    return ret;
}

int sceHttp2SetTimeOut_hook(int templateOrReqId, uint32_t usec) {
    auto original = original_late<decltype(&::sceHttp2SetTimeOut)>("sceHttp2SetTimeOut");
    const int ret = original ? original(templateOrReqId, usec) : -1;
    online_klog("sceHttp2SetTimeOut id=%d usec=%u -> %d", templateOrReqId, usec, ret);
    return ret;
}

int sceHttp2SetResolveTimeOut_hook(int templateOrReqId, uint32_t usec) {
    auto original =
        original_late<decltype(&::sceHttp2SetResolveTimeOut)>("sceHttp2SetResolveTimeOut");
    const int ret = original ? original(templateOrReqId, usec) : -1;
    online_klog("sceHttp2SetResolveTimeOut id=%d usec=%u -> %d", templateOrReqId, usec, ret);
    return ret;
}

int sceHttp2SetResolveRetry_hook(int templateOrReqId, int retry) {
    auto original = original_late<decltype(&::sceHttp2SetResolveRetry)>("sceHttp2SetResolveRetry");
    const int ret = original ? original(templateOrReqId, retry) : -1;
    online_klog("sceHttp2SetResolveRetry id=%d retry=%d -> %d", templateOrReqId, retry, ret);
    return ret;
}

int sceHttp2SetConnectTimeOut_hook(int templateOrReqId, uint32_t usec) {
    auto original =
        original_late<decltype(&::sceHttp2SetConnectTimeOut)>("sceHttp2SetConnectTimeOut");
    const int ret = original ? original(templateOrReqId, usec) : -1;
    online_klog("sceHttp2SetConnectTimeOut id=%d usec=%u -> %d", templateOrReqId, usec, ret);
    return ret;
}

int sceHttp2SetSendTimeOut_hook(int templateOrReqId, uint32_t usec) {
    auto original = original_late<decltype(&::sceHttp2SetSendTimeOut)>("sceHttp2SetSendTimeOut");
    const int ret = original ? original(templateOrReqId, usec) : -1;
    online_klog("sceHttp2SetSendTimeOut id=%d usec=%u -> %d", templateOrReqId, usec, ret);
    return ret;
}

int sceHttp2SetRecvTimeOut_hook(int templateOrReqId, uint32_t usec) {
    auto original = original_late<decltype(&::sceHttp2SetRecvTimeOut)>("sceHttp2SetRecvTimeOut");
    const int ret = original ? original(templateOrReqId, usec) : -1;
    online_klog("sceHttp2SetRecvTimeOut id=%d usec=%u -> %d", templateOrReqId, usec, ret);
    return ret;
}

int sceHttp2SetConnectionWaitTimeOut_hook(int templateOrReqId, uint32_t usec) {
    auto original =
        original_late<decltype(&::sceHttp2SetConnectionWaitTimeOut)>("sceHttp2SetConnectionWaitTimeOut");
    const int ret = original ? original(templateOrReqId, usec) : -1;
    online_klog("sceHttp2SetConnectionWaitTimeOut id=%d usec=%u -> %d",
                templateOrReqId,
                usec,
                ret);
    return ret;
}

int sceHttp2SetProxyWithURL_hook(int templateOrReqId, const char* proxyUrl) {
    using Fn = int (*)(int, const char*);
    auto original = original_late<Fn>("sceHttp2SetProxyWithURL");
    const int ret = original ? original(templateOrReqId, proxyUrl) : -1;
    online_klog("sceHttp2SetProxyWithURL id=%d proxy=%s -> %d",
                templateOrReqId,
                proxyUrl ? proxyUrl : "<null>",
                ret);
    return ret;
}

int sceHttp2WebSocketCreateRequest_hook(int tmplId,
                                        const char* url,
                                        void* textMessageFunc,
                                        void* dataMessageFunc,
                                        void* normalCloseFunc,
                                        void* errorCloseFunc,
                                        void* recvMessageBuffer,
                                        size_t recvMessageBufferSize,
                                        void* callbackUserArg,
                                        void* option) {
    using Fn = int (*)(int, const char*, void*, void*, void*, void*, void*, size_t, void*, void*);
    auto original = original_late<Fn>("sceHttp2WebSocketCreateRequest");
    const int ret = original ? original(tmplId,
                                        url,
                                        textMessageFunc,
                                        dataMessageFunc,
                                        normalCloseFunc,
                                        errorCloseFunc,
                                        recvMessageBuffer,
                                        recvMessageBufferSize,
                                        callbackUserArg,
                                        option)
                             : -1;
    online_klog("sceHttp2WebSocketCreateRequest tmpl=%d url=%s recv=%p size=%zu -> %d",
                tmplId,
                url ? url : "<null>",
                recvMessageBuffer,
                recvMessageBufferSize,
                ret);
    return ret;
}

int sceHttp2WebSocketSendTextMessage_hook(int reqId,
                                          const char* utf8Message,
                                          int flags,
                                          void* option) {
    using Fn = int (*)(int, const char*, int, void*);
    auto original = original_late<Fn>("sceHttp2WebSocketSendTextMessage");
    const int ret = original ? original(reqId, utf8Message, flags, option) : -1;
    online_klog("sceHttp2WebSocketSendTextMessage req=%d len=%zu flags=0x%x -> %d",
                reqId,
                utf8Message ? strlen(utf8Message) : 0,
                flags,
                ret);
    return ret;
}

int sceHttp2WebSocketSendTextMessageAsync_hook(int reqId,
                                               const char* utf8Message,
                                               int flags,
                                               SceHttp2TriggerUserEventArgs* kqueueOption,
                                               void* option) {
    using Fn = int (*)(int, const char*, int, SceHttp2TriggerUserEventArgs*, void*);
    auto original = original_late<Fn>("sceHttp2WebSocketSendTextMessageAsync");
    const int ret = original ? original(reqId, utf8Message, flags, kqueueOption, option) : -1;
    online_klog("sceHttp2WebSocketSendTextMessageAsync req=%d len=%zu flags=0x%x event=%p -> %d",
                reqId,
                utf8Message ? strlen(utf8Message) : 0,
                flags,
                static_cast<void*>(kqueueOption),
                ret);
    return ret;
}

int sceHttp2WebSocketSendDataMessage_hook(int reqId,
                                          const void* data,
                                          size_t dataSize,
                                          int flags,
                                          void* option) {
    using Fn = int (*)(int, const void*, size_t, int, void*);
    auto original = original_late<Fn>("sceHttp2WebSocketSendDataMessage");
    const int ret = original ? original(reqId, data, dataSize, flags, option) : -1;
    online_klog("sceHttp2WebSocketSendDataMessage req=%d data=%p size=%zu flags=0x%x -> %d",
                reqId,
                data,
                dataSize,
                flags,
                ret);
    return ret;
}

int sceHttp2WebSocketSendDataMessageAsync_hook(int reqId,
                                               const void* data,
                                               size_t dataSize,
                                               int flags,
                                               SceHttp2TriggerUserEventArgs* kqueueOption,
                                               void* option) {
    using Fn = int (*)(int, const void*, size_t, int, SceHttp2TriggerUserEventArgs*, void*);
    auto original = original_late<Fn>("sceHttp2WebSocketSendDataMessageAsync");
    const int ret = original ? original(reqId, data, dataSize, flags, kqueueOption, option) : -1;
    online_klog("sceHttp2WebSocketSendDataMessageAsync req=%d data=%p size=%zu flags=0x%x event=%p -> %d",
                reqId,
                data,
                dataSize,
                flags,
                static_cast<void*>(kqueueOption),
                ret);
    return ret;
}

int sceHttp2WebSocketClose_hook(int reqId,
                                const uint16_t* optionalStatusCode,
                                const char* optionalUtf8Message,
                                int flags,
                                void* option) {
    using Fn = int (*)(int, const uint16_t*, const char*, int, void*);
    auto original = original_late<Fn>("sceHttp2WebSocketClose");
    const int ret = original ? original(reqId, optionalStatusCode, optionalUtf8Message, flags, option) : -1;
    online_klog("sceHttp2WebSocketClose req=%d code=%u msg=%s flags=0x%x -> %d",
                reqId,
                optionalStatusCode ? static_cast<unsigned>(*optionalStatusCode) : 0,
                optionalUtf8Message ? optionalUtf8Message : "<null>",
                flags,
                ret);
    return ret;
}

int sceHttp2WebSocketCloseAsync_hook(int reqId,
                                     const uint16_t* optionalStatusCode,
                                     const char* optionalUtf8Message,
                                     int flags,
                                     SceHttp2TriggerUserEventArgs* kqueueOption,
                                     void* option) {
    using Fn = int (*)(int, const uint16_t*, const char*, int, SceHttp2TriggerUserEventArgs*, void*);
    auto original = original_late<Fn>("sceHttp2WebSocketCloseAsync");
    const int ret =
        original ? original(reqId, optionalStatusCode, optionalUtf8Message, flags, kqueueOption, option) : -1;
    online_klog("sceHttp2WebSocketCloseAsync req=%d code=%u msg=%s flags=0x%x event=%p -> %d",
                reqId,
                optionalStatusCode ? static_cast<unsigned>(*optionalStatusCode) : 0,
                optionalUtf8Message ? optionalUtf8Message : "<null>",
                flags,
                static_cast<void*>(kqueueOption),
                ret);
    return ret;
}

int sceHttp2WebSocketSetPingTimeout_hook(int reqId, uint32_t usec) {
    using Fn = int (*)(int, uint32_t);
    auto original = original_late<Fn>("sceHttp2WebSocketSetPingTimeout");
    const int ret = original ? original(reqId, usec) : -1;
    online_klog("sceHttp2WebSocketSetPingTimeout req=%d usec=%u -> %d", reqId, usec, ret);
    return ret;
}

int sceHttp2WebSocketSetPingInterval_hook(int reqId, uint32_t usec) {
    using Fn = int (*)(int, uint32_t);
    auto original = original_late<Fn>("sceHttp2WebSocketSetPingInterval");
    const int ret = original ? original(reqId, usec) : -1;
    online_klog("sceHttp2WebSocketSetPingInterval req=%d usec=%u -> %d", reqId, usec, ret);
    return ret;
}

int sceHttp2AbortRequest_hook(int reqId) {
    auto original = original_late<decltype(&::sceHttp2AbortRequest)>("sceHttp2AbortRequest");
    const int ret = original ? original(reqId) : -1;
    online_klog("sceHttp2AbortRequest req=%d -> %d", reqId, ret);
    return ret;
}

int sceNetCtlInit_hook(void) {
    online_klog("sceNetCtlInit -> OK");
    return SCE_OK;
}

void sceNetCtlTerm_hook(void) {
    online_klog("sceNetCtlTerm");
}

int sceNetCtlCheckCallback_hook(void) {
    bool delivered = false;
    if (g_netCtlCallbackPending.exchange(false, std::memory_order_relaxed)) {
        auto callback = reinterpret_cast<SceNetCtlCallback>(
            g_netCtlCallback.load(std::memory_order_relaxed));
        if (callback) {
            callback(SCE_NET_CTL_EVENT_TYPE_IPOBTAINED,
                     g_netCtlCallbackArg.load(std::memory_order_relaxed));
            delivered = true;
        }
    }
    if (g_netCtlCallbackV6Pending.exchange(false, std::memory_order_relaxed)) {
        auto callback = reinterpret_cast<SceNetCtlCallback>(
            g_netCtlCallbackV6.load(std::memory_order_relaxed));
        if (callback) {
            callback(SCE_NET_CTL_EVENT_TYPE_IPOBTAINED,
                     g_netCtlCallbackV6Arg.load(std::memory_order_relaxed));
            delivered = true;
        }
    }
    online_klog("sceNetCtlCheckCallback -> %s", delivered ? "delivered" : "OK");
    return SCE_OK;
}

int sceNetCtlRegisterCallback_hook(SceNetCtlCallback func, void* arg, int* cid) {
    if (!func || !cid) {
        online_klog("sceNetCtlRegisterCallback cb=%p cid=%p -> invalid_addr",
                    reinterpret_cast<void*>(func),
                    static_cast<void*>(cid));
        return SCE_NET_CTL_ERROR_INVALID_ADDR;
    }
    *cid = next_id(g_netCtlCallbackId);
    g_netCtlCallback.store(reinterpret_cast<uintptr_t>(func), std::memory_order_relaxed);
    g_netCtlCallbackArg.store(arg, std::memory_order_relaxed);
    g_netCtlCallbackPending.store(true, std::memory_order_relaxed);
    online_klog("sceNetCtlRegisterCallback cb=%p -> cid=%d",
                reinterpret_cast<void*>(func),
                *cid);
    return SCE_OK;
}

int sceNetCtlRegisterCallbackV6_hook(SceNetCtlCallback func, void* arg, int* cid) {
    if (!func || !cid) {
        online_klog("sceNetCtlRegisterCallbackV6 cb=%p cid=%p -> invalid_addr",
                    reinterpret_cast<void*>(func),
                    static_cast<void*>(cid));
        return SCE_NET_CTL_ERROR_INVALID_ADDR;
    }
    *cid = next_id(g_netCtlCallbackV6Id);
    g_netCtlCallbackV6.store(reinterpret_cast<uintptr_t>(func), std::memory_order_relaxed);
    g_netCtlCallbackV6Arg.store(arg, std::memory_order_relaxed);
    g_netCtlCallbackV6Pending.store(true, std::memory_order_relaxed);
    online_klog("sceNetCtlRegisterCallbackV6 cb=%p -> cid=%d",
                reinterpret_cast<void*>(func),
                *cid);
    return SCE_OK;
}

int sceNetCtlUnregisterCallback_hook(int cid) {
    g_netCtlCallback.store(0, std::memory_order_relaxed);
    g_netCtlCallbackArg.store(nullptr, std::memory_order_relaxed);
    g_netCtlCallbackPending.store(false, std::memory_order_relaxed);
    online_klog("sceNetCtlUnregisterCallback cid=%d -> OK", cid);
    return SCE_OK;
}

int sceNetCtlUnregisterCallbackV6_hook(int cid) {
    g_netCtlCallbackV6.store(0, std::memory_order_relaxed);
    g_netCtlCallbackV6Arg.store(nullptr, std::memory_order_relaxed);
    g_netCtlCallbackV6Pending.store(false, std::memory_order_relaxed);
    online_klog("sceNetCtlUnregisterCallbackV6 cid=%d -> OK", cid);
    return SCE_OK;
}

int sceNetCtlGetResult_hook(int eventType, int* errorCode) {
    if (!errorCode) {
        online_klog("sceNetCtlGetResult event=%d -> invalid_addr", eventType);
        return SCE_NET_CTL_ERROR_INVALID_ADDR;
    }
    *errorCode = SCE_OK;
    online_klog("sceNetCtlGetResult event=%d -> error=OK", eventType);
    return SCE_OK;
}

int sceNetCtlGetResultV6_hook(int eventType, int* errorCode) {
    if (!errorCode) {
        online_klog("sceNetCtlGetResultV6 event=%d -> invalid_addr", eventType);
        return SCE_NET_CTL_ERROR_INVALID_ADDR;
    }
    *errorCode = SCE_OK;
    online_klog("sceNetCtlGetResultV6 event=%d -> error=OK", eventType);
    return SCE_OK;
}

int sceNetCtlGetState_hook(int* state) {
    if (!state) {
        online_klog("sceNetCtlGetState -> invalid_addr");
        return SCE_NET_CTL_ERROR_INVALID_ADDR;
    }
    *state = SCE_NET_CTL_STATE_IPOBTAINED;
    online_klog("sceNetCtlGetState -> IPOBTAINED");
    return SCE_OK;
}

int sceNetCtlGetStateV6_hook(int* state) {
    if (!state) {
        online_klog("sceNetCtlGetStateV6 -> invalid_addr");
        return SCE_NET_CTL_ERROR_INVALID_ADDR;
    }
    *state = SCE_NET_CTL_STATE_IPOBTAINED;
    online_klog("sceNetCtlGetStateV6 -> IPOBTAINED");
    return SCE_OK;
}

int sceNetCtlGetInfo_hook(int code, SceNetCtlInfo* info) {
    if (!info) {
        online_klog("sceNetCtlGetInfo code=%d -> invalid_addr", code);
        return SCE_NET_CTL_ERROR_INVALID_ADDR;
    }
    memset(info, 0, sizeof(*info));
    switch (code) {
    case SCE_NET_CTL_INFO_DEVICE:
        info->device = SCE_NET_CTL_DEVICE_WIRED;
        break;
    case SCE_NET_CTL_INFO_MTU:
        info->mtu = 1500;
        break;
    case SCE_NET_CTL_INFO_LINK:
        info->link = SCE_NET_CTL_LINK_CONNECTED;
        break;
    case SCE_NET_CTL_INFO_IP_CONFIG:
        info->ip_config = SCE_NET_CTL_IP_DHCP;
        break;
    case SCE_NET_CTL_INFO_IP_ADDRESS:
        copy_cstr(info->ip_address, sizeof(info->ip_address), "192.168.0.2");
        break;
    case SCE_NET_CTL_INFO_NETMASK:
        copy_cstr(info->netmask, sizeof(info->netmask), "255.255.255.0");
        break;
    case SCE_NET_CTL_INFO_DEFAULT_ROUTE:
        copy_cstr(info->default_route, sizeof(info->default_route), "192.168.0.1");
        break;
    case SCE_NET_CTL_INFO_PRIMARY_DNS:
        copy_cstr(info->primary_dns, sizeof(info->primary_dns), "1.1.1.1");
        break;
    case SCE_NET_CTL_INFO_SECONDARY_DNS:
        copy_cstr(info->secondary_dns, sizeof(info->secondary_dns), "8.8.8.8");
        break;
    case SCE_NET_CTL_INFO_HTTP_PROXY_CONFIG:
        info->http_proxy_config = SCE_NET_CTL_HTTP_PROXY_OFF;
        break;
    case SCE_NET_CTL_INFO_HTTP_PROXY_PORT:
        info->http_proxy_port = 0;
        break;
    default:
        break;
    }
    online_klog("sceNetCtlGetInfo code=%d -> OK", code);
    return SCE_OK;
}

int sceNetCtlGetInfoV6_hook(int code, SceNetCtlInfoV6* info) {
    if (!info) {
        online_klog("sceNetCtlGetInfoV6 code=%d -> invalid_addr", code);
        return SCE_NET_CTL_ERROR_INVALID_ADDR;
    }
    memset(info, 0, sizeof(*info));
    switch (code) {
    case SCE_NET_CTL_INFO_V6_IP_ADDRESS:
        copy_cstr(info->ip_address.address, sizeof(info->ip_address.address), "2001:db8::2");
        info->ip_address.prefix_len = 64;
        break;
    case SCE_NET_CTL_INFO_V6_LINK_LOCAL_ADDRESS:
        copy_cstr(info->link_local_address.address,
                  sizeof(info->link_local_address.address),
                  "fe80::2");
        info->link_local_address.prefix_len = 64;
        break;
    case SCE_NET_CTL_INFO_V6_DEFAULT_ROUTE:
        copy_cstr(info->default_route, sizeof(info->default_route), "fe80::1");
        break;
    case SCE_NET_CTL_INFO_V6_PRIMARY_DNS:
        copy_cstr(info->primary_dns, sizeof(info->primary_dns), "2606:4700:4700::1111");
        break;
    case SCE_NET_CTL_INFO_V6_SECONDARY_DNS:
        copy_cstr(info->secondary_dns, sizeof(info->secondary_dns), "2001:4860:4860::8888");
        break;
    default:
        break;
    }
    online_klog("sceNetCtlGetInfoV6 code=%d -> OK", code);
    return SCE_OK;
}

int sceNetCtlGetIfStat_hook(SceNetCtlIfStat* ifStat) {
    if (!ifStat) {
        online_klog("sceNetCtlGetIfStat -> invalid_addr");
        return SCE_NET_CTL_ERROR_INVALID_ADDR;
    }
    memset(ifStat, 0, sizeof(*ifStat));
    ifStat->device = SCE_NET_CTL_DEVICE_WIRED;
    ifStat->txBytes = 1024 * 1024;
    ifStat->rxBytes = 1024 * 1024;
    online_klog("sceNetCtlGetIfStat -> wired tx=%llu rx=%llu",
                static_cast<unsigned long long>(ifStat->txBytes),
                static_cast<unsigned long long>(ifStat->rxBytes));
    return SCE_OK;
}

int sceNetCtlGetNatInfo_hook(SceNetCtlNatInfo* natInfo) {
    if (!natInfo) {
        online_klog("sceNetCtlGetNatInfo -> invalid_addr");
        return SCE_NET_CTL_ERROR_INVALID_ADDR;
    }
    memset(natInfo, 0, sizeof(*natInfo));
    natInfo->size = sizeof(*natInfo);
    natInfo->stunStatus = SCE_NET_CTL_NATINFO_STUN_OK;
    natInfo->natType = SCE_NET_CTL_NATINFO_NAT_TYPE_2;
    natInfo->mappedAddr.s_addr = 0x0200A8C0u;
    online_klog("sceNetCtlGetNatInfo -> stun=OK nat=2");
    return SCE_OK;
}

int sceNetResolverStartNtoa_hook(SceNetId rid,
                                 const char* hostname,
                                 SceNetInAddr* addr,
                                 int timeout,
                                 int retry,
                                 int flags) {
    auto original =
        original_late<decltype(&::sceNetResolverStartNtoa)>("sceNetResolverStartNtoa");
    const int ret = original ? original(rid, hostname, addr, timeout, retry, flags) : -1;
    char ip[32];
    format_net_in_addr(addr ? *addr : SceNetInAddr{}, ip, sizeof(ip));
    online_klog("sceNetResolverStartNtoa rid=%d host=%s timeout=%d retry=%d flags=0x%x -> ret=%d addr=%s",
                rid,
                hostname ? hostname : "<null>",
                timeout,
                retry,
                flags,
                ret,
                addr ? ip : "<null>");
    return ret;
}

int sceNetResolverStartNtoaMultipleRecords_hook(SceNetId rid,
                                                const char* hostname,
                                                SceNetResolverInfo* info,
                                                int timeout,
                                                int retry,
                                                int flags) {
    auto original = original_late<decltype(&::sceNetResolverStartNtoaMultipleRecords)>(
        "sceNetResolverStartNtoaMultipleRecords");
    const int ret = original ? original(rid, hostname, info, timeout, retry, flags) : -1;
    char firstIp[32] = "<none>";
    if (info && info->records > 0) {
        format_net_in_addr(info->addrs[0].un.addr, firstIp, sizeof(firstIp));
    }
    online_klog("sceNetResolverStartNtoaMultipleRecords rid=%d host=%s timeout=%d retry=%d flags=0x%x -> ret=%d records=%d first=%s",
                rid,
                hostname ? hostname : "<null>",
                timeout,
                retry,
                flags,
                ret,
                info ? info->records : 0,
                firstIp);
    return ret;
}

int sceNetResolverGetError_hook(SceNetId rid, int* result) {
    auto original = original_late<decltype(&::sceNetResolverGetError)>("sceNetResolverGetError");
    const int ret = original ? original(rid, result) : -1;
    online_klog("sceNetResolverGetError rid=%d -> ret=%d result=%d",
                rid,
                ret,
                result ? *result : 0);
    return ret;
}

SceNetId sceNetSocket_hook(const char* name, int domain, int type, int protocol) {
    auto original = original_late<decltype(&::sceNetSocket)>("sceNetSocket");
    const SceNetId ret = original ? original(name, domain, type, protocol) : -1;
    online_klog("sceNetSocket name=%s domain=%d type=%d proto=%d -> %d",
                name ? name : "<null>",
                domain,
                type,
                protocol,
                ret);
    return ret;
}

int sceNetConnect_hook(SceNetId s, const SceNetSockaddr* name, SceNetSocklen_t namelen) {
    auto original = original_late<decltype(&::sceNetConnect)>("sceNetConnect");
    char addr[64];
    describe_net_sockaddr(name, addr, sizeof(addr));
    const int ret = original ? original(s, name, namelen) : -1;
    online_klog("sceNetConnect sock=%d addr=%s len=%u -> %d",
                s,
                addr,
                static_cast<unsigned>(namelen),
                ret);
    return ret;
}

int sceNetSend_hook(SceNetId s, const void* msg, size_t len, int flags) {
    auto original = original_late<decltype(&::sceNetSend)>("sceNetSend");
    const int ret = original ? original(s, msg, len, flags) : -1;
    online_klog("sceNetSend sock=%d len=%zu flags=0x%x -> %d", s, len, flags, ret);
    return ret;
}

int sceNetRecv_hook(SceNetId s, void* buf, size_t len, int flags) {
    auto original = original_late<decltype(&::sceNetRecv)>("sceNetRecv");
    const int ret = original ? original(s, buf, len, flags) : -1;
    online_klog("sceNetRecv sock=%d len=%zu flags=0x%x -> %d", s, len, flags, ret);
    return ret;
}

int sceNetSocketClose_hook(SceNetId s) {
    auto original = original_late<decltype(&::sceNetSocketClose)>("sceNetSocketClose");
    const int ret = original ? original(s) : -1;
    online_klog("sceNetSocketClose sock=%d -> %d", s, ret);
    return ret;
}

#define CHECK_HOOK_SIGNATURE(name) \
    static_assert(std::is_same_v<decltype(&name##_hook), decltype(&::name)>, #name " hook signature mismatch")

CHECK_HOOK_SIGNATURE(sceCommonDialogInitialize);
CHECK_HOOK_SIGNATURE(sceCommonDialogIsUsed);
CHECK_HOOK_SIGNATURE(sceUserServiceInitialize);
CHECK_HOOK_SIGNATURE(sceUserServiceInitialize2);
CHECK_HOOK_SIGNATURE(sceUserServiceTerminate);
CHECK_HOOK_SIGNATURE(sceUserServiceGetLoginUserIdList);
CHECK_HOOK_SIGNATURE(sceUserServiceGetEvent);
CHECK_HOOK_SIGNATURE(sceUserServiceGetInitialUser);
CHECK_HOOK_SIGNATURE(sceUserServiceGetUserName);
CHECK_HOOK_SIGNATURE(sceUserServiceGetUserNumber);
CHECK_HOOK_SIGNATURE(sceUserServiceGetGamePresets);
CHECK_HOOK_SIGNATURE(sceUserServiceGetAgeLevel);
CHECK_HOOK_SIGNATURE(sceUserServiceGetAccessibilityChatTranscription);
CHECK_HOOK_SIGNATURE(sceUserServiceGetAccessibilityPressAndHoldDelay);
CHECK_HOOK_SIGNATURE(sceUserServiceGetAccessibilityTriggerEffect);
CHECK_HOOK_SIGNATURE(sceSystemServiceReceiveEvent);
CHECK_HOOK_SIGNATURE(sceSystemServiceGetStatus);
CHECK_HOOK_SIGNATURE(sceNpSetNpTitleId);
CHECK_HOOK_SIGNATURE(sceNpSetAdditionalScope);
CHECK_HOOK_SIGNATURE(sceNpCheckCallback);
CHECK_HOOK_SIGNATURE(sceNpGetState);
CHECK_HOOK_SIGNATURE(sceNpRegisterStateCallbackA);
CHECK_HOOK_SIGNATURE(sceNpUnregisterStateCallbackA);
CHECK_HOOK_SIGNATURE(sceNpGetNpReachabilityState);
CHECK_HOOK_SIGNATURE(sceNpRegisterNpReachabilityStateCallback);
CHECK_HOOK_SIGNATURE(sceNpUnregisterNpReachabilityStateCallback);
CHECK_HOOK_SIGNATURE(sceNpHasSignedUp);
CHECK_HOOK_SIGNATURE(sceNpGetAccountIdA);
CHECK_HOOK_SIGNATURE(sceNpGetUserIdByAccountId);
CHECK_HOOK_SIGNATURE(sceNpGetOnlineId);
CHECK_HOOK_SIGNATURE(sceNpGetAccountCountryA);
CHECK_HOOK_SIGNATURE(sceNpNotifyPremiumFeature);
CHECK_HOOK_SIGNATURE(sceNpRegisterPremiumEventCallback);
CHECK_HOOK_SIGNATURE(sceNpUnregisterPremiumEventCallback);
CHECK_HOOK_SIGNATURE(sceNpCreateRequest);
CHECK_HOOK_SIGNATURE(sceNpCreateAsyncRequest);
CHECK_HOOK_SIGNATURE(sceNpDeleteRequest);
CHECK_HOOK_SIGNATURE(sceNpAbortRequest);
CHECK_HOOK_SIGNATURE(sceNpSetTimeout);
CHECK_HOOK_SIGNATURE(sceNpWaitAsync);
CHECK_HOOK_SIGNATURE(sceNpPollAsync);
CHECK_HOOK_SIGNATURE(sceNpGetAccountLanguage2);
CHECK_HOOK_SIGNATURE(sceNpGetAccountAge);
CHECK_HOOK_SIGNATURE(sceNpCheckNpReachability);
CHECK_HOOK_SIGNATURE(sceNpCheckPremium);
CHECK_HOOK_SIGNATURE(sceNpAuthCreateRequest);
CHECK_HOOK_SIGNATURE(sceNpAuthCreateAsyncRequest);
CHECK_HOOK_SIGNATURE(sceNpAuthDeleteRequest);
CHECK_HOOK_SIGNATURE(sceNpAuthAbortRequest);
CHECK_HOOK_SIGNATURE(sceNpAuthSetTimeout);
CHECK_HOOK_SIGNATURE(sceNpAuthWaitAsync);
CHECK_HOOK_SIGNATURE(sceNpAuthPollAsync);
CHECK_HOOK_SIGNATURE(sceNpAuthGetAuthorizationCodeV3);
CHECK_HOOK_SIGNATURE(sceNpAuthGetIdTokenV3);
CHECK_HOOK_SIGNATURE(sceSigninDialogInitialize);
CHECK_HOOK_SIGNATURE(sceSigninDialogTerminate);
CHECK_HOOK_SIGNATURE(sceSigninDialogOpen);
CHECK_HOOK_SIGNATURE(sceSigninDialogClose);
CHECK_HOOK_SIGNATURE(sceSigninDialogUpdateStatus);
CHECK_HOOK_SIGNATURE(sceSigninDialogGetStatus);
CHECK_HOOK_SIGNATURE(sceSigninDialogGetResult);
CHECK_HOOK_SIGNATURE(sceNpCommerceDialogInitialize);
CHECK_HOOK_SIGNATURE(sceNpCommerceDialogOpen);
CHECK_HOOK_SIGNATURE(sceNpCommerceDialogUpdateStatus);
CHECK_HOOK_SIGNATURE(sceNpCommerceDialogGetStatus);
CHECK_HOOK_SIGNATURE(sceNpCommerceDialogGetResult);
CHECK_HOOK_SIGNATURE(sceNpCommerceDialogClose);
CHECK_HOOK_SIGNATURE(sceNpCommerceDialogTerminate);
CHECK_HOOK_SIGNATURE(sceNpCommerceShowPsStoreIcon);
CHECK_HOOK_SIGNATURE(sceNpCommerceHidePsStoreIcon);
CHECK_HOOK_SIGNATURE(sceNpCommerceSetPsStoreIconLayout);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessInitialize);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessGetSkuFlag);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessGetAddcontEntitlementInfoList);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessGetAddcontEntitlementInfo);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessGetEntitlementKey);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessGenerateTransactionId);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessRequestConsumeUnifiedEntitlement);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessRequestConsumeServiceEntitlement);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessPollConsumeEntitlement);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessRequestUnifiedEntitlementInfo);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessPollUnifiedEntitlementInfo);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessRequestUnifiedEntitlementInfoList);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessPollUnifiedEntitlementInfoList);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessRequestServiceEntitlementInfo);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessPollServiceEntitlementInfo);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessRequestServiceEntitlementInfoList);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessPollServiceEntitlementInfoList);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessDeleteRequest);
CHECK_HOOK_SIGNATURE(sceNpEntitlementAccessAbortRequest);
CHECK_HOOK_SIGNATURE(sceNpGameIntentInitialize);
CHECK_HOOK_SIGNATURE(sceNpGameIntentTerminate);
CHECK_HOOK_SIGNATURE(sceNpGameIntentReceiveIntent);
CHECK_HOOK_SIGNATURE(sceNpGameIntentGetPropertyValueString);
CHECK_HOOK_SIGNATURE(sceNpBandwidthTestInitStartUpload);
CHECK_HOOK_SIGNATURE(sceNpBandwidthTestInitStartDownload);
CHECK_HOOK_SIGNATURE(sceNpBandwidthTestGetStatus);
CHECK_HOOK_SIGNATURE(sceNpBandwidthTestShutdown);
CHECK_HOOK_SIGNATURE(sceNpBandwidthTestAbort);
CHECK_HOOK_SIGNATURE(sceNpSessionSignalingInitialize);
CHECK_HOOK_SIGNATURE(sceNpSessionSignalingTerminate);
CHECK_HOOK_SIGNATURE(sceNpSessionSignalingCreateContext);
CHECK_HOOK_SIGNATURE(sceNpSessionSignalingRequestPrepare);
CHECK_HOOK_SIGNATURE(sceNpSessionSignalingDestroyContext);
CHECK_HOOK_SIGNATURE(sceNpSessionSignalingActivateUser);
CHECK_HOOK_SIGNATURE(sceNpSessionSignalingActivateSession);
CHECK_HOOK_SIGNATURE(sceNpSessionSignalingDeactivate);
CHECK_HOOK_SIGNATURE(sceNpSessionSignalingGetConnectionInfo);
CHECK_HOOK_SIGNATURE(sceNpSessionSignalingGetConnectionStatus);
CHECK_HOOK_SIGNATURE(sceNpSessionSignalingGetConnectionFromPeerAddress);
CHECK_HOOK_SIGNATURE(sceNpSessionSignalingGetConnectionFromNetAddress);
CHECK_HOOK_SIGNATURE(sceNpSessionSignalingGetLocalNetInfo);
CHECK_HOOK_SIGNATURE(sceNpSessionSignalingGetConnectionStatistics);
CHECK_HOOK_SIGNATURE(sceNpSessionSignalingGetMemoryInfo);
CHECK_HOOK_SIGNATURE(sceNpWebApi2Initialize);
CHECK_HOOK_SIGNATURE(sceNpWebApi2Terminate);
CHECK_HOOK_SIGNATURE(sceNpWebApi2CreateUserContext);
CHECK_HOOK_SIGNATURE(sceNpWebApi2DeleteUserContext);
CHECK_HOOK_SIGNATURE(sceNpWebApi2CreateRequest);
CHECK_HOOK_SIGNATURE(sceNpWebApi2DeleteRequest);
CHECK_HOOK_SIGNATURE(sceNpWebApi2AbortRequest);
CHECK_HOOK_SIGNATURE(sceNpWebApi2SendRequest);
CHECK_HOOK_SIGNATURE(sceNpWebApi2ReadData);
CHECK_HOOK_SIGNATURE(sceNpWebApi2AddHttpRequestHeader);
CHECK_HOOK_SIGNATURE(sceNpWebApi2GetHttpResponseHeaderValueLength);
CHECK_HOOK_SIGNATURE(sceNpWebApi2GetHttpResponseHeaderValue);
CHECK_HOOK_SIGNATURE(sceNpWebApi2GetMemoryPoolStats);
CHECK_HOOK_SIGNATURE(sceNpWebApi2SetRequestTimeout);
CHECK_HOOK_SIGNATURE(sceNpWebApi2CheckTimeout);
CHECK_HOOK_SIGNATURE(sceNpWebApi2AddWebTraceTag);
CHECK_HOOK_SIGNATURE(sceNpWebApi2PushEventCreateHandle);
CHECK_HOOK_SIGNATURE(sceNpWebApi2PushEventDeleteHandle);
CHECK_HOOK_SIGNATURE(sceNpWebApi2PushEventAbortHandle);
CHECK_HOOK_SIGNATURE(sceNpWebApi2PushEventSetHandleTimeout);
CHECK_HOOK_SIGNATURE(sceNpWebApi2PushEventCreateFilter);
CHECK_HOOK_SIGNATURE(sceNpWebApi2PushEventDeleteFilter);
CHECK_HOOK_SIGNATURE(sceNpWebApi2PushEventRegisterCallback);
CHECK_HOOK_SIGNATURE(sceNpWebApi2PushEventUnregisterCallback);
CHECK_HOOK_SIGNATURE(sceNpWebApi2PushEventRegisterPushContextCallback);
CHECK_HOOK_SIGNATURE(sceNpWebApi2PushEventUnregisterPushContextCallback);
CHECK_HOOK_SIGNATURE(sceNpWebApi2PushEventCreatePushContext);
CHECK_HOOK_SIGNATURE(sceNpWebApi2PushEventDeletePushContext);
CHECK_HOOK_SIGNATURE(sceNpWebApi2PushEventStartPushContextCallback);
CHECK_HOOK_SIGNATURE(sceHttpInit);
CHECK_HOOK_SIGNATURE(sceHttpTerm);
CHECK_HOOK_SIGNATURE(sceHttpCreateTemplate);
CHECK_HOOK_SIGNATURE(sceHttpCreateConnection);
CHECK_HOOK_SIGNATURE(sceHttpCreateConnectionWithURL);
CHECK_HOOK_SIGNATURE(sceHttpCreateRequest);
CHECK_HOOK_SIGNATURE(sceHttpCreateRequest2);
CHECK_HOOK_SIGNATURE(sceHttpCreateRequestWithURL);
CHECK_HOOK_SIGNATURE(sceHttpCreateRequestWithURL2);
CHECK_HOOK_SIGNATURE(sceHttpAddRequestHeader);
CHECK_HOOK_SIGNATURE(sceHttpSendRequest);
CHECK_HOOK_SIGNATURE(sceHttpGetStatusCode);
CHECK_HOOK_SIGNATURE(sceHttpGetLastErrno);
CHECK_HOOK_SIGNATURE(sceHttpReadData);
CHECK_HOOK_SIGNATURE(sceHttp2Init);
CHECK_HOOK_SIGNATURE(sceHttp2Term);
CHECK_HOOK_SIGNATURE(sceHttp2GetMemoryPoolStats);
CHECK_HOOK_SIGNATURE(sceHttp2CreateTemplate);
CHECK_HOOK_SIGNATURE(sceHttp2DeleteTemplate);
CHECK_HOOK_SIGNATURE(sceHttp2CreateRequestWithURL);
CHECK_HOOK_SIGNATURE(sceHttp2DeleteRequest);
CHECK_HOOK_SIGNATURE(sceHttp2SslEnableOption);
CHECK_HOOK_SIGNATURE(sceHttp2SslDisableOption);
CHECK_HOOK_SIGNATURE(sceHttp2SetSslCallback);
CHECK_HOOK_SIGNATURE(sceHttp2AddRequestHeader);
CHECK_HOOK_SIGNATURE(sceHttp2RemoveRequestHeader);
CHECK_HOOK_SIGNATURE(sceHttp2SetRequestContentLength);
CHECK_HOOK_SIGNATURE(sceHttp2SetInflateGZIPEnabled);
CHECK_HOOK_SIGNATURE(sceHttp2SendRequest);
CHECK_HOOK_SIGNATURE(sceHttp2SendRequestAsync);
CHECK_HOOK_SIGNATURE(sceHttp2GetResponseContentLength);
CHECK_HOOK_SIGNATURE(sceHttp2GetStatusCode);
CHECK_HOOK_SIGNATURE(sceHttp2GetAllResponseHeaders);
CHECK_HOOK_SIGNATURE(sceHttp2ReadData);
CHECK_HOOK_SIGNATURE(sceHttp2ReadDataAsync);
CHECK_HOOK_SIGNATURE(sceHttp2WaitAsync);
CHECK_HOOK_SIGNATURE(sceHttp2SetAuthInfoCallback);
CHECK_HOOK_SIGNATURE(sceHttp2SetAuthEnabled);
CHECK_HOOK_SIGNATURE(sceHttp2GetAuthEnabled);
CHECK_HOOK_SIGNATURE(sceHttp2AuthCacheFlush);
CHECK_HOOK_SIGNATURE(sceHttp2SetRedirectCallback);
CHECK_HOOK_SIGNATURE(sceHttp2SetAutoRedirect);
CHECK_HOOK_SIGNATURE(sceHttp2GetAutoRedirect);
CHECK_HOOK_SIGNATURE(sceHttp2RedirectCacheFlush);
CHECK_HOOK_SIGNATURE(sceHttp2SetTimeOut);
CHECK_HOOK_SIGNATURE(sceHttp2SetResolveTimeOut);
CHECK_HOOK_SIGNATURE(sceHttp2SetResolveRetry);
CHECK_HOOK_SIGNATURE(sceHttp2SetConnectTimeOut);
CHECK_HOOK_SIGNATURE(sceHttp2SetSendTimeOut);
CHECK_HOOK_SIGNATURE(sceHttp2SetRecvTimeOut);
CHECK_HOOK_SIGNATURE(sceHttp2SetConnectionWaitTimeOut);
CHECK_HOOK_SIGNATURE(sceHttp2AbortRequest);
CHECK_HOOK_SIGNATURE(sceNetCtlInit);
CHECK_HOOK_SIGNATURE(sceNetCtlTerm);
CHECK_HOOK_SIGNATURE(sceNetCtlCheckCallback);
CHECK_HOOK_SIGNATURE(sceNetCtlRegisterCallback);
CHECK_HOOK_SIGNATURE(sceNetCtlRegisterCallbackV6);
CHECK_HOOK_SIGNATURE(sceNetCtlUnregisterCallback);
CHECK_HOOK_SIGNATURE(sceNetCtlUnregisterCallbackV6);
CHECK_HOOK_SIGNATURE(sceNetCtlGetResult);
CHECK_HOOK_SIGNATURE(sceNetCtlGetResultV6);
CHECK_HOOK_SIGNATURE(sceNetCtlGetState);
CHECK_HOOK_SIGNATURE(sceNetCtlGetStateV6);
CHECK_HOOK_SIGNATURE(sceNetCtlGetInfo);
CHECK_HOOK_SIGNATURE(sceNetCtlGetInfoV6);
CHECK_HOOK_SIGNATURE(sceNetCtlGetIfStat);
CHECK_HOOK_SIGNATURE(sceNetCtlGetNatInfo);
CHECK_HOOK_SIGNATURE(sceNetResolverStartNtoa);
CHECK_HOOK_SIGNATURE(sceNetResolverStartNtoaMultipleRecords);
CHECK_HOOK_SIGNATURE(sceNetResolverGetError);
CHECK_HOOK_SIGNATURE(sceNetSocket);
CHECK_HOOK_SIGNATURE(sceNetConnect);
CHECK_HOOK_SIGNATURE(sceNetSend);
CHECK_HOOK_SIGNATURE(sceNetRecv);
CHECK_HOOK_SIGNATURE(sceNetSocketClose);

#undef CHECK_HOOK_SIGNATURE

const LateDlsymHookSpec g_onlineLateDlsymHooks[] = {
    {nullptr, "sceCommonDialogInitialize", reinterpret_cast<void*>(&sceCommonDialogInitialize_hook)},
    {nullptr, "sceCommonDialogIsUsed", reinterpret_cast<void*>(&sceCommonDialogIsUsed_hook)},
    {nullptr, "sceUserServiceInitialize", reinterpret_cast<void*>(&sceUserServiceInitialize_hook)},
    {nullptr, "sceUserServiceInitialize2", reinterpret_cast<void*>(&sceUserServiceInitialize2_hook)},
    {nullptr, "sceUserServiceTerminate", reinterpret_cast<void*>(&sceUserServiceTerminate_hook)},
    {nullptr, "sceUserServiceGetLoginUserIdList", reinterpret_cast<void*>(&sceUserServiceGetLoginUserIdList_hook)},
    {nullptr, "sceUserServiceGetEvent", reinterpret_cast<void*>(&sceUserServiceGetEvent_hook)},
    {nullptr, "sceUserServiceGetInitialUser", reinterpret_cast<void*>(&sceUserServiceGetInitialUser_hook)},
    {nullptr, "sceUserServiceGetUserName", reinterpret_cast<void*>(&sceUserServiceGetUserName_hook)},
    {nullptr, "sceUserServiceGetUserNumber", reinterpret_cast<void*>(&sceUserServiceGetUserNumber_hook)},
    {nullptr, "sceUserServiceGetGamePresets", reinterpret_cast<void*>(&sceUserServiceGetGamePresets_hook)},
    {nullptr, "sceUserServiceGetAgeLevel", reinterpret_cast<void*>(&sceUserServiceGetAgeLevel_hook)},
    {nullptr,
     "sceUserServiceGetAccessibilityChatTranscription",
     reinterpret_cast<void*>(&sceUserServiceGetAccessibilityChatTranscription_hook)},
    {nullptr,
     "sceUserServiceGetAccessibilityPressAndHoldDelay",
     reinterpret_cast<void*>(&sceUserServiceGetAccessibilityPressAndHoldDelay_hook)},
    {nullptr,
     "sceUserServiceGetAccessibilityTriggerEffect",
     reinterpret_cast<void*>(&sceUserServiceGetAccessibilityTriggerEffect_hook)},
    {nullptr, "sceSystemServiceReceiveEvent", reinterpret_cast<void*>(&sceSystemServiceReceiveEvent_hook)},
    {nullptr, "sceSystemServiceGetStatus", reinterpret_cast<void*>(&sceSystemServiceGetStatus_hook)},
    {nullptr, "sceNpSetNpTitleId", reinterpret_cast<void*>(&sceNpSetNpTitleId_hook)},
    {nullptr, "sceNpSetAdditionalScope", reinterpret_cast<void*>(&sceNpSetAdditionalScope_hook)},
    {nullptr, "sceNpCheckCallback", reinterpret_cast<void*>(&sceNpCheckCallback_hook)},
    {nullptr, "sceNpGetState", reinterpret_cast<void*>(&sceNpGetState_hook)},
    {nullptr, "sceNpRegisterStateCallbackA", reinterpret_cast<void*>(&sceNpRegisterStateCallbackA_hook)},
    {nullptr, "sceNpUnregisterStateCallbackA", reinterpret_cast<void*>(&sceNpUnregisterStateCallbackA_hook)},
    {nullptr, "sceNpGetNpReachabilityState", reinterpret_cast<void*>(&sceNpGetNpReachabilityState_hook)},
    {nullptr,
     "sceNpRegisterNpReachabilityStateCallback",
     reinterpret_cast<void*>(&sceNpRegisterNpReachabilityStateCallback_hook)},
    {nullptr,
     "sceNpUnregisterNpReachabilityStateCallback",
     reinterpret_cast<void*>(&sceNpUnregisterNpReachabilityStateCallback_hook)},
    {nullptr, "sceNpHasSignedUp", reinterpret_cast<void*>(&sceNpHasSignedUp_hook)},
    {nullptr, "sceNpGetAccountIdA", reinterpret_cast<void*>(&sceNpGetAccountIdA_hook)},
    {nullptr, "sceNpGetUserIdByAccountId", reinterpret_cast<void*>(&sceNpGetUserIdByAccountId_hook)},
    {nullptr, "sceNpGetOnlineId", reinterpret_cast<void*>(&sceNpGetOnlineId_hook)},
    {nullptr, "sceNpGetAccountCountryA", reinterpret_cast<void*>(&sceNpGetAccountCountryA_hook)},
    {nullptr, "sceNpNotifyPremiumFeature", reinterpret_cast<void*>(&sceNpNotifyPremiumFeature_hook)},
    {nullptr, "sceNpRegisterPremiumEventCallback", reinterpret_cast<void*>(&sceNpRegisterPremiumEventCallback_hook)},
    {nullptr, "sceNpUnregisterPremiumEventCallback", reinterpret_cast<void*>(&sceNpUnregisterPremiumEventCallback_hook)},
    {nullptr, "sceNpCreateRequest", reinterpret_cast<void*>(&sceNpCreateRequest_hook)},
    {nullptr, "sceNpCreateAsyncRequest", reinterpret_cast<void*>(&sceNpCreateAsyncRequest_hook)},
    {nullptr, "sceNpDeleteRequest", reinterpret_cast<void*>(&sceNpDeleteRequest_hook)},
    {nullptr, "sceNpAbortRequest", reinterpret_cast<void*>(&sceNpAbortRequest_hook)},
    {nullptr, "sceNpSetTimeout", reinterpret_cast<void*>(&sceNpSetTimeout_hook)},
    {nullptr, "sceNpWaitAsync", reinterpret_cast<void*>(&sceNpWaitAsync_hook)},
    {nullptr, "sceNpPollAsync", reinterpret_cast<void*>(&sceNpPollAsync_hook)},
    {nullptr, "sceNpGetAccountLanguage2", reinterpret_cast<void*>(&sceNpGetAccountLanguage2_hook)},
    {nullptr, "sceNpGetAccountAge", reinterpret_cast<void*>(&sceNpGetAccountAge_hook)},
    {nullptr, "sceNpCheckNpReachability", reinterpret_cast<void*>(&sceNpCheckNpReachability_hook)},
    {nullptr, "sceNpCheckPremium", reinterpret_cast<void*>(&sceNpCheckPremium_hook)},
    {nullptr, "sceNpAuthCreateRequest", reinterpret_cast<void*>(&sceNpAuthCreateRequest_hook)},
    {nullptr, "sceNpAuthCreateAsyncRequest", reinterpret_cast<void*>(&sceNpAuthCreateAsyncRequest_hook)},
    {nullptr, "sceNpAuthDeleteRequest", reinterpret_cast<void*>(&sceNpAuthDeleteRequest_hook)},
    {nullptr, "sceNpAuthAbortRequest", reinterpret_cast<void*>(&sceNpAuthAbortRequest_hook)},
    {nullptr, "sceNpAuthSetTimeout", reinterpret_cast<void*>(&sceNpAuthSetTimeout_hook)},
    {nullptr, "sceNpAuthWaitAsync", reinterpret_cast<void*>(&sceNpAuthWaitAsync_hook)},
    {nullptr, "sceNpAuthPollAsync", reinterpret_cast<void*>(&sceNpAuthPollAsync_hook)},
    {nullptr, "sceNpAuthGetAuthorizationCodeV3", reinterpret_cast<void*>(&sceNpAuthGetAuthorizationCodeV3_hook)},
    {nullptr, "sceNpAuthGetAuthorizedAppCode", reinterpret_cast<void*>(&sceNpAuthGetAuthorizedAppCode_hook)},
    {nullptr, "sceNpAuthGetIdTokenV3", reinterpret_cast<void*>(&sceNpAuthGetIdTokenV3_hook)},
    {nullptr, "sceSigninDialogInitialize", reinterpret_cast<void*>(&sceSigninDialogInitialize_hook)},
    {nullptr, "sceSigninDialogTerminate", reinterpret_cast<void*>(&sceSigninDialogTerminate_hook)},
    {nullptr, "sceSigninDialogOpen", reinterpret_cast<void*>(&sceSigninDialogOpen_hook)},
    {nullptr, "sceSigninDialogClose", reinterpret_cast<void*>(&sceSigninDialogClose_hook)},
    {nullptr, "sceSigninDialogUpdateStatus", reinterpret_cast<void*>(&sceSigninDialogUpdateStatus_hook)},
    {nullptr, "sceSigninDialogGetStatus", reinterpret_cast<void*>(&sceSigninDialogGetStatus_hook)},
    {nullptr, "sceSigninDialogGetResult", reinterpret_cast<void*>(&sceSigninDialogGetResult_hook)},
    {nullptr, "sceNpCommerceDialogInitialize", reinterpret_cast<void*>(&sceNpCommerceDialogInitialize_hook)},
    {nullptr, "sceNpCommerceDialogOpen", reinterpret_cast<void*>(&sceNpCommerceDialogOpen_hook)},
    {nullptr, "sceNpCommerceDialogOpen2", reinterpret_cast<void*>(&sceNpCommerceDialogOpen2_hook)},
    {nullptr, "sceNpCommerceDialogUpdateStatus", reinterpret_cast<void*>(&sceNpCommerceDialogUpdateStatus_hook)},
    {nullptr, "sceNpCommerceDialogGetStatus", reinterpret_cast<void*>(&sceNpCommerceDialogGetStatus_hook)},
    {nullptr, "sceNpCommerceDialogGetResult", reinterpret_cast<void*>(&sceNpCommerceDialogGetResult_hook)},
    {nullptr, "sceNpCommerceDialogClose", reinterpret_cast<void*>(&sceNpCommerceDialogClose_hook)},
    {nullptr, "sceNpCommerceDialogTerminate", reinterpret_cast<void*>(&sceNpCommerceDialogTerminate_hook)},
    {nullptr, "sceNpCommerceShowPsStoreIcon", reinterpret_cast<void*>(&sceNpCommerceShowPsStoreIcon_hook)},
    {nullptr, "sceNpCommerceHidePsStoreIcon", reinterpret_cast<void*>(&sceNpCommerceHidePsStoreIcon_hook)},
    {nullptr, "sceNpCommerceSetPsStoreIconLayout", reinterpret_cast<void*>(&sceNpCommerceSetPsStoreIconLayout_hook)},
    {nullptr,
     "sceNpCommerceDialogParamInitialize",
     reinterpret_cast<void*>(&sceNpCommerceDialogParamInitialize_hook)},
    {nullptr,
     "sceNpCommerceDialogParamInitialize2",
     reinterpret_cast<void*>(&sceNpCommerceDialogParamInitialize2_hook)},
    {nullptr, "sceNpEntitlementAccessInitialize", reinterpret_cast<void*>(&sceNpEntitlementAccessInitialize_hook)},
    {nullptr, "sceNpEntitlementAccessGetSkuFlag", reinterpret_cast<void*>(&sceNpEntitlementAccessGetSkuFlag_hook)},
    {nullptr,
     "sceNpEntitlementAccessGetAddcontEntitlementInfoList",
     reinterpret_cast<void*>(&sceNpEntitlementAccessGetAddcontEntitlementInfoList_hook)},
    {nullptr,
     "sceNpEntitlementAccessGetAddcontEntitlementInfo",
     reinterpret_cast<void*>(&sceNpEntitlementAccessGetAddcontEntitlementInfo_hook)},
    {nullptr,
     "sceNpEntitlementAccessGetEntitlementKey",
     reinterpret_cast<void*>(&sceNpEntitlementAccessGetEntitlementKey_hook)},
    {nullptr,
     "sceNpEntitlementAccessGenerateTransactionId",
     reinterpret_cast<void*>(&sceNpEntitlementAccessGenerateTransactionId_hook)},
    {nullptr,
     "sceNpEntitlementAccessRequestConsumeUnifiedEntitlement",
     reinterpret_cast<void*>(&sceNpEntitlementAccessRequestConsumeUnifiedEntitlement_hook)},
    {nullptr,
     "sceNpEntitlementAccessRequestConsumeServiceEntitlement",
     reinterpret_cast<void*>(&sceNpEntitlementAccessRequestConsumeServiceEntitlement_hook)},
    {nullptr,
     "sceNpEntitlementAccessPollConsumeEntitlement",
     reinterpret_cast<void*>(&sceNpEntitlementAccessPollConsumeEntitlement_hook)},
    {nullptr,
     "sceNpEntitlementAccessRequestUnifiedEntitlementInfo",
     reinterpret_cast<void*>(&sceNpEntitlementAccessRequestUnifiedEntitlementInfo_hook)},
    {nullptr,
     "sceNpEntitlementAccessPollUnifiedEntitlementInfo",
     reinterpret_cast<void*>(&sceNpEntitlementAccessPollUnifiedEntitlementInfo_hook)},
    {nullptr,
     "sceNpEntitlementAccessRequestUnifiedEntitlementInfoList",
     reinterpret_cast<void*>(&sceNpEntitlementAccessRequestUnifiedEntitlementInfoList_hook)},
    {nullptr,
     "sceNpEntitlementAccessPollUnifiedEntitlementInfoList",
     reinterpret_cast<void*>(&sceNpEntitlementAccessPollUnifiedEntitlementInfoList_hook)},
    {nullptr,
     "sceNpEntitlementAccessRequestServiceEntitlementInfo",
     reinterpret_cast<void*>(&sceNpEntitlementAccessRequestServiceEntitlementInfo_hook)},
    {nullptr,
     "sceNpEntitlementAccessPollServiceEntitlementInfo",
     reinterpret_cast<void*>(&sceNpEntitlementAccessPollServiceEntitlementInfo_hook)},
    {nullptr,
     "sceNpEntitlementAccessRequestServiceEntitlementInfoList",
     reinterpret_cast<void*>(&sceNpEntitlementAccessRequestServiceEntitlementInfoList_hook)},
    {nullptr,
     "sceNpEntitlementAccessPollServiceEntitlementInfoList",
     reinterpret_cast<void*>(&sceNpEntitlementAccessPollServiceEntitlementInfoList_hook)},
    {nullptr,
     "sceNpEntitlementAccessDeleteRequest",
     reinterpret_cast<void*>(&sceNpEntitlementAccessDeleteRequest_hook)},
    {nullptr,
     "sceNpEntitlementAccessAbortRequest",
     reinterpret_cast<void*>(&sceNpEntitlementAccessAbortRequest_hook)},
    {nullptr,
     "sceNpEntitlementAccessGetGameTrialsFlag",
     reinterpret_cast<void*>(&sceNpEntitlementAccessGetGameTrialsFlag_hook)},
    {nullptr, "sceNpGameIntentInitialize", reinterpret_cast<void*>(&sceNpGameIntentInitialize_hook)},
    {nullptr, "sceNpGameIntentTerminate", reinterpret_cast<void*>(&sceNpGameIntentTerminate_hook)},
    {nullptr, "sceNpGameIntentReceiveIntent", reinterpret_cast<void*>(&sceNpGameIntentReceiveIntent_hook)},
    {nullptr,
     "sceNpGameIntentGetPropertyValueString",
     reinterpret_cast<void*>(&sceNpGameIntentGetPropertyValueString_hook)},
    {nullptr, "sceNpBandwidthTestInitStartUpload", reinterpret_cast<void*>(&sceNpBandwidthTestInitStartUpload_hook)},
    {nullptr, "sceNpBandwidthTestInitStartDownload", reinterpret_cast<void*>(&sceNpBandwidthTestInitStartDownload_hook)},
    {nullptr, "sceNpBandwidthTestGetStatus", reinterpret_cast<void*>(&sceNpBandwidthTestGetStatus_hook)},
    {nullptr, "sceNpBandwidthTestShutdown", reinterpret_cast<void*>(&sceNpBandwidthTestShutdown_hook)},
    {nullptr, "sceNpBandwidthTestAbort", reinterpret_cast<void*>(&sceNpBandwidthTestAbort_hook)},
    {nullptr, "sceNpSessionSignalingInitialize", reinterpret_cast<void*>(&sceNpSessionSignalingInitialize_hook)},
    {nullptr, "sceNpSessionSignalingTerminate", reinterpret_cast<void*>(&sceNpSessionSignalingTerminate_hook)},
    {nullptr,
     "sceNpSessionSignalingCreateContext",
     reinterpret_cast<void*>(&sceNpSessionSignalingCreateContext_hook)},
    {nullptr,
     "sceNpSessionSignalingCreateContext2",
     reinterpret_cast<void*>(&sceNpSessionSignalingCreateContext2_hook)},
    {nullptr,
     "sceNpSessionSignalingRequestPrepare",
     reinterpret_cast<void*>(&sceNpSessionSignalingRequestPrepare_hook)},
    {nullptr,
     "sceNpSessionSignalingDestroyContext",
     reinterpret_cast<void*>(&sceNpSessionSignalingDestroyContext_hook)},
    {nullptr,
     "sceNpSessionSignalingActivateUser",
     reinterpret_cast<void*>(&sceNpSessionSignalingActivateUser_hook)},
    {nullptr,
     "sceNpSessionSignalingActivateSession",
     reinterpret_cast<void*>(&sceNpSessionSignalingActivateSession_hook)},
    {nullptr,
     "sceNpSessionSignalingDeactivate",
     reinterpret_cast<void*>(&sceNpSessionSignalingDeactivate_hook)},
    {nullptr,
     "sceNpSessionSignalingGetGroupInfo",
     reinterpret_cast<void*>(&sceNpSessionSignalingGetGroupInfo_hook)},
    {nullptr,
     "sceNpSessionSignalingGetConnectionInfo",
     reinterpret_cast<void*>(&sceNpSessionSignalingGetConnectionInfo_hook)},
    {nullptr,
     "sceNpSessionSignalingGetConnectionStatus",
     reinterpret_cast<void*>(&sceNpSessionSignalingGetConnectionStatus_hook)},
    {nullptr,
     "sceNpSessionSignalingGetConnectionFromPeerAddress",
     reinterpret_cast<void*>(&sceNpSessionSignalingGetConnectionFromPeerAddress_hook)},
    {nullptr,
     "sceNpSessionSignalingGetConnectionFromNetAddress",
     reinterpret_cast<void*>(&sceNpSessionSignalingGetConnectionFromNetAddress_hook)},
    {nullptr,
     "sceNpSessionSignalingGetConnectionFromPeerAddress2",
     reinterpret_cast<void*>(&sceNpSessionSignalingGetConnectionFromPeerAddress2_hook)},
    {nullptr,
     "sceNpSessionSignalingGetConnectionFromNetAddress2",
     reinterpret_cast<void*>(&sceNpSessionSignalingGetConnectionFromNetAddress2_hook)},
    {nullptr,
     "sceNpSessionSignalingGetGroupFromPeerAddress",
     reinterpret_cast<void*>(&sceNpSessionSignalingGetGroupFromPeerAddress_hook)},
    {nullptr,
     "sceNpSessionSignalingGetGroupFromSessionId",
     reinterpret_cast<void*>(&sceNpSessionSignalingGetGroupFromSessionId_hook)},
    {nullptr,
     "sceNpSessionSignalingGetLocalNetInfo",
     reinterpret_cast<void*>(&sceNpSessionSignalingGetLocalNetInfo_hook)},
    {nullptr,
     "sceNpSessionSignalingGetConnectionStatistics",
     reinterpret_cast<void*>(&sceNpSessionSignalingGetConnectionStatistics_hook)},
    {nullptr,
     "sceNpSessionSignalingGetMemoryInfo",
     reinterpret_cast<void*>(&sceNpSessionSignalingGetMemoryInfo_hook)},
    {nullptr, "sceNpWebApi2Initialize", reinterpret_cast<void*>(&sceNpWebApi2Initialize_hook)},
    {nullptr, "sceNpWebApi2Terminate", reinterpret_cast<void*>(&sceNpWebApi2Terminate_hook)},
    {nullptr, "sceNpWebApi2CreateUserContext", reinterpret_cast<void*>(&sceNpWebApi2CreateUserContext_hook)},
    {nullptr, "sceNpWebApi2DeleteUserContext", reinterpret_cast<void*>(&sceNpWebApi2DeleteUserContext_hook)},
    {nullptr, "sceNpWebApi2CreateRequest", reinterpret_cast<void*>(&sceNpWebApi2CreateRequest_hook)},
    {nullptr, "sceNpWebApi2DeleteRequest", reinterpret_cast<void*>(&sceNpWebApi2DeleteRequest_hook)},
    {nullptr, "sceNpWebApi2AbortRequest", reinterpret_cast<void*>(&sceNpWebApi2AbortRequest_hook)},
    {nullptr, "sceNpWebApi2SendRequest", reinterpret_cast<void*>(&sceNpWebApi2SendRequest_hook)},
    {nullptr, "sceNpWebApi2ReadData", reinterpret_cast<void*>(&sceNpWebApi2ReadData_hook)},
    {nullptr, "sceNpWebApi2AddHttpRequestHeader", reinterpret_cast<void*>(&sceNpWebApi2AddHttpRequestHeader_hook)},
    {nullptr,
     "sceNpWebApi2GetHttpResponseHeaderValueLength",
     reinterpret_cast<void*>(&sceNpWebApi2GetHttpResponseHeaderValueLength_hook)},
    {nullptr,
     "sceNpWebApi2GetHttpResponseHeaderValue",
     reinterpret_cast<void*>(&sceNpWebApi2GetHttpResponseHeaderValue_hook)},
    {nullptr, "sceNpWebApi2GetMemoryPoolStats", reinterpret_cast<void*>(&sceNpWebApi2GetMemoryPoolStats_hook)},
    {nullptr, "sceNpWebApi2SetRequestTimeout", reinterpret_cast<void*>(&sceNpWebApi2SetRequestTimeout_hook)},
    {nullptr, "sceNpWebApi2CheckTimeout", reinterpret_cast<void*>(&sceNpWebApi2CheckTimeout_hook)},
    {nullptr, "sceNpWebApi2AddWebTraceTag", reinterpret_cast<void*>(&sceNpWebApi2AddWebTraceTag_hook)},
    {nullptr, "sceNpWebApi2PushEventCreateHandle", reinterpret_cast<void*>(&sceNpWebApi2PushEventCreateHandle_hook)},
    {nullptr, "sceNpWebApi2PushEventDeleteHandle", reinterpret_cast<void*>(&sceNpWebApi2PushEventDeleteHandle_hook)},
    {nullptr, "sceNpWebApi2PushEventAbortHandle", reinterpret_cast<void*>(&sceNpWebApi2PushEventAbortHandle_hook)},
    {nullptr, "sceNpWebApi2PushEventSetHandleTimeout", reinterpret_cast<void*>(&sceNpWebApi2PushEventSetHandleTimeout_hook)},
    {nullptr, "sceNpWebApi2PushEventCreateFilter", reinterpret_cast<void*>(&sceNpWebApi2PushEventCreateFilter_hook)},
    {nullptr, "sceNpWebApi2PushEventDeleteFilter", reinterpret_cast<void*>(&sceNpWebApi2PushEventDeleteFilter_hook)},
    {nullptr, "sceNpWebApi2PushEventRegisterCallback", reinterpret_cast<void*>(&sceNpWebApi2PushEventRegisterCallback_hook)},
    {nullptr, "sceNpWebApi2PushEventUnregisterCallback", reinterpret_cast<void*>(&sceNpWebApi2PushEventUnregisterCallback_hook)},
    {nullptr,
     "sceNpWebApi2PushEventRegisterPushContextCallback",
     reinterpret_cast<void*>(&sceNpWebApi2PushEventRegisterPushContextCallback_hook)},
    {nullptr,
     "sceNpWebApi2PushEventUnregisterPushContextCallback",
     reinterpret_cast<void*>(&sceNpWebApi2PushEventUnregisterPushContextCallback_hook)},
    {nullptr, "sceNpWebApi2PushEventCreatePushContext", reinterpret_cast<void*>(&sceNpWebApi2PushEventCreatePushContext_hook)},
    {nullptr, "sceNpWebApi2PushEventDeletePushContext", reinterpret_cast<void*>(&sceNpWebApi2PushEventDeletePushContext_hook)},
    {nullptr,
     "sceNpWebApi2PushEventStartPushContextCallback",
     reinterpret_cast<void*>(&sceNpWebApi2PushEventStartPushContextCallback_hook)},
    {nullptr, "sceHttpInit", reinterpret_cast<void*>(&sceHttpInit_hook)},
    {nullptr, "sceHttpTerm", reinterpret_cast<void*>(&sceHttpTerm_hook)},
    {nullptr, "sceHttpCreateTemplate", reinterpret_cast<void*>(&sceHttpCreateTemplate_hook)},
    {nullptr, "sceHttpCreateConnection", reinterpret_cast<void*>(&sceHttpCreateConnection_hook)},
    {nullptr,
     "sceHttpCreateConnectionWithURL",
     reinterpret_cast<void*>(&sceHttpCreateConnectionWithURL_hook)},
    {nullptr, "sceHttpCreateRequest", reinterpret_cast<void*>(&sceHttpCreateRequest_hook)},
    {nullptr, "sceHttpCreateRequest2", reinterpret_cast<void*>(&sceHttpCreateRequest2_hook)},
    {nullptr,
     "sceHttpCreateRequestWithURL",
     reinterpret_cast<void*>(&sceHttpCreateRequestWithURL_hook)},
    {nullptr,
     "sceHttpCreateRequestWithURL2",
     reinterpret_cast<void*>(&sceHttpCreateRequestWithURL2_hook)},
    {nullptr, "sceHttpAddRequestHeader", reinterpret_cast<void*>(&sceHttpAddRequestHeader_hook)},
    {nullptr, "sceHttpSendRequest", reinterpret_cast<void*>(&sceHttpSendRequest_hook)},
    {nullptr, "sceHttpGetStatusCode", reinterpret_cast<void*>(&sceHttpGetStatusCode_hook)},
    {nullptr, "sceHttpGetLastErrno", reinterpret_cast<void*>(&sceHttpGetLastErrno_hook)},
    {nullptr, "sceHttpReadData", reinterpret_cast<void*>(&sceHttpReadData_hook)},
    {nullptr, "sceHttp2Init", reinterpret_cast<void*>(&sceHttp2Init_hook)},
    {nullptr, "sceHttp2Term", reinterpret_cast<void*>(&sceHttp2Term_hook)},
    {nullptr, "sceHttp2GetMemoryPoolStats", reinterpret_cast<void*>(&sceHttp2GetMemoryPoolStats_hook)},
    {nullptr, "sceHttp2CreateTemplate", reinterpret_cast<void*>(&sceHttp2CreateTemplate_hook)},
    {nullptr, "sceHttp2DeleteTemplate", reinterpret_cast<void*>(&sceHttp2DeleteTemplate_hook)},
    {nullptr,
     "sceHttp2CreateRequestWithURL",
     reinterpret_cast<void*>(&sceHttp2CreateRequestWithURL_hook)},
    {nullptr, "sceHttp2DeleteRequest", reinterpret_cast<void*>(&sceHttp2DeleteRequest_hook)},
    {nullptr, "sceHttp2SslEnableOption", reinterpret_cast<void*>(&sceHttp2SslEnableOption_hook)},
    {nullptr, "sceHttp2SslDisableOption", reinterpret_cast<void*>(&sceHttp2SslDisableOption_hook)},
    {nullptr, "sceHttp2SetMinSslVersion", reinterpret_cast<void*>(&sceHttp2SetMinSslVersion_hook)},
    {nullptr, "sceHttp2SetSslCallback", reinterpret_cast<void*>(&sceHttp2SetSslCallback_hook)},
    {nullptr, "sceHttp2AddRequestHeader", reinterpret_cast<void*>(&sceHttp2AddRequestHeader_hook)},
    {nullptr, "sceHttp2RemoveRequestHeader", reinterpret_cast<void*>(&sceHttp2RemoveRequestHeader_hook)},
    {nullptr,
     "sceHttp2SetRequestContentLength",
     reinterpret_cast<void*>(&sceHttp2SetRequestContentLength_hook)},
    {nullptr,
     "sceHttp2SetRequestNoContentLength",
     reinterpret_cast<void*>(&sceHttp2SetRequestNoContentLength_hook)},
    {nullptr, "sceHttp2SetRequestServerName", reinterpret_cast<void*>(&sceHttp2SetRequestServerName_hook)},
    {nullptr,
     "sceHttp2SetInflateGZIPEnabled",
     reinterpret_cast<void*>(&sceHttp2SetInflateGZIPEnabled_hook)},
    {nullptr, "sceHttp2SendRequest", reinterpret_cast<void*>(&sceHttp2SendRequest_hook)},
    {nullptr,
     "sceHttp2SendRequestAsync",
     reinterpret_cast<void*>(&sceHttp2SendRequestAsync_hook)},
    {nullptr,
     "sceHttp2GetResponseContentLength",
     reinterpret_cast<void*>(&sceHttp2GetResponseContentLength_hook)},
    {nullptr, "sceHttp2GetStatusCode", reinterpret_cast<void*>(&sceHttp2GetStatusCode_hook)},
    {nullptr, "sceHttp2GetAllResponseHeaders", reinterpret_cast<void*>(&sceHttp2GetAllResponseHeaders_hook)},
    {nullptr, "sceHttp2GetAllTrailingHeaders", reinterpret_cast<void*>(&sceHttp2GetAllTrailingHeaders_hook)},
    {nullptr, "sceHttp2ReadData", reinterpret_cast<void*>(&sceHttp2ReadData_hook)},
    {nullptr, "sceHttp2ReadDataAsync", reinterpret_cast<void*>(&sceHttp2ReadDataAsync_hook)},
    {nullptr, "sceHttp2WaitAsync", reinterpret_cast<void*>(&sceHttp2WaitAsync_hook)},
    {nullptr, "sceHttp2SetAuthInfoCallback", reinterpret_cast<void*>(&sceHttp2SetAuthInfoCallback_hook)},
    {nullptr, "sceHttp2SetAuthEnabled", reinterpret_cast<void*>(&sceHttp2SetAuthEnabled_hook)},
    {nullptr, "sceHttp2GetAuthEnabled", reinterpret_cast<void*>(&sceHttp2GetAuthEnabled_hook)},
    {nullptr, "sceHttp2AuthCacheFlush", reinterpret_cast<void*>(&sceHttp2AuthCacheFlush_hook)},
    {nullptr, "sceHttp2SetRedirectCallback", reinterpret_cast<void*>(&sceHttp2SetRedirectCallback_hook)},
    {nullptr, "sceHttp2SetAutoRedirect", reinterpret_cast<void*>(&sceHttp2SetAutoRedirect_hook)},
    {nullptr, "sceHttp2GetAutoRedirect", reinterpret_cast<void*>(&sceHttp2GetAutoRedirect_hook)},
    {nullptr, "sceHttp2RedirectCacheFlush", reinterpret_cast<void*>(&sceHttp2RedirectCacheFlush_hook)},
    {nullptr, "sceHttp2SetTimeOut", reinterpret_cast<void*>(&sceHttp2SetTimeOut_hook)},
    {nullptr, "sceHttp2SetResolveTimeOut", reinterpret_cast<void*>(&sceHttp2SetResolveTimeOut_hook)},
    {nullptr, "sceHttp2SetResolveRetry", reinterpret_cast<void*>(&sceHttp2SetResolveRetry_hook)},
    {nullptr, "sceHttp2SetConnectTimeOut", reinterpret_cast<void*>(&sceHttp2SetConnectTimeOut_hook)},
    {nullptr, "sceHttp2SetSendTimeOut", reinterpret_cast<void*>(&sceHttp2SetSendTimeOut_hook)},
    {nullptr, "sceHttp2SetRecvTimeOut", reinterpret_cast<void*>(&sceHttp2SetRecvTimeOut_hook)},
    {nullptr,
     "sceHttp2SetConnectionWaitTimeOut",
     reinterpret_cast<void*>(&sceHttp2SetConnectionWaitTimeOut_hook)},
    {nullptr, "sceHttp2SetProxyWithURL", reinterpret_cast<void*>(&sceHttp2SetProxyWithURL_hook)},
    {nullptr,
     "sceHttp2WebSocketCreateRequest",
     reinterpret_cast<void*>(&sceHttp2WebSocketCreateRequest_hook)},
    {nullptr,
     "sceHttp2WebSocketSendTextMessage",
     reinterpret_cast<void*>(&sceHttp2WebSocketSendTextMessage_hook)},
    {nullptr,
     "sceHttp2WebSocketSendTextMessageAsync",
     reinterpret_cast<void*>(&sceHttp2WebSocketSendTextMessageAsync_hook)},
    {nullptr,
     "sceHttp2WebSocketSendDataMessage",
     reinterpret_cast<void*>(&sceHttp2WebSocketSendDataMessage_hook)},
    {nullptr,
     "sceHttp2WebSocketSendDataMessageAsync",
     reinterpret_cast<void*>(&sceHttp2WebSocketSendDataMessageAsync_hook)},
    {nullptr, "sceHttp2WebSocketClose", reinterpret_cast<void*>(&sceHttp2WebSocketClose_hook)},
    {nullptr, "sceHttp2WebSocketCloseAsync", reinterpret_cast<void*>(&sceHttp2WebSocketCloseAsync_hook)},
    {nullptr,
     "sceHttp2WebSocketSetPingTimeout",
     reinterpret_cast<void*>(&sceHttp2WebSocketSetPingTimeout_hook)},
    {nullptr,
     "sceHttp2WebSocketSetPingInterval",
     reinterpret_cast<void*>(&sceHttp2WebSocketSetPingInterval_hook)},
    {nullptr, "sceHttp2AbortRequest", reinterpret_cast<void*>(&sceHttp2AbortRequest_hook)},
    {nullptr, "sceNetCtlInit", reinterpret_cast<void*>(&sceNetCtlInit_hook)},
    {nullptr, "sceNetCtlTerm", reinterpret_cast<void*>(&sceNetCtlTerm_hook)},
    {nullptr, "sceNetCtlCheckCallback", reinterpret_cast<void*>(&sceNetCtlCheckCallback_hook)},
    {nullptr, "sceNetCtlRegisterCallback", reinterpret_cast<void*>(&sceNetCtlRegisterCallback_hook)},
    {nullptr, "sceNetCtlRegisterCallbackV6", reinterpret_cast<void*>(&sceNetCtlRegisterCallbackV6_hook)},
    {nullptr, "sceNetCtlUnregisterCallback", reinterpret_cast<void*>(&sceNetCtlUnregisterCallback_hook)},
    {nullptr, "sceNetCtlUnregisterCallbackV6", reinterpret_cast<void*>(&sceNetCtlUnregisterCallbackV6_hook)},
    {nullptr, "sceNetCtlGetResult", reinterpret_cast<void*>(&sceNetCtlGetResult_hook)},
    {nullptr, "sceNetCtlGetResultV6", reinterpret_cast<void*>(&sceNetCtlGetResultV6_hook)},
    {nullptr, "sceNetCtlGetState", reinterpret_cast<void*>(&sceNetCtlGetState_hook)},
    {nullptr, "sceNetCtlGetStateV6", reinterpret_cast<void*>(&sceNetCtlGetStateV6_hook)},
    {nullptr, "sceNetCtlGetInfo", reinterpret_cast<void*>(&sceNetCtlGetInfo_hook)},
    {nullptr, "sceNetCtlGetInfoV6", reinterpret_cast<void*>(&sceNetCtlGetInfoV6_hook)},
    {nullptr, "sceNetCtlGetIfStat", reinterpret_cast<void*>(&sceNetCtlGetIfStat_hook)},
    {nullptr, "sceNetCtlGetNatInfo", reinterpret_cast<void*>(&sceNetCtlGetNatInfo_hook)},
    {nullptr, "sceNetResolverStartNtoa", reinterpret_cast<void*>(&sceNetResolverStartNtoa_hook)},
    {nullptr,
     "sceNetResolverStartNtoaMultipleRecords",
     reinterpret_cast<void*>(&sceNetResolverStartNtoaMultipleRecords_hook)},
    {nullptr, "sceNetResolverGetError", reinterpret_cast<void*>(&sceNetResolverGetError_hook)},
    {nullptr, "sceNetSocket", reinterpret_cast<void*>(&sceNetSocket_hook)},
    {nullptr, "sceNetConnect", reinterpret_cast<void*>(&sceNetConnect_hook)},
    {nullptr, "sceNetSend", reinterpret_cast<void*>(&sceNetSend_hook)},
    {nullptr, "sceNetRecv", reinterpret_cast<void*>(&sceNetRecv_hook)},
    {nullptr, "sceNetSocketClose", reinterpret_cast<void*>(&sceNetSocketClose_hook)},
};

} // namespace

extern "C" const LateDlsymHookSpec* getOnlineLateDlsymHookSpecs(size_t* count) {
    if (count) {
        *count = sizeof(g_onlineLateDlsymHooks) / sizeof(g_onlineLateDlsymHooks[0]);
    }
    return g_onlineLateDlsymHooks;
}
