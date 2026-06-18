#include "hooks.h"

#include "rtc.h"

#include <save_data/save_data_api.h>
#include <stdint.h>

namespace {

using SceKernelGettimezoneFn = int (*)(void*);
using SceSaveDataMount3Fn = int32_t (*)(const SceSaveDataMount3*, SceSaveDataMountResult*);

extern "C" int sceKernelGettimezone(void* tz);
extern "C" const LateDlsymHookSpec* getOnlineLateDlsymHookSpecs(size_t* count);

int sceKernelGettimezone_hook(void* tz) {
    auto* original = reinterpret_cast<SceKernelGettimezoneFn>(hookGetOriginalFunction("sceKernelGettimezone"));
    if (original) {
        const int rc = original(tz);
        if (rc >= 0) {
            return rc;
        }
    }
    if (tz) {
        int* offsets = static_cast<int*>(tz);
        offsets[0] = 0;
        offsets[1] = 0;
    }
    return SCE_OK;
}

int32_t sceSaveDataMount3_hook(const SceSaveDataMount3* mount, SceSaveDataMountResult* mountResult) {
    auto* original = reinterpret_cast<SceSaveDataMount3Fn>(hookGetOriginalLateDlsymFunction("sceSaveDataMount3"));
    if (!original) {
        return SCE_RTC_ERROR_NOT_SUPPORTED;
    }
    return original(mount, mountResult);
}

const HookSpec g_backportHooks[] = {
    /*
     * Example hook. If sceKernelGettimezone fails on a target runtime, fall
     * back to UTC instead of propagating the kernel error.
     */
    {"sceKernelGettimezone",
     reinterpret_cast<void*>(&sceKernelGettimezone),
     reinterpret_cast<void*>(&sceKernelGettimezone_hook),
     1},
};

const LateDlsymHookSpec g_lateDlsymHooks[] = {
    /*
     * Example for a module that may be loaded after libSceRtc. Use nullptr
     * when the export name is known but the owning module is not: the runtime
     * hook engine scans already loaded modules and each module loaded later.
     */
    {nullptr, "sceSaveDataMount3", reinterpret_cast<void*>(&sceSaveDataMount3_hook)},
};

constexpr size_t kMaxCombinedLateDlsymHooks = 256;
LateDlsymHookSpec g_combinedLateDlsymHooks[kMaxCombinedLateDlsymHooks] = {};
size_t g_combinedLateDlsymHookCount = 0;

void append_late_specs(const LateDlsymHookSpec* specs, size_t count) {
    if (!specs) {
        return;
    }
    for (size_t i = 0; i < count && g_combinedLateDlsymHookCount < kMaxCombinedLateDlsymHooks; ++i) {
        g_combinedLateDlsymHooks[g_combinedLateDlsymHookCount++] = specs[i];
    }
}

} // namespace

extern "C" const HookSpec* getBackportHookSpecs(size_t* count) {
    if (count) {
        *count = sizeof(g_backportHooks) / sizeof(g_backportHooks[0]);
    }
    return g_backportHooks;
}

extern "C" const LateDlsymHookSpec* getLateDlsymHookSpecs(size_t* count) {
    if (g_combinedLateDlsymHookCount == 0) {
        append_late_specs(g_lateDlsymHooks, sizeof(g_lateDlsymHooks) / sizeof(g_lateDlsymHooks[0]));

        size_t onlineCount = 0;
        const LateDlsymHookSpec* onlineSpecs = getOnlineLateDlsymHookSpecs(&onlineCount);
        append_late_specs(onlineSpecs, onlineCount);
    }
    if (count) {
        *count = g_combinedLateDlsymHookCount;
    }
    return g_combinedLateDlsymHooks;
}
