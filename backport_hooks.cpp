#include "hooks.h"

#include "rtc.h"

#include <save_data/save_data_api.h>
#include <stdint.h>

namespace {

using SceKernelGettimezoneFn = int (*)(void*);
using SceSaveDataMount3Fn = int32_t (*)(const SceSaveDataMount3*, SceSaveDataMountResult*);

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
    {"sceKernelGettimezone", reinterpret_cast<void*>(&sceKernelGettimezone_hook), 1},
};

const LateDlsymHookSpec g_lateDlsymHooks[] = {
    /*
     * Example for a module loaded after libSceRtc. When later code resolves
     * sceSaveDataMount3 with sceKernelDlsym, return this replacement and keep
     * the resolved original for forwarding from sceSaveDataMount3_hook.
     */
    {"libSceSaveData", "sceSaveDataMount3", reinterpret_cast<void*>(&sceSaveDataMount3_hook)},
};

} // namespace

extern "C" const HookSpec* getBackportHookSpecs(size_t* count) {
    if (count) {
        *count = sizeof(g_backportHooks) / sizeof(g_backportHooks[0]);
    }
    return g_backportHooks;
}

extern "C" const LateDlsymHookSpec* getLateDlsymHookSpecs(size_t* count) {
    if (count) {
        *count = sizeof(g_lateDlsymHooks) / sizeof(g_lateDlsymHooks[0]);
    }
    return g_lateDlsymHooks;
}
