#include "hooks.h"

#include "hde64.h"
#include "rtc.h"

#include <_kernel.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

extern "C" int sceKernelDlsym(SceKernelModule handle, const char* symbol, void** addrp);
extern "C" int sceKernelMprotect(const void* addr, size_t len, int prot);
extern "C" int* __error(void);
extern "C" int sceKernelDebugOutText(int channel, const char* text);
extern "C" int sceKernelGetModuleList(SceKernelModule* modules, size_t capacity, size_t* actualNum);
extern "C" int sceKernelGetModuleInfo(SceKernelModule module, void* info);
extern "C" SceKernelModule sceKernelLoadStartModuleForSysmodule(const char* moduleFileName,
                                                                size_t args,
                                                                const void* argp,
                                                                uint32_t flags,
                                                                const SceKernelLoadModuleOpt* pOpt,
                                                                int* pRes);

namespace {

constexpr size_t kJumpSize = 14;
constexpr size_t kMaxStolenBytes = 64;
constexpr size_t kTrampolinePageSize = SCE_KERNEL_PAGE_SIZE;
constexpr size_t kTrampolineSize = 512;
constexpr size_t kTrampolineSlotsPerPage = kTrampolinePageSize / kTrampolineSize;
constexpr int kCodeProt = SCE_KERNEL_PROT_CPU_READ | SCE_KERNEL_PROT_CPU_EXEC;
constexpr int kRwProt = SCE_KERNEL_PROT_CPU_ALL;
constexpr size_t kLoadStartModuleBodyOffset = 0x20;
constexpr const char* kLoadStartModuleSymbol = "sceKernelLoadStartModule";
static_assert((kTrampolinePageSize % kTrampolineSize) == 0, "trampoline slots must divide the page size");
static_assert(kTrampolineSlotsPerPage <= 32, "trampoline slot bitmap is uint32_t");

struct InlineDetour {
    void* target;
    void* replacement;
    void* trampoline;
    size_t stolenLen;
    uint8_t original[kMaxStolenBytes];
    bool installed;
};

struct TinyDetour {
    void* target;
    void* replacement;
    uint8_t original[11];
    bool installed;
};

struct InstalledHook {
    const char* symbol;
    void* target;
    void* replacement;
    bool optional;
    InlineDetour detour;
};

struct LateFunctionHook {
    const char* moduleName;
    const char* symbol;
    void* replacement;
    InlineDetour detour;
};

struct KernelModuleInfoCompat {
    uint64_t size;
    char name[256];
    uint8_t reserved[0x160 - sizeof(uint64_t) - 256];
};
static_assert(sizeof(KernelModuleInfoCompat) == 0x160, "kernel module info size must match libkernel");

struct ErrnoGuard {
    int* slot;
    int value;

    ErrnoGuard() : slot(__error()), value(slot ? *slot : 0) {}
    ~ErrnoGuard() {
        if (slot) {
            *slot = value;
        }
    }
};

using SceKernelLoadStartModuleFn =
    SceKernelModule (*)(const char*, size_t, const void*, uint32_t, const SceKernelLoadModuleOpt*, int*);

SceKernelModule sceKernelLoadStartModule_hook(const char* moduleFileName,
                                              size_t args,
                                              const void* argp,
                                              uint32_t flags,
                                              const SceKernelLoadModuleOpt* pOpt,
                                              int* pRes);
SceKernelModule sceKernelLoadStartModuleForSysmodule_hook(const char* moduleFileName,
                                                          size_t args,
                                                          const void* argp,
                                                          uint32_t flags,
                                                          const SceKernelLoadModuleOpt* pOpt,
                                                          int* pRes);

constexpr size_t kMaxHookSpecs = 32;
constexpr size_t kMaxLateHookSpecs = 256;
constexpr size_t kMaxRawHookSpecs = 8;
constexpr size_t kMaxInlineDetours = kMaxHookSpecs + kMaxLateHookSpecs + kMaxRawHookSpecs;
constexpr size_t kMaxTrampolinePages = (kMaxInlineDetours + kTrampolineSlotsPerPage - 1u) / kTrampolineSlotsPerPage;
constexpr size_t kMaxLoadedModuleScan = 0x400;

InstalledHook g_hooks[kMaxHookSpecs] = {};
size_t g_hookCount = 0;
LateFunctionHook g_lateHooks[kMaxLateHookSpecs] = {};
size_t g_lateHookCount = 0;
InlineDetour g_rawHooks[kMaxRawHookSpecs] = {};
size_t g_rawHookCount = 0;
SceKernelModule g_loadedModuleScan[kMaxLoadedModuleScan] = {};
KernelModuleInfoCompat g_loadedModuleInfo = {};
alignas(SCE_KERNEL_PAGE_SIZE) uint8_t g_trampolineStorage[kMaxTrampolinePages][kTrampolinePageSize] = {};
uint32_t g_trampolinePageUsed[kMaxTrampolinePages] = {};
int g_trampolinePageProt[kMaxTrampolinePages] = {};
int g_hooksInstalled = 0;
int g_lateHookInstallDepth = 0;
int g_loadStartHookDepth = 0;
void* g_loadStartModuleBody = nullptr;
TinyDetour g_loadStartModuleForSysmoduleDetour = {};

uintptr_t page_floor(uintptr_t value) {
    return value & ~(static_cast<uintptr_t>(SCE_KERNEL_PAGE_SIZE) - 1u);
}

uintptr_t page_ceil(uintptr_t value) {
    return (value + SCE_KERNEL_PAGE_SIZE - 1u) & ~(static_cast<uintptr_t>(SCE_KERNEL_PAGE_SIZE) - 1u);
}

void copy_bytes(void* dst, const void* src, size_t len) {
    memcpy(dst, src, len);
}

void set_bytes(void* dst, int value, size_t len) {
    memset(dst, value, len);
}

void klog_text(const char* text) {
    if (text && *text) {
        (void)sceKernelDebugOutText(0, text);
    }
}

void klog_hook_result(const char* symbol, const char* status, void* target, void* trampoline) {
    char line[256];
    snprintf(line,
             sizeof(line),
             "[backport-helper] hook symbol=%s status=%s target=%p trampoline=%p\n",
             symbol ? symbol : "<null>",
             status ? status : "<null>",
             target,
             trampoline);
    klog_text(line);
}

void store_u64_le(void* dst, uint64_t value) {
    auto* p = static_cast<uint8_t*>(dst);
    for (size_t i = 0; i < 8; ++i) {
        p[i] = static_cast<uint8_t>((value >> (8u * i)) & 0xffu);
    }
}

void store_i32_le(void* dst, int32_t value) {
    auto* p = static_cast<uint8_t*>(dst);
    const uint32_t u = static_cast<uint32_t>(value);
    p[0] = static_cast<uint8_t>(u & 0xffu);
    p[1] = static_cast<uint8_t>((u >> 8) & 0xffu);
    p[2] = static_cast<uint8_t>((u >> 16) & 0xffu);
    p[3] = static_cast<uint8_t>((u >> 24) & 0xffu);
}

void write_abs_jump(void* dst, void* target) {
    auto* p = static_cast<uint8_t*>(dst);
    p[0] = 0xff;
    p[1] = 0x25;
    p[2] = 0x00;
    p[3] = 0x00;
    p[4] = 0x00;
    p[5] = 0x00;
    store_u64_le(p + 6, reinterpret_cast<uintptr_t>(target));
}

bool write_rel_jump(void* dst, void* target) {
    const auto from = reinterpret_cast<uintptr_t>(dst);
    const auto to = reinterpret_cast<uintptr_t>(target);
    const int64_t disp64 = static_cast<int64_t>(to) - static_cast<int64_t>(from + 5);
    if (disp64 < INT32_MIN || disp64 > INT32_MAX) {
        return false;
    }

    auto* p = static_cast<uint8_t*>(dst);
    p[0] = 0xe9;
    store_i32_le(p + 1, static_cast<int32_t>(disp64));
    return true;
}

bool make_code_writable(void* addr, size_t len) {
    const uintptr_t begin = page_floor(reinterpret_cast<uintptr_t>(addr));
    const uintptr_t end = page_ceil(reinterpret_cast<uintptr_t>(addr) + len);
    return sceKernelMprotect(reinterpret_cast<void*>(begin), end - begin, kRwProt) == 0;
}

void restore_code_protection(void* addr, size_t len) {
    const uintptr_t begin = page_floor(reinterpret_cast<uintptr_t>(addr));
    const uintptr_t end = page_ceil(reinterpret_cast<uintptr_t>(addr) + len);
    (void)sceKernelMprotect(reinterpret_cast<void*>(begin), end - begin, kCodeProt);
}

bool protect_trampoline_page(void* page, int prot) {
    for (size_t pageIndex = 0; pageIndex < kMaxTrampolinePages; ++pageIndex) {
        if (page != g_trampolineStorage[pageIndex]) {
            continue;
        }
        if (g_trampolinePageProt[pageIndex] == prot) {
            return true;
        }
        if (sceKernelMprotect(page, kTrampolinePageSize, prot) != 0) {
            return false;
        }
        g_trampolinePageProt[pageIndex] = prot;
        return true;
    }
    return sceKernelMprotect(page, kTrampolinePageSize, prot) == 0;
}

void* trampoline_page(size_t pageIndex) {
    return g_trampolineStorage[pageIndex];
}

void* allocate_trampoline() {
    for (size_t pageIndex = 0; pageIndex < kMaxTrampolinePages; ++pageIndex) {
        void* page = trampoline_page(pageIndex);
        const uint32_t used = g_trampolinePageUsed[pageIndex];
        for (size_t slot = 0; slot < kTrampolineSlotsPerPage; ++slot) {
            const uint32_t bit = 1u << slot;
            if ((used & bit) != 0) {
                continue;
            }
            if (!protect_trampoline_page(page, kRwProt)) {
                return nullptr;
            }
            g_trampolinePageUsed[pageIndex] = used | bit;
            void* trampoline = static_cast<uint8_t*>(page) + slot * kTrampolineSize;
            set_bytes(trampoline, 0, kTrampolineSize);
            return trampoline;
        }
    }
    return nullptr;
}

bool make_trampoline_executable(void* trampoline) {
    const uintptr_t slot = reinterpret_cast<uintptr_t>(trampoline);
    for (size_t pageIndex = 0; pageIndex < kMaxTrampolinePages; ++pageIndex) {
        void* page = trampoline_page(pageIndex);
        const uintptr_t begin = reinterpret_cast<uintptr_t>(page);
        if (slot >= begin && slot < begin + kTrampolinePageSize) {
            return protect_trampoline_page(page, kCodeProt);
        }
    }
    return false;
}

void release_trampoline(void* trampoline) {
    if (!trampoline) {
        return;
    }
    const uintptr_t slot = reinterpret_cast<uintptr_t>(trampoline);
    for (size_t pageIndex = 0; pageIndex < kMaxTrampolinePages; ++pageIndex) {
        void* page = trampoline_page(pageIndex);
        const uintptr_t begin = reinterpret_cast<uintptr_t>(page);
        if (slot < begin || slot >= begin + kTrampolinePageSize) {
            continue;
        }
        const size_t slotIndex = (slot - begin) / kTrampolineSize;
        g_trampolinePageUsed[pageIndex] &= ~(1u << slotIndex);
        (void)protect_trampoline_page(page, kCodeProt);
        return;
    }
}

bool append_bytes(uint8_t* dst, size_t& dstLen, size_t dstCap, const void* src, size_t len) {
    if (dstLen + len > dstCap) {
        return false;
    }
    copy_bytes(dst + dstLen, src, len);
    dstLen += len;
    return true;
}

bool append_abs_jump(uint8_t* dst, size_t& dstLen, size_t dstCap, uintptr_t target) {
    if (dstLen + kJumpSize > dstCap) {
        return false;
    }
    write_abs_jump(dst + dstLen, reinterpret_cast<void*>(target));
    dstLen += kJumpSize;
    return true;
}

bool append_abs_call(uint8_t* dst, size_t& dstLen, size_t dstCap, uintptr_t target) {
    constexpr size_t kAbsCallSize = 16;
    if (dstLen + kAbsCallSize > dstCap) {
        return false;
    }
    uint8_t* out = dst + dstLen;
    out[0] = 0xff;
    out[1] = 0x15;
    out[2] = 0x02;
    out[3] = 0x00;
    out[4] = 0x00;
    out[5] = 0x00;
    out[6] = 0xeb;
    out[7] = 0x08;
    store_u64_le(out + 8, target);
    dstLen += kAbsCallSize;
    return true;
}

bool append_abs_cond_jump(uint8_t* dst, size_t& dstLen, size_t dstCap, uint8_t opcode, uintptr_t target) {
    constexpr size_t kAbsCondJumpSize = 16;
    if (dstLen + kAbsCondJumpSize > dstCap) {
        return false;
    }
    uint8_t* out = dst + dstLen;
    out[0] = opcode ^ 1u;
    out[1] = static_cast<uint8_t>(kJumpSize);
    write_abs_jump(out + 2, reinterpret_cast<void*>(target));
    dstLen += kAbsCondJumpSize;
    return true;
}

bool relocate_instruction(uint8_t* dst,
                          size_t& dstLen,
                          size_t dstCap,
                          const uint8_t* src,
                          uintptr_t srcIp,
                          uintptr_t dstIp,
                          const hde64s& hs,
                          bool& terminal) {
    if ((hs.flags & F_RELATIVE) != 0) {
        uintptr_t target = 0;
        if (!hde64_relative_target(src, srcIp, &hs, &target)) {
            return false;
        }
        if (hs.meta == HDE64_META_REL_CALL) {
            return append_abs_call(dst, dstLen, dstCap, target);
        }
        if (hs.meta == HDE64_META_REL_JMP) {
            terminal = true;
            return append_abs_jump(dst, dstLen, dstCap, target);
        }
        if (hs.meta == HDE64_META_REL_JCC) {
            return append_abs_cond_jump(dst, dstLen, dstCap, hs.branch_opcode, target);
        }
        return false;
    }

    const size_t outOffset = dstLen;
    if (!append_bytes(dst, dstLen, dstCap, src, hs.len)) {
        return false;
    }

    if ((hs.flags & F_RIP_RELATIVE) != 0) {
        uintptr_t absolute = 0;
        if (!hde64_rip_absolute(src, srcIp, &hs, &absolute)) {
            return false;
        }
        const int64_t newDisp64 = static_cast<int64_t>(absolute) - static_cast<int64_t>(dstIp + hs.len);
        if (newDisp64 < INT32_MIN || newDisp64 > INT32_MAX) {
            return false;
        }
        store_i32_le(dst + outOffset + hs.disp_offset, static_cast<int32_t>(newDisp64));
    }
    return true;
}

bool install_inline_detour(InlineDetour& detour, void* target, void* replacement) {
    if (detour.installed) {
        return true;
    }
    if (!target || !replacement || target == replacement) {
        return false;
    }

    auto* src = static_cast<uint8_t*>(target);
    auto* trampoline = static_cast<uint8_t*>(allocate_trampoline());
    if (!trampoline) {
        return false;
    }
    if (!make_code_writable(target, kMaxStolenBytes)) {
        release_trampoline(trampoline);
        return false;
    }

    size_t stolen = 0;
    size_t trampolineLen = 0;
    bool terminal = false;
    while (stolen < kJumpSize && stolen < kMaxStolenBytes) {
        hde64s hs = {};
        const unsigned int len = hde64_disasm(src + stolen, &hs);
        if (len == 0 || (hs.flags & F_ERROR) != 0 || stolen + len > kMaxStolenBytes) {
            restore_code_protection(target, kMaxStolenBytes);
            release_trampoline(trampoline);
            return false;
        }
        if (!terminal &&
            !relocate_instruction(trampoline,
                                  trampolineLen,
                                  kTrampolineSize,
                                  src + stolen,
                                  reinterpret_cast<uintptr_t>(src + stolen),
                                  reinterpret_cast<uintptr_t>(trampoline + trampolineLen),
                                  hs,
                                  terminal)) {
            restore_code_protection(target, kMaxStolenBytes);
            release_trampoline(trampoline);
            return false;
        }
        stolen += len;
    }
    if (stolen < kJumpSize) {
        restore_code_protection(target, kMaxStolenBytes);
        release_trampoline(trampoline);
        return false;
    }
    if (!terminal && !append_abs_jump(trampoline, trampolineLen, kTrampolineSize, reinterpret_cast<uintptr_t>(src + stolen))) {
        restore_code_protection(target, kMaxStolenBytes);
        release_trampoline(trampoline);
        return false;
    }

    copy_bytes(detour.original, target, stolen);
    __builtin___clear_cache(reinterpret_cast<char*>(trampoline), reinterpret_cast<char*>(trampoline + trampolineLen));
    if (!make_trampoline_executable(trampoline)) {
        restore_code_protection(target, kMaxStolenBytes);
        release_trampoline(trampoline);
        return false;
    }
    write_abs_jump(src, replacement);
    if (stolen > kJumpSize) {
        set_bytes(src + kJumpSize, 0x90, stolen - kJumpSize);
    }
    __builtin___clear_cache(reinterpret_cast<char*>(src), reinterpret_cast<char*>(src + stolen));
    restore_code_protection(target, kMaxStolenBytes);

    detour.target = target;
    detour.replacement = replacement;
    detour.trampoline = trampoline;
    detour.stolenLen = stolen;
    detour.installed = true;
    return true;
}

bool uninstall_inline_detour(InlineDetour& detour) {
    if (!detour.installed) {
        return true;
    }
    if (!make_code_writable(detour.target, detour.stolenLen)) {
        return false;
    }
    copy_bytes(detour.target, detour.original, detour.stolenLen);
    __builtin___clear_cache(static_cast<char*>(detour.target), static_cast<char*>(detour.target) + detour.stolenLen);
    restore_code_protection(detour.target, detour.stolenLen);
    release_trampoline(detour.trampoline);
    detour = {};
    return true;
}

bool install_tiny_detour(TinyDetour& detour, void* target, void* replacement) {
    constexpr size_t kTinyPatchSize = sizeof(detour.original);
    if (detour.installed) {
        return true;
    }
    if (!target || !replacement || target == replacement) {
        return false;
    }
    if (!make_code_writable(target, kTinyPatchSize)) {
        return false;
    }

    auto* src = static_cast<uint8_t*>(target);
    copy_bytes(detour.original, src, kTinyPatchSize);
    if (!write_rel_jump(src, replacement)) {
        restore_code_protection(target, kTinyPatchSize);
        return false;
    }
    if (kTinyPatchSize > 5) {
        set_bytes(src + 5, 0x90, kTinyPatchSize - 5);
    }
    __builtin___clear_cache(reinterpret_cast<char*>(src), reinterpret_cast<char*>(src + kTinyPatchSize));
    restore_code_protection(target, kTinyPatchSize);

    detour.target = target;
    detour.replacement = replacement;
    detour.installed = true;
    return true;
}

bool uninstall_tiny_detour(TinyDetour& detour) {
    constexpr size_t kTinyPatchSize = sizeof(detour.original);
    if (!detour.installed) {
        return true;
    }
    if (!make_code_writable(detour.target, kTinyPatchSize)) {
        return false;
    }
    copy_bytes(detour.target, detour.original, kTinyPatchSize);
    __builtin___clear_cache(static_cast<char*>(detour.target), static_cast<char*>(detour.target) + kTinyPatchSize);
    restore_code_protection(detour.target, kTinyPatchSize);
    detour = {};
    return true;
}

InstalledHook* find_hook(const char* symbol) {
    if (!symbol) {
        return nullptr;
    }
    for (size_t i = 0; i < g_hookCount; ++i) {
        InstalledHook& hook = g_hooks[i];
        if (strcmp(hook.symbol, symbol) == 0) {
            return &hook;
        }
    }
    return nullptr;
}

LateFunctionHook* find_late_hook(const char* symbol) {
    if (!symbol) {
        return nullptr;
    }
    for (size_t i = 0; i < g_lateHookCount; ++i) {
        LateFunctionHook& hook = g_lateHooks[i];
        if (strcmp(hook.symbol, symbol) == 0) {
            return &hook;
        }
    }
    return nullptr;
}

bool has_pending_late_hooks(void) {
    for (size_t i = 0; i < g_lateHookCount; ++i) {
        if (!g_lateHooks[i].detour.installed) {
            return true;
        }
    }
    return false;
}

bool has_module_filtered_pending_late_hooks(void) {
    for (size_t i = 0; i < g_lateHookCount; ++i) {
        const LateFunctionHook& hook = g_lateHooks[i];
        if (!hook.detour.installed && hook.moduleName && *hook.moduleName) {
            return true;
        }
    }
    return false;
}

const char* late_hook_module_label(const char* moduleName) {
    return moduleName && *moduleName ? moduleName : "<any>";
}

void* resolve_load_start_module_body(void* entry) {
    if (!entry) {
        return nullptr;
    }
    return static_cast<uint8_t*>(entry) + kLoadStartModuleBodyOffset;
}

void* resolve_hook_target(const InstalledHook& hook, void* target) {
    if (target && strcmp(hook.symbol, kLoadStartModuleSymbol) == 0) {
        void* body = resolve_load_start_module_body(target);
        if (body) {
            g_loadStartModuleBody = body;
            return body;
        }
        return nullptr;
    }
    return target;
}

bool append_hook_spec(const char* symbol, void* target, void* replacement, bool optional) {
    if (!symbol || !target || !replacement || g_hookCount >= kMaxHookSpecs) {
        return false;
    }
    g_hooks[g_hookCount++] = InstalledHook{
        symbol,
        target,
        replacement,
        optional,
        {},
    };
    return true;
}

void load_hook_specs(void) {
    if (g_hookCount != 0) {
        return;
    }

    (void)append_hook_spec(kLoadStartModuleSymbol,
                           reinterpret_cast<void*>(&sceKernelLoadStartModule),
                           reinterpret_cast<void*>(&sceKernelLoadStartModule_hook),
                           true);

    size_t count = 0;
    const HookSpec* specs = getBackportHookSpecs(&count);
    if (!specs) {
        return;
    }
    const size_t room = kMaxHookSpecs - g_hookCount;
    if (count > room) {
        count = room;
    }
    for (size_t i = 0; i < count; ++i) {
        if (!specs[i].symbol || !specs[i].target || !specs[i].replacement) {
            continue;
        }
        (void)append_hook_spec(specs[i].symbol,
                               specs[i].target,
                               specs[i].replacement,
                               specs[i].optional != 0);
    }
}

void load_late_hook_specs(void) {
    if (g_lateHookCount != 0) {
        return;
    }

    size_t count = 0;
    const LateDlsymHookSpec* specs = getLateDlsymHookSpecs(&count);
    if (!specs) {
        return;
    }
    if (count > kMaxLateHookSpecs) {
        count = kMaxLateHookSpecs;
    }
    for (size_t i = 0; i < count; ++i) {
        if (!specs[i].symbol || !specs[i].replacement) {
            continue;
        }
        g_lateHooks[g_lateHookCount++] = LateFunctionHook{
            specs[i].moduleName,
            specs[i].symbol,
            specs[i].replacement,
            {},
        };
    }
}

bool module_name_matches(const char* moduleFileName, const char* expectedName) {
    if (!expectedName || !*expectedName) {
        return true;
    }
    if (!moduleFileName || !*moduleFileName) {
        return false;
    }
    return strstr(moduleFileName, expectedName) != nullptr;
}

const char* get_module_info_name(SceKernelModule moduleHandle, const char* fallbackName) {
    set_bytes(&g_loadedModuleInfo, 0, sizeof(g_loadedModuleInfo));
    g_loadedModuleInfo.size = sizeof(g_loadedModuleInfo);
    if (sceKernelGetModuleInfo(moduleHandle, &g_loadedModuleInfo) == 0) {
        g_loadedModuleInfo.name[sizeof(g_loadedModuleInfo.name) - 1] = '\0';
        if (g_loadedModuleInfo.name[0] != '\0') {
            return g_loadedModuleInfo.name;
        }
    }
    return fallbackName;
}

void install_late_hooks_for_module(SceKernelModule moduleHandle, const char* moduleFileName) {
    if (moduleHandle <= 0 || g_lateHookInstallDepth != 0 || !has_pending_late_hooks()) {
        return;
    }

    ++g_lateHookInstallDepth;
    const bool needModuleName = has_module_filtered_pending_late_hooks();
    bool triedModuleInfo = needModuleName;
    const char* moduleName = needModuleName ? get_module_info_name(moduleHandle, moduleFileName) : moduleFileName;
    for (size_t i = 0; i < g_lateHookCount; ++i) {
        LateFunctionHook& hook = g_lateHooks[i];
        if (hook.detour.installed || !module_name_matches(moduleName, hook.moduleName)) {
            continue;
        }

        void* target = nullptr;
        const int rc = sceKernelDlsym(moduleHandle, hook.symbol, &target);
        if (rc != 0 || !target) {
            continue;
        }

        if (!moduleName && !triedModuleInfo) {
            moduleName = get_module_info_name(moduleHandle, nullptr);
            triedModuleInfo = true;
        }

        char line[256];
        snprintf(line,
                 sizeof(line),
                 "[backport-helper] late.resolve module=%s expected=%s handle=0x%x symbol=%s target=%p\n",
                 moduleName ? moduleName : "<null>",
                 late_hook_module_label(hook.moduleName),
                 static_cast<unsigned int>(moduleHandle),
                 hook.symbol ? hook.symbol : "<null>",
                 target);
        klog_text(line);

        if (install_inline_detour(hook.detour, target, hook.replacement)) {
            klog_hook_result(hook.symbol, "installed", hook.detour.target, hook.detour.trampoline);
        } else {
            klog_hook_result(hook.symbol, "failed", target, nullptr);
        }
    }
    --g_lateHookInstallDepth;
}

void install_late_hooks_for_loaded_modules(void) {
    if (!has_pending_late_hooks()) {
        return;
    }

    size_t actualNum = 0;
    int rc = sceKernelGetModuleList(g_loadedModuleScan, kMaxLoadedModuleScan, &actualNum);
    char line[192];
    snprintf(line,
             sizeof(line),
             "[backport-helper] late.scan list=sceKernelGetModuleList rc=0x%x actual=%llu capacity=%llu\n",
             static_cast<unsigned int>(rc),
             static_cast<unsigned long long>(actualNum),
             static_cast<unsigned long long>(kMaxLoadedModuleScan));
    klog_text(line);
    if (rc != 0) {
        return;
    }

    if (actualNum > kMaxLoadedModuleScan) {
        actualNum = kMaxLoadedModuleScan;
    }
    for (size_t i = 0; i < actualNum; ++i) {
        if (!has_pending_late_hooks()) {
            break;
        }
        install_late_hooks_for_module(g_loadedModuleScan[i], nullptr);
    }
}

SceKernelModule call_load_start_module_original(void* original,
                                              const char* moduleFileName,
                                              size_t args,
                                              const void* argp,
                                              uint32_t flags,
                                              const SceKernelLoadModuleOpt* pOpt,
                                              int* pRes) {
    if (!original) {
        return static_cast<SceKernelModule>(SCE_KERNEL_ERROR_ENOSYS);
    }

    if (g_loadStartHookDepth != 0) {
        return reinterpret_cast<SceKernelLoadStartModuleFn>(original)(moduleFileName, args, argp, flags, pOpt, pRes);
    }

    ++g_loadStartHookDepth;
    const SceKernelModule moduleHandle =
        reinterpret_cast<SceKernelLoadStartModuleFn>(original)(moduleFileName, args, argp, flags, pOpt, pRes);
    ErrnoGuard errnoGuard;

    char line[256];
    snprintf(line,
             sizeof(line),
             "[backport-helper] load_start result module=%s handle=0x%x pRes=0x%x\n",
             moduleFileName ? moduleFileName : "<null>",
             static_cast<unsigned int>(moduleHandle),
             pRes ? static_cast<unsigned int>(*pRes) : 0u);
    klog_text(line);

    if (moduleHandle > 0) {
        install_late_hooks_for_module(moduleHandle, moduleFileName);
    }
    --g_loadStartHookDepth;
    return moduleHandle;
}

SceKernelModule sceKernelLoadStartModule_hook(const char* moduleFileName,
                                              size_t args,
                                              const void* argp,
                                              uint32_t flags,
                                              const SceKernelLoadModuleOpt* pOpt,
                                              int* pRes) {
    InstalledHook* hook = find_hook(kLoadStartModuleSymbol);
    void* original = hook && hook->detour.installed ? hook->detour.trampoline : nullptr;
    return call_load_start_module_original(original,
                                           moduleFileName,
                                           args,
                                           argp,
                                           flags,
                                           pOpt,
                                           pRes);
}

SceKernelModule sceKernelLoadStartModuleForSysmodule_hook(const char* moduleFileName,
                                                          size_t args,
                                                          const void* argp,
                                                          uint32_t flags,
                                                          const SceKernelLoadModuleOpt* pOpt,
                                                          int* pRes) {
    return call_load_start_module_original(g_loadStartModuleBody,
                                           moduleFileName,
                                           args,
                                           argp,
                                           flags | 0x10000u,
                                           pOpt,
                                           pRes);
}

} // namespace

extern "C" int hooksInstall(void) {
    if (g_hooksInstalled) {
        return SCE_OK;
    }

    load_hook_specs();
    load_late_hook_specs();

    g_loadStartModuleBody = resolve_load_start_module_body(reinterpret_cast<void*>(&sceKernelLoadStartModule));

    int failedRequired = 0;
    for (size_t i = 0; i < g_hookCount; ++i) {
        InstalledHook& hook = g_hooks[i];
        void* rawTarget = hook.target;
        void* target = resolve_hook_target(hook, rawTarget);
        if (!target) {
            klog_hook_result(hook.symbol, rawTarget ? "failed" : "missing", rawTarget, nullptr);
            if (!hook.optional) {
                ++failedRequired;
            }
            continue;
        }
        if (install_inline_detour(hook.detour, target, hook.replacement)) {
            klog_hook_result(hook.symbol, "installed", hook.detour.target, hook.detour.trampoline);
        } else {
            klog_hook_result(hook.symbol, "failed", target, nullptr);
            if (!hook.optional) {
                ++failedRequired;
            }
        }
    }

    void* sysmoduleTarget = reinterpret_cast<void*>(&sceKernelLoadStartModuleForSysmodule);
    InstalledHook* loadStartHook = find_hook(kLoadStartModuleSymbol);
    if (sysmoduleTarget &&
        !(loadStartHook && loadStartHook->detour.installed && loadStartHook->detour.target == g_loadStartModuleBody) &&
        g_loadStartModuleBody) {
        if (install_tiny_detour(g_loadStartModuleForSysmoduleDetour,
                                sysmoduleTarget,
                                reinterpret_cast<void*>(&sceKernelLoadStartModuleForSysmodule_hook))) {
            klog_hook_result("sceKernelLoadStartModuleForSysmodule", "installed", sysmoduleTarget, nullptr);
        } else {
            klog_hook_result("sceKernelLoadStartModuleForSysmodule", "failed", sysmoduleTarget, nullptr);
        }
    }

    if (failedRequired != 0) {
        (void)hooksUninstall();
        return SCE_RTC_ERROR_NOT_SUPPORTED;
    }

    install_late_hooks_for_loaded_modules();

    g_hooksInstalled = 1;
    return SCE_OK;
}

extern "C" int hooksUninstall(void) {
    int failed = 0;
    if (!uninstall_tiny_detour(g_loadStartModuleForSysmoduleDetour)) {
        ++failed;
    }
    for (size_t i = g_rawHookCount; i > 0; --i) {
        if (!uninstall_inline_detour(g_rawHooks[i - 1])) {
            ++failed;
        }
    }
    if (failed == 0) {
        g_rawHookCount = 0;
    }
    for (size_t i = g_lateHookCount; i > 0; --i) {
        if (!uninstall_inline_detour(g_lateHooks[i - 1].detour)) {
            ++failed;
        }
    }
    for (size_t i = g_hookCount; i > 0; --i) {
        if (!uninstall_inline_detour(g_hooks[i - 1].detour)) {
            ++failed;
        }
    }
    if (failed == 0) {
        g_hooksInstalled = 0;
    }
    return failed == 0 ? SCE_OK : SCE_RTC_ERROR_NOT_SUPPORTED;
}

extern "C" int hooksInstalled(void) {
    return g_hooksInstalled;
}

extern "C" void* hookGetOriginalFunction(const char* symbol) {
    InstalledHook* hook = find_hook(symbol);
    if (!hook) {
        return nullptr;
    }
    return hook->detour.installed ? hook->detour.trampoline : hook->detour.target;
}

extern "C" void* hookGetOriginalLateDlsymFunction(const char* symbol) {
    LateFunctionHook* hook = find_late_hook(symbol);
    if (!hook) {
        return nullptr;
    }
    return hook->detour.installed ? hook->detour.trampoline : hook->detour.target;
}

extern "C" int hookInstallAbsolute(void* target, void* replacement, void** originalOut) {
    if (originalOut) {
        *originalOut = nullptr;
    }
    if (!target || !replacement) {
        klog_hook_result("<absolute>", "invalid", target, nullptr);
        return SCE_RTC_ERROR_NOT_SUPPORTED;
    }

    for (size_t i = 0; i < g_rawHookCount; ++i) {
        InlineDetour& hook = g_rawHooks[i];
        if (hook.target != target) {
            continue;
        }
        if (originalOut) {
            *originalOut = hook.trampoline;
        }
        klog_hook_result("<absolute>", hook.installed ? "existing" : "failed", target, hook.trampoline);
        return hook.installed ? SCE_OK : SCE_RTC_ERROR_NOT_SUPPORTED;
    }

    if (g_rawHookCount >= kMaxRawHookSpecs) {
        klog_hook_result("<absolute>", "full", target, nullptr);
        return SCE_RTC_ERROR_NOT_SUPPORTED;
    }

    InlineDetour& hook = g_rawHooks[g_rawHookCount];
    if (!install_inline_detour(hook, target, replacement)) {
        klog_hook_result("<absolute>", "failed", target, nullptr);
        hook = {};
        return SCE_RTC_ERROR_NOT_SUPPORTED;
    }

    ++g_rawHookCount;
    if (originalOut) {
        *originalOut = hook.trampoline;
    }
    klog_hook_result("<absolute>", "installed", hook.target, hook.trampoline);
    return SCE_OK;
}
