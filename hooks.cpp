#include "hooks.h"

#include "hde64.h"
#include "rtc.h"

#include <_kernel.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

extern "C" int sceKernelDlsym(SceKernelModule handle, const char* symbol, void** addrp);
extern "C" int sceKernelMprotect(const void* addr, size_t len, int prot);
extern "C" int sceKernelMapFlexibleMemory(void** addr, size_t len, int prot, int flags);
extern "C" int sceKernelMunmap(void* addr, size_t len);

namespace {

constexpr size_t kJumpSize = 14;
constexpr size_t kMaxStolenBytes = 64;
constexpr size_t kTrampolinePageSize = SCE_KERNEL_PAGE_SIZE;
constexpr size_t kTrampolineSize = 512;
constexpr size_t kTrampolineSlotsPerPage = kTrampolinePageSize / kTrampolineSize;
constexpr SceKernelModule kLibkernelHandle = 0x2001;
constexpr int kCodeProt = SCE_KERNEL_PROT_CPU_READ | SCE_KERNEL_PROT_CPU_EXEC;
constexpr int kRwProt = SCE_KERNEL_PROT_CPU_ALL;

struct InlineDetour {
    void* target;
    void* replacement;
    void* trampoline;
    size_t stolenLen;
    uint8_t original[kMaxStolenBytes];
    bool installed;
};

struct InstalledHook {
    const char* symbol;
    void* replacement;
    bool optional;
    InlineDetour detour;
};

struct LateDlsymHook {
    const char* moduleName;
    const char* symbol;
    void* replacement;
    void* original;
};

using SceKernelDlsymFn = int (*)(SceKernelModule, const char*, void**);

constexpr size_t kMaxHookSpecs = 32;
constexpr size_t kMaxLateDlsymHookSpecs = 32;
constexpr size_t kMaxInlineDetours = kMaxHookSpecs + 1u;
constexpr size_t kMaxTrampolinePages = (kMaxInlineDetours + kTrampolineSlotsPerPage - 1u) / kTrampolineSlotsPerPage;

InstalledHook g_hooks[kMaxHookSpecs] = {};
size_t g_hookCount = 0;
LateDlsymHook g_lateDlsymHooks[kMaxLateDlsymHookSpecs] = {};
size_t g_lateDlsymHookCount = 0;
InlineDetour g_dlsymDetour = {};
void* g_trampolinePages[kMaxTrampolinePages] = {};
uint32_t g_trampolinePageUsed[kMaxTrampolinePages] = {};
int g_hooksInstalled = 0;

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
    return sceKernelMprotect(page, kTrampolinePageSize, prot) == 0;
}

void* allocate_trampoline() {
    for (size_t pageIndex = 0; pageIndex < kMaxTrampolinePages; ++pageIndex) {
        if (!g_trampolinePages[pageIndex]) {
            void* mem = nullptr;
            if (sceKernelMapFlexibleMemory(&mem, kTrampolinePageSize, kRwProt, 0) != 0) {
                return nullptr;
            }
            g_trampolinePages[pageIndex] = mem;
            g_trampolinePageUsed[pageIndex] = 0;
        }
        const uint32_t used = g_trampolinePageUsed[pageIndex];
        for (size_t slot = 0; slot < kTrampolineSlotsPerPage; ++slot) {
            const uint32_t bit = 1u << slot;
            if ((used & bit) != 0) {
                continue;
            }
            if (!protect_trampoline_page(g_trampolinePages[pageIndex], kRwProt)) {
                return nullptr;
            }
            g_trampolinePageUsed[pageIndex] = used | bit;
            return static_cast<uint8_t*>(g_trampolinePages[pageIndex]) + slot * kTrampolineSize;
        }
    }
    return nullptr;
}

bool make_trampoline_executable(void* trampoline) {
    const uintptr_t slot = reinterpret_cast<uintptr_t>(trampoline);
    for (size_t pageIndex = 0; pageIndex < kMaxTrampolinePages; ++pageIndex) {
        void* page = g_trampolinePages[pageIndex];
        const uintptr_t begin = reinterpret_cast<uintptr_t>(page);
        if (page && slot >= begin && slot < begin + kTrampolinePageSize) {
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
        void* page = g_trampolinePages[pageIndex];
        const uintptr_t begin = reinterpret_cast<uintptr_t>(page);
        if (!page || slot < begin || slot >= begin + kTrampolinePageSize) {
            continue;
        }
        const size_t slotIndex = (slot - begin) / kTrampolineSize;
        g_trampolinePageUsed[pageIndex] &= ~(1u << slotIndex);
        if (g_trampolinePageUsed[pageIndex] == 0) {
            (void)sceKernelMunmap(page, kTrampolinePageSize);
            g_trampolinePages[pageIndex] = nullptr;
        } else {
            (void)protect_trampoline_page(page, kCodeProt);
        }
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

LateDlsymHook* find_late_dlsym_hook(const char* symbol) {
    if (!symbol) {
        return nullptr;
    }
    for (size_t i = 0; i < g_lateDlsymHookCount; ++i) {
        LateDlsymHook& hook = g_lateDlsymHooks[i];
        if (strcmp(hook.symbol, symbol) == 0) {
            return &hook;
        }
    }
    return nullptr;
}

void* resolve_libkernel_symbol(const char* symbol) {
    void* addr = nullptr;
    if (!symbol || sceKernelDlsym(kLibkernelHandle, symbol, &addr) != 0) {
        return nullptr;
    }
    return addr;
}

void load_hook_specs(void) {
    if (g_hookCount != 0) {
        return;
    }
    size_t count = 0;
    const HookSpec* specs = getBackportHookSpecs(&count);
    if (!specs) {
        return;
    }
    if (count > kMaxHookSpecs) {
        count = kMaxHookSpecs;
    }
    for (size_t i = 0; i < count; ++i) {
        if (!specs[i].symbol || !specs[i].replacement) {
            continue;
        }
        g_hooks[g_hookCount++] = InstalledHook{
            specs[i].symbol,
            specs[i].replacement,
            specs[i].optional != 0,
            {},
        };
    }
}

void load_late_dlsym_hook_specs(void) {
    if (g_lateDlsymHookCount != 0) {
        return;
    }
    size_t count = 0;
    const LateDlsymHookSpec* specs = getLateDlsymHookSpecs(&count);
    if (!specs) {
        return;
    }
    if (count > kMaxLateDlsymHookSpecs) {
        count = kMaxLateDlsymHookSpecs;
    }
    for (size_t i = 0; i < count; ++i) {
        if (!specs[i].symbol || !specs[i].replacement) {
            continue;
        }
        g_lateDlsymHooks[g_lateDlsymHookCount++] = LateDlsymHook{
            specs[i].moduleName,
            specs[i].symbol,
            specs[i].replacement,
            nullptr,
        };
    }
}

int sceKernelDlsym_hook(SceKernelModule handle, const char* symbol, void** addrp) {
    auto* original = reinterpret_cast<SceKernelDlsymFn>(g_dlsymDetour.trampoline);
    if (!original) {
        return SCE_RTC_ERROR_NOT_SUPPORTED;
    }

    const int rc = original(handle, symbol, addrp);
    if (rc == 0 && addrp && *addrp) {
        LateDlsymHook* hook = find_late_dlsym_hook(symbol);
        if (hook) {
            if (!hook->original) {
                hook->original = *addrp;
            }
            *addrp = hook->replacement;
        }
    }
    return rc;
}

void install_late_dlsym_dispatcher(void) {
    if (g_lateDlsymHookCount == 0 || g_dlsymDetour.installed) {
        return;
    }
    void* target = nullptr;
    if (sceKernelDlsym(kLibkernelHandle, "sceKernelDlsym", &target) != 0 || !target) {
        return;
    }
    (void)install_inline_detour(g_dlsymDetour, target, reinterpret_cast<void*>(&sceKernelDlsym_hook));
}

} // namespace

extern "C" int hooksInstall(void) {
    if (g_hooksInstalled) {
        return SCE_OK;
    }

    load_hook_specs();
    load_late_dlsym_hook_specs();

    int failedRequired = 0;
    for (size_t i = 0; i < g_hookCount; ++i) {
        InstalledHook& hook = g_hooks[i];
        void* target = resolve_libkernel_symbol(hook.symbol);
        if (!target) {
            if (!hook.optional) {
                ++failedRequired;
            }
            continue;
        }
        if (!install_inline_detour(hook.detour, target, hook.replacement) && !hook.optional) {
            ++failedRequired;
        }
    }
    if (failedRequired != 0) {
        (void)hooksUninstall();
        return SCE_RTC_ERROR_NOT_SUPPORTED;
    }

    install_late_dlsym_dispatcher();
    g_hooksInstalled = 1;
    return SCE_OK;
}

extern "C" int hooksUninstall(void) {
    int failed = 0;
    if (!uninstall_inline_detour(g_dlsymDetour)) {
        ++failed;
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
    LateDlsymHook* hook = find_late_dlsym_hook(symbol);
    return hook ? hook->original : nullptr;
}
