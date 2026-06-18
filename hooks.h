#ifndef HOOKS_H
#define HOOKS_H

#include <stddef.h>

typedef struct HookSpec {
    const char* symbol;
    void* target;
    void* replacement;
    int optional;
} HookSpec;

typedef struct LateDlsymHookSpec {
    /* nullptr or "" means: resolve the symbol in any loaded or future module. */
    const char* moduleName;
    const char* symbol;
    void* replacement;
} LateDlsymHookSpec;

#ifdef __cplusplus
extern "C" {
#endif

int hooksInstall(void);
int hooksUninstall(void);
int hooksInstalled(void);
void* hookGetOriginalFunction(const char* symbol);
void* hookGetOriginalLateDlsymFunction(const char* symbol);
const HookSpec* getBackportHookSpecs(size_t* count);
const LateDlsymHookSpec* getLateDlsymHookSpecs(size_t* count);

#ifdef __cplusplus
}
#endif

#endif
