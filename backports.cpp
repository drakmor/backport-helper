#define LIBRARY_IMPL 1
#include "rtc.h"

/*
 * Add compatibility exports here.
 *
 * BACKPORT_SDK is the target compatibility version selected by MSBuild.
 * A function guarded with "#if BACKPORT_SDK <= 6" is exported by targets
 * Backport4, Backport5, and Backport6.
 */

#if BACKPORT_SDK <= 10
PRX_INTERFACE int sceKernelGetOperationMode(int* operationMode, int* lowEnergyMode) {
    if (operationMode) {
        *operationMode = 0;
    }
    if (lowEnergyMode) {
        *lowEnergyMode = 0;
    }
    return SCE_OK;
}
#endif

#if defined(BACKPORT_RAW_NID_EXAMPLE)
/*
 * Example for exporting a function when only the target NID is known.
 *
 * 1. Keep this local alias stable: backportRawNid_ReplaceMe.
 * 2. Add backportRawNid_ReplaceMe=<target raw NID> to
 *    tools/nidmaps/libSceRtc.raw-nids.txt.
 * 3. The post-link build step computes the lld-generated NID automatically
 *    and replaces it with the target raw NID.
 *    /p:BackportExtraPreprocessorDefinitions=BACKPORT_RAW_NID_EXAMPLE
 */
extern "C" PRX_INTERFACE int backportRawNid_ReplaceMe(void) __asm__("backportRawNid_ReplaceMe");
extern "C" PRX_INTERFACE int backportRawNid_ReplaceMe(void) {
    return SCE_OK;
}
#endif
