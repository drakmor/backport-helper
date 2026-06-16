#ifndef RTC_H
#define RTC_H

#include <stdint.h>
#include <sys/types.h>
#include <_rtc.h>

#ifndef BACKPORT_SDK
#define BACKPORT_SDK 13
#endif

#ifdef LIBRARY_IMPL
#  if defined(__ORBIS__) || defined(__PROSPERO__)
#    define PRX_INTERFACE __declspec(dllexport)
#  else
#    define PRX_INTERFACE __attribute__((visibility("default")))
#  endif
#else
#  if defined(__ORBIS__) || defined(__PROSPERO__)
#    define PRX_INTERFACE __declspec(dllimport)
#  else
#    define PRX_INTERFACE
#  endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SCE_OK
#define SCE_OK 0
#endif

#ifndef SCE_RTC_ERROR_NOT_INITIALIZED
#define SCE_RTC_ERROR_NOT_INITIALIZED       (-2135621631)
#define SCE_RTC_ERROR_INVALID_POINTER       (-2135621630)
#define SCE_RTC_ERROR_INVALID_VALUE         (-2135621629)
#define SCE_RTC_ERROR_INVALID_ARG           (-2135621628)
#define SCE_RTC_ERROR_NOT_SUPPORTED         (-2135621627)
#define SCE_RTC_ERROR_NO_CLOCK              (-2135621626)
#define SCE_RTC_ERROR_BAD_PARSE             (-2135621625)
#define SCE_RTC_ERROR_INVALID_YEAR          (-2135621624)
#define SCE_RTC_ERROR_INVALID_MONTH         (-2135621623)
#define SCE_RTC_ERROR_INVALID_DAY           (-2135621622)
#define SCE_RTC_ERROR_INVALID_HOUR          (-2135621621)
#define SCE_RTC_ERROR_INVALID_MINUTE        (-2135621620)
#define SCE_RTC_ERROR_INVALID_SECOND        (-2135621619)
#define SCE_RTC_ERROR_INVALID_MICROSECOND   (-2135621618)
#endif

typedef struct SceRtcDateTime {
    unsigned short year;
    unsigned short month;
    unsigned short day;
    unsigned short hour;
    unsigned short minute;
    unsigned short second;
    unsigned int microsecond;
} SceRtcDateTime;

PRX_INTERFACE int sceRtcInit(void);
PRX_INTERFACE int sceRtcEnd(void);
PRX_INTERFACE int sceRtcSetConf(int64_t a1, int64_t a2, int64_t a3, int64_t a4, int64_t a5, int64_t a6);
PRX_INTERFACE int sceRtcSetCurrentTick(const SceRtcTick* pTick);
PRX_INTERFACE int sceRtcGetCurrentTick(SceRtcTick* pTick);
PRX_INTERFACE int sceRtcGetCurrentClock(SceRtcDateTime* pTime, int iTimeZone);
PRX_INTERFACE int sceRtcGetCurrentClockLocalTime(SceRtcDateTime* pTime);
PRX_INTERFACE int sceRtcConvertUtcToLocalTime(const SceRtcTick* pUtc, SceRtcTick* pLocalTime);
PRX_INTERFACE int sceRtcConvertLocalTimeToUtc(const SceRtcTick* pLocalTime, SceRtcTick* pUtc);
PRX_INTERFACE int sceRtcGetCurrentNetworkTick(SceRtcTick* pTick);
PRX_INTERFACE int sceRtcGetCurrentRawNetworkTick(SceRtcTick* pTick);
PRX_INTERFACE int sceRtcGetCurrentDebugNetworkTick(SceRtcTick* pTick);
PRX_INTERFACE int sceRtcGetCurrentAdNetworkTick(SceRtcTick* pTick);
PRX_INTERFACE int sceRtcSetCurrentNetworkTick(const SceRtcTick* pTick);
PRX_INTERFACE int sceRtcSetCurrentDebugNetworkTick(const SceRtcTick* pTick);
PRX_INTERFACE int sceRtcSetCurrentAdNetworkTick(const SceRtcTick* pTick);
PRX_INTERFACE int sceRtcParseDateTime(SceRtcTick* pUtc, const char* pszDateTime);
PRX_INTERFACE int sceRtcParseRFC3339(SceRtcTick* pUtc, const char* pszDateTime);
PRX_INTERFACE int sceRtcFormatRFC2822LocalTime(char* pszDateTime, const SceRtcTick* pUtc);
PRX_INTERFACE int sceRtcFormatRFC2822(char* pszDateTime, const SceRtcTick* pUtc, int iTimeZoneMinutes);
PRX_INTERFACE int sceRtcFormatRFC3339PreciseLocalTime(char* pszDateTime, const SceRtcTick* pUtc, unsigned int nFractionDigits);
PRX_INTERFACE int sceRtcFormatRFC3339Precise(char* pszDateTime, const SceRtcTick* pUtc, int iTimeZoneMinutes, unsigned int nFractionDigits);
PRX_INTERFACE int sceRtcFormatRFC3339LocalTime(char* pszDateTime, const SceRtcTick* pUtc);
PRX_INTERFACE int sceRtcFormatRFC3339(char* pszDateTime, const SceRtcTick* pUtc, int iTimeZoneMinutes);
PRX_INTERFACE unsigned int sceRtcGetTickResolution(void);
PRX_INTERFACE int sceRtcIsLeapYear(int year);
PRX_INTERFACE int sceRtcGetDaysInMonth(int year, int month);
PRX_INTERFACE int sceRtcGetDayOfWeek(int year, int month, int day);
PRX_INTERFACE int sceRtcCheckValid(const SceRtcDateTime* pTime);
PRX_INTERFACE int sceRtcSetDosTime(SceRtcDateTime* pTime, unsigned int uiDosTime);
PRX_INTERFACE int sceRtcGetDosTime(const SceRtcDateTime* pTime, unsigned int* puiDosTime);
PRX_INTERFACE int sceRtcSetWin32FileTime(SceRtcDateTime* pTime, uint64_t ulWin32Time);
PRX_INTERFACE int sceRtcSetTick(SceRtcDateTime* pTime, const SceRtcTick* pTick);
PRX_INTERFACE int sceRtcGetWin32FileTime(const SceRtcDateTime* pTime, uint64_t* ulWin32Time);
PRX_INTERFACE int sceRtcGetTick(const SceRtcDateTime* pTime, SceRtcTick* pTick);
PRX_INTERFACE int sceRtcSetTime_t(SceRtcDateTime* pTime, time_t llTime);
PRX_INTERFACE int sceRtcGetTime_t(const SceRtcDateTime* pTime, time_t* pllTime);
PRX_INTERFACE int sceRtcTickAddTicks(SceRtcTick* pTick0, const SceRtcTick* pTick1, int64_t lAdd);
PRX_INTERFACE int sceRtcTickAddMicroseconds(SceRtcTick* pTick0, const SceRtcTick* pTick1, int64_t lAdd);
PRX_INTERFACE int sceRtcTickAddSeconds(SceRtcTick* pTick0, const SceRtcTick* pTick1, int64_t lAdd);
PRX_INTERFACE int sceRtcTickAddMinutes(SceRtcTick* pTick0, const SceRtcTick* pTick1, int64_t lAdd);
PRX_INTERFACE int sceRtcTickAddHours(SceRtcTick* pTick0, const SceRtcTick* pTick1, int lAdd);
PRX_INTERFACE int sceRtcTickAddDays(SceRtcTick* pTick0, const SceRtcTick* pTick1, int lAdd);
PRX_INTERFACE int sceRtcTickAddWeeks(SceRtcTick* pTick0, const SceRtcTick* pTick1, int lAdd);
PRX_INTERFACE int sceRtcTickAddMonths(SceRtcTick* pTick0, const SceRtcTick* pTick1, int lAdd);
PRX_INTERFACE int sceRtcTickAddYears(SceRtcTick* pTick0, const SceRtcTick* pTick1, int lAdd);
PRX_INTERFACE int sceRtcCompareTick(const SceRtcTick* pTick0, const SceRtcTick* pTick1);

#ifdef __cplusplus
}
#endif

#endif
