#define LIBRARY_IMPL 1
#include "rtc.h"
#include "hooks.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static constexpr int64_t kTicksPerSecond = 1000000LL;
static constexpr int64_t kTicksPerMinute = 60LL * kTicksPerSecond;
static constexpr int64_t kTicksPerHour = 60LL * kTicksPerMinute;
static constexpr int64_t kTicksPerDay = 24LL * kTicksPerHour;
static constexpr uint64_t kUnixEpochTick = 62135596800000000ULL;
static constexpr uint64_t kWin32EpochTick = 50491123200000000ULL;

extern "C" int sceKernelError(int error);
extern "C" int sceKernelConvertUtcToLocaltime(int64_t utc_seconds, void* local, void* tz, int flags);
extern "C" int sceKernelConvertLocaltimeToUtc(int64_t local_seconds, int64_t dst, void* utc, void* tz, int flags);
extern "C" int sceKernelGettimezone(void* tz);
extern "C" int sceKernelClockGettime(clockid_t clock_id, struct timespec* tp);
extern "C" int sceKernelSettimeofday(const void* tv, const void* tz, int64_t a3, int64_t a4, int64_t a5, int64_t a6);
extern "C" int clock_settime(clockid_t clock_id, const struct timespec* ts);

extern "C" {
    int module_start(size_t args, const void* argp) {
        (void)args;
        (void)argp;
        return hooksInstall();
    }

    int module_stop(size_t args, const void* argp) {
        (void)args;
        (void)argp;
        return hooksUninstall();
    }
}

static inline int rtc_is_leap_year(int year) {
    return (year % 400 == 0) || ((year % 4 == 0) && (year % 100 != 0));
}

static inline int rtc_days_in_month_unchecked(int year, int month) {
    static const unsigned char days[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
    if (month == 2 && rtc_is_leap_year(year)) {
        return 29;
    }
    return days[month - 1];
}

static inline int64_t rtc_days_before_year(int year) {
    const int64_t y = (int64_t)year - 1;
    return y * 365 + y / 4 - y / 100 + y / 400;
}

static inline int64_t rtc_days_before_month(int year, int month) {
    static const int cumulative[12] = {0,31,59,90,120,151,181,212,243,273,304,334};
    int64_t days = cumulative[month - 1];
    if (month > 2 && rtc_is_leap_year(year)) {
        ++days;
    }
    return days;
}

static int rtc_check_valid(const SceRtcDateTime* pTime) {
    if (pTime == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    if (pTime->year < 1 || pTime->year > 9999) return SCE_RTC_ERROR_INVALID_YEAR;
    if (pTime->month < 1 || pTime->month > 12) return SCE_RTC_ERROR_INVALID_MONTH;
    if (pTime->day < 1 || pTime->day > rtc_days_in_month_unchecked(pTime->year, pTime->month)) return SCE_RTC_ERROR_INVALID_DAY;
    if (pTime->hour > 23) return SCE_RTC_ERROR_INVALID_HOUR;
    if (pTime->minute > 59) return SCE_RTC_ERROR_INVALID_MINUTE;
    if (pTime->second > 59) return SCE_RTC_ERROR_INVALID_SECOND;
    if (pTime->microsecond > 999999) return SCE_RTC_ERROR_INVALID_MICROSECOND;
    return SCE_OK;
}

static int rtc_tick_to_datetime(uint64_t tick, SceRtcDateTime* out) {
    if (out == NULL) return SCE_RTC_ERROR_INVALID_POINTER;

    uint64_t day = tick / (uint64_t)kTicksPerDay;
    uint64_t rem = tick % (uint64_t)kTicksPerDay;
    out->hour = (unsigned short)(rem / (uint64_t)kTicksPerHour);
    rem %= (uint64_t)kTicksPerHour;
    out->minute = (unsigned short)(rem / (uint64_t)kTicksPerMinute);
    rem %= (uint64_t)kTicksPerMinute;
    out->second = (unsigned short)(rem / (uint64_t)kTicksPerSecond);
    out->microsecond = (unsigned int)(rem % (uint64_t)kTicksPerSecond);

    int year = 1;
    int64_t days = (int64_t)day;
    int q400 = (int)(days / 146097);
    year += q400 * 400;
    days -= (int64_t)q400 * 146097;
    while (true) {
        int dy = rtc_is_leap_year(year) ? 366 : 365;
        if (days < dy) break;
        days -= dy;
        ++year;
    }

    int month = 1;
    while (month < 12) {
        int dm = rtc_days_in_month_unchecked(year, month);
        if (days < dm) break;
        days -= dm;
        ++month;
    }

    out->year = (unsigned short)year;
    out->month = (unsigned short)month;
    out->day = (unsigned short)(days + 1);
    return SCE_OK;
}

static int rtc_datetime_to_tick(const SceRtcDateTime* pTime, SceRtcTick* pTick) {
    int rc = rtc_check_valid(pTime);
    if (rc != SCE_OK) return rc;
    if (pTick == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    const int64_t days = rtc_days_before_year(pTime->year) + rtc_days_before_month(pTime->year, pTime->month) + (pTime->day - 1);
    pTick->tick = (uint64_t)(days * kTicksPerDay +
        (int64_t)pTime->hour * kTicksPerHour +
        (int64_t)pTime->minute * kTicksPerMinute +
        (int64_t)pTime->second * kTicksPerSecond +
        pTime->microsecond);
    return SCE_OK;
}

static inline int rtc_errno_result(void) {
    if (errno == EIO) {
        return SCE_RTC_ERROR_NOT_INITIALIZED;
    }
    return sceKernelError(errno);
}

static inline uint64_t rtc_tick_from_timespec(const timespec& ts) {
    return (uint64_t)((int64_t)ts.tv_sec * kTicksPerSecond + ts.tv_nsec / 1000) + kUnixEpochTick;
}

static int rtc_get_clock_tick(int clock_id, SceRtcTick* out) {
    if (out == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    timespec ts;
    if (clock_id == 0) {
        const int rc = sceKernelClockGettime(clock_id, &ts);
        if (rc < 0) return rc;
    } else if (clock_gettime(clock_id, &ts) != 0) {
        return rtc_errno_result();
    }
    out->tick = rtc_tick_from_timespec(ts);
    return SCE_OK;
}

static int rtc_set_clock_tick(int clock_id, const SceRtcTick* tick, int allow_null_clear) {
    if (tick == NULL) {
        if (!allow_null_clear) return SCE_RTC_ERROR_INVALID_POINTER;
        if (clock_settime(clock_id, NULL) != 0) return rtc_errno_result();
        return SCE_OK;
    }
    if (tick->tick < kUnixEpochTick) return SCE_RTC_ERROR_INVALID_VALUE;
    const uint64_t delta = tick->tick - kUnixEpochTick;
    timespec ts;
    ts.tv_sec = (time_t)(delta / (uint64_t)kTicksPerSecond);
    ts.tv_nsec = (long)((delta % (uint64_t)kTicksPerSecond) * 1000ULL);
    if (clock_settime(clock_id, &ts) != 0) return rtc_errno_result();
    return SCE_OK;
}

static int rtc_set_realtime_tick(const SceRtcTick* tick) {
    if (tick == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    if (tick->tick < kUnixEpochTick) return SCE_RTC_ERROR_INVALID_VALUE;
    const uint64_t delta = tick->tick - kUnixEpochTick;
    uint64_t tv[2];
    tv[0] = delta / (uint64_t)kTicksPerSecond;
    tv[1] = delta % (uint64_t)kTicksPerSecond;
    return sceKernelSettimeofday(tv, NULL, 0, 0, 0, 0);
}

struct KernelTimezone {
    int32_t standard_offset_seconds;
    int32_t daylight_offset_seconds;
};

static int rtc_current_timezone_offset(int* minutes) {
    unsigned char local_buf[8] = {};
    KernelTimezone tz = {};
    int rc = sceKernelConvertUtcToLocaltime(0, local_buf, &tz, 0);
    if (rc < 0) return rc;
    *minutes = (tz.standard_offset_seconds + tz.daylight_offset_seconds) / 60;
    return SCE_OK;
}

static int rtc_current_local_to_utc_offset(int* minutes) {
    unsigned char utc_buf[8] = {};
    KernelTimezone tz = {};
    int rc = sceKernelConvertLocaltimeToUtc(0, -1, utc_buf, &tz, 0);
    if (rc < 0) return rc;
    *minutes = -((tz.standard_offset_seconds + tz.daylight_offset_seconds) / 60);
    return SCE_OK;
}

static inline int rtc_tick_add_wrap(SceRtcTick* pTick0, const SceRtcTick* pTick1, int64_t add) {
    if (pTick0 == NULL || pTick1 == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    pTick0->tick = pTick1->tick + add;
    return SCE_OK;
}

static inline int rtc_tick_add_checked(SceRtcTick* out, const SceRtcTick* source, int64_t add) {
    if (out == NULL || source == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    const uint64_t tick = source->tick;
    if (add < 0) {
        const uint64_t sub = 0ULL - (uint64_t)add;
        if (tick < sub) return SCE_RTC_ERROR_INVALID_VALUE;
    } else if (UINT64_MAX - tick < (uint64_t)add) {
        return SCE_RTC_ERROR_INVALID_VALUE;
    }
    out->tick = tick + add;
    return SCE_OK;
}

static int rtc_resolve_tick_with_timezone_checked(SceRtcTick* out, const SceRtcTick* source, int timezone_minutes) {
    int rc;
    if (source != NULL) {
        rc = rtc_tick_add_checked(out, source, (int64_t)timezone_minutes * kTicksPerMinute);
    } else {
        sceRtcGetCurrentTick(out);
        rc = rtc_tick_add_checked(out, out, (int64_t)timezone_minutes * kTicksPerMinute);
    }
    return rc;
}

static inline int rtc_parse_ndigits(const char*& p, int count, int* out) {
    int value = 0;
    for (int i = 0; i < count; ++i) {
        if (p[i] < '0' || p[i] > '9') return 0;
        value = value * 10 + (p[i] - '0');
    }
    p += count;
    *out = value;
    return 1;
}

static int rtc_parse_rfc3339_timezone(const char*& p, int* out_minutes) {
    if ((*p & 0xDF) == 'Z') {
        ++p;
        *out_minutes = 0;
        return 1;
    }
    if (*p != '+' && *p != '-') return 0;
    const int sign = (*p++ == '+') ? 1 : -1;
    int hh, mm;
    if (!rtc_parse_ndigits(p, 2, &hh) || *p++ != ':' || !rtc_parse_ndigits(p, 2, &mm)) return 0;
    if (hh < 0 || mm < 0) return 0;
    *out_minutes = sign * (hh * 60 + mm);
    return 1;
}

static inline int rtc_ascii_ieq_n(const char* a, const char* b, int n) {
    for (int i = 0; i < n; ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'a' && ca <= 'z') ca = (char)(ca - 32);
        if (cb >= 'a' && cb <= 'z') cb = (char)(cb - 32);
        if (ca != cb) return 0;
    }
    return 1;
}

static inline int rtc_is_digit(char c) {
    return c >= '0' && c <= '9';
}

static inline void rtc_skip_space(const char*& p) {
    while (*p == ' ' || *p == '\t') ++p;
}

static int rtc_parse_1_or_2_digits(const char*& p, int* out) {
    if (!rtc_is_digit(*p)) return 0;
    int value = *p++ - '0';
    if (rtc_is_digit(*p)) value = value * 10 + (*p++ - '0');
    *out = value;
    return 1;
}

static const char* rtc_parse_named_month(const char* p, int* month) {
    static const char* names[12] = {
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"
    };
    for (int i = 0; i < 12; ++i) {
        int len = (int)strlen(names[i]);
        if (rtc_ascii_ieq_n(p, names[i], len)) {
            *month = i + 1;
            return p + len;
        }
        if (rtc_ascii_ieq_n(p, names[i], 3)) {
            *month = i + 1;
            return p + 3;
        }
    }
    return NULL;
}

static const char* rtc_skip_weekday_prefix(const char* p) {
    static const char* names[7] = {
        "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"
    };
    for (int i = 0; i < 7; ++i) {
        int len = (int)strlen(names[i]);
        const char* end = NULL;
        if (rtc_ascii_ieq_n(p, names[i], len)) end = p + len;
        else if (rtc_ascii_ieq_n(p, names[i], 3)) end = p + 3;
        if (end != NULL) {
            if (*end == ',') ++end;
            rtc_skip_space(end);
            return end;
        }
    }
    return p;
}

static inline int rtc_parse_4_digit_year(const char*& p, int* year) {
    return rtc_parse_ndigits(p, 4, year);
}

static int rtc_parse_2_or_4_digit_year(const char*& p, int* year) {
    if (rtc_is_digit(p[0]) && rtc_is_digit(p[1]) && rtc_is_digit(p[2]) && rtc_is_digit(p[3])) {
        return rtc_parse_4_digit_year(p, year);
    }
    int yy;
    if (!rtc_parse_ndigits(p, 2, &yy)) return 0;
    *year = (yy < 50) ? (2000 + yy) : (1900 + yy);
    return 1;
}

static int rtc_parse_time_of_day(const char*& p, int* hour, int* minute, int* second, int second_required) {
    if (!rtc_parse_1_or_2_digits(p, hour) || *p++ != ':' || !rtc_parse_1_or_2_digits(p, minute)) return 0;
    if (*p == ':') {
        ++p;
        if (!rtc_parse_1_or_2_digits(p, second)) return 0;
    } else {
        if (second_required) return 0;
        *second = 0;
    }
    return 1;
}

static int rtc_parse_zone_abbreviation(const char* p, int* out_minutes, const char** end) {
    struct ZoneEntry { const char* name; int minutes; };
    static const ZoneEntry zones[] = {
        {"GMT", 0}, {"EST", -300}, {"EDT", -240}, {"CST", -360}, {"CDT", -300},
        {"MST", -420}, {"MDT", -360}, {"PST", -480}, {"PDT", -420}, {"NZDT", 780},
        {"NZST", 720}, {"IDLE", 720}, {"NZT", 720}, {"AESST", 660}, {"ACSST", 630},
        {"CADT", 630}, {"SADT", 630}, {"AEST", 600}, {"EAST", 600}, {"GST", 600},
        {"LIGT", 600}, {"ACST", 570}, {"SAST", 570}, {"CAST", 570}, {"AWSST", 540},
        {"JST", 540}, {"KST", 540}, {"WDT", 540}, {"MT", 510}, {"AWST", 480},
        {"CCT", 480}, {"WADT", 480}, {"WST", 480}, {"JT", 450}, {"WAST", 420},
        {"IT", 210}, {"BT", 180}, {"EETDST", 180}, {"EET", 120}, {"CETDST", 120},
        {"FWT", 120}, {"IST", 120}, {"MEST", 120}, {"METDST", 120}, {"SST", 120},
        {"BST", 60}, {"CET", 60}, {"DNT", 60}, {"FST", 60}, {"MET", 60},
        {"MEWT", 60}, {"MEZ", 60}, {"NOR", 60}, {"SET", 60}, {"SWT", 60},
        {"WETDST", 60}, {"WET", 0}, {"WAT", -60}, {"NDT", -90}, {"ADT", -180},
        {"NFT", -150}, {"NST", -150}, {"AST", -240}, {"YDT", -480}, {"HDT", -540},
        {"YST", -540}, {"AHST", -600}, {"CAT", -600}, {"NT", -660}, {"IDLW", -720},
    };
    for (size_t i = 0; i < sizeof(zones) / sizeof(zones[0]); ++i) {
        int len = (int)strlen(zones[i].name);
        if (rtc_ascii_ieq_n(p, zones[i].name, len)) {
            *out_minutes = zones[i].minutes;
            *end = p + len;
            return 1;
        }
    }
    return 0;
}

static int rtc_parse_rfc822_zone(const char*& p, int* out_minutes) {
    *out_minutes = 0;
    if (*p == '+' || *p == '-') {
        const int sign = (*p++ == '+') ? 1 : -1;
        int hh, mm;
        if (!rtc_parse_ndigits(p, 2, &hh) || !rtc_parse_ndigits(p, 2, &mm)) return 0;
        *out_minutes = sign * (hh * 60 + mm);
        return 1;
    }
    if ((*p & 0xDF) == 'U' && (p[1] & 0xDF) == 'T') {
        p += 2;
        return 1;
    }
    if ((*p & 0xDF) == 'Z') {
        ++p;
        return 1;
    }
    const char* end = NULL;
    if (rtc_parse_zone_abbreviation(p, out_minutes, &end)) {
        p = end;
        return 1;
    }
    unsigned int c = (unsigned char)(*p & 0xDF);
    if ((c >= 'A' && c <= 'I') || (c >= 'K' && c <= 'M')) {
        *out_minutes = (int)c * 60 - 3900;
        ++p;
        return 1;
    }
    if (c >= 'N' && c <= 'Y') {
        *out_minutes = 60 * (78 - (int)c);
        ++p;
        return 1;
    }
    return 0;
}

static int rtc_finish_parsed_datetime(SceRtcTick* out, SceRtcDateTime* dt, int timezone_minutes) {
    dt->microsecond = 0;
    sceRtcGetTick(dt, out);
    sceRtcTickAddMinutes(out, out, -timezone_minutes);
    return SCE_OK;
}

static inline int rtc_format_2(char*& p, unsigned int v) {
    *p++ = (char)('0' + (v / 10) % 10);
    *p++ = (char)('0' + v % 10);
    return 0;
}

static inline int rtc_format_4(char*& p, unsigned int v) {
    *p++ = (char)('0' + (v / 1000) % 10);
    *p++ = (char)('0' + (v / 100) % 10);
    *p++ = (char)('0' + (v / 10) % 10);
    *p++ = (char)('0' + v % 10);
    return 0;
}

extern "C" {

PRX_INTERFACE int sceRtcInit(void) {
    return SCE_OK;
}

PRX_INTERFACE int sceRtcEnd(void) {
    return SCE_OK;
}

PRX_INTERFACE int sceRtcSetConf(int64_t a1, int64_t a2, int64_t a3, int64_t a4, int64_t a5, int64_t a6) {
    (void)a1; (void)a2;
    int tz[2];
    tz[0] = (int)a3;
    tz[1] = (int)a4;
    return sceKernelSettimeofday(NULL, tz, a3, a4, a5, a6);
}

PRX_INTERFACE int sceRtcSetCurrentTick(const SceRtcTick* pTick) {
    return rtc_set_realtime_tick(pTick);
}

PRX_INTERFACE int sceRtcGetCurrentTick(SceRtcTick* pTick) {
    return rtc_get_clock_tick(0, pTick);
}

PRX_INTERFACE int sceRtcGetCurrentClock(SceRtcDateTime* pTime, int iTimeZone) {
    if (pTime == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    SceRtcTick tick;
    timespec ts;
    const int rc = sceKernelClockGettime(0, &ts);
    if (rc >= 0) {
        tick.tick = rtc_tick_from_timespec(ts);
    }
    sceRtcTickAddMinutes(&tick, &tick, iTimeZone);
    sceRtcSetTick(pTime, &tick);
    return rc;
}

PRX_INTERFACE int sceRtcGetCurrentClockLocalTime(SceRtcDateTime* pTime) {
    if (pTime == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    SceRtcTick tick;
    timespec ts;
    int rc = sceKernelClockGettime(0, &ts);
    if (rc >= 0) {
        tick.tick = rtc_tick_from_timespec(ts);
        if (rc == SCE_OK) {
            int timezone_minutes;
            rc = rtc_current_timezone_offset(&timezone_minutes);
            if (rc >= 0) {
                sceRtcTickAddMinutes(&tick, &tick, timezone_minutes);
                sceRtcSetTick(pTime, &tick);
                return SCE_OK;
            }
        }
    }
    return rc;
}

PRX_INTERFACE int sceRtcConvertUtcToLocalTime(const SceRtcTick* pUtc, SceRtcTick* pLocalTime) {
    if (pUtc == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    int timezone_minutes;
    int rc = rtc_current_timezone_offset(&timezone_minutes);
    if (rc < 0) return rc;
    return rtc_tick_add_checked(pLocalTime, pUtc, (int64_t)timezone_minutes * kTicksPerMinute);
}

PRX_INTERFACE int sceRtcConvertLocalTimeToUtc(const SceRtcTick* pLocalTime, SceRtcTick* pUtc) {
    if (pLocalTime == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    int timezone_minutes;
    int rc = rtc_current_local_to_utc_offset(&timezone_minutes);
    if (rc < 0) return rc;
    return sceRtcTickAddMinutes(pUtc, pLocalTime, timezone_minutes);
}

PRX_INTERFACE int sceRtcGetCurrentNetworkTick(SceRtcTick* pTick) {
    return rtc_get_clock_tick(16, pTick);
}

PRX_INTERFACE int sceRtcGetCurrentRawNetworkTick(SceRtcTick* pTick) {
    return rtc_get_clock_tick(19, pTick);
}

PRX_INTERFACE int sceRtcGetCurrentDebugNetworkTick(SceRtcTick* pTick) {
    int rc = rtc_get_clock_tick(17, pTick);
    return (rc == SCE_RTC_ERROR_NOT_INITIALIZED) ? rtc_get_clock_tick(16, pTick) : rc;
}

PRX_INTERFACE int sceRtcGetCurrentAdNetworkTick(SceRtcTick* pTick) {
    int rc = rtc_get_clock_tick(18, pTick);
    return (rc == SCE_RTC_ERROR_NOT_INITIALIZED) ? rtc_get_clock_tick(16, pTick) : rc;
}

PRX_INTERFACE int sceRtcSetCurrentNetworkTick(const SceRtcTick* pTick) {
    return rtc_set_clock_tick(16, pTick, 1);
}

PRX_INTERFACE int sceRtcSetCurrentDebugNetworkTick(const SceRtcTick* pTick) {
    return rtc_set_clock_tick(17, pTick, 1);
}

PRX_INTERFACE int sceRtcSetCurrentAdNetworkTick(const SceRtcTick* pTick) {
    return rtc_set_clock_tick(18, pTick, 1);
}
PRX_INTERFACE int sceRtcParseDateTime(SceRtcTick* pUtc, const char* pszDateTime) {
    if (pUtc == NULL || pszDateTime == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    const char* p = pszDateTime;
    rtc_skip_space(p);
    int rc = sceRtcParseRFC3339(pUtc, p);
    if (rc != SCE_RTC_ERROR_BAD_PARSE) return rc;

    p = rtc_skip_weekday_prefix(p);
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    const char* after_month = rtc_parse_named_month(p, &month);
    if (after_month != NULL && (*after_month == ' ' || *after_month == '\t')) {
        p = after_month;
        rtc_skip_space(p);
        if (!rtc_parse_1_or_2_digits(p, &day)) return SCE_RTC_ERROR_BAD_PARSE;
        rtc_skip_space(p);
        if (!rtc_parse_time_of_day(p, &hour, &minute, &second, 1)) return SCE_RTC_ERROR_BAD_PARSE;
        rtc_skip_space(p);
        if (!rtc_parse_4_digit_year(p, &year)) return SCE_RTC_ERROR_BAD_PARSE;
        SceRtcDateTime dt = {(unsigned short)year, (unsigned short)month, (unsigned short)day,
            (unsigned short)hour, (unsigned short)minute, (unsigned short)second, 0};
        return rtc_finish_parsed_datetime(pUtc, &dt, 0);
    }

    if (!rtc_parse_1_or_2_digits(p, &day)) return SCE_RTC_ERROR_BAD_PARSE;
    if (*p != '-' && *p != ' ') return SCE_RTC_ERROR_BAD_PARSE;
    ++p;
    after_month = rtc_parse_named_month(p, &month);
    if (after_month == NULL) return SCE_RTC_ERROR_BAD_PARSE;
    p = after_month;
    if (*p != '-' && *p != ' ') return SCE_RTC_ERROR_BAD_PARSE;
    ++p;
    if (!rtc_parse_2_or_4_digit_year(p, &year)) return SCE_RTC_ERROR_BAD_PARSE;
    if (*p != ' ') return SCE_RTC_ERROR_BAD_PARSE;
    rtc_skip_space(p);
    if (!rtc_parse_time_of_day(p, &hour, &minute, &second, 0)) return SCE_RTC_ERROR_BAD_PARSE;
    int tz = 0;
    if (*p == ' ') {
        rtc_skip_space(p);
        if (*p != '\0') {
            const char* zp = p;
            if (rtc_parse_rfc822_zone(zp, &tz)) {
                p = zp;
            } else {
                return SCE_RTC_ERROR_BAD_PARSE;
            }
        }
    }
    SceRtcDateTime dt = {(unsigned short)year, (unsigned short)month, (unsigned short)day,
        (unsigned short)hour, (unsigned short)minute, (unsigned short)second, 0};
    return rtc_finish_parsed_datetime(pUtc, &dt, tz);
}

PRX_INTERFACE int sceRtcParseRFC3339(SceRtcTick* pUtc, const char* pszDateTime) {
    if (pUtc == NULL || pszDateTime == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    const char* p = pszDateTime;
    int year, month, day, hour, minute, second;
    if (!rtc_parse_ndigits(p, 4, &year) || *p++ != '-' ||
        !rtc_parse_ndigits(p, 2, &month) || *p++ != '-' ||
        !rtc_parse_ndigits(p, 2, &day) || (*p != 'T' && *p != 't')) {
        return SCE_RTC_ERROR_BAD_PARSE;
    }
    ++p;
    if (!rtc_parse_ndigits(p, 2, &hour) || *p++ != ':' ||
        !rtc_parse_ndigits(p, 2, &minute) || *p++ != ':' ||
        !rtc_parse_ndigits(p, 2, &second)) {
        return SCE_RTC_ERROR_BAD_PARSE;
    }
    unsigned int usec = 0;
    if (*p == '.') {
        ++p;
        int scale = 100000;
        int digits = 0;
        while (*p >= '0' && *p <= '9') {
            if (digits < 6) {
                usec += (unsigned int)(*p - '0') * (unsigned int)scale;
                scale /= 10;
            }
            ++digits;
            ++p;
        }
    }
    int tz = 0;
    if (!rtc_parse_rfc3339_timezone(p, &tz)) return SCE_RTC_ERROR_BAD_PARSE;

    SceRtcDateTime dt;
    dt.year = (unsigned short)year;
    dt.month = (unsigned short)month;
    dt.day = (unsigned short)day;
    dt.hour = (unsigned short)hour;
    dt.minute = (unsigned short)minute;
    dt.second = (unsigned short)second;
    dt.microsecond = usec;
    int rc = sceRtcCheckValid(&dt);
    if (rc < 0 && !(rc == SCE_RTC_ERROR_INVALID_SECOND && second == 60)) return rc;
    sceRtcGetTick(&dt, pUtc);
    sceRtcTickAddMinutes(pUtc, pUtc, -tz);
    return SCE_OK;
}

PRX_INTERFACE int sceRtcFormatRFC2822LocalTime(char* pszDateTime, const SceRtcTick* pUtc) {
    if (pszDateTime == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    SceRtcTick tick;
    const SceRtcTick* source = pUtc;
    if (source == NULL) {
        sceRtcGetCurrentTick(&tick);
        source = &tick;
    }
    int timezone_minutes;
    int rc = rtc_current_timezone_offset(&timezone_minutes);
    if (rc < 0) return rc;
    return sceRtcFormatRFC2822(pszDateTime, source, timezone_minutes);
}

PRX_INTERFACE int sceRtcFormatRFC2822(char* pszDateTime, const SceRtcTick* pUtc, int iTimeZoneMinutes) {
    if (pszDateTime == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    if (iTimeZoneMinutes <= -1440 || iTimeZoneMinutes >= 1440) return SCE_RTC_ERROR_INVALID_VALUE;
    SceRtcTick tick;
    int rc = rtc_resolve_tick_with_timezone_checked(&tick, pUtc, iTimeZoneMinutes);
    if (rc != SCE_OK) return rc;
    SceRtcDateTime dt;
    rc = sceRtcSetTick(&dt, &tick);
    if (rc != SCE_OK) return rc;
    rc = sceRtcCheckValid(&dt);
    if (rc != SCE_OK) return rc;
    static const char* wdays[7] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
    static const char* mons[12] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
    int dow = sceRtcGetDayOfWeek(dt.year, dt.month, dt.day);
    int sign = iTimeZoneMinutes < 0 ? -1 : 1;
    int tz = iTimeZoneMinutes * sign;
    char* p = pszDateTime;
    *p++ = wdays[dow][0]; *p++ = wdays[dow][1]; *p++ = wdays[dow][2];
    *p++ = ','; *p++ = ' ';
    rtc_format_2(p, dt.day); *p++ = ' ';
    *p++ = mons[dt.month - 1][0]; *p++ = mons[dt.month - 1][1]; *p++ = mons[dt.month - 1][2];
    *p++ = ' ';
    rtc_format_4(p, dt.year); *p++ = ' ';
    rtc_format_2(p, dt.hour); *p++ = ':';
    rtc_format_2(p, dt.minute); *p++ = ':';
    rtc_format_2(p, dt.second); *p++ = ' ';
    *p++ = sign < 0 ? '-' : '+';
    rtc_format_2(p, (unsigned int)(tz / 60));
    rtc_format_2(p, (unsigned int)(tz % 60));
    *p = '\0';
    return SCE_OK;
}

PRX_INTERFACE int sceRtcFormatRFC3339PreciseLocalTime(char* pszDateTime, const SceRtcTick* pUtc, unsigned int nFractionDigits) {
    if (pszDateTime == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    SceRtcTick tick;
    const SceRtcTick* source = pUtc;
    if (source == NULL) {
        sceRtcGetCurrentTick(&tick);
        source = &tick;
    }
    if (nFractionDigits > 6) return SCE_RTC_ERROR_INVALID_VALUE;
    int timezone_minutes;
    int rc = rtc_current_timezone_offset(&timezone_minutes);
    if (rc < 0) return rc;
    return sceRtcFormatRFC3339Precise(pszDateTime, source, timezone_minutes, nFractionDigits);
}

PRX_INTERFACE int sceRtcFormatRFC3339Precise(char* pszDateTime, const SceRtcTick* pUtc, int iTimeZoneMinutes, unsigned int nFractionDigits) {
    if (pszDateTime == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    if (iTimeZoneMinutes <= -1440 || iTimeZoneMinutes >= 1440 || nFractionDigits > 6) return SCE_RTC_ERROR_INVALID_VALUE;
    SceRtcTick tick;
    int rc = rtc_resolve_tick_with_timezone_checked(&tick, pUtc, iTimeZoneMinutes);
    if (rc != SCE_OK) return rc;
    SceRtcDateTime dt;
    rc = sceRtcSetTick(&dt, &tick);
    if (rc != SCE_OK) return rc;
    rc = sceRtcCheckValid(&dt);
    if (rc != SCE_OK) return rc;

    char* p = pszDateTime;
    rtc_format_4(p, dt.year); *p++ = '-';
    rtc_format_2(p, dt.month); *p++ = '-';
    rtc_format_2(p, dt.day); *p++ = 'T';
    rtc_format_2(p, dt.hour); *p++ = ':';
    rtc_format_2(p, dt.minute); *p++ = ':';
    rtc_format_2(p, dt.second);
    if (nFractionDigits > 0) {
        *p++ = '.';
        unsigned int divisor = 100000;
        for (unsigned int i = 0; i < nFractionDigits; ++i) {
            *p++ = (char)('0' + (dt.microsecond / divisor) % 10);
            divisor /= 10;
        }
    }
    if (iTimeZoneMinutes == 0) {
        *p++ = 'Z';
    } else {
        int sign = iTimeZoneMinutes < 0 ? -1 : 1;
        int tz = iTimeZoneMinutes * sign;
        *p++ = sign < 0 ? '-' : '+';
        rtc_format_2(p, (unsigned int)(tz / 60));
        *p++ = ':';
        rtc_format_2(p, (unsigned int)(tz % 60));
    }
    *p = '\0';
    return SCE_OK;
}

PRX_INTERFACE int sceRtcFormatRFC3339LocalTime(char* pszDateTime, const SceRtcTick* pUtc) {
    return sceRtcFormatRFC3339PreciseLocalTime(pszDateTime, pUtc, 2);
}

PRX_INTERFACE int sceRtcFormatRFC3339(char* pszDateTime, const SceRtcTick* pUtc, int iTimeZoneMinutes) {
    return sceRtcFormatRFC3339Precise(pszDateTime, pUtc, iTimeZoneMinutes, 2);
}

PRX_INTERFACE unsigned int sceRtcGetTickResolution(void) {
    return 1000000u;
}

PRX_INTERFACE int sceRtcIsLeapYear(int year) {
    if (year <= 0) return SCE_RTC_ERROR_INVALID_YEAR;
    return rtc_is_leap_year(year);
}

PRX_INTERFACE int sceRtcGetDaysInMonth(int year, int month) {
    if (year <= 0) return SCE_RTC_ERROR_INVALID_YEAR;
    if (month < 1 || month > 12) return SCE_RTC_ERROR_INVALID_MONTH;
    return rtc_days_in_month_unchecked(year, month);
}

PRX_INTERFACE int sceRtcGetDayOfWeek(int year, int month, int day) {
    if (year <= 0) return SCE_RTC_ERROR_INVALID_YEAR;
    if (month < 1 || month > 12) return SCE_RTC_ERROR_INVALID_MONTH;
    if (day < 1 || day > rtc_days_in_month_unchecked(year, month)) return SCE_RTC_ERROR_INVALID_DAY;
    return (int)((rtc_days_before_year(year) + rtc_days_before_month(year, month) + day) % 7);
}

PRX_INTERFACE int sceRtcCheckValid(const SceRtcDateTime* pTime) {
    return rtc_check_valid(pTime);
}

PRX_INTERFACE int sceRtcSetDosTime(SceRtcDateTime* pTime, unsigned int uiDosTime) {
    if (pTime == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    pTime->year = (unsigned short)(1980 + ((uiDosTime >> 25) & 0x7F));
    pTime->month = (unsigned short)((uiDosTime >> 21) & 0x0F);
    pTime->day = (unsigned short)((uiDosTime >> 16) & 0x1F);
    pTime->hour = (unsigned short)((uiDosTime >> 11) & 0x1F);
    pTime->minute = (unsigned short)((uiDosTime >> 5) & 0x3F);
    pTime->second = (unsigned short)((uiDosTime & 0x1F) * 2);
    pTime->microsecond = 0;
    return SCE_OK;
}

PRX_INTERFACE int sceRtcGetDosTime(const SceRtcDateTime* pTime, unsigned int* puiDosTime) {
    if (pTime == NULL || puiDosTime == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    int rc = sceRtcCheckValid(pTime);
    if (rc != SCE_OK) return rc;
    if (pTime->year < 1980) {
        *puiDosTime = 0;
        return SCE_RTC_ERROR_INVALID_YEAR;
    }
    if (pTime->year > 2107) {
        *puiDosTime = 0xFF9FBF7D;
        return SCE_RTC_ERROR_INVALID_YEAR;
    }
    *puiDosTime = ((unsigned int)(pTime->year - 1980) << 25) |
        ((unsigned int)pTime->month << 21) |
        ((unsigned int)pTime->day << 16) |
        ((unsigned int)pTime->hour << 11) |
        ((unsigned int)pTime->minute << 5) |
        ((unsigned int)pTime->second / 2);
    return SCE_OK;
}

PRX_INTERFACE int sceRtcSetWin32FileTime(SceRtcDateTime* pTime, uint64_t ulWin32Time) {
    if (pTime == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    SceRtcTick tick;
    tick.tick = kWin32EpochTick + ulWin32Time / 10ULL;
    return sceRtcSetTick(pTime, &tick);
}

PRX_INTERFACE int sceRtcSetTick(SceRtcDateTime* pTime, const SceRtcTick* pTick) {
    if (pTime == NULL || pTick == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    return rtc_tick_to_datetime(pTick->tick, pTime);
}

PRX_INTERFACE int sceRtcGetWin32FileTime(const SceRtcDateTime* pTime, uint64_t* ulWin32Time) {
    if (pTime == NULL || ulWin32Time == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    SceRtcTick tick;
    int rc = sceRtcGetTick(pTime, &tick);
    if (rc != SCE_OK) return rc;
    if (tick.tick < kWin32EpochTick) {
        *ulWin32Time = 0;
        return (pTime->year < 1601) ? SCE_RTC_ERROR_INVALID_YEAR : SCE_RTC_ERROR_INVALID_VALUE;
    }
    *ulWin32Time = (tick.tick - kWin32EpochTick) * 10ULL;
    return SCE_OK;
}

PRX_INTERFACE int sceRtcGetTick(const SceRtcDateTime* pTime, SceRtcTick* pTick) {
    if (pTime == NULL || pTick == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    return rtc_datetime_to_tick(pTime, pTick);
}

PRX_INTERFACE int sceRtcSetTime_t(SceRtcDateTime* pTime, time_t llTime) {
    if (pTime == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    if (llTime < 0) return SCE_RTC_ERROR_INVALID_VALUE;
    SceRtcTick tick;
    tick.tick = (uint64_t)((int64_t)llTime * kTicksPerSecond) + kUnixEpochTick;
    return sceRtcSetTick(pTime, &tick);
}

PRX_INTERFACE int sceRtcGetTime_t(const SceRtcDateTime* pTime, time_t* pllTime) {
    if (pTime == NULL || pllTime == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    SceRtcTick tick;
    int rc = sceRtcGetTick(pTime, &tick);
    if (rc != SCE_OK) return rc;
    if (tick.tick < kUnixEpochTick) {
        *pllTime = 0;
        return (pTime->year < 1970) ? SCE_RTC_ERROR_INVALID_YEAR : SCE_RTC_ERROR_INVALID_VALUE;
    }
    *pllTime = (time_t)((int64_t)(tick.tick - kUnixEpochTick) / kTicksPerSecond);
    return SCE_OK;
}

PRX_INTERFACE int sceRtcTickAddTicks(SceRtcTick* pTick0, const SceRtcTick* pTick1, int64_t lAdd) {
    return rtc_tick_add_wrap(pTick0, pTick1, lAdd);
}

PRX_INTERFACE int sceRtcTickAddMicroseconds(SceRtcTick* pTick0, const SceRtcTick* pTick1, int64_t lAdd) {
    return rtc_tick_add_wrap(pTick0, pTick1, lAdd);
}

PRX_INTERFACE int sceRtcTickAddSeconds(SceRtcTick* pTick0, const SceRtcTick* pTick1, int64_t lAdd) {
    return rtc_tick_add_wrap(pTick0, pTick1, lAdd * kTicksPerSecond);
}

PRX_INTERFACE int sceRtcTickAddMinutes(SceRtcTick* pTick0, const SceRtcTick* pTick1, int64_t lAdd) {
    return rtc_tick_add_wrap(pTick0, pTick1, lAdd * kTicksPerMinute);
}

PRX_INTERFACE int sceRtcTickAddHours(SceRtcTick* pTick0, const SceRtcTick* pTick1, int lAdd) {
    return rtc_tick_add_wrap(pTick0, pTick1, (int64_t)lAdd * kTicksPerHour);
}

PRX_INTERFACE int sceRtcTickAddDays(SceRtcTick* pTick0, const SceRtcTick* pTick1, int lAdd) {
    return rtc_tick_add_wrap(pTick0, pTick1, (int64_t)lAdd * kTicksPerDay);
}

PRX_INTERFACE int sceRtcTickAddWeeks(SceRtcTick* pTick0, const SceRtcTick* pTick1, int lAdd) {
    return rtc_tick_add_wrap(pTick0, pTick1, (int64_t)lAdd * 7LL * kTicksPerDay);
}

PRX_INTERFACE int sceRtcTickAddMonths(SceRtcTick* pTick0, const SceRtcTick* pTick1, int lAdd) {
    if (pTick0 == NULL || pTick1 == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    SceRtcDateTime dt;
    sceRtcSetTick(&dt, pTick1);
    int total = (int)dt.year * 12 + (int)dt.month - 1 + lAdd;
    int year = total / 12;
    int month = total % 12 + 1;
    if (month <= 0) {
        month += 12;
        --year;
    }
    dt.year = (unsigned short)year;
    dt.month = (unsigned short)month;
    if (year < 1 || year > 9999 || month < 1 || month > 12) return SCE_OK;
    int dim = rtc_days_in_month_unchecked(year, month);
    if (dt.day > dim) dt.day = (unsigned short)dim;
    if (sceRtcCheckValid(&dt) == SCE_OK) {
        sceRtcGetTick(&dt, pTick0);
    }
    return SCE_OK;
}

PRX_INTERFACE int sceRtcTickAddYears(SceRtcTick* pTick0, const SceRtcTick* pTick1, int lAdd) {
    if (pTick0 == NULL || pTick1 == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    SceRtcDateTime dt;
    sceRtcSetTick(&dt, pTick1);
    int year = (int)dt.year + lAdd;
    dt.year = (unsigned short)year;
    if (year < 1 || year > 9999 || dt.month < 1 || dt.month > 12) return SCE_OK;
    int dim = rtc_days_in_month_unchecked(year, dt.month);
    if (dt.day > dim) dt.day = (unsigned short)dim;
    if (sceRtcCheckValid(&dt) == SCE_OK) {
        sceRtcGetTick(&dt, pTick0);
    }
    return SCE_OK;
}

PRX_INTERFACE int sceRtcCompareTick(const SceRtcTick* pTick0, const SceRtcTick* pTick1) {
    if (pTick0 == NULL || pTick1 == NULL) return SCE_RTC_ERROR_INVALID_POINTER;
    if (pTick0->tick < pTick1->tick) return -1;
    if (pTick0->tick > pTick1->tick) return 1;
    return 0;
}

} /* extern "C" */
