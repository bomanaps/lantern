#include "lantern/consensus/shadow_cost.h"

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>

static const char LANTERN_ENV_SHADOW_XMSS_AGGREGATE_RATE[] =
    "LANTERN_SHADOW_XMSS_AGGREGATE_RATE";
static const char LANTERN_ENV_SHADOW_XMSS_VERIFY_RATE[] =
    "LANTERN_SHADOW_XMSS_VERIFY_RATE";
static const char LANTERN_ENV_SHADOW_XMSS_MERGE_RATE[] =
    "LANTERN_SHADOW_XMSS_MERGE_RATE";

static double g_aggregate_rate = 0.0;
static double g_verify_rate = 0.0;
static double g_merge_rate = 0.0;

static bool parse_rate(const char *text, double *out_rate) {
    if (!text || !out_rate) {
        return false;
    }

    if (isspace((unsigned char)text[0])) {
        return false;
    }

    char *end = NULL;
    double value = strtod(text, &end);
    if (end == text || (end && *end != '\0')) {
        return false;
    }

    *out_rate = value;
    return true;
}

static double read_env_rate(const char *key) {
    double rate = 0.0;
    const char *raw = getenv(key);
    if (!raw || !parse_rate(raw, &rate)) {
        return 0.0;
    }
    return rate;
}

static uint64_t compute_delay_ns(double rate, size_t n) {
    if (!isfinite(rate) || rate <= 0.0) {
        return 0u;
    }

    double ns = ((double)n / rate) * 1000000000.0;
    if (!isfinite(ns) || ns <= 0.0) {
        return 0u;
    }
    if (ns >= (double)UINT64_MAX) {
        return UINT64_MAX;
    }
    return (uint64_t)ns;
}

void lantern_shadow_xmss_cost_init(
    double cli_aggregate_rate,
    bool has_cli_aggregate_rate,
    double cli_verify_rate,
    bool has_cli_verify_rate,
    double cli_merge_rate,
    bool has_cli_merge_rate) {
    g_aggregate_rate = has_cli_aggregate_rate
        ? cli_aggregate_rate
        : read_env_rate(LANTERN_ENV_SHADOW_XMSS_AGGREGATE_RATE);
    g_verify_rate = has_cli_verify_rate
        ? cli_verify_rate
        : read_env_rate(LANTERN_ENV_SHADOW_XMSS_VERIFY_RATE);
    g_merge_rate = has_cli_merge_rate
        ? cli_merge_rate
        : read_env_rate(LANTERN_ENV_SHADOW_XMSS_MERGE_RATE);
}

uint64_t lantern_shadow_xmss_aggregate_delay_ns(size_t n) {
    return compute_delay_ns(g_aggregate_rate, n);
}

uint64_t lantern_shadow_xmss_verify_delay_ns(size_t n) {
    return compute_delay_ns(g_verify_rate, n);
}

uint64_t lantern_shadow_xmss_merge_delay_ns(size_t n) {
    return compute_delay_ns(g_merge_rate, n);
}

void lantern_shadow_xmss_sleep_ns(uint64_t ns) {
    if (ns == 0u) {
        return;
    }

    struct timespec remaining = {
        .tv_sec = (time_t)(ns / 1000000000u),
        .tv_nsec = (long)(ns % 1000000000u),
    };
    while (nanosleep(&remaining, &remaining) != 0 && errno == EINTR) {
    }
}
