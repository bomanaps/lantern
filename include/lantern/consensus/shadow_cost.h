#ifndef LANTERN_CONSENSUS_SHADOW_COST_H
#define LANTERN_CONSENSUS_SHADOW_COST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void lantern_shadow_xmss_cost_init(
    double cli_aggregate_rate,
    bool has_cli_aggregate_rate,
    double cli_verify_rate,
    bool has_cli_verify_rate,
    double cli_merge_rate,
    bool has_cli_merge_rate);

uint64_t lantern_shadow_xmss_aggregate_delay_ns(size_t n);
uint64_t lantern_shadow_xmss_verify_delay_ns(size_t n);
uint64_t lantern_shadow_xmss_merge_delay_ns(size_t n);
void lantern_shadow_xmss_sleep_ns(uint64_t ns);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_CONSENSUS_SHADOW_COST_H */
