// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
// DMR burst capture for bench work on encryption schemes (dmr_burst_cap.h)
#include "config.h"

#if CONFIG_VOICE_CAPTURE

#include <string.h>
#include "dmr/call/dmr_burst_cap.h"

static dmr_burst_cap_entry_t cap[DMR_BURST_CAP];
static volatile uint8_t cap_count, cap_want, cap_first;
static int8_t cap_ts;
static uint32_t cap_t0;

void dmr_burst_cap_arm(uint8_t n)
{
	cap_want = 0;	// the call task stops taking bursts before the count goes back
	cap_count = 0;
	cap_first = 0;
	cap_ts = 0;
	cap_want = n < DMR_BURST_CAP ? n : (uint8_t)DMR_BURST_CAP;
}

static bool wanted(uint8_t kind)
{
	return kind == DMR_BURST_VOICE || kind == DMR_BURST_PI_HEADER || kind == DMR_BURST_VOICE_LC_HEADER ||
	       kind == DMR_BURST_TERMINATOR_LC;
}

void dmr_burst_cap_put(const dmr_burst_t *b, uint32_t now_ms)
{
	uint8_t n = cap_count;

	if (n >= cap_want || !wanted(b->kind)) {
		return;
	}
	if (n == 0) {
		cap_ts = b->ts;
		cap_t0 = now_ms;
	} else if (cap_ts != 0 && b->ts != 0 && b->ts != cap_ts) {
		return;	// the other slot: another call
	}

	dmr_burst_cap_entry_t *e = &cap[n];
	uint32_t dt = now_ms - cap_t0;
	uint8_t len = b->len < DMR_PAYLOAD_MAX ? b->len : (uint8_t)DMR_PAYLOAD_MAX;

	e->kind = b->kind;
	e->voice_index = b->voice_index;
	e->ts = b->ts;
	e->flags = (uint8_t)((b->crc_ok ? DMR_BURST_CAP_CRC_OK : 0u) | (b->pi ? DMR_BURST_CAP_PI : 0u) |
			     (b->lc_valid ? DMR_BURST_CAP_LC : 0u));
	e->len = len;
	e->dt_ms = dt > 0xFFFFu ? (uint16_t)0xFFFFu : (uint16_t)dt;
	memset(e->payload, 0, sizeof e->payload);
	memcpy(e->payload, b->payload, len);
	if (b->lc_valid) {
		memcpy(e->lc, b->lc, sizeof e->lc);
	} else {
		memset(e->lc, 0, sizeof e->lc);
	}
	cap_count = (uint8_t)(n + 1u);
}

uint8_t dmr_burst_cap_get(const dmr_burst_cap_entry_t **entries, uint8_t *want)
{
	*entries = cap;
	*want = cap_want;
	return cap_count;
}

void dmr_burst_cap_set_page(uint8_t first)
{
	cap_first = first < DMR_BURST_CAP ? first : (uint8_t)DMR_BURST_CAP;
}

uint8_t dmr_burst_cap_page(void)
{
	return cap_first;
}

#endif
