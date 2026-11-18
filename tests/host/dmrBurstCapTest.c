// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
/*
 * Host tests for the DMR burst capture (core/dmr/call/dmr_burst_cap.c, CONFIG_VOICE_CAPTURE)
 *
 *   make -C tests/host dmrBurstCapTest && tests/host/dmrBurstCapTest
 */

#include <stdio.h>
#include <string.h>
#include "dmr/call/dmr_burst_cap.h"

static int failures = 0;

#define CHECK(cond, ...) do { if (!(cond)) { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static dmr_burst_t burst(uint8_t kind, uint8_t vi, int8_t ts, uint8_t len, uint8_t fill)
{
	dmr_burst_t b;

	memset(&b, 0, sizeof b);
	b.kind = kind;
	b.voice_index = vi;
	b.ts = ts;
	b.len = len;
	b.crc_ok = true;
	memset(b.payload, fill, len);
	return b;
}

int main(void)
{
	const dmr_burst_cap_entry_t *e;
	uint8_t want;

	// Not armed: nothing taken
	dmr_burst_t b = burst(DMR_BURST_VOICE, 0, 1, DMR_VOICE_BYTES, 0x11);
	dmr_burst_cap_put(&b, 100);
	CHECK(dmr_burst_cap_get(&e, &want) == 0 && want == 0, "unarmed capture took a burst");

	// An encrypted call: voice LC header, PI header (10 octets + CRC), voice A-F with the PI bit, terminator
	dmr_burst_cap_arm(10);
	b = burst(DMR_BURST_VOICE_LC_HEADER, 0, 1, 12, 0x00);
	b.lc_valid = true;
	for (int i = 0; i < 9; i++)
		b.lc[i] = (uint8_t)(0xA0 + i);
	dmr_burst_cap_put(&b, 1000);

	b = burst(DMR_BURST_PI_HEADER, 0, 1, 12, 0x00);
	for (int i = 0; i < 12; i++)
		b.payload[i] = (uint8_t)(0x20 + i);
	dmr_burst_cap_put(&b, 1060);

	b = burst(DMR_BURST_CSBK, 0, 1, 12, 0x55);	// not a call burst: skipped
	dmr_burst_cap_put(&b, 1080);
	b = burst(DMR_BURST_VOICE, 0, 2, DMR_VOICE_BYTES, 0x66);	// the other slot: skipped
	dmr_burst_cap_put(&b, 1090);

	for (uint8_t v = 0; v < 6; v++) {
		b = burst(DMR_BURST_VOICE, v, 1, DMR_VOICE_BYTES, (uint8_t)(0x30 + v));
		b.pi = true;
		dmr_burst_cap_put(&b, 1120u + 60u * v);
	}
	b = burst(DMR_BURST_TERMINATOR_LC, 0, 1, 12, 0x77);
	dmr_burst_cap_put(&b, 1500);

	uint8_t n = dmr_burst_cap_get(&e, &want);
	CHECK(want == 10, "want %u", want);
	CHECK(n == 9, "count %u, expected header, PI, 6 voice, terminator", n);
	CHECK(e[0].kind == DMR_BURST_VOICE_LC_HEADER && (e[0].flags & DMR_BURST_CAP_LC) && e[0].lc[8] == 0xA8,
	      "voice LC header and its LC");
	CHECK(e[1].kind == DMR_BURST_PI_HEADER && e[1].len == 12 && e[1].payload[0] == 0x20 && e[1].payload[9] == 0x29 &&
	      e[1].dt_ms == 60, "PI header octets kept, dt %u", e[1].dt_ms);
	CHECK(!(e[1].flags & DMR_BURST_CAP_LC) && e[1].lc[0] == 0, "no LC on a PI header");
	for (uint8_t v = 0; v < 6; v++)
		CHECK(e[2 + v].kind == DMR_BURST_VOICE && e[2 + v].voice_index == v && e[2 + v].payload[26] == 0x30 + v &&
		      (e[2 + v].flags & (DMR_BURST_CAP_PI | DMR_BURST_CAP_CRC_OK)) == (DMR_BURST_CAP_PI | DMR_BURST_CAP_CRC_OK),
		      "voice %c", 'A' + v);
	CHECK(e[8].kind == DMR_BURST_TERMINATOR_LC && e[8].dt_ms == 500, "terminator");

	// Full: one more call burst fills it, then nothing
	b = burst(DMR_BURST_VOICE, 0, 1, DMR_VOICE_BYTES, 0x99);
	dmr_burst_cap_put(&b, 1600);
	dmr_burst_cap_put(&b, 1660);
	CHECK(dmr_burst_cap_get(&e, &want) == 10, "stops at want");

	// Re-arming clears, and the slot is taken from the new first burst; the count is capped
	dmr_burst_cap_arm(200);
	CHECK(dmr_burst_cap_get(&e, &want) == 0 && want == DMR_BURST_CAP, "re-arm clears, want capped at %u", want);
	b = burst(DMR_BURST_VOICE, 0, 2, DMR_VOICE_BYTES, 0x12);
	dmr_burst_cap_put(&b, 5000);
	b = burst(DMR_BURST_VOICE, 1, 1, DMR_VOICE_BYTES, 0x13);
	dmr_burst_cap_put(&b, 5060);
	CHECK(dmr_burst_cap_get(&e, &want) == 1 && e[0].ts == 2, "slot follows the first burst");

	// The time saturates
	b = burst(DMR_BURST_VOICE, 1, 2, DMR_VOICE_BYTES, 0x14);
	dmr_burst_cap_put(&b, 5000u + 70000u);
	CHECK(dmr_burst_cap_get(&e, &want) == 2 && e[1].dt_ms == 0xFFFF, "dt saturates");

	// Page offset for the view
	dmr_burst_cap_set_page(8);
	CHECK(dmr_burst_cap_page() == 8, "page");
	dmr_burst_cap_set_page(250);
	CHECK(dmr_burst_cap_page() == DMR_BURST_CAP, "page capped");

	// 0 stops
	dmr_burst_cap_arm(0);
	dmr_burst_cap_put(&b, 6000);
	CHECK(dmr_burst_cap_get(&e, &want) == 0 && want == 0, "stopped");

	printf("dmrBurstCapTest: %s\n", failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
}
