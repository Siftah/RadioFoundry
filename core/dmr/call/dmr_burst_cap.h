// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
/*
 * DMR burst capture (CONFIG_VOICE_CAPTURE): the next bursts of a call as the modem reported them, before the call
 * stack decides whether to play them. Unlike the voice capture (core/dmr/ambe/ambeVoice.h), which sees only frames
 * that reach the vocoder, it keeps the PI header (all 10 octets), the voice LC header, the terminator and the voice
 * bursts of an encrypted call the stack drops. For bench work on encryption schemes (docs/spec/dmr-voice.md 5): the
 * MI in the PI header and the ciphertext of known frames (silence) come back over the debug link (RADIO op 44, the
 * burst_cap view).
 *
 * Bursts are taken from the call stack's receive path after the color code filter and before the slot filter, never
 * while we transmit. The first burst taken fixes the slot; later bursts of the other slot are skipped. Arming clears
 * what was captured. No RTOS calls: the call task writes, the debug link reads count first, then entries below it.
 */
#ifndef RFOUNDRY_DMR_BURST_CAP_H
#define RFOUNDRY_DMR_BURST_CAP_H

#include <stdbool.h>
#include <stdint.h>
#include "hal_dmr_modem.h"

#define DMR_BURST_CAP		32u	// bursts kept: about 1.75 s of one slot's voice (a header, the PI header and five
					// superframes); more doesn't fit a capture build on the boards with the least RAM

#define DMR_BURST_CAP_CRC_OK	0x01u	// dmr_burst_t.crc_ok
#define DMR_BURST_CAP_PI	0x02u	// dmr_burst_t.pi (the EMB PI bit of a voice burst)
#define DMR_BURST_CAP_LC	0x04u	// lc[] holds a complete LC (header, terminator, embedded in burst F)

typedef struct {
	uint8_t kind;			// dmr_burst_kind_t
	uint8_t voice_index;		// 0..5 (A..F) for voice
	int8_t ts;			// 1, 2, 0 unknown; with MS sync (direct mode) the receiver's slot, not one on air
	uint8_t flags;			// DMR_BURST_CAP_*
	uint8_t len;			// payload bytes
	uint16_t dt_ms;			// since the first burst captured (saturates)
	uint8_t payload[DMR_PAYLOAD_MAX];
	uint8_t lc[9];
} dmr_burst_cap_entry_t;

// Capture the next n bursts (up to DMR_BURST_CAP; 0 stops). Clears what was captured
void dmr_burst_cap_arm(uint8_t n);
// From the call stack: one burst heard. Keeps PI headers, voice LC headers, terminators and voice
void dmr_burst_cap_put(const dmr_burst_t *b, uint32_t now_ms);
// The bursts captured so far (count returned) and how many were asked for
uint8_t dmr_burst_cap_get(const dmr_burst_cap_entry_t **entries, uint8_t *want);
// The first entry the burst_cap view shows (the view holds DMR_BURST_CAP_PAGE entries, a reply's worth)
#define DMR_BURST_CAP_PAGE	8u
void dmr_burst_cap_set_page(uint8_t first);
uint8_t dmr_burst_cap_page(void);

#endif
