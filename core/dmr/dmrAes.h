// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
/*
 * DMR voice encryption with AES-256 and a message indicator (the DMRA "enhanced" scheme, algorithm ID 0x25), receive
 * side. The layout was measured on the SDR bench against stock radios and checked with a reference decoder used
 * as a black box (docs/spec/dmr-voice.md 5.1):
 *
 *   PI header octets 0-6: algorithm ID, an octet not interpreted, key ID, MI (32 bits, most significant octet first)
 *   MI words      w0 = the PI header's MI; w(n+1) = 32 steps of the LFSR x^32 + x^22 + x^2 + x + 1 from w(n):
 *                 shift left, the new bit 0 = bits 31 ^ 21 ^ 1 ^ 0 of the old word (taps 0x80200003)
 *   Superframe s  IV = w(s) w(s+1) w(s+2) w(s+3) (128 bits, w(s) first); keystream = AES-256 OFB from that IV, the
 *                 first 16 octets skipped; frame j (0-17: burst A frames 0-2, ..., burst F frames 15-17) takes octets
 *                 7j .. 7j+6 of what follows, and the top 49 of their 56 bits are XORed onto its 49 AMBE+2 parameter
 *                 bits (ambe_d[] order, parameter bit 0 = the most significant keystream bit)
 */

#ifndef RFOUNDRY_DMRAES_H
#define RFOUNDRY_DMRAES_H

#include <stdint.h>

#define DMR_AES_ALG_ID		0x25	// PI header octet 0: AES-256
#define DMR_AES_KEY_BYTES	32
#define DMR_AES_FRAMES		18	// vocoder frames in a superframe
#define DMR_AES_FRAME_KS_BYTES	7	// keystream octets per frame (49 bits used)
#define DMR_AES_KS_BYTES	(DMR_AES_FRAMES * DMR_AES_FRAME_KS_BYTES)

// An AES-256 key, expanded (FIPS-197 5.2): 15 round keys
typedef struct {
	uint8_t rk[240];
} dmrAesKey_t;

void dmrAesKeyExpand(dmrAesKey_t *k, const uint8_t key[DMR_AES_KEY_BYTES]);
// FIPS-197 AES-256 cipher of one 16-octet block (in and out may be the same)
void dmrAesEncryptBlock(const dmrAesKey_t *k, const uint8_t in[16], uint8_t out[16]);

// The next 32-bit MI word (32 LFSR steps)
uint32_t dmrAesMiNext(uint32_t w);
// Superframe s's IV from the PI header's MI (s = 0 for the superframe after the PI header)
void dmrAesSuperframeIv(uint32_t pi_mi, uint16_t s, uint8_t iv[16]);
// A superframe's keystream: DMR_AES_KS_BYTES octets, frame j's at 7j
void dmrAesKeystream(const dmrAesKey_t *k, const uint8_t iv[16], uint8_t ks[DMR_AES_KS_BYTES]);
// XOR frame j's keystream onto its 49 parameter bits (one per byte, 0/1)
void dmrAesApplyFrame(const uint8_t ks[DMR_AES_KS_BYTES], uint8_t frame, uint8_t bits[49]);

#endif
