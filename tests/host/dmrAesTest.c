// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The RadioFoundry Authors
/*
 * Host tests for DMR AES-256 voice decryption (core/dmr/dmrAes.c)
 *
 *   make -C tests/host dmrAesTest && tests/host/dmrAesTest
 */

#include <stdio.h>
#include <string.h>
#include "dmr/dmrAes.h"
#include "dmr/ambe/ambeFec.h"

static int failures, checks;

#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); \
	printf(__VA_ARGS__); printf("\n"); } } while (0)

static void hex(const char *s, uint8_t *out, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		unsigned v;

		sscanf(s + 2 * i, "%2x", &v);
		out[i] = (uint8_t)v;
	}
}

// FIPS-197 appendix C.3: AES-256
static void test_fips197(void)
{
	uint8_t key[32], in[16], out[16], want[16];
	dmrAesKey_t k;

	for (unsigned i = 0; i < 32; i++)
		key[i] = (uint8_t)i;
	hex("00112233445566778899aabbccddeeff", in, 16);
	hex("8ea2b7ca516745bfeafc49904b496089", want, 16);
	dmrAesKeyExpand(&k, key);
	dmrAesEncryptBlock(&k, in, out);
	CHECK(memcmp(out, want, 16) == 0, "FIPS-197 C.3 ciphertext");
}

// The MI words a stock radio sent after PI header MI 0xCD6554E0 (the IVs of its first superframes, as a reference
// decoder printed them)
static void test_mi(void)
{
	static const uint32_t w[] = { 0xCD6554E0, 0x7B451C0A, 0x899C283D, 0x2190A622, 0x82D6E6E1, 0x170A8391,
				      0x91B0B11F, 0x19F0BC4D };
	uint8_t iv[16], want[16];

	for (unsigned i = 0; i + 1 < sizeof w / sizeof w[0]; i++)
		CHECK(dmrAesMiNext(w[i]) == w[i + 1], "MI word %u", i + 1);
	dmrAesSuperframeIv(0xCD6554E0, 0, iv);
	hex("CD6554E07B451C0A899C283D2190A622", want, 16);
	CHECK(memcmp(iv, want, 16) == 0, "superframe 0 IV");
	dmrAesSuperframeIv(0xCD6554E0, 4, iv);
	hex("82D6E6E1170A839191B0B11F19F0BC4D", want, 16);
	CHECK(memcmp(iv, want, 16) == 0, "superframe 4 IV");
}

/*
 * An encrypted call from a stock radio (AES-256, key ID 1, a throwaway bench test key), captured by our firmware's
 * burst capture (bursts A-F of the first two superframes after the PI header, as on air, sync removed). The plain
 * frames are what a reference decoder printed with the key: a silent key-up, so the AMBE+2 silence family from burst
 * C on (the stock radio's first two bursts carry what its vocoder had before the call)
 */
static const char *TEST_KEY = "15168A8DF27104730488F2BB1E351641F2E1BEC86901EBCB6E01778B64301E2D";
static const uint32_t TEST_MI = 0xCD6554E0;
static const char *BURSTS[12] = {
	"9d1c20fffa9a8ab79ef8a066ac9a92cff7fc7fab6034708c9c9a16", "d26745b66d73513747bb8173b07990637428a30bf6d707baafc903",
	"d7527c532b57b58e1ab1860a361505fca4d7ec16d8aaad1018c3ca", "bb95d062bb0995084e9b2fb2f34f90f5fb3823eaafef190e164f1f",
	"33efd973ce00372cccfb37470609b1825d8b2abde6409e1a65a180", "84402cb2d6e174fc88b16949fee6f548ec437b66966e417dd98469",
	"09f9f50ada22820e272d23e18377c380a41371aee41b80534d7da6", "2843f7ea241634346dcd3a15f0e0466c818cf9ddbf733b7f9fb6f5",
	"0792f2e48768acd84d772df53d22b2e8e041092d39dc92b7db3b6e", "23be01b327bbaaffab3d7536e6726b9531404de17df0592c44411e",
	"63473631d54e4d6d1370a737d20165c34cb41750f7ad253afe83a0", "fdcd2882ad5f4ee438ae1243c5da5092aa9e2964052ba97043a637",
};
// 49 bits each, most significant first, left aligned in 56
static const uint64_t PLAIN[36] = {
	0x00000000000400, 0x00000000000500, 0x00000000000000, 0x9D1C20FFFA9880, 0xF8A066AC9A9480, 0x7FAB6034708F00,
	0xF819ED3384B900, 0xF81B6D3384BA00, 0xF81B6D3384BB00, 0xF81B6D3384BE00, 0xF81B6D3384BB00, 0xF81B6D2384B000,
	0xF81B6D3F84BF80, 0xF81B6D3384B900, 0xF81B6D3384B980, 0xF81B6DC384BF00, 0xF81B6D5384BA80, 0xF81B6DC384BB00,
	0xF81B6C2384B480, 0xF81B6C3384BE80, 0xF81B6C5384BC80, 0xF81B6C5384B880, 0xF81B6C2384B400, 0xF81B6D3384BF00,
	0xF81B6423849580, 0xF81B6423849280, 0xF81B64C3841880, 0xF81B6453841B00, 0xF81B6D2384B500, 0xF81B6D2384B100,
	0xF81B6D2384B300, 0xF81B6D3384BE00, 0xF81B6D2244B480, 0xF81B6D5244B800, 0xF819ED9384A400, 0xF81B6CCF84F900,
};

static uint64_t pack(const uint8_t bits[49])
{
	uint64_t v = 0;

	for (unsigned i = 0; i < 49; i++)
		v |= (uint64_t)bits[i] << (55 - i);
	return v;
}

static void test_call(void)
{
	uint8_t key[32], iv[16], ks[DMR_AES_KS_BYTES];
	dmrAesKey_t k;

	hex(TEST_KEY, key, 32);
	dmrAesKeyExpand(&k, key);
	for (unsigned s = 0; s < 2; s++) {
		dmrAesSuperframeIv(TEST_MI, (uint16_t)s, iv);
		dmrAesKeystream(&k, iv, ks);
		for (unsigned b = 0; b < 6; b++) {
			uint8_t burst[AMBE_BURST_BYTES], frames[3][AMBE_FRAME_BYTES];

			hex(BURSTS[6 * s + b], burst, sizeof burst);
			ambeBurstSplit(burst, frames);
			for (unsigned f = 0; f < 3; f++) {
				uint8_t bits[AMBE_PARAM_BITS];
				unsigned j = 3 * b + f;
				ambe_fec_result_t r;

				ambeFecDecode(frames[f], bits, &r);
				CHECK(r.errors == 0, "superframe %u frame %u: FEC errors %u", s, j, r.errors);
				dmrAesApplyFrame(ks, (uint8_t)j, bits);
				CHECK(pack(bits) == PLAIN[18 * s + j], "superframe %u frame %u: %014llX, want %014llX", s, j,
				      (unsigned long long)pack(bits), (unsigned long long)PLAIN[18 * s + j]);
			}
		}
	}
	// A wrong key gives something else
	key[31] ^= 1;
	dmrAesKeyExpand(&k, key);
	dmrAesSuperframeIv(TEST_MI, 0, iv);
	dmrAesKeystream(&k, iv, ks);
	uint8_t burst[AMBE_BURST_BYTES], frames[3][AMBE_FRAME_BYTES], bits[AMBE_PARAM_BITS];

	hex(BURSTS[2], burst, sizeof burst);
	ambeBurstSplit(burst, frames);
	ambeFecDecode(frames[0], bits, NULL);
	dmrAesApplyFrame(ks, 6, bits);
	CHECK(pack(bits) != PLAIN[6], "wrong key decrypts");
}

int main(void)
{
	test_fips197();
	test_mi();
	test_call();
	printf("# dmrAesTest: %d checks, %d failures\n", checks, failures);
	return failures != 0;
}
