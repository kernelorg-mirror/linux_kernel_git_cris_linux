// SPDX-License-Identifier: GPL-2.0
/*
 * SCMI Telemetry Test Tool
 *
 * Copyright (C) 2026 ARM Ltd.
 */

/*
 * Userspace decoder for a snapshot of an SCMI v4.0 Telemetry SHMTI area
 * (TDCF format). libc only, no alignment or endianness assumptions on the
 * host or on the snapshot buffer.
 *
 * Layout (all fields little-endian, except the UUID line payload):
 *
 *   Prologue  (16 bytes)
 *     +0   u32 signature      0x5442474E ("TBGN" as a LE-decoded u32)
 *     +4   u32 match seq      LSB set => platform update in progress
 *     +8   u32 num_qwords     payload size in 64-bit units
 *     +12  u32 hdr meta       [7:0] TDCF revision
 *   Payload   (num_qwords * 8 bytes of lines, each 2 or 3 qwords)
 *     +0   u32 meta           [7:4] line type: 0 DATA, 1 BLK_TS, 2 UUID
 *                             [3] USE_BLK_TS  [2] HAS_LINE_EXT
 *                             [1] TS_VALID    [0] DATA_INVALID
 *     +4   u32 id             DATA: DE id    BLK_TS: clock rate
 *     +8   DATA : u64 value    BLK_TS: u64 timestamp   UUID: 16 bytes
 *     +16  u64 line timestamp (only when HAS_LINE_EXT; UUID lines: part
 *          of the 16 bytes above, HAS_LINE_EXT is mandatory for them)
 *   Epilogue  (last 8 bytes of the SHMTI)
 *     +0   u32 match seq      must equal the prologue one
 *     +4   u32 signature      0x54454E44 ("TEND" as a LE-decoded u32)
 *
 * Line length: 16 bytes, or 24 bytes when HAS_LINE_EXT is set.
 *
 * Returns 0 on success, -EINVAL on bad size/signature, -EOVERFLOW/-EPROTO
 * on malformed payload, -EAGAIN if the snapshot looks torn (odd start
 * sequence or start/end sequence mismatch): the content is still decoded.
 */
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define TDCF_SIG_BEGIN		0x5442474Eu
#define TDCF_SIG_END		0x54454E44u
#define TDCF_PRLG_SZ		16u
#define TDCF_EPLG_SZ		8u
#define TDCF_MIN_SZ		(TDCF_PRLG_SZ + TDCF_EPLG_SZ)

#define TDCF_LINE_DATA		0u
#define TDCF_LINE_BLK_TS	1u
#define TDCF_LINE_UUID		2u

#define TDCF_META_TYPE(m)	(((m) >> 4) & 0xfu)
#define TDCF_META_USE_BLK_TS	(1u << 3)
#define TDCF_META_HAS_EXT	(1u << 2)
#define TDCF_META_TS_VALID	(1u << 1)
#define TDCF_META_INVALID	(1u << 0)

#define TDCF_LINE_SZ		16u
#define TDCF_LINE_EXT_SZ	24u

static uint32_t tdcf_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t tdcf_le64(const uint8_t *p)
{
	return ((uint64_t)tdcf_le32(p + 4) << 32) | tdcf_le32(p);
}

static void tdcf_flags(uint32_t m, char out[16])
{
	snprintf(out, 16, "%c%c%c%c",
		 (m & TDCF_META_USE_BLK_TS) ? 'B' : '-',
		 (m & TDCF_META_HAS_EXT) ? 'E' : '-',
		 (m & TDCF_META_TS_VALID) ? 'T' : '-',
		 (m & TDCF_META_INVALID) ? 'I' : '-');
}

/* UUID bytes are in memory order, i.e. 4 x BE dwords: no swapping needed */
static void tdcf_uuid_str(const uint8_t *u, char out[40])
{
	snprintf(out, 40,
		 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
		 "%02x%02x%02x%02x%02x%02x",
		 u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
		 u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
}

int tdcf_decode(const void *buf, size_t len)
{
	const uint8_t *b = buf;
	uint32_t sig_s, mseq_s, nq, hdr, mseq_e, sig_e;
	size_t off = TDCF_PRLG_SZ, end, left;
	/* Payload starts at 16, so offset 0 can safely mean "none" */
	size_t bts_off = 0, uuid_off = 0;
	uint64_t bts_ts = 0;
	uint32_t bts_rate = 0;
	int torn = 0;

	if (!b || len < TDCF_MIN_SZ) {
		fprintf(stderr, "TDCF: buffer too small (%zu bytes)\n", len);
		return -EINVAL;
	}

	end = len - TDCF_EPLG_SZ;	/* payload lives in [off, end) */

	sig_s  = tdcf_le32(b);
	mseq_s = tdcf_le32(b + 4);
	nq     = tdcf_le32(b + 8);
	hdr    = tdcf_le32(b + 12);
	mseq_e = tdcf_le32(b + end);
	sig_e  = tdcf_le32(b + end + 4);

	if (sig_s != TDCF_SIG_BEGIN || sig_e != TDCF_SIG_END) {
		fprintf(stderr,
			"TDCF: bad signature START:0x%08" PRIx32
			" (exp 0x%08x) END:0x%08" PRIx32 " (exp 0x%08x)\n",
			sig_s, TDCF_SIG_BEGIN, sig_e, TDCF_SIG_END);
		return -EINVAL;
	}

	printf("PRLG  @0x0000 sig=TBGN mseq=0x%08" PRIx32 " qwords=%" PRIu32
	       " rev=%" PRIu32 " hdr_meta=0x%08" PRIx32 "\n",
	       mseq_s, nq, hdr & 0xffu, hdr);

	if (mseq_s & 1u) {
		fprintf(stderr, "TDCF: odd start sequence: update in progress\n");
		torn = 1;
	}
	if (mseq_s != mseq_e) {
		fprintf(stderr,
			"TDCF: sequence mismatch start:0x%08" PRIx32
			" end:0x%08" PRIx32 "\n", mseq_s, mseq_e);
		torn = 1;
	}

	left = nq;
	while (left) {
		const uint8_t *p = b + off;
		char fl[16], us[40];
		uint32_t meta, id;
		size_t lb;

		if (end - off < 4) {
			fprintf(stderr, "TDCF: line @0x%zx overflows SHMTI\n", off);
			return -EOVERFLOW;
		}

		meta = tdcf_le32(p);
		lb = (meta & TDCF_META_HAS_EXT) ? TDCF_LINE_EXT_SZ : TDCF_LINE_SZ;
		if (end - off < lb) {
			fprintf(stderr, "TDCF: line @0x%zx overflows SHMTI\n", off);
			return -EOVERFLOW;
		}
		if (left < lb / 8) {
			fprintf(stderr,
				"TDCF: line @0x%zx exceeds prologue num_qwords\n",
				off);
			return -EPROTO;
		}

		id = tdcf_le32(p + 4);
		tdcf_flags(meta, fl);
		printf("LINE  @0x%04zx %-6s [%s] ", off,
		       TDCF_META_TYPE(meta) == TDCF_LINE_DATA ? "DATA" :
		       TDCF_META_TYPE(meta) == TDCF_LINE_BLK_TS ? "BLK_TS" :
		       TDCF_META_TYPE(meta) == TDCF_LINE_UUID ? "UUID" : "???",
		       fl);

		if (meta & TDCF_META_INVALID) {
			/* Disabled/unused slot: not an error */
			printf("id=0x%08" PRIx32 " <invalid/unused>\n", id);
			goto next;
		}

		switch (TDCF_META_TYPE(meta)) {
		case TDCF_LINE_DATA: {
			uint64_t val = tdcf_le64(p + 8);

			printf("id=0x%08" PRIx32 " val=0x%016" PRIx64
			       " (%" PRIu64 ") ", id, val, val);

			if (meta & TDCF_META_USE_BLK_TS) {
				if (bts_off)
					printf("ts=0x%016" PRIx64
					       " (blk@0x%zx rate=%" PRIu32 ")",
					       bts_ts, bts_off, bts_rate);
				else
					printf("ts=<USE_BLK_TS without preceding BLK_TS>");
			} else if (meta & TDCF_META_TS_VALID) {
				if (meta & TDCF_META_HAS_EXT)
					printf("ts=0x%016" PRIx64 " (line)",
					       tdcf_le64(p + 16));
				else
					printf("ts=<TS_VALID without EXT: malformed>");
			} else if (meta & TDCF_META_HAS_EXT) {
				printf("ts=invalid");
			} else {
				printf("ts=none");
			}

			if (uuid_off)
				printf(" uuid=line@0x%zx", uuid_off);
			else
				printf(" uuid=primary");
			printf("\n");
			break;
		}
		case TDCF_LINE_BLK_TS:
			if (meta & (TDCF_META_USE_BLK_TS | TDCF_META_HAS_EXT |
				    TDCF_META_TS_VALID)) {
				printf("rate=%" PRIu32 " <malformed, ignored>\n", id);
				break;
			}
			bts_off = off;
			bts_rate = id;
			bts_ts = tdcf_le64(p + 8);
			printf("rate=%" PRIu32 "%s ts=0x%016" PRIx64
			       " (%" PRIu64 ")\n", bts_rate,
			       bts_rate ? "" : " (0: protocol default)",
			       bts_ts, bts_ts);
			break;
		case TDCF_LINE_UUID:
			if ((meta & (TDCF_META_TS_VALID | TDCF_META_USE_BLK_TS)) ||
			    !(meta & TDCF_META_HAS_EXT)) {
				printf("<malformed, ignored>\n");
				break;
			}
			uuid_off = off;
			tdcf_uuid_str(p + 8, us);
			printf("id=0x%08" PRIx32 " %s\n", id, us);
			break;
		default:
			printf("id=0x%08" PRIx32 " <unknown line type %u, skipped>\n",
			       id, TDCF_META_TYPE(meta));
			break;
		}
next:
		off += lb;
		left -= lb / 8;
	}

	if (end > off)
		printf("PAD   @0x%04zx %zu unused payload bytes\n", off, end - off);
	printf("EPLG  @0x%04zx mseq=0x%08" PRIx32 " sig=TEND\n", end, mseq_e);

	return torn ? -EAGAIN : len;
}
