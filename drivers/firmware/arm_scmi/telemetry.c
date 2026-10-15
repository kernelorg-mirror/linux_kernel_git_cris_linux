// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Telemetry Protocol
 *
 * Copyright (C) 2026 ARM Ltd.
 */

#include <linux/atomic.h>
#include <linux/bitfield.h>
#include <linux/compiler_types.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/io.h>
#include <linux/limits.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/sprintf.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/uuid.h>
#include <linux/xarray.h>

#include "errors.h"
#include "protocols.h"
#include "notify.h"

#include <trace/events/scmi.h>

/* Updated only after ALL the mandatory features for that version are merged */
#define SCMI_PROTOCOL_SUPPORTED_VERSION		0x10000

#define SCMI_TLM_TDCF_MAX_RETRIES	15
#define SCMI_TLM_TDCF_RETRY_GAP_US	1234

#define SCMI_TLM_DE_IMPL_NUM_DWORDS	4

/* An enum listing the protocol specific commands definitions */
enum scmi_telemetry_protocol_cmd {
	TELEMETRY_LIST_SHMTI = 0x3,
	TELEMETRY_DE_DESCRIPTION = 0x4,
	TELEMETRY_LIST_UPDATE_INTERVALS = 0x5,
	TELEMETRY_DE_CONFIGURE = 0x6,
	TELEMETRY_DE_ENABLED_LIST = 0x7,
	TELEMETRY_CONFIG_SET = 0x8,
	TELEMETRY_READING_COMPLETE = TELEMETRY_CONFIG_SET,
	TELEMETRY_CONFIG_GET = 0x9,
	TELEMETRY_RESET = 0xA,
};

struct scmi_msg_resp_telemetry_protocol_attributes {
	__le32 de_num;
	__le32 groups_num;
	__le32 de_implem_rev_dword[SCMI_TLM_DE_IMPL_NUM_DWORDS];
	__le32 attributes_1;
#define SUPPORTS_SINGLE_READ(x)		(le32_get_bits((x), BIT(31)))
#define SUPPORTS_CONTINUOS_UPDATE(x)	(le32_get_bits((x), BIT(30)))
#define SUPPORTS_PER_GROUP_CONFIG(x)	(le32_get_bits((x), BIT(18)))
#define SUPPORTS_RESET(x)		(le32_get_bits((x), BIT(17)))
#define SUPPORTS_FC(x)			(le32_get_bits((x), BIT(16)))
	__le32 default_blk_ts_rate;
};

struct scmi_telemetry_update_notify_payld {
	__le32 agent_id;
	__le32 status;
	__le32 num_dwords;
	__le32 array[] __counted_by_le(num_dwords);
};

struct scmi_shmti_desc {
	__le32 id;
	__le32 addr_low;
	__le32 addr_high;
	__le32 length;
	__le32 flags;
};

struct scmi_msg_resp_telemetry_shmti_list {
	__le32 num_shmti;
	struct scmi_shmti_desc desc[];
};

struct de_desc_fastchannel {
	__le32 addr_low;
	__le32 addr_high;
	__le32 size;
};

struct scmi_de_desc {
	__le32 de_id;
	__le32 group_id;
	__le32 de_data_sz;
	__le32 de_attributes_1;
#define	IS_NAME_SUPPORTED(d)	(le32_get_bits((d)->de_attributes_1, BIT(31)))
#define	IS_FC_SUPPORTED(d)	(le32_get_bits((d)->de_attributes_1, BIT(30)))
#define	GET_DE_TYPE(d)		(le32_get_bits((d)->de_attributes_1, GENMASK(29, 22)))
#define	IS_PERSISTENT(d)	(le32_get_bits((d)->de_attributes_1, BIT(21)))
#define GET_DE_UNIT_EXP(d)							\
	({									\
		__u32 __signed_exp =						\
			le32_get_bits((d)->de_attributes_1, GENMASK(20, 13));	\
										\
		sign_extend32(__signed_exp, 7);					\
	})
#define	GET_DE_UNIT(d)		(le32_get_bits((d)->de_attributes_1, GENMASK(12, 5)))
#define	TSTAMP_SUPPORT(d)	(le32_get_bits((d)->de_attributes_1, GENMASK(1, 0)))
	__le32 de_attributes_2;
#define	GET_DE_INSTA_ID(d)	(le32_get_bits((d)->de_attributes_2, GENMASK(31, 24)))
#define	GET_COMPO_INSTA_ID(d)	(le32_get_bits((d)->de_attributes_2, GENMASK(23, 8)))
#define	GET_COMPO_TYPE(d)	(le32_get_bits((d)->de_attributes_2, GENMASK(7, 0)))
	__le32 de_attributes_3;
};

struct scmi_msg_resp_telemetry_de_description {
	__le32 num_desc;	/* This does NOT count desc[] by the spec */
	struct scmi_de_desc desc[];
};

struct scmi_msg_telemetry_update_intervals {
	__le32 index;
	__le32 group_identifier;
#define	ALL_DES_NO_GROUP	0x0
#define SPECIFIC_GROUP_DES	0x1
#define ALL_DES_ANY_GROUP	0x2
	__le32 flags;
};

struct scmi_msg_resp_telemetry_update_intervals {
	__le32 flags;
#define INTERVALS_DISCRETE(x)	(le32_get_bits((x), BIT(12)) == 0)
	__le32 intervals[];
};

struct scmi_msg_telemetry_de_configure {
	__le32 identifier;
	__le32 flags;
#define CFG_ENABLE_NO_TSTAMP	BIT(0)
#define CFG_ENABLE_WTH_TSTAMP	BIT(1)
#define CFG_DISABLE_ALL		BIT(2)
#define CFG_GROUP_SELECTOR		BIT(3)
#define CFG_EVENT_DE		0
#define CFG_EVENT_GROUP		1
#define CFG_DISABLE_ONE		0x0
};

struct scmi_msg_resp_telemetry_de_configure {
	__le32 shmti_id;
#define SHMTI_ID_INVALID	GENMASK(31, 0)
#define IS_SHMTI_ID_VALID(x)	((x) != SHMTI_ID_INVALID)
	__le32 shmti_de_offset;
	__le32 blk_ts_offset;
};

struct scmi_msg_telemetry_config_set {
	__le32 group_identifier;
	__le32 control;
#define TELEMETRY_ENABLE		(BIT(0))
#define TELEMETRY_MODE			GENMASK(4, 1)
#define TELEMETRY_MODE_SET(x)		(FIELD_PREP(TELEMETRY_MODE, (x)))
#define	TLM_ONDEMAND			(0)
#define	TLM_NOTIFS			(1)
#define	TLM_SINGLE			(2)
#define TELEMETRY_MODE_ONDEMAND		TELEMETRY_MODE_SET(TLM_ONDEMAND)
#define TELEMETRY_MODE_NOTIFS		TELEMETRY_MODE_SET(TLM_NOTIFS)
#define TELEMETRY_MODE_SINGLE		TELEMETRY_MODE_SET(TLM_SINGLE)

#define TLM_ORPHANS			(0)
#define TLM_GROUP			(1)
#define TLM_ALL				(2)
#define TELEMETRY_SET_SELECTOR(x)	(FIELD_PREP(GENMASK(8, 5), (x)))
#define	TELEMETRY_SET_SELECTOR_ORPHANS	TELEMETRY_SET_SELECTOR(TLM_ORPHANS)
#define	TELEMETRY_SET_SELECTOR_GROUP	TELEMETRY_SET_SELECTOR(TLM_GROUP)
#define	TELEMETRY_SET_SELECTOR_ALL	TELEMETRY_SET_SELECTOR(TLM_ALL)
	__le32 sampling_rate;
};

struct scmi_msg_resp_telemetry_reading_complete {
	__le32 num_dwords;
	__le32 array[] __counted_by_le(num_dwords);
};

/* TDCF */

#define _I(__a)		(ioread32((void __iomem *)(__a)))

/*
 * Define the behaviour of a SHMTI scan defining what information will
 * be gathered and which Telemetry items can be updated.
 */
enum scan_mode {
	SCAN_LOOKUP,	/* Update only value/tstamp */
	SCAN_UPDATE,	/* Update also location offset */
	SCAN_DISCOVERY  /* Update xa_des: allows for new DEs to be discovered */
};

struct fc_line {
	__le32 data_low;
	__le32 data_high;
};

struct fc_tsline {
	__le32 data_low;
	__le32 data_high;
	__le32 ts_low;
	__le32 ts_high;
};

struct line {
	__le32 data_low;
	__le32 data_high;
};

struct blk_tsline {
	__le32 ts_low;
	__le32 ts_high;
};

struct tsline {
	__le32 data_low;
	__le32 data_high;
	__le32 ts_low;
	__le32 ts_high;
};

struct uuid_line {
	__be32 dwords[SCMI_TLM_DE_IMPL_NUM_DWORDS];
};

#define LINE_DATA_GET_RAW(f)				\
({							\
	typeof(f) _f = (f);				\
	u32 _high = le32_to_cpu(_f->data_high);		\
	u32 _low = le32_to_cpu(_f->data_low);		\
	u64 _res;					\
							\
	_res = (((u64)(_high)) << 32) | (_low);		\
	_res;						\
})

#define LINE_DATA_GET(f)				\
({							\
	typeof(f) _f = (f);				\
	u32 _high = _I(&_f->data_high);			\
	u32 _low = _I(&_f->data_low);			\
	u64 _res;					\
							\
	_res = (((u64)(_high)) << 32) | (_low);		\
	_res;						\
})

#define LINE_TSTAMP_GET_RAW(f)				\
({							\
	typeof(f) _f = (f);				\
	u32 _high = le32_to_cpu(_f->ts_high);		\
	u32 _low = le32_to_cpu(_f->ts_low);		\
	u64 _res;					\
							\
	_res = (((u64)(_high)) << 32) | (_low);		\
	_res;						\
})

#define LINE_TSTAMP_GET(f)				\
({							\
	typeof(f) _f = (f);				\
	u32 _high = _I(&_f->ts_high);			\
	u32 _low = _I(&_f->ts_low);			\
	u64 _res;					\
							\
	_res = (((u64)(_high)) << 32) | (_low);		\
	_res;						\
})

#define BLK_TS_STAMP(f)		LINE_TSTAMP_GET(f)
#define BLK_TS_STAMP_RAW(f)	LINE_TSTAMP_GET_RAW(f)
#define BLK_TS_RATE(p)		PAYLD_ID(p)
#define BLK_TS_RATE_RAW(p)	PAYLD_ID_RAW(p)

enum tdcf_line_types {
	TDCF_DATA_LINE = 0,
	TDCF_BLK_TS_LINE = 1,
	TDCF_UUID_LINE = 2,
};

struct payload {
	__le32 meta;
#define PAYLD_META(x)		(_I(&((x)->meta)))
#define PAYLD_META_RAW(x)	(le32_to_cpu((x)->meta))
#define LINE_TYPE_RAW(m)	(FIELD_GET(GENMASK(7, 4), (m)))
#define LINE_TYPE(x)		(LINE_TYPE_RAW(PAYLD_META(x)))
#define IS_DATA_LINE(x)		(LINE_TYPE(x) == TDCF_DATA_LINE)
#define IS_DATA_LINE_RAW(x)	(LINE_TYPE_RAW(x) == TDCF_DATA_LINE)
#define IS_BLK_TS_LINE(x)	(LINE_TYPE(x) == TDCF_BLK_TS_LINE)
#define IS_BLK_TS_LINE_RAW(x)	(LINE_TYPE_RAW(x) == TDCF_BLK_TS_LINE)
#define IS_UUID_LINE(x)		(LINE_TYPE(x) == TDCF_UUID_LINE)
#define USE_BLK_TS_RAW(m)	((m) & BIT(3))
#define USE_BLK_TS(x)		(USE_BLK_TS_RAW(PAYLD_META(x)))
#define HAS_LINE_EXT_RAW(m)	((m) & BIT(2))
#define HAS_LINE_EXT(x)		(HAS_LINE_EXT_RAW(PAYLD_META(x)))
#define LINE_TS_VALID_RAW(m)	((m) & BIT(1))
#define LINE_TS_VALID(x)	(LINE_TS_VALID_RAW(PAYLD_META(x)))
#define	DATA_INVALID_RAW(m)	((m) & BIT(0))
#define	DATA_INVALID(x)		(DATA_INVALID_RAW(PAYLD_META(x)))
#define	BLK_TS_INVALID_RAW(m)						\
({									\
	bool invalid;							\
									\
	invalid  = LINE_TS_VALID_RAW(m) || HAS_LINE_EXT_RAW(m) ||	\
			USE_BLK_TS_RAW(m) || DATA_INVALID_RAW(m);	\
	invalid;							\
})
#define	BLK_TS_INVALID(p)	BLK_TS_INVALID_RAW(PAYLD_META(p))

#define	UUID_INVALID_RAW(m)						\
({									\
	bool invalid;							\
									\
	invalid = LINE_TS_VALID_RAW(m) || USE_BLK_TS_RAW(m) ||	\
			DATA_INVALID_RAW(m) || !HAS_LINE_EXT_RAW(m);	\
	invalid;							\
})
#define	UUID_INVALID(p)		UUID_INVALID_RAW(PAYLD_META(p))
	__le32 id;
	union {
		struct line l;
		struct tsline tsl;
		struct blk_tsline blk_tsl;
		struct uuid_line uuid_l;
	};
};

#define PAYLD_ID(x)	(_I(&(((struct payload __iomem *)(x))->id)))
#define PAYLD_ID_RAW(x)	(le32_to_cpu((((struct payload *)(x))->id)))

#define LINE_DATA_PAYLD_WORDS						       \
	((sizeof(u32) + sizeof(u32) + sizeof(struct line)) / sizeof(u32))
#define EXT_LINE_DATA_PAYLD_WORDS					       \
	((sizeof(u32) + sizeof(u32) + sizeof(struct tsline)) / sizeof(u32))

#define LINE_LENGTH_WORDS_RAW(m)		\
	(HAS_LINE_EXT_RAW((m)) ? EXT_LINE_DATA_PAYLD_WORDS : LINE_DATA_PAYLD_WORDS)

#define LINE_LENGTH_WORDS(x)		LINE_LENGTH_WORDS_RAW(PAYLD_META(x))
#define LINE_LENGTH_QWORDS(x)		((LINE_LENGTH_WORDS(x)) / 2)
#define LINE_LENGTH_QWORDS_RAW(x)	((LINE_LENGTH_WORDS_RAW(x)) / 2)

#define LINE_LENGTH_BYTES_RAW(m)	((LINE_LENGTH_WORDS_RAW(m)) * sizeof(u32))
#define LINE_LENGTH_BYTES(x)		(LINE_LENGTH_BYTES_RAW(PAYLD_META(x)))

struct prlg {
	__le32 sign_start;
#define SIGNATURE_START	0x5442474E	/* TBGN */
	__le32 match_start;
	__le32 num_qwords;
	__le32 hdr_meta_1;
#define TDCF_REVISION_GET(x)	(le32_get_bits((x)->hdr_meta_1, GENMASK(7, 0)))
};

struct eplg {
	__le32 match_end;
	__le32 sign_end;
#define SIGNATURE_END	0x54454E44	/* TEND */
};

#define TDCF_EPLG_SZ	(sizeof(struct eplg))

struct tdcf {
	struct prlg prlg;
	unsigned char payld[];
};

#define QWORDS(_t)	(_I(&(_t)->prlg.num_qwords))
#define QWORDS_RAW(_t)	(le32_to_cpu((_t)->prlg.num_qwords))

#define SHMTI_MIN_SIZE	(sizeof(struct tdcf) + TDCF_EPLG_SZ)
/* An arbitrary upper bound to avoid crazy allocations driven by buggy FW */
#define SHMTI_MAX_SIZE	SZ_64K

#define TDCF_START_SIGNATURE(x)		(_I(&((x)->prlg.sign_start)))
#define TDCF_START_SEQ_GET(x)		(_I(&((x)->prlg.match_start)))
#define TDCF_START_SEQ_GET_RAW(x)	(le32_to_cpu((x)->prlg.match_start))
/* TDCF MatchSequence cannot be zero by the SCMI v4.0 Specification */
#define TDCF_INVALID_MATCH_SEQ	0
#define IS_BAD_START_SEQ(s)	((s) & 0x1 || (s) == TDCF_INVALID_MATCH_SEQ)

#define TDCF_END_SEQ_GET(e)	(_I(&((e)->match_end)))
#define TDCF_END_SEQ_GET_RAW(e)	(le32_to_cpu((e)->match_end))
#define TDCF_END_SIGNATURE(e)	(_I(&((e)->sign_end)))
#define	TDCF_BAD_END_SEQ	GENMASK(31, 0)

struct telemetry_de_snapshot {
	u32 magic;
	struct payload payld;
	struct payload bts_payld;
};

struct telemetry_shmti;

struct shmti_snap {
	struct telemetry_shmti *shmti;
	u32 magic;
	u8 base[] __aligned(8);
};

struct telemetry_shmti {
	u32 flags;
	void __iomem *base;
	struct scmi_telemetry_shmti_info info;
	/* Protect srcu operation */
	struct mutex lock;
	struct srcu_struct srcu;
	struct shmti_snap *snaps[2];
	struct shmti_snap __rcu	*cur;
	/* Mutex to protect @xa_lines */
	struct mutex lines_mtx;
	struct xarray xa_lines;
	#define PAYLD_HASH_BITS  4
	struct mutex payld_locks[1 << PAYLD_HASH_BITS];
};

#define TDCF_OFFS(_b, _p)				\
	((unsigned long)((__force void *)(_p) - (__force void *)(_b)))

#define SHMTI_EPLG(s)						\
	({							\
		struct telemetry_shmti *_s = (s);		\
		struct eplg __iomem *_eplg;			\
								\
		_eplg = _s->base + _s->info.len - TDCF_EPLG_SZ;	\
		(_eplg);					\
	})

#define SNAP_EPLG(s)								\
	({									\
		struct shmti_snap *_s = (s);					\
		struct eplg *_eplg;						\
										\
		_eplg = (void *)_s->base + _s->shmti->info.len - TDCF_EPLG_SZ;	\
		(_eplg);							\
	})

struct telemetry_info;

struct telemetry_line {
	enum tdcf_line_types type;
	u32 last_magic;
	unsigned long offset;
	refcount_t users;
	struct telemetry_shmti *shmti;
	/* Protect line accesses  */
	struct mutex mtx;
};

struct telemetry_block_ts {
	u64 last_ts;
	u32 last_rate;
	struct telemetry_line line;
};

#define to_blkts(l)	container_of(l, struct telemetry_block_ts, line)

struct telemetry_uuid {
	struct hlist_node node_ht;
	struct hlist_node node_lst;
	uuid_t uuid;
};

#define to_uuid_from_uuid_t(u)	container_of(u, struct telemetry_uuid, uuid)

#define IS_TDE_TSTAMP_TYPE(__t, __ttype)	((__t)->ts_type == (__ttype))
#define IS_TDE_TS_NONE(_t)	(IS_TDE_TSTAMP_TYPE((_t), TSTAMP_NONE))
#define IS_TDE_TS_LINE(_t)	(IS_TDE_TSTAMP_TYPE((_t), TSTAMP_LINE))
#define IS_TDE_TS_BLK(_t)	(IS_TDE_TSTAMP_TYPE((_t), TSTAMP_BLK))

#define TDE_FC_SIZE(_t)							\
({									\
	struct telemetry_de *__t = (_t);				\
	size_t fc_size;							\
									\
	fc_size = __t->de.info->data_sz;				\
	fc_size += __t->de.tstamp_support ? sizeof(u32) * 2 : 0;	\
	(fc_size);							\
})

enum timestamps {
	TSTAMP_NONE = 0,
	TSTAMP_LINE = 1,
	TSTAMP_BLK = 2,
};

struct telemetry_de {
	enum timestamps ts_type;
	u32 ts_rate;
	bool enumerated;
	bool cached_msg;
	void __iomem *base;
	struct eplg __iomem *eplg;
	u32 sid;
	u32 offset;
	/* NOTE THAT DE data_sz is registered in scmi_telemetry_de */
	u32 fc_size;
	u64 last_val;
	u64 last_ts;
	u32 last_magic;
	struct list_head item;
	struct telemetry_block_ts *bts;
#define BLK_TS_CHANGED(t, s, o)			\
	(!((t)->bts) || (t)->bts->line.shmti != (s) || (t)->bts->line.offset != (o))
	struct telemetry_uuid *uuid;
	struct scmi_telemetry_de de;
	/* Protect last_val/ts/magic accesses - MUST BE KEPT LAST */
	struct mutex mtx;
};

#define to_tde(d)	container_of(d, struct telemetry_de, de)

static inline bool scmi_tde_has_tstamp(struct telemetry_de *t)
{
	return t->de.tstamp_support && t->de.tstamp_enabled;
}

enum de_state {
	ENA_STATE,
	ENA_TSTAMP,
	ENA_MAX
};

struct telemetry_info {
	bool streaming_mode;
	unsigned int num_shmti;
	unsigned int num_des_tstamp;
#define SCMI_UUID_DB_THRESH	3
	/* Protect uuids_len */
	struct mutex uuids_mtx;
	unsigned int uuids_len;
#define SCMI_UUID_HASH_SZ	5
	DECLARE_HASHTABLE(uuids_ht, SCMI_UUID_HASH_SZ);
	/* Mutex to protect des_enabled_mtx */
	struct mutex des_enabled_mtx;
	atomic_t des_enabled[ENA_MAX];
	unsigned int default_blk_ts_rate;
	const struct scmi_protocol_handle *ph;
	struct telemetry_shmti *shmti;
	struct telemetry_de *tdes;
	struct xarray xa_des;
	struct telemetry_uuid *primary_uuid;
	/* Mutex to protect access to @free_des */
	struct mutex free_mtx;
	struct list_head free_des;
	struct list_head fcs_des;
	/* Protect global and per-group configuration data */
	struct mutex config_mtx;
	struct scmi_telemetry_info info;
	struct notifier_block telemetry_nb;
	atomic_t rinfo_initializing;
	struct completion rinfo_initdone;
	struct scmi_telemetry_res_info *rinfo;
	struct scmi_telemetry_res_info *(*res_get)(struct telemetry_info *ti);
};

#define telemetry_nb_to_info(x)	\
	container_of(x, struct telemetry_info, telemetry_nb)

static struct scmi_telemetry_res_info *
__scmi_telemetry_resources_get(struct telemetry_info *ti);

static inline struct tdcf *snap_tdcf(struct shmti_snap *s);

static int scmi_telemetry_shmti_scan(struct telemetry_info *ti,
				     unsigned int shmti_id, enum scan_mode mode);

static inline void scmi_telemetry_uuid_link(struct telemetry_de *tde,
					    struct telemetry_uuid *uuid);

static inline
struct mutex *lock_for_payld(struct mutex *locks, unsigned long offset)
{
	return &locks[hash_long(offset, PAYLD_HASH_BITS)];
}

static inline void
scmi_telemetry_de_state_update(struct telemetry_info *ti, enum de_state state,
			       bool *current_state, const bool next_state)
{
	guard(mutex)(&ti->des_enabled_mtx);
	if (!current_state || *current_state != next_state)
		atomic_add(next_state ? 1 : -1, &ti->des_enabled[state]);

	if (current_state)
		*current_state = next_state;

	dev_dbg(ti->ph->dev, "Telemetry des_enabled[%s]:%u\n",
		state == ENA_STATE ? "STATE" : "TSTAMP",
		atomic_read(&ti->des_enabled[state]));
}

static struct telemetry_de *
scmi_telemetry_free_tde_get(struct telemetry_info *ti)
{
	struct telemetry_de *tde;

	guard(mutex)(&ti->free_mtx);

	tde = list_first_entry_or_null(&ti->free_des, struct telemetry_de, item);
	if (!tde)
		return tde;

	list_del(&tde->item);

	return tde;
}

static inline void scmi_telemetry_free_tdes_add(struct telemetry_info *ti,
						struct telemetry_de *tde)
{
	guard(mutex)(&ti->free_mtx);
	list_add_tail(&tde->item, &ti->free_des);
}

static void scmi_telemetry_free_tde_put(struct telemetry_info *ti,
					struct telemetry_de *tde)
{
	struct scmi_telemetry_de_info *info;

	lockdep_assert_held(&tde->mtx);

	/* Unmap any valid FC */
	if (tde->de.fc_support && tde->base)
		iounmap(tde->base);

	/* Save clear and restore */
	info = tde->de.info;
	memset(info, 0, sizeof(*info));
	memset(tde, 0, offsetof(struct telemetry_de, mtx));
	tde->de.info = info;

	scmi_telemetry_free_tdes_add(ti, tde);
}

static struct telemetry_de *scmi_telemetry_tde_lookup(struct telemetry_info *ti,
						      unsigned int de_id)
{
	struct scmi_telemetry_de *de;

	de = xa_load(&ti->xa_des, de_id);
	if (!de)
		return NULL;

	return to_tde(de);
}

static struct telemetry_de *scmi_telemetry_tde_get(struct telemetry_info *ti,
						   unsigned int de_id)
{
	struct telemetry_de *tde;

	tde = scmi_telemetry_free_tde_get(ti);
	if (!tde) {
		dev_err(ti->ph->dev, "Cannot get TDE for ID:0x%08X\n", de_id);
		return ERR_PTR(-ENOSPC);
	}

	tde->sid = SHMTI_ID_INVALID;

	return tde;
}

static int scmi_telemetry_tde_register(struct telemetry_info *ti,
				       struct telemetry_de *tde)
{
	struct scmi_telemetry_res_info *rinfo;
	int ret;

	lockdep_assert_held(&tde->mtx);

	/* Get rinfo without triggering a recursive enumeration */
	rinfo = __scmi_telemetry_resources_get(ti);

	if (rinfo->num_des >= ti->info.base.num_des) {
		ret = -ENOSPC;
		goto err;
	}

	/* Store DE pointer by de_id ... */
	ret = xa_insert(&ti->xa_des, tde->de.info->id, &tde->de, GFP_KERNEL);
	if (ret)
		goto err;

	/* ... and in the general array */
	rinfo->des[rinfo->num_des] = &tde->de;
	/* Make sure the freshly registered DE is visible before the index update */
	smp_store_release(&rinfo->num_des, rinfo->num_des + 1);

	return 0;

err:
	dev_err(ti->ph->dev, "Cannot register TDE for ID:0x%08X - ret:%d\n",
		tde->de.info->id, ret);

	return ret;
}

static inline bool
scmi_telemetry_tde_cache_stale(struct telemetry_de *tde, u32 magic)
{
	lockdep_assert_held(&tde->mtx);

	/* last_magic < magic */
	return time_before32(tde->last_magic, magic);
}

static void
scmi_telemetry_tde_cache_update(struct telemetry_de *tde,
				struct scmi_telemetry_de_sample *sample,
				u32 *magic)
{
	lockdep_assert_held(&tde->mtx);

	/*
	 * Update the cache only if stale compared to the current
	 * sample, so bail-out when last_magic >= *magic
	 */
	if (magic && !scmi_telemetry_tde_cache_stale(tde, *magic))
		return;

	tde->last_magic = magic ? *magic : TDCF_BAD_END_SEQ;
	tde->last_val = sample->val;
	tde->last_ts = scmi_tde_has_tstamp(tde) ? sample->tstamp : 0;
	/* Update returned value too */
	sample->tstamp = tde->last_ts;

	trace_scmi_tlm_collect(tde->last_ts, tde->de.info->id,
			       tde->last_val, "CACHED_DE_UPDATED");
}

static int
scmi_telemetry_tde_cache_lookup(struct telemetry_de *tde,
				struct scmi_telemetry_de_sample *sample,
				u32 *magic)
{
	lockdep_assert_held(&tde->mtx);

	/*
	 * Bailout without providing any sample when the cache is
	 * stale, i.e. last_magic < *magic
	 */
	if (magic && scmi_telemetry_tde_cache_stale(tde, *magic))
		return -EAGAIN;

	sample->id = tde->de.info->id;
	sample->val = tde->last_val;
	sample->tstamp = tde->last_ts;

	trace_scmi_tlm_collect(sample->tstamp, sample->id,
			       sample->val, "CACHED_DE_READ");

	return 0;
}

struct scmi_tlm_de_priv {
	struct telemetry_info *ti;
	void *next;
	size_t rx_len;
};

static int
scmi_telemetry_protocol_attributes_get(struct telemetry_info *ti)
{
	struct scmi_msg_resp_telemetry_protocol_attributes *resp;
	const struct scmi_protocol_handle *ph = ti->ph;
	struct scmi_xfer *t;
	int ret;

	ret = ph->xops->xfer_get_init(ph, PROTOCOL_ATTRIBUTES, 0,
				      sizeof(*resp), &t);
	if (ret)
		return ret;

	resp = t->rx.buf;
	ret = ph->xops->do_xfer(ph, t);
	if (!ret) {
		__le32 attr = resp->attributes_1;
		__be32 de_impl_version[SCMI_TLM_DE_IMPL_NUM_DWORDS];

		ti->info.base.num_des = le32_to_cpu(resp->de_num);
		ti->info.base.num_groups = le32_to_cpu(resp->groups_num);
		for (int i = 0; i < SCMI_TLM_DE_IMPL_NUM_DWORDS; i++)
			de_impl_version[i] =
				cpu_to_be32(le32_to_cpu(resp->de_implem_rev_dword[i]));
		import_uuid(&ti->info.base.primary_revision, (const __u8 *)&de_impl_version);
		ti->info.single_read_support = SUPPORTS_SINGLE_READ(attr);
		ti->info.continuous_update_support = SUPPORTS_CONTINUOS_UPDATE(attr);
		ti->info.per_group_config_support = SUPPORTS_PER_GROUP_CONFIG(attr);
		ti->info.reset_support = SUPPORTS_RESET(attr);
		ti->info.fc_support = SUPPORTS_FC(attr);
		ti->num_shmti = le32_get_bits(attr, GENMASK(15, 0));
		ti->default_blk_ts_rate = le32_to_cpu(resp->default_blk_ts_rate);
	}

	ph->xops->xfer_put(ph, t);

	return ret;
}

static void iter_tlm_prepare_message(void *message,
				     unsigned int desc_index, const void *priv)
{
	put_unaligned_le32(desc_index, message);
}

static int iter_de_descr_update_state(struct scmi_iterator_state *st,
				      const void *response, void *priv)
{
	const struct scmi_msg_resp_telemetry_de_description *r = response;
	struct scmi_tlm_de_priv *p = priv;

	st->num_returned = le32_get_bits(r->num_desc, GENMASK(15, 0));
	st->num_remaining = le32_get_bits(r->num_desc, GENMASK(31, 16));

	if (st->rx_len < (sizeof(*r) + sizeof(r->desc[0]) * st->num_returned))
		return -EINVAL;

	/* Initialized to first descriptor and initial payload size */
	p->next = (void *)r->desc;
	p->rx_len = st->rx_len - sizeof(*r);

	return 0;
}

static inline size_t scmi_telemetry_tde_var_size_calc(struct telemetry_de *tde)
{
	size_t sz = 0;

	sz += IS_TDE_TS_LINE(tde) ? sizeof(__le32) : 0;
	sz += tde->de.fc_support ? sizeof(struct de_desc_fastchannel) : 0;
	sz += tde->de.name_support ? SCMI_SHORT_NAME_MAX_SIZE : 0;

	return sz;
}

static inline int
scmi_telemetry_area_check(struct device *dev, const char *tag,
			  u32 low, u32 high, u32 size,
			  phys_addr_t *phys_addr, size_t *len)
{
	u64 addr = ((u64)high << 32) | low;
	phys_addr_t pa = (phys_addr_t)addr;
	unsigned long end_phys;

	/* Does the returned pointer fits architetural size ? */
	if ((u64)pa != addr) {
		dev_err(dev, FW_BUG "%s phys_addr (0x%llX) pointer too big.\n",
			tag, pa);
		return -EOVERFLOW;
	}

	if (!IS_ALIGNED(pa, 4)) {
		dev_err(dev, FW_BUG "%s phys_addr (0x%llX) misaligned.\n",
			tag, pa);
		return -EINVAL;
	}

	if (!IS_ALIGNED(size, 4)) {
		dev_err(dev, FW_BUG "%s area length (%u) misaligned\n",
			tag, size);
		return -EINVAL;
	}

	if (check_add_overflow(pa, size, &end_phys)) {
		dev_err(dev, FW_BUG "%s area (0x%llX/%u) wrap-around.\n",
			tag, pa, size);
		return -EOVERFLOW;
	}

	*phys_addr = pa;
	*len = size;

	return 0;
}

static int scmi_telemetry_de_descriptor_parse(struct telemetry_info *ti,
					      struct telemetry_de *tde,
					      void **next, size_t *rx_len)
{
	const struct scmi_de_desc *desc = *next;
	size_t payld_sz = sizeof(*desc);
	unsigned int grp_id;

	lockdep_assert_held(&tde->mtx);

	if (*rx_len < payld_sz)
		return -ENOSPC;

	tde->de.info->id = le32_to_cpu(desc->de_id);
	grp_id = le32_to_cpu(desc->group_id);
	if (grp_id != SCMI_TLM_GRP_INVALID) {
		struct scmi_telemetry_res_info *rinfo;

		/* Get rinfo without triggering a recursive enumeration */
		rinfo = __scmi_telemetry_resources_get(ti);

		/* Group descriptors are empty but allocated at this point */
		if (grp_id >= ti->info.base.num_groups)
			return -EINVAL;

		/* Link to parent group */
		tde->de.grp = &rinfo->grps[grp_id];
	}

	tde->de.info->grp_id = grp_id;
	tde->de.info->data_sz = le32_to_cpu(desc->de_data_sz);
	tde->de.info->type = GET_DE_TYPE(desc);
	tde->de.info->unit = GET_DE_UNIT(desc);
	tde->de.info->unit_exp = GET_DE_UNIT_EXP(desc);
	tde->de.info->instance_id = GET_DE_INSTA_ID(desc);
	tde->de.info->compo_instance_id = GET_COMPO_INSTA_ID(desc);
	tde->de.info->compo_type = GET_COMPO_TYPE(desc);
	tde->de.info->persistent = IS_PERSISTENT(desc);
	tde->ts_type = TSTAMP_SUPPORT(desc);
	tde->de.tstamp_support = !!tde->ts_type;
	tde->de.fc_support = IS_FC_SUPPORTED(desc);
	tde->de.name_support = IS_NAME_SUPPORTED(desc);
	/* Update DE_DESCRIPTOR size for the next iteration */
	*next += sizeof(*desc);

	payld_sz += scmi_telemetry_tde_var_size_calc(tde);
	if (*rx_len < payld_sz)
		return -ENOSPC;

	if (IS_TDE_TS_LINE(tde)) {
		__le32 *line_ts_rate = *next;

		tde->de.info->ts_rate = le32_to_cpu((*line_ts_rate));

		/* Variably sized depending on TS support */
		*next += sizeof(*line_ts_rate);
	} else if (tde->ts_type == TSTAMP_BLK) {
		/* Setup default BLK TS value at first */
		tde->de.info->ts_rate = ti->default_blk_ts_rate;
	}

	if (tde->de.fc_support) {
		struct de_desc_fastchannel *dfc;
		phys_addr_t phys_addr;
		void __iomem *addr;
		size_t size;
		int ret;

		dfc = *next;

		ret = scmi_telemetry_area_check(ti->ph->dev, "FC",
						le32_to_cpu(dfc->addr_low),
						le32_to_cpu(dfc->addr_high),
						le32_to_cpu(dfc->size),
						&phys_addr, &size);
		if (ret)
			return ret;

		/* Does it fit ? */
		if (size < TDE_FC_SIZE(tde)) {
			dev_err(ti->ph->dev,
				FW_BUG "TDE FC size too small (%zu)\n", size);
			return -EPROTO;
		}

		addr = ioremap(phys_addr, size);
		if (!addr)
			return -EADDRNOTAVAIL;

		tde->base = addr;
		tde->offset = 0;
		tde->fc_size = size;

		/* Variably sized depending on FC support */
		*next += sizeof(*dfc);
	}

	if (tde->de.name_support) {
		const char *de_name = *next;

		strscpy(tde->de.info->name, de_name, SCMI_SHORT_NAME_MAX_SIZE);
		/* Variably sized depending on name support */
		*next += SCMI_SHORT_NAME_MAX_SIZE;
	}

	*rx_len -= payld_sz;

	return 0;
}

static int iter_de_descr_process_response(const struct scmi_protocol_handle *ph,
					  const void *response,
					  struct scmi_iterator_state *st,
					  void *priv)
{
	struct scmi_tlm_de_priv *p = priv;
	struct telemetry_info *ti = p->ti;
	const struct scmi_de_desc *desc = p->next;
	struct telemetry_de *tde;
	bool discovered = false;
	unsigned int de_id;
	int ret;

	/* Is at least reading de_id safe */
	if (p->rx_len < sizeof(desc->de_id))
		return -ENOSPC;

	de_id = le32_to_cpu(desc->de_id);
	/*
	 * Check if this DE was already been discovered by other means,
	 * such as during boot if Telemetry was detected as already enabled
	 * and the list of enabled DEs was enumerated separately.
	 */
	tde = scmi_telemetry_tde_lookup(ti, de_id);
	if (!tde) {
		/* Create a new one */
		tde = scmi_telemetry_tde_get(ti, de_id);
		if (IS_ERR(tde))
			return PTR_ERR(tde);

		discovered = true;
	}

	guard(mutex)(&tde->mtx);
	if (tde->enumerated) {
		/* Cannot be a duplicate of a DE already created by enumeration */
		dev_err(ph->dev,
			"Discovered INVALID DE with DUPLICATED ID:0x%08X\n",
			de_id);
		return -EINVAL;
	}

	ret = scmi_telemetry_de_descriptor_parse(ti, tde, &p->next, &p->rx_len);
	if (ret) {
		dev_err(ph->dev, "Malformed DE Descriptor - ret:%d\n", ret);
		/* DE not enumerated at this point were created in this call */
		if (discovered)
			scmi_telemetry_free_tde_put(ti, tde);
		return ret;
	}

	/* Now fully enumerated */
	tde->enumerated = true;

	/* Register if it was not already ... */
	if (discovered) {
		ret = scmi_telemetry_tde_register(ti, tde);
		if (ret) {
			/* DE not enumerated at this point were created in this call */
			scmi_telemetry_free_tde_put(ti, tde);
			return ret;
		}
	}

	/* Count timestamped DEs */
	ti->num_des_tstamp += !!tde->de.tstamp_support;

	/* Add to FastChannels list */
	if (tde->de.fc_support) {
		scmi_telemetry_uuid_link(tde, ti->primary_uuid);
		list_add(&tde->item, &ti->fcs_des);
	}

	/* Account for this DE in group num_de counter */
	if (tde->de.grp)
		tde->de.grp->info->num_des++;

	return 0;
}

static int
scmi_telemetry_de_groups_init(struct telemetry_info *ti)
{
	struct scmi_telemetry_res_info *rinfo;
	unsigned int num_groups = 0;

	/* Get rinfo without triggering a recursive enumeration */
	rinfo = __scmi_telemetry_resources_get(ti);

	/* Bailout when no DEs were discovered */
	if (!rinfo->num_des)
		return 0;

	/* Allocate all groups DEs IDs arrays at first ... */
	for (int i = 0; i < ti->info.base.num_groups; i++, num_groups++) {
		struct scmi_telemetry_group *grp = &rinfo->grps[i];
		size_t des_str_sz;

		unsigned int *des __free(kfree) =
			kzalloc_objs(unsigned int, grp->info->num_des);
		if (!des)
			break;

		/*
		 * Max size 32bit ID string in Hex: 0xCAFECAFE
		 *  - 10 digits + ' '/'\n' = 11 bytes per  number
		 *  - terminating NUL character
		 */
		des_str_sz = grp->info->num_des * 11 + 1;
		char *des_str __free(kfree) = kzalloc_objs(*des_str, des_str_sz);
		if (!des_str)
			break;

		grp->des = no_free_ptr(des);
		grp->des_str = no_free_ptr(des_str);
	}

	/* Unroll on failure... */
	if (num_groups < ti->info.base.num_groups) {
		for (int i = num_groups - 1; i >= 0; i--) {
			kfree(rinfo->grps[i].des);
			rinfo->grps[i].des = NULL;
			kfree(rinfo->grps[i].des_str);
			rinfo->grps[i].des_str = NULL;
		}

		return -ENOMEM;
	}

	/* Reset group DE counters before populating */
	for (int i = 0; i < ti->info.base.num_groups; i++)
		rinfo->grps[i].info->num_des = 0;

	/* Scan DEs and populate DE IDs arrays for all groups */
	for (int i = 0; i < rinfo->num_des; i++) {
		struct scmi_telemetry_group *grp;

		grp = rinfo->des[i]->grp;
		if (!grp)
			continue;

		/*
		 * Note that, at this point, num_des is guaranteed to be
		 * sane (in-bounds) by construction.
		 */
		grp->des[grp->info->num_des++] = i;
	}

	/* Build composing DES string */
	for (int i = 0; i < ti->info.base.num_groups; i++) {
		struct scmi_telemetry_group *grp = &rinfo->grps[i];
		size_t bufsize = grp->info->num_des * 11 + 1;
		char *buf = grp->des_str;

		for (int j = 0; j < grp->info->num_des; j++) {
			char term = j != (grp->info->num_des - 1) ? ' ' : '\0';
			int len;

			len = scnprintf(buf, bufsize, "0x%08X%c",
					rinfo->des[grp->des[j]]->info->id, term);

			buf += len;
			bufsize -= len;
		}
	}

	/* Expose all groups once all fully initialized */
	rinfo->num_groups = num_groups;

	return 0;
}

static int scmi_telemetry_de_descriptors_get(struct telemetry_info *ti)
{
	const struct scmi_protocol_handle *ph = ti->ph;

	struct scmi_iterator_ops ops = {
		.prepare_message = iter_tlm_prepare_message,
		.update_state = iter_de_descr_update_state,
		.process_response = iter_de_descr_process_response,
	};
	struct scmi_tlm_de_priv tpriv = {
		.ti = ti,
		.next = NULL,
	};
	void *iter;
	int ret;

	if (!ti->info.base.num_des)
		return 0;

	iter = ph->hops->iter_response_init(ph, &ops, ti->info.base.num_des,
					    TELEMETRY_DE_DESCRIPTION,
					    sizeof(u32), &tpriv);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	ret = ph->hops->iter_response_run(iter);
	if (ret)
		return ret;

	return scmi_telemetry_de_groups_init(ti);
}

struct scmi_tlm_ivl_priv {
	struct scmi_telemetry_intervals **intrvs;
	unsigned int grp_id;
	unsigned int flags;
};

static void iter_intervals_prepare_message(void *message,
					   unsigned int desc_index,
					   const void *priv)
{
	struct scmi_msg_telemetry_update_intervals *msg = message;
	const struct scmi_tlm_ivl_priv *p = priv;

	msg->index = cpu_to_le32(desc_index);
	msg->group_identifier = cpu_to_le32(p->grp_id);
	msg->flags = cpu_to_le32(FIELD_PREP(GENMASK(3, 0), p->flags));
}

static int iter_intervals_update_state(struct scmi_iterator_state *st,
				       const void *response, void *priv)
{
	const struct scmi_msg_resp_telemetry_update_intervals *r = response;

	st->num_returned = le32_get_bits(r->flags, GENMASK(11, 0));
	st->num_remaining = le32_get_bits(r->flags, GENMASK(31, 16));

	if (st->rx_len < (sizeof(*r) + sizeof(r->intervals[0]) * st->num_returned))
		return -EINVAL;

	/*
	 * total intervals is not declared previously anywhere so we
	 * assume it's returned+remaining on first call.
	 */
	if (!st->max_resources) {
		struct scmi_tlm_ivl_priv *p = priv;
		struct scmi_telemetry_intervals *intrvs;
		bool discrete;
		int inum;

		discrete = INTERVALS_DISCRETE(r->flags);
		/* Check consistency on first call */
		if (!discrete && (st->num_returned != 3 || st->num_remaining != 0))
			return -EINVAL;

		inum = st->num_returned + st->num_remaining;
		intrvs = kzalloc_flex(*intrvs, update_intervals, inum);
		if (!intrvs)
			return -ENOMEM;

		intrvs->num_intervals = inum;
		intrvs->discrete = discrete;
		intrvs->grp_id = p->grp_id;
		st->max_resources = intrvs->num_intervals;

		*p->intrvs = intrvs;
	}

	return 0;
}

static int
iter_intervals_process_response(const struct scmi_protocol_handle *ph,
				const void *response,
				struct scmi_iterator_state *st, void *priv)
{
	const struct scmi_msg_resp_telemetry_update_intervals *r = response;
	struct scmi_tlm_ivl_priv *p = priv;
	struct scmi_telemetry_intervals *intrvs = *p->intrvs;
	unsigned int idx = st->loop_idx;

	intrvs->update_intervals[st->desc_index + idx] =
		le32_to_cpu(r->intervals[idx]);

	return 0;
}

static int
scmi_tlm_enumerate_update_intervals(struct telemetry_info *ti,
				    struct scmi_telemetry_intervals **intervals,
				    int grp_id, unsigned int flags)
{
	struct scmi_iterator_ops ops = {
		.prepare_message = iter_intervals_prepare_message,
		.update_state = iter_intervals_update_state,
		.process_response = iter_intervals_process_response,
	};
	const struct scmi_protocol_handle *ph = ti->ph;
	struct scmi_telemetry_intervals *intrvs = NULL;
	struct scmi_tlm_ivl_priv ipriv = {
		.grp_id = grp_id,
		.intrvs = &intrvs,
		.flags = flags,
	};
	void *iter;
	int ret;

	iter = ph->hops->iter_response_init(ph, &ops, 0,
		TELEMETRY_LIST_UPDATE_INTERVALS,
		sizeof(struct scmi_msg_telemetry_update_intervals),
		&ipriv);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	/* Cleanup iterator inner allocations on failure */
	ret = ph->hops->iter_response_run(iter);
	if (ret) {
		kfree(intrvs);
		return ret;
	}

	*intervals = intrvs;

	return 0;
}

static int
scmi_telemetry_enumerate_groups_intervals(struct telemetry_info *ti)
{
	struct scmi_telemetry_res_info *rinfo;

	if (!ti->info.per_group_config_support)
		return 0;

	/* Get rinfo without triggering a recursive enumeration */
	rinfo = __scmi_telemetry_resources_get(ti);

	for (int id = 0; id < rinfo->num_groups; id++) {
		int ret;

		ret = scmi_tlm_enumerate_update_intervals(ti,
							  &rinfo->grps[id].intervals,
							  id, SPECIFIC_GROUP_DES);
		if (ret)
			return ret;

		rinfo->grps_store[id].num_intervals =
			rinfo->grps[id].intervals->num_intervals;
	}

	return 0;
}

static void scmi_telemetry_intervals_free(void *interval)
{
	kfree(interval);
}

static int
scmi_telemetry_enumerate_common_intervals(struct telemetry_info *ti)
{
	unsigned int flags;
	int ret;

	flags = !ti->info.per_group_config_support ?
		ALL_DES_ANY_GROUP : ALL_DES_NO_GROUP;

	ret = scmi_tlm_enumerate_update_intervals(ti, &ti->info.intervals,
						  SCMI_TLM_GRP_INVALID, flags);
	if (ret)
		return ret;

	/* A copy for UAPI access... */
	ti->info.base.num_intervals = ti->info.intervals->num_intervals;

	/* Delegate freeing of allocated intervals to unbind time */
	return devm_add_action_or_reset(ti->ph->dev,
					scmi_telemetry_intervals_free,
					ti->info.intervals);
}

static int iter_shmti_update_state(struct scmi_iterator_state *st,
				   const void *response, void *priv)
{
	const struct scmi_msg_resp_telemetry_shmti_list *r = response;

	st->num_returned = le32_get_bits(r->num_shmti, GENMASK(15, 0));
	st->num_remaining = le32_get_bits(r->num_shmti, GENMASK(31, 16));

	if (st->rx_len < (sizeof(*r) + sizeof(r->desc[0]) * st->num_returned))
		return -EINVAL;

	return 0;
}

static inline int
scmi_telemetry_shmti_validate(struct device *dev, struct telemetry_shmti *shmti)
{
	struct tdcf __iomem *tdcf = shmti->base;
	u32 sign_start, sign_end;

	sign_start = TDCF_START_SIGNATURE(tdcf);
	sign_end = TDCF_END_SIGNATURE(SHMTI_EPLG(shmti));

	if (sign_start != SIGNATURE_START || sign_end != SIGNATURE_END) {
		dev_err(dev,
			"BAD signature for SHMTI ID:%u @phys:%pa - START:0x%08X END:0x%08X\n",
			shmti->info.sid, &shmti->info.phys, sign_start, sign_end);
		return -EINVAL;
	}

	return 0;
}

static int iter_shmti_process_response(const struct scmi_protocol_handle *ph,
				       const void *response,
				       struct scmi_iterator_state *st,
				       void *priv)
{
	const struct scmi_msg_resp_telemetry_shmti_list *r = response;
	struct telemetry_info *ti = priv;
	struct telemetry_shmti *shmti;
	const struct scmi_shmti_desc *desc;
	void __iomem *addr;
	phys_addr_t phys_addr;
	size_t len;
	int ret;

	desc = &r->desc[st->loop_idx];
	shmti = &ti->shmti[st->desc_index + st->loop_idx];

	shmti->info.sid = le32_to_cpu(desc->id);
	shmti->flags = le32_to_cpu(desc->flags);

	ret = scmi_telemetry_area_check(ph->dev, "SHMTI",
					le32_to_cpu(desc->addr_low),
					le32_to_cpu(desc->addr_high),
					le32_to_cpu(desc->length),
					&phys_addr, &len);
	if (ret) {
		dev_err(ph->dev, "Malformed SHMTI ID:%u. Abort.\n",
			shmti->info.sid);
		return ret;
	}

	if (len < SHMTI_MIN_SIZE || len > SHMTI_MAX_SIZE) {
		dev_err(ph->dev,
			FW_BUG "Invalid length for SHMTI ID:%u len:%zu. Abort.\n",
			shmti->info.sid, len);
		return -EINVAL;
	}

	/* SHMTI base phys_addr SHOULD be 64bit aligned by the SCMI spec */
	if (!IS_ALIGNED(phys_addr, 8))
		dev_warn(ph->dev,
			 "SHMTI ID:%u is NOT 64bit aligned (paddr:0x%llX)\n",
			 shmti->info.sid, phys_addr);

	addr = devm_ioremap(ph->dev, phys_addr, len);
	if (!addr)
		return -EADDRNOTAVAIL;

	shmti->base = addr;
	shmti->info.len = len;
	shmti->info.phys = phys_addr;
	shmti->info.offset = shmti->info.phys & ~PAGE_MASK;

	ret = scmi_telemetry_shmti_validate(ph->dev, shmti);
	if (ret)
		return ret;

	ti->num_shmti++;

	return 0;
}

static int scmi_telemetry_shmti_list(const struct scmi_protocol_handle *ph,
				     struct telemetry_info *ti)
{
	struct scmi_iterator_ops ops = {
		.prepare_message = iter_tlm_prepare_message,
		.update_state = iter_shmti_update_state,
		.process_response = iter_shmti_process_response,
	};
	int num_shmti;
	void *iter;
	int ret;

	/* Save and zero...calculate real number of returned */
	num_shmti = ti->num_shmti;
	ti->num_shmti = 0;
	iter = ph->hops->iter_response_init(ph, &ops, num_shmti,
					    TELEMETRY_LIST_SHMTI,
					    sizeof(u32), ti);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	ret = ph->hops->iter_response_run(iter);
	if (ret)
		return ret;

	if (num_shmti != ti->num_shmti)
		dev_warn(ph->dev,
			 FW_BUG "SHMTI enumeration returned %u items, expected %u\n",
			 ti->num_shmti, num_shmti);

	return 0;
}

static void scmi_telemetry_shmti_cleanup(void *arg)
{
	struct telemetry_shmti *shmti = arg;

	cleanup_srcu_struct(&shmti->srcu);

	kvfree(shmti->snaps[0]);
	kvfree(shmti->snaps[1]);

	/*
	 * Note that xa_lines will be destroyed later on instance cleanup
	 * since it has to be scanned to free any remaining unbound line.
	 */
}

static int scmi_telemetry_shmti_init(struct device *dev,
				     struct telemetry_shmti *shmti)
{
	int ret;

	struct shmti_snap *s0 __free(kvfree) =
		kvzalloc_flex(*s0, base, shmti->info.len);
	if (!s0)
		return -ENOMEM;

	struct shmti_snap *s1 __free(kvfree) =
		kvzalloc_flex(*s1, base, shmti->info.len);
	if (!s1)
		return -ENOMEM;

	ret = init_srcu_struct(&shmti->srcu);
	if (ret)
		return ret;

	for (int i = 0; i < 1 << PAYLD_HASH_BITS; i++)
		mutex_init(&shmti->payld_locks[i]);

	mutex_init(&shmti->lock);
	RCU_INIT_POINTER(shmti->cur, NULL);

	mutex_init(&shmti->lines_mtx);
	xa_init(&shmti->xa_lines);

	s0->shmti = shmti;
	shmti->snaps[0] = no_free_ptr(s0);

	s1->shmti = shmti;
	shmti->snaps[1] = no_free_ptr(s1);

	return devm_add_action_or_reset(dev, scmi_telemetry_shmti_cleanup, shmti);
}

static int scmi_telemetry_enumerate_shmti(struct telemetry_info *ti)
{
	const struct scmi_protocol_handle *ph = ti->ph;
	int ret;

	if (!ti->num_shmti)
		return 0;

	ret = scmi_telemetry_shmti_list(ph, ti);
	if (ret) {
		dev_err(ph->dev, "Cannot get SHMTI list descriptors");
		return ret;
	}

	for (int i = 0; i < ti->num_shmti; i++) {
		ret = scmi_telemetry_shmti_init(ph->dev, &ti->shmti[i]);
		if (ret)
			return ret;

		ti->info.shmtis[i] = &ti->shmti[i].info;
	}

	/* Expose the fully initialized SHMTI infos */
	smp_store_release(&ti->info.base.num_shmtis, ti->num_shmti);

	return 0;
}

static const struct scmi_telemetry_info *
scmi_telemetry_info_get(const struct scmi_protocol_handle *ph)
{
	struct telemetry_info *ti = ph->get_priv(ph);

	return &ti->info;
}

static const struct scmi_telemetry_res_info *
scmi_telemetry_resources_get(const struct scmi_protocol_handle *ph)
{
	struct scmi_telemetry_res_info *(*res_get)(struct telemetry_info *ti);
	struct telemetry_info *ti = ph->get_priv(ph);

	/* Ensure the latest installed res_get helper is visible */
	res_get = smp_load_acquire(&ti->res_get);

	return res_get(ti);
}

static const struct scmi_telemetry_de *
scmi_telemetry_de_lookup(const struct scmi_protocol_handle *ph, u32 id)
{
	struct telemetry_info *ti = ph->get_priv(ph);

	/* Trigger a full proper enumeration */
	scmi_telemetry_resources_get(ph);

	return xa_load(&ti->xa_des, id);
}

static inline struct payload __iomem *
scmi_telemetry_payld_offset_safe_calc(struct telemetry_shmti *shmti, u32 offs)
{
	struct payload __iomem *payld;
	unsigned long p;
	u32 end;

	/* Check if accessing payld->meta is safe. */
	if (check_add_overflow(offs, sizeof(u32), &end) ||
	    end > shmti->info.len)
		return IOMEM_ERR_PTR(-EPROTO);

	if (check_add_overflow((__force unsigned long)shmti->base, offs, &p))
		return IOMEM_ERR_PTR(-EPROTO);

	payld = shmti->base + offs;
	/* Check line boundary */
	if (check_add_overflow(offs, LINE_LENGTH_BYTES(payld), &end) ||
	    end > shmti->info.len)
		return IOMEM_ERR_PTR(-EPROTO);

	return payld;
}

static u64
scmi_telemetry_blkts_read(u32 magic, struct telemetry_de *tde,
			  struct payload *bts_payld, struct shmti_snap *snap)
{
	struct telemetry_block_ts *bts;

	/* Acquiring order is: tde -> line */
	lockdep_assert_held(&tde->mtx);
	if (WARN_ON(!tde->bts || (!bts_payld && !snap)))
		return 0;

	bts = tde->bts;
	guard(mutex)(&bts->line.mtx);

	if (bts->line.last_magic == magic)
		return bts->last_ts;

	/* Unless specified otherwise, use the snapshot BLK_TS paylod */
	if (!bts_payld) {
		void *base = snap_tdcf(snap);

		bts_payld = base + bts->line.offset;
	}

	/* Note that the bts->last_rate can change ONLY on creation */
	bts->last_ts = BLK_TS_STAMP_RAW(&bts_payld->blk_tsl);
	bts->line.last_magic = magic;

	return bts->last_ts;
}

static void
scmi_telemetry_blkts_update_snap(struct telemetry_info *ti,
				 struct telemetry_block_ts *bts,
				 struct payload *bts_payld, u32 magic)
{
	guard(mutex)(&bts->line.mtx);
	if (bts->line.last_magic != magic) {
		bts->last_ts = BLK_TS_STAMP_RAW(&bts_payld->blk_tsl);
		bts->last_rate = BLK_TS_RATE_RAW(bts_payld);
		/* BLK_TS clock rate value can change ONLY here on creation */
		if (!bts->last_rate)
			bts->last_rate = ti->default_blk_ts_rate;
		bts->line.last_magic = magic;

		trace_scmi_tlm_access(0, "BLK_TS_UPDATE", magic, 0);
	}
}

static inline void scmi_telemetry_line_free(struct telemetry_line *line)
{
	void *blob;

	switch (line->type) {
	case TDCF_BLK_TS_LINE:
		blob = to_blkts(line);
		kfree(blob);
		break;
	default:
		WARN_ON(1);
		break;
	}
}

static void __scmi_telemetry_line_put(struct telemetry_line *line)
{
	lockdep_assert_held(&line->shmti->lines_mtx);

	mutex_lock(&line->mtx);
	if (refcount_dec_and_test(&line->users)) {
		xa_erase(&line->shmti->xa_lines, line->offset);

		/* Unlock and free the containing structure: blkts or uuid */
		mutex_unlock(&line->mtx);

		trace_scmi_tlm_access(0, "DROP_LINE", line->type, line->last_magic);
		scmi_telemetry_line_free(line);

		return;
	}
	mutex_unlock(&line->mtx);
}

static void scmi_telemetry_line_put(struct telemetry_line *line)
{
	/* Acquiring coarse grain first ... */
	guard(mutex)(&line->shmti->lines_mtx);
	__scmi_telemetry_line_put(line);
}

static void scmi_telemetry_blkts_unlink(struct telemetry_de *tde)
{
	/* Acquiring order is: tde -> line */
	lockdep_assert_held(&tde->mtx);
	if (!tde->bts)
		return;

	scmi_telemetry_line_put(&tde->bts->line);
	tde->bts = NULL;

	trace_scmi_tlm_access(tde->de.info->id, "BLKTS_UNLINK", 0, 0);
}

static void scmi_telemetry_uuid_unlink(struct telemetry_de *tde)
{
	/* Acquiring order is: tde -> line */
	lockdep_assert_held(&tde->mtx);
	if (!tde->uuid)
		return;

	tde->uuid = NULL;
	trace_scmi_tlm_access(tde->de.info->id, "UUID_UNLINK", 0, 0);
}

static void scmi_telemetry_de_unlink(struct scmi_telemetry_de *de)
{
	struct telemetry_de *tde = to_tde(de);

	lockdep_assert_held(&tde->mtx);

	/* Unlink all related lines triggering their deallocation */
	scmi_telemetry_blkts_unlink(tde);
	scmi_telemetry_uuid_unlink(tde);
}

static struct telemetry_line *
scmi_telemetry_line_get(struct telemetry_shmti *shmti, unsigned long offset)
{
	struct telemetry_line *line;

	/* Acquiring coarse grain first ... */
	guard(mutex)(&shmti->lines_mtx);
	line = xa_load(&shmti->xa_lines, offset);
	if (!line)
		return NULL;

	guard(mutex)(&line->mtx);
	refcount_inc(&line->users);

	return line;
}

static int
scmi_telemetry_line_init(struct telemetry_shmti *shmti, struct telemetry_line *line,
			 unsigned long offset, enum tdcf_line_types type)
{
	line->type = type;
	refcount_set(&line->users, 1);
	line->offset = offset;
	line->shmti = shmti;
	mutex_init(&line->mtx);

	guard(mutex)(&shmti->lines_mtx);
	return xa_insert(&shmti->xa_lines, offset, line, GFP_KERNEL);
}

static struct telemetry_block_ts *
scmi_telemetry_blkts_create(struct telemetry_shmti *shmti, unsigned long offset)
{
	struct telemetry_block_ts *bts;
	int ret;

	bts = kzalloc_obj(*bts);
	if (!bts)
		return NULL;

	ret = scmi_telemetry_line_init(shmti, &bts->line, offset, TDCF_BLK_TS_LINE);
	if (ret) {
		kfree(bts);
		return NULL;
	}

	trace_scmi_tlm_collect(0, shmti->info.sid, offset, "SHMTI_NEW_BLKTS");

	return bts;
}

static struct telemetry_block_ts *
scmi_telemetry_blkts_get_or_create(struct telemetry_shmti *shmti,
				   unsigned long offset)
{
	struct telemetry_line *line;

	/* Avoid races on line creation for this payld */
	guard(mutex)(lock_for_payld(shmti->payld_locks, offset));

	line = scmi_telemetry_line_get(shmti, offset);
	if (line)
		return to_blkts(line);

	return scmi_telemetry_blkts_create(shmti, offset);
}

static int scmi_telemetry_uuids_update(struct telemetry_info *ti,
				       struct telemetry_uuid *uuid)
{
	uuid_t **cur_uuids;

	/* Resize array if needed ... */
	if (ti->info.num_uuids + SCMI_UUID_DB_THRESH >= ti->uuids_len) {
		uuid_t **new_uuids, **old_uuids;
		unsigned int new_len = ti->uuids_len * 2;

		new_uuids = kzalloc_objs(*new_uuids, new_len);
		if (!new_uuids)
			return -ENOMEM;

		old_uuids = rcu_dereference_protected(ti->info.uuids,
						      lockdep_is_held(&ti->uuids_mtx));
		/* Copy/move old allocated UUIDs */
		for (int i = 0; i < ti->info.num_uuids; i++)
			new_uuids[i] = old_uuids[i];

		/* Expose new UUID pointer */
		rcu_assign_pointer(ti->info.uuids, new_uuids);
		ti->uuids_len = new_len;

		kfree_rcu_mightsleep(old_uuids);
	}

	/* Store new UUID reference into the globally accessible UUIDS */
	cur_uuids = rcu_dereference_protected(ti->info.uuids,
					      lockdep_is_held(&ti->uuids_mtx));
	cur_uuids[ti->info.num_uuids] = &uuid->uuid;
	rcu_assign_pointer(ti->info.uuids, cur_uuids);
	/* Update UUIDs count */
	smp_store_release(&ti->info.num_uuids, ti->info.num_uuids + 1);

	return 0;
}

static int scmi_telemetry_uuid_register(struct telemetry_info *ti, u32 key,
					struct telemetry_uuid *uuid)
{
	int ret;

	lockdep_assert_held(&ti->uuids_mtx);

	ret = scmi_telemetry_uuids_update(ti, uuid);
	if (ret)
		return ret;

	/* Register by key for easy lookup */
	hash_add(ti->uuids_ht, &uuid->node_ht, key);

	trace_scmi_tlm_collect(0, key, 0, "SHMTI_NEW_UUID");

	return 0;
}

static struct telemetry_uuid *
scmi_telemetry_uuid_create(struct telemetry_info *ti, __be32 *dwords)
{
	u32 key;
	int ret;

	lockdep_assert_held(&ti->uuids_mtx);

	struct telemetry_uuid *uuid __free(kfree) = kzalloc_obj(*uuid);
	if (!uuid)
		return NULL;

	/*
	 * Fetch BigEndian in-memory UUID fields as per SCMIv4.0
	 * specification 3.12.2.2
	 */
	import_uuid(&uuid->uuid, (__force const __u8 *)dwords);
	key = jhash2((__force const u32 *)dwords, SCMI_TLM_DE_IMPL_NUM_DWORDS, 1);
	ret = scmi_telemetry_uuid_register(ti, key, uuid);
	if (ret)
		return NULL;

	return no_free_ptr(uuid);
}

static struct telemetry_uuid *
scmi_telemetry_uuid_lookup(struct telemetry_info *ti, __be32 *dwords)
{
	struct telemetry_uuid *uuid;
	u32 key;

	lockdep_assert_held(&ti->uuids_mtx);

	key = jhash2((__force const u32 *)dwords, SCMI_TLM_DE_IMPL_NUM_DWORDS, 1);
	hash_for_each_possible(ti->uuids_ht, uuid, node_ht, key)
		if (!memcmp(&uuid->uuid, dwords, sizeof(uuid->uuid)))
			return uuid;

	return NULL;
}

static struct telemetry_uuid *
scmi_telemetry_uuid_get_or_create(struct telemetry_info *ti, __be32 *dwords)
{
	struct telemetry_uuid *uuid;

	guard(mutex)(&ti->uuids_mtx);

	uuid = scmi_telemetry_uuid_lookup(ti, dwords);
	if (uuid)
		return uuid;

	return scmi_telemetry_uuid_create(ti, dwords);
}

/**
 * scmi_telemetry_tdcf_uuid_parse  - A UUID line parser
 *
 * @ti: A reference to the telemetry_info descriptor
 * @uuid_payld: UUID payld line to process
 * @snap: A reference to the working SHMTI snapshot that will be processed
 * @active_uuid: Input/output reference to keep track of the last uuid found
 *
 * Note that by the SCMI v4.0 Telemetry specification the associations between
 * DEs and UUIDs, both primary and secondary, are permanent across the same
 * session (boot): once discovered they cannot change.
 */
static void scmi_telemetry_tdcf_uuid_parse(struct telemetry_info *ti,
					   struct payload *uuid_payld,
					   struct shmti_snap *snap,
					   struct telemetry_uuid **active_uuid)
{
	__be32 *dwords = uuid_payld->uuid_l.dwords;
	u32 meta = PAYLD_META_RAW(uuid_payld);

	if (UUID_INVALID_RAW(meta)) {
		trace_scmi_tlm_access(0, "UUID_INVALID",
				      snap->magic, snap->magic);
		return;
	}

	*active_uuid = scmi_telemetry_uuid_get_or_create(ti, dwords);

	WARN_ON(!*active_uuid);
}

static struct payload __iomem *
scmi_telemetry_nearest_line_by_type(struct telemetry_shmti *shmti,
				    void __iomem *last, enum tdcf_line_types ltype)
{
	struct tdcf __iomem *tdcf = shmti->base;
	void __iomem *next, *found = NULL;

	/* Scan from start of the first TDCF payload up to last payld */
	next = tdcf->payld;
	while (next < last) {
		struct payload __iomem *payld;
		enum tdcf_line_types cur_type;
		u32 meta, offs;

		if (check_sub_overflow((__force unsigned long)next,
				       (__force unsigned long)tdcf, &offs)) {
			trace_scmi_tlm_access(ltype, "LINE_OFFSET_OUT_OF_RANGE", 0, 0);
			return NULL;
		}

		payld = scmi_telemetry_payld_offset_safe_calc(shmti, offs);
		if (IS_ERR(payld)) {
			trace_scmi_tlm_access(ltype, "LINE_PAYLD_MALFORMED", 0, 0);
			return NULL;
		}

		meta = PAYLD_META(payld);
		cur_type = LINE_TYPE_RAW(meta);

		/*
		 * Bail-out on malformed lines, since the whole TDCF scan
		 * could be affected.
		 */
		if ((cur_type == TDCF_BLK_TS_LINE && BLK_TS_INVALID_RAW(meta)) ||
		    (cur_type == TDCF_UUID_LINE && UUID_INVALID_RAW(meta))) {
			trace_scmi_tlm_access(ltype, "LINE_TYPE_MALFORMED", 0, 0);
			return NULL;
		}

		if (cur_type == ltype)
			found = next;

		next += LINE_LENGTH_BYTES_RAW(meta);
	}

	return found;
}

static struct telemetry_block_ts *
scmi_telemetry_blkts_bind(struct telemetry_info *ti,
			  struct telemetry_shmti *shmti,
			  struct payload *bts_payld,
			  unsigned long offset, u32 magic)
{
	struct telemetry_block_ts *bts;

	bts = scmi_telemetry_blkts_get_or_create(shmti, offset);
	/* Update the descriptor with the lastest TS */
	if (bts)
		scmi_telemetry_blkts_update_snap(ti, bts, bts_payld, magic);

	return bts;
}

/**
 * scmi_telemetry_tdcf_blkts_parse  - A BLK_TS line parser
 *
 * @ti: A reference to the telemetry_info descriptor
 * @bts_payld: TDCF payld line to process
 * @snap: A reference to the working SHMTI snapshot that will be processed
 * @active_bts: Input/output reference to keep track of the last blk_ts found
 *
 * Process a valid TDCF BLK_TS line and, after having looked up or created a
 * blk_ts descriptor, update the related data and return it as the currently
 * active blk_ts, given that it is effectively the last found during this
 * scan.
 */
static void scmi_telemetry_tdcf_blkts_parse(struct telemetry_info *ti,
					    struct payload *bts_payld,
					    struct shmti_snap *snap,
					    struct telemetry_block_ts **active_bts)
{
	struct telemetry_block_ts *bts, *previous = *active_bts;
	struct telemetry_shmti *shmti = snap->shmti;
	u32 meta = PAYLD_META_RAW(bts_payld);
	unsigned long offset;

	/* Check for spec compliance */
	if (BLK_TS_INVALID_RAW(meta)) {
		trace_scmi_tlm_access(0, "BLK_TS_INVALID", 0, meta);
		return;
	}

	offset = TDCF_OFFS(snap->base, bts_payld);
	/* A BLK_TS descriptor MUST be returned: it is found or it is created */
	bts = scmi_telemetry_blkts_get_or_create(shmti, offset);
	/*
	 * On error processing the new BLK_TS bailout taking care to clear
	 * the previous last active BLK_TS to avoid mistakenly binding to the
	 * next data lines.
	 */
	if (WARN_ON(!bts))
		goto out;

	/* Update the descriptor with the lastest TS */
	scmi_telemetry_blkts_update_snap(ti, bts, bts_payld, snap->magic);

out:
	/* Drop one refcount on the previous active since we found a new one */
	if (previous)
		scmi_telemetry_line_put(&previous->line);

	*active_bts = bts;
}

static inline struct telemetry_de *
scmi_telemetry_tde_allocate(struct telemetry_info *ti, u32 de_id,
			    struct payload *payld)
{
	u32 meta = PAYLD_META_RAW(payld);
	struct telemetry_de *tde;

	tde = scmi_telemetry_tde_get(ti, de_id);
	if (IS_ERR(tde))
		return NULL;

	guard(mutex)(&tde->mtx);
	tde->de.info->id = de_id;
	tde->de.enabled = true;
	tde->de.tstamp_enabled = LINE_TS_VALID_RAW(meta) || USE_BLK_TS_RAW(meta);
	/* An approximation till the real DE discovery is performed */
	tde->de.tstamp_support = tde->de.tstamp_enabled;

	if (scmi_telemetry_tde_register(ti, tde)) {
		scmi_telemetry_free_tde_put(ti, tde);
		return NULL;
	}

	scmi_telemetry_de_state_update(ti, ENA_STATE, NULL, true);
	if (tde->de.tstamp_enabled)
		scmi_telemetry_de_state_update(ti, ENA_TSTAMP, NULL, true);

	/* Count timestamped DEs */
	ti->num_des_tstamp += !!tde->de.tstamp_support;

	return tde;
}

static inline int
scmi_telemetry_line_data_parse(struct telemetry_de *tde, struct shmti_snap *snap,
			       struct scmi_telemetry_de_sample *sample,
			       struct payload *payld, struct payload *bts_payld,
			       u32 magic)
{
	u32 meta = PAYLD_META_RAW(payld);

	lockdep_assert_held(&tde->mtx);

	/* Clear returned values in case of errors */
	sample->tstamp = 0;
	sample->val = 0;

	if (USE_BLK_TS_RAW(meta)) {
		/* Read out the actual BLK_TS */
		sample->tstamp = scmi_telemetry_blkts_read(magic, tde,
							   bts_payld, snap);
	} else if (LINE_TS_VALID_RAW(meta)) {
		/*
		 * Note that LINE_TS_VALID implies HAS_LINE_EXT and that
		 * the per DE line_ts_rate is advertised in the DE
		 * descriptor, BUT we check anyway against buggy FW.
		 */
		if (!HAS_LINE_EXT_RAW(meta)) {
			trace_scmi_tlm_access(tde->de.info->id,
					      "SHMTI_BAD_TS_LINE", 0, 0);
			return -EPROTO;
		}

		sample->tstamp = LINE_TSTAMP_GET_RAW(&payld->tsl);
	}

	/* Data is always valid since we are NOT handling BLK TS lines here */
	sample->val = LINE_DATA_GET_RAW(&payld->l);

	/* Trace originally read tstamp */
	trace_scmi_tlm_collect(sample->tstamp, tde->de.info->id,
			       sample->val, "SHMTI_DE_READ");

	scmi_telemetry_tde_cache_update(tde, sample, &magic);

	return 0;
}

static inline void scmi_telemetry_blkts_link(struct telemetry_de *tde,
					     struct telemetry_block_ts *bts)
{
	/* Acquiring order is: tde -> line */
	lockdep_assert_held(&tde->mtx);

	/* Unlink old stale BTS if existent */
	scmi_telemetry_blkts_unlink(tde);

	guard(mutex)(&bts->line.mtx);
	refcount_inc(&bts->line.users);

	/* Update TS clock rate if provided by the BLK_TS */
	if (bts->last_rate)
		tde->de.info->ts_rate = bts->last_rate;

	tde->bts = bts;
	trace_scmi_tlm_access(tde->de.info->id, "BLKTS_LINK", 0, 0);
}

static inline void scmi_telemetry_uuid_link(struct telemetry_de *tde,
					    struct telemetry_uuid *uuid)
{
	lockdep_assert_held(&tde->mtx);
	if (tde->uuid)
		return;

	/* Update UUID association */
	tde->uuid = uuid;
	trace_scmi_tlm_access(tde->de.info->id, "UUID_LINK", 0, 0);
}

static struct telemetry_uuid *
scmi_telemetry_uuid_bind(struct telemetry_info *ti,
			 struct telemetry_shmti *shmti,
			 struct payload __iomem *payld)
{
	__be32 dwords[SCMI_TLM_DE_IMPL_NUM_DWORDS];
	struct payload __iomem *uuid_payld;
	struct uuid_line __iomem *uuid_l;

	uuid_payld = scmi_telemetry_nearest_line_by_type(shmti, payld,
							 TDCF_UUID_LINE);
	if (!uuid_payld)
		return NULL;

	/*
	 * Use proper mem accessors BUT no swapping, maintain UUID
	 * in memory BE layout.
	 */
	uuid_l = &uuid_payld->uuid_l;
	for (int i = 0; i < SCMI_TLM_DE_IMPL_NUM_DWORDS; i++)
		dwords[i] = (__force __be32)__raw_readl(&uuid_l->dwords[i]);

	/* Here the nearest UUID line just found has been already validated */
	return scmi_telemetry_uuid_get_or_create(ti, dwords);
}

/**
 * scmi_telemetry_tdcf_data_parse  - TDCF DataLine parsing
 * @ti: A reference to the telemetry info descriptor
 * @payld: Line payload to parse
 * @snap: A reference to the working SHMTI snapshot that will be processed
 * @mode: A flag to determine the behaviour of the scan
 * @active_bts: A pointer to keep track and report any found BLK timestamp line
 * @active_uuid: A pointer to keep track and report any found UUID line
 *
 * This routine takes care to:
 *  - verify line consistency in relation to the used flags and the current
 *    context: e.g. is there an active preceding BLK_TS line if the DataLine
 *    sports a USE_BLKTS flag ?
 *  - verify the related Data Event ID exists OR create a brand new DE
 *    (depending on the @mode of operation)
 *  - links any active BLK_TS or UUID line to the current DE
 *  - read and save value/tstamp for the DE ONLY if anything has changed (by
 *    tracking the last TDCF magic) and update related magic: this allows to
 *    minimize future needs of single-DE reads
 *
 *    Modes of operation.
 *
 *    The scan behaviour depends on the chosen @mode:
 *    - SCAN_LOOKUP: the basic scan which aims to update value associated to
 *		     existing DEs. Any discovered DataLine that could NOT be
 *		     matched to an existing, previously discovered, DE is
 *		     discarded. This is the normal scan behaviour.
 *    - SCAN_UPDATE: a more advanced scan which provides all the SCAN_LOOKUP
 *		     features plus takes care to update the DEs location
 *		     coordinates inside the SHMTI: note that the related DEs are
 *		     still supposed to have been previously discovered when
 *		     this scan runs. This is used to update location
 *		     coordinates for DEs contained in a Group when such group
 *		     is enabled.
 *    - SCAN_DISCOVERY: the most advanced scan available which provides all
 *			the SCAN_LOOKUP features plus discovery capabilities:
 *			any DataLine referring to a previously unknown DE leads
 *			to the allocation of a new DE descriptor.
 *			This mode is used on the first scan at init time, ONLY
 *			if Telemetry was found to be already enabled at boot on
 *			the platform side: this helps to maximize gathered
 *			information when dealing with out of spec firmwares.
 *			Any usage of this discovery mode other than in a boot-on
 *			enabled scenario is discouraged since it can easily
 *			lead to spurious DE discoveries.
 */
static void scmi_telemetry_tdcf_data_parse(struct telemetry_info *ti,
					   struct payload *payld,
					   struct shmti_snap *snap,
					   enum scan_mode mode,
					   struct telemetry_block_ts *active_bts,
					   struct telemetry_uuid *active_uuid)
{
	struct telemetry_shmti *shmti = snap->shmti;
	struct scmi_telemetry_de_sample sample = {};
	u32 meta = PAYLD_META_RAW(payld);
	bool use_blk_ts = USE_BLK_TS_RAW(meta);
	struct telemetry_de *tde;
	u32 de_id;

	de_id = PAYLD_ID_RAW(payld);
	/* Discard malformed lines...a preceding BLK_TS must exist */
	if (use_blk_ts && !active_bts) {
		trace_scmi_tlm_access(de_id, "BAD_USE_BLK_TS", 0, 0);
		return;
	}

	/* Is this DE ID known ? */
	tde = scmi_telemetry_tde_lookup(ti, de_id);
	if (!tde) {
		if (mode != SCAN_DISCOVERY) {
			trace_scmi_tlm_access(de_id, "DE_INVALID", 0, 0);
			return;
		}

		/* In SCAN_DISCOVERY mode we allocate new DEs for unknown IDs */
		tde = scmi_telemetry_tde_allocate(ti, de_id, payld);
		if (!tde) {
			dev_err(ti->ph->dev,
				"Cannot allocate TDE for ID:0x%08X\n", de_id);
			return;
		}
	}

	guard(mutex)(&tde->mtx);
	/*
	 * Update DE location refs if requested: normally done only on group
	 * enable.
	 * Note that all the DE location information is relative to the
	 * original SHMTI device-memory area, NOT to the snapshot we are parsing.
	 */
	if (mode >= SCAN_UPDATE) {
		u32 de_offs;
		void __iomem *p;

		/* Offest is the same in the SHMTI and in the snapshot indeed */
		de_offs = (void __iomem *)payld - (void __iomem *)snap->base;
		/* Validate location before update */
		p = scmi_telemetry_payld_offset_safe_calc(shmti, de_offs);
		if (IS_ERR(p)) {
			dev_err(ti->ph->dev,
				"TDE 0x%08X updated location invalid - shmti:%u offs:%u\n",
				de_id, shmti->info.sid, de_offs);
			trace_scmi_tlm_access(de_id, "DE_LOCATION_INVALID", 0, 0);
			return;
		}

		tde->sid = shmti->info.sid;
		tde->base = shmti->base;
		tde->eplg = SHMTI_EPLG(shmti);
		tde->offset = de_offs;

		trace_scmi_tlm_access(de_id, "DE_LOCATION_UPDATED", 0, 0);

		dev_dbg(ti->ph->dev,
			"TDCF-updated DE_ID:0x%08X - shmti:%pK  offset:%u\n",
			tde->de.info->id, tde->base, tde->offset);
	}

	/*
	 * Has any value/tstamp really changed ?
	 * Note that, if the magic currently associated with this TDE has
	 * NOT changed compared to the current SHMTI magic, nothing could have
	 * been changed across the whole TDCF, including any relation to
	 * BLK_TS or UUID lines.
	 */
	if (!scmi_telemetry_tde_cache_stale(tde, snap->magic))
		return;

	/*
	 * Link the related BTS when needed, it's unlinked on disable.
	 * Note that each DEs timestamp types is statically defined and
	 * enumerated once for all at init: a Data line cannot suddenly
	 * 'migrate' to a different timestamp type.
	 */
	if (use_blk_ts && BLK_TS_CHANGED(tde, shmti, active_bts->line.offset))
		scmi_telemetry_blkts_link(tde, active_bts);

	/* Link the active UUID or the primary, it's unlinked on disable */
	scmi_telemetry_uuid_link(tde, active_uuid ?: ti->primary_uuid);

	/*
	 * Parse data words ... only for the sake of updating TDE cache,
	 * any error is logged by ignored.
	 */
	scmi_telemetry_line_data_parse(tde, snap, &sample, payld, NULL, snap->magic);
}

/**
 * scmi_telemetry_tdcf_line_parse  - Line parser
 * @ti: A reference to the Telemetry instance
 * @payld: A reference to the payload representing the line to parse
 * @snap: A reference to the working SHMTI snapshot that will be processed
 * @mode: Specification of the scanning mode
 * @active_bts: A reference used to track the last BLK_TS line found
 * @active_uuid: A reference used to track the last UUID line found
 *
 * Note that @active_bts and @active_uuid references are propagated back and
 * forth from the line parsers to keep track of the nearest active BLK_TS or
 * UUID line found in the SHMTI areas and, while doing that, such descriptors
 * are refcounted and tracked in the xa_lines XArray indexed by @payld.
 * BLK_TS and UUID descriptors are dropped when no more linked to any DATA line,
 * during the normal system operation OR later on when the protocol is
 * de-initialized following a driver removal.
 *
 * Return: Number of QWORDS consumed from @payld by this line parsing; note
 *	   that buggy firmware could return bad, out of range values, so this
 *	   value MUST be carefully checked for SHMTI boundary overflows by the
 *	   caller.
 */
static int scmi_telemetry_tdcf_line_parse(struct telemetry_info *ti,
					  struct payload *payld,
					  struct shmti_snap *snap,
					  enum scan_mode mode,
					  struct telemetry_block_ts **active_bts,
					  struct telemetry_uuid **active_uuid)
{
	u32 meta = le32_to_cpu(payld->meta);
	int used_qwords;

	used_qwords = LINE_LENGTH_QWORDS_RAW(meta);
	/* Invalid lines are not an error, could simply be disabled DEs */
	if (DATA_INVALID_RAW(meta)) {
		trace_scmi_tlm_access(le32_to_cpu(payld->id), "TDCF_INVALID", 0, 0);
		return used_qwords;
	}

	/*
	 * Problematic lines are ignored, their information discarded, and such
	 * issues are logged, but the scan process continues.
	 */
	switch (LINE_TYPE_RAW(meta)) {
	case TDCF_DATA_LINE:
		scmi_telemetry_tdcf_data_parse(ti, payld, snap, mode,
					       *active_bts, *active_uuid);
		break;
	case TDCF_BLK_TS_LINE:
		scmi_telemetry_tdcf_blkts_parse(ti, payld, snap, active_bts);
		break;
	case TDCF_UUID_LINE:
		scmi_telemetry_tdcf_uuid_parse(ti, payld, snap, active_uuid);
		break;
	default:
		trace_scmi_tlm_access(PAYLD_ID_RAW(payld), "TDCF_LINE_UNKNOWN", 0, 0);
		break;
	}

	return used_qwords;
}

static inline bool
scmi_telemetry_shmti_overflow(struct telemetry_shmti *shmti, void __iomem *next)
{
	void __iomem *limit = SHMTI_EPLG(shmti);

	/* Is payld->meta accessible ? */
	if (next >= limit - sizeof(u32))
		return true;

	next += LINE_LENGTH_BYTES((struct payload __iomem *)next);

	return next > limit;
}

static inline struct tdcf *snap_tdcf(struct shmti_snap *s)
{
	return (struct tdcf *)s->base;
}

static inline bool
scmi_telemetry_snap_overflow(struct shmti_snap *snap, const void *next)
{
	void *limit = SNAP_EPLG(snap);

	/* Is payld->meta accessible ? */
	if (next >= limit - sizeof(u32))
		return true;

	next += LINE_LENGTH_BYTES_RAW(PAYLD_META_RAW((struct payload *)next));

	return next > limit;
}

static int scmi_telemetry_shmti_snapshot(struct telemetry_shmti *shmti,
					 struct shmti_snap *work)
{
	struct tdcf __iomem *tdcf = shmti->base;
	int retries = SCMI_TLM_TDCF_MAX_RETRIES;
	struct tdcf *snap = snap_tdcf(work);
	u32 startm = 0, endm = 0, live;

	lockdep_assert_held(&shmti->lock);

	do {
		/* A bit of exponential backoff between retries */
		fsleep((SCMI_TLM_TDCF_MAX_RETRIES - retries) * SCMI_TLM_TDCF_RETRY_GAP_US);

		memcpy_fromio(snap, tdcf, shmti->info.len);
		/* Assure the TDCF snapshot has been fully taken before checking seqnum */
		rmb();
		/* Used to detect changes while copying */
		live = TDCF_START_SEQ_GET(tdcf);

		startm = TDCF_START_SEQ_GET_RAW(snap);
		if (IS_BAD_START_SEQ(startm)) {
			trace_scmi_tlm_access(0, "MSEQ_BADSTART", startm, 0);
			continue;
		}

		endm = TDCF_END_SEQ_GET_RAW(SNAP_EPLG(work));
		if (startm != endm || startm != live) {
			trace_scmi_tlm_access(0, "MSEQ_MISMATCH", startm,
					      startm != endm ? endm : live);
			continue;
		}

		trace_scmi_tlm_access(0, "TDCF_SNAPSHOT_OK", startm, endm);

		/* Ensure any snapshot is visible before updating magic */
		smp_store_release(&work->magic, startm);

		return 0;
	} while (--retries);

	trace_scmi_tlm_access(0, "TDCF_SNAPSHOT_FAIL", startm, endm);

	return -EPROTO;
}

/*
 * True if neither TDCF marker has moved since the cached snapshot was taken.
 * Any platform update must write one marker before touching data (start first
 * or end first, depending on the spec's order), so checking both is
 * independent of that order.
 */
static bool scmi_telemetry_shmti_unchanged(struct telemetry_shmti *shmti, u32 magic)
{
	struct tdcf __iomem *tdcf = shmti->base;

	return TDCF_START_SEQ_GET(tdcf) == magic &&
	       TDCF_END_SEQ_GET(SHMTI_EPLG(shmti)) == magic;
}

/* Returns with the SRCU read lock held (index in *idx) on a snapshot that matched at check time */
static struct shmti_snap *
scmi_telemetry_shmti_refresh(struct telemetry_shmti *shmti, int *idx)
{
	struct shmti_snap *cur, *work;
	int ret;

	guard(mutex)(&shmti->lock);

	cur = rcu_dereference_protected(shmti->cur, lockdep_is_held(&shmti->lock));
	/* Someone else may have refreshed while we waited for the mutex */
	if (cur && scmi_telemetry_shmti_unchanged(shmti, cur->magic)) {
		/* Safe: recycling cur requires shmti->lock, which we hold */
		*idx = srcu_read_lock(&shmti->srcu);
		return cur;
	}

	/* Pick the spare buffer */
	work = (cur == shmti->snaps[0]) ? shmti->snaps[1] : shmti->snaps[0];
	/*
	 * Wait for readers that may still be parsing 'work' from its time
	 * as current
	 */
	synchronize_srcu(&shmti->srcu);

	ret = scmi_telemetry_shmti_snapshot(shmti, work);
	if (ret)
		return ERR_PTR(ret);

	/*
	 * Take our read lock BEFORE publishing so 'work' cannot be
	 * recycled under us
	 */
	*idx = srcu_read_lock(&shmti->srcu);
	rcu_assign_pointer(shmti->cur, work);

	return work;
}

static inline void
scmi_telemetry_reset_active_lines(struct telemetry_block_ts **active_bts)
{
	if (*active_bts) {
		scmi_telemetry_line_put(&(*active_bts)->line);
		*active_bts = NULL;
	}
}

/**
 * scmi_telemetry_shmti_scan  - Full SHMTI scan
 * @ti: A reference to the telemetry info descriptor
 * @shmti_id: ID of the SHMTI area that has to be scanned
 * @mode: A flag to determine the behaviour of the scan
 *
 * Return: 0 on Success
 */
static int scmi_telemetry_shmti_scan(struct telemetry_info *ti,
				     unsigned int shmti_id, enum scan_mode mode)
{
	struct telemetry_shmti *shmti = &ti->shmti[shmti_id];
	struct telemetry_block_ts *active_bts = NULL;
	struct telemetry_uuid *active_uuid = NULL;
	unsigned int qwords;
	struct shmti_snap *snap;
	struct tdcf *tdcf;
	int idx, ret = 0;
	void *next;

	if (!shmti->base)
		return -ENODEV;

	idx = srcu_read_lock(&shmti->srcu);
	snap = srcu_dereference(shmti->cur, &shmti->srcu);
	if (!snap || !scmi_telemetry_shmti_unchanged(shmti, snap->magic)) {
		/* MUST drop the read lock: refresh calls synchronize_srcu() */
		srcu_read_unlock(&shmti->srcu, idx);
		snap = scmi_telemetry_shmti_refresh(shmti, &idx);
		if (IS_ERR(snap))
			return PTR_ERR(snap);
	}

	tdcf = snap_tdcf(snap);
	next = tdcf->payld;
	qwords = QWORDS_RAW(tdcf);
	while (qwords) {
		int used_qwords;

		/*
		 * Bailout on any error since we are processing a supposedly
		 * stable snapshot at this point, so any further error is on
		 * firmware-side and NOT recoverable: this would mean having to
		 * drop the remaining part of the scan results after having
		 * cached the initial good snapshot: log this down below.
		 */
		if (scmi_telemetry_snap_overflow(snap, next)) {
			trace_scmi_tlm_access(0, "SHMTI_OVERFLOW", snap->magic, 0);
			ret = -EPROTO;
			break;
		}

		used_qwords = scmi_telemetry_tdcf_line_parse(ti, next, snap, mode,
							     &active_bts, &active_uuid);
		if (used_qwords <= 0 || qwords < used_qwords) {
			/*
			 * Stop scanning when qwords inconsistent; if the last
			 * line processed was sane in itself, though, keep it
			 * since we anyway previously checked for overflow.
			 */
			trace_scmi_tlm_access(PAYLD_ID_RAW(next), "BAD_QWORDS",
					      snap->magic, 0);
			ret = -EPROTO;
			break;
		}

		next += used_qwords * 8;
		qwords -= used_qwords;
	}

	scmi_telemetry_reset_active_lines(&active_bts);
	srcu_read_unlock(&shmti->srcu, idx);

	if (ret)
		dev_err(ti->ph->dev, FW_BUG "Inconsistent TDCF. Scan aborted.\n");

	return ret;
}

static void scmi_telemetry_group_state_update(struct telemetry_info *ti,
					      struct scmi_telemetry_group *grp,
					      const bool *enable, const bool *tstamp)
{
	struct scmi_telemetry_res_info *rinfo;

	rinfo = ti->res_get(ti);
	for (int i = 0; i < grp->info->num_des; i++) {
		struct scmi_telemetry_de *de = rinfo->des[grp->des[i]];

		guard(mutex)(&(to_tde(de)->mtx));
		if (enable)
			scmi_telemetry_de_state_update(ti, ENA_STATE,
						       &de->enabled, *enable);

		if (tstamp && de->tstamp_support)
			scmi_telemetry_de_state_update(ti, ENA_TSTAMP,
						       &de->tstamp_enabled, *tstamp);
	}
}

static void scmi_telemetry_group_disable(struct telemetry_info *ti,
					 struct scmi_telemetry_group *grp)
{
	struct scmi_telemetry_res_info *rinfo;

	rinfo = ti->res_get(ti);
	/*
	 * Unlink the related BLK_TS/UUID lines of DEs composing the group
	 * and invalidate SHMTI reference.
	 */
	for (int i = 0; i < grp->info->num_des; i++) {
		struct telemetry_de *tde = to_tde(rinfo->des[grp->des[i]]);

		guard(mutex)(&tde->mtx);

		scmi_telemetry_blkts_unlink(tde);

		tde->sid = SHMTI_ID_INVALID;
		tde->offset = 0;
	}
}

static struct payload __iomem *
scmi_telemetry_blkts_payld_locate(struct device *dev,
				  struct telemetry_shmti *shmti, u32 *bts_offs,
				  struct payload __iomem *payld, u32 de_id)
{
	struct payload __iomem *bts_payld = NULL;

	if (!bts_offs)
		return IOMEM_ERR_PTR(-EINVAL);

	if (*bts_offs &&
	    check_add_overflow((__force unsigned long)shmti->base, *bts_offs,
			       (__force unsigned long *)&bts_payld))
		return IOMEM_ERR_PTR(-EPROTO);

	/* Check SHMTI overflow on returned offset */
	if (bts_payld) {
		if (scmi_telemetry_shmti_overflow(shmti, bts_payld)) {
			trace_scmi_tlm_access(de_id, "SHMTI_OVERFLOW", 0, 0);
			return IOMEM_ERR_PTR(-EINVAL);
		}
	} else {
		dev_warn_once(dev, "Received BLK_TS with zero offset.\n");
		trace_scmi_tlm_access(de_id, "BLKTS_WITH_ZERO_OFFSET", 0, 0);

		/*
		 * Find the BLK_TS immediately preceding this DE payld by
		 * scanning.
		 */
		bts_payld = scmi_telemetry_nearest_line_by_type(shmti, payld,
								TDCF_BLK_TS_LINE);
		if (WARN_ON(!bts_payld))
			return IOMEM_ERR_PTR(-EPROTO);

		/* Calculate offset of found blkts */
		*bts_offs = (void __iomem *)bts_payld - shmti->base;
	}

	return bts_payld;
}

static int
scmi_telemetry_tdcf_bts_payld_check(struct payload *bts_snap, u32 de_id)
{
	u32 meta = PAYLD_META_RAW(bts_snap);

	if (!IS_BLK_TS_LINE_RAW(meta)) {
		trace_scmi_tlm_access(de_id, "BAD_BLK_TS_LINE_OFFSET", 0, meta);
		return -EPROTO;
	}

	/* Check for spec compliance */
	if (BLK_TS_INVALID_RAW(meta)) {
		trace_scmi_tlm_access(de_id, "BLK_TS_INVALID", 0, meta);
		return -EINVAL;
	}

	return 0;
}

static int scmi_telemetry_blkts_snapshot(struct telemetry_shmti *shmti,
					 struct payload __iomem *bts_payld,
					 struct payload *bts_snap, u32 *magic,
					 u32 de_id)
{
	int retries = SCMI_TLM_TDCF_MAX_RETRIES;
	struct tdcf __iomem *tdcf = shmti->base;
	u32 startm, endm;
	int err = 0;

	do {
		/* A bit of exponential backoff between retries */
		fsleep((SCMI_TLM_TDCF_MAX_RETRIES - retries) * SCMI_TLM_TDCF_RETRY_GAP_US);

		startm = TDCF_START_SEQ_GET(tdcf);
		/* Build a default endm certainly different from startm */
		endm = startm + 1;
		if (IS_BAD_START_SEQ(startm)) {
			trace_scmi_tlm_access(de_id, "MSEQ_BADSTART", startm, 0);
			continue;
		}

		memcpy_fromio(bts_snap, bts_payld, LINE_LENGTH_BYTES(bts_payld));
		/*
		 * In this context any anomaly detected on the payload could
		 * due to a torn read, and it is worth retrying a snapshot.
		 */
		err = scmi_telemetry_tdcf_bts_payld_check(bts_snap, de_id);
		if (err)
			continue;

		/* Assure the snapshot has been fully taken before checking seqnum */
		rmb();

		endm = TDCF_END_SEQ_GET(SHMTI_EPLG(shmti));
		if (startm != endm)
			trace_scmi_tlm_access(de_id, "MSEQ_MISMATCH", startm, endm);
	} while ((startm != endm || err) && --retries);

	if (startm != endm || err) {
		trace_scmi_tlm_access(de_id, "TDCF_SNAPSHOT_BLKTS_FAIL", startm, endm);
		return err ?: -EPROTO;
	}

	/* Ensure any snapshot is visible before updating magic */
	smp_store_release(magic, startm);

	trace_scmi_tlm_access(de_id, "TDCF_SNAPSHOT_BLKTS_OK", startm, endm);

	return 0;
}

static int
scmi_telemetry_tde_linked_lines_process(struct telemetry_info *ti,
					struct telemetry_de *tde,
					struct telemetry_shmti *shmti,
					struct payload __iomem *payld,
					u32 bts_offs)
{
	struct payload __iomem *bts_payld;
	struct telemetry_block_ts *bts;
	struct payload bts_snap = {};
	struct telemetry_uuid *uuid;
	u32 magic = 0;
	int ret;

	lockdep_assert_held(&ti->config_mtx);
	lockdep_assert_held(&tde->mtx);

	/*
	 * On enable, if a UUID was NOT already assigned, scan looking for
	 * possible Secondary UUID to bind: if NO secondary could be found
	 * embedded in the preceding SHMTI lines, install the primary UUID
	 * for this DE.
	 * NOTE that UUID lines content is immutable once created and no
	 * concurrent configuration request is possible at this point since
	 * config_mtx is held, so while the platform can still concurrently
	 * update all the existing SHMTI lines variable values, existing lines
	 * CANNOT be shuffled around: as a consequence a full snapshot is NOT
	 * needed as a pre-requisite to perform a scan when looking for
	 * UUID lines.
	 */
	if (!tde->uuid) {
		uuid = scmi_telemetry_uuid_bind(ti, shmti, payld);
		if (uuid)
			tde->uuid = uuid;
		else
			scmi_telemetry_uuid_link(tde, ti->primary_uuid);
	}

	/* Process related BLK_TS lines if any */
	if (!USE_BLK_TS(payld)) {
		/* Unlink old stale BTS if existent */
		if (IS_TDE_TS_BLK(tde) && tde->bts)
			scmi_telemetry_blkts_unlink(tde);
		return 0;
	}

	if (!IS_TDE_TS_BLK(tde)) {
		trace_scmi_tlm_access(tde->de.info->id, "BAD_DE_TSTAMP_TYPE", 0, 0);
		return -EPROTO;
	}

	/* Has associated BLK_TS line changed at all ? */
	if (!BLK_TS_CHANGED(tde, shmti, bts_offs))
		return 0;

	bts_payld = scmi_telemetry_blkts_payld_locate(ti->ph->dev, shmti,
						      &bts_offs, payld,
						      tde->de.info->id);
	if (IS_ERR(bts_payld))
		return PTR_ERR(bts_payld);

	ret = scmi_telemetry_blkts_snapshot(shmti, bts_payld,
					    &bts_snap, &magic, tde->de.info->id);
	if (ret)
		return ret;

	/* Look for a viable BLK_TS line */
	bts = scmi_telemetry_blkts_bind(ti, shmti, &bts_snap, bts_offs, magic);
	if (WARN_ON(!bts)) {
		trace_scmi_tlm_access(tde->de.info->id, "INVALID_USE_BLK_TS", 0, 0);
		return -EPROTO;
	}

	/* Unlink old stale BTS if existent */
	scmi_telemetry_blkts_unlink(tde);

	/* Store freshly discovered sane BLK_TS */
	tde->bts = bts;

	/* Update per-DE BLK_TS if any */
	if (tde->bts->last_rate)
		tde->de.info->ts_rate = tde->bts->last_rate;

	return 0;
}

static int
scmi_telemetry_state_set_tde_resp(struct telemetry_info *ti,
				  struct scmi_telemetry_de *de,
				  u32 sid, u32 de_offs, u32 bts_offs)
{
	struct telemetry_de *tde = to_tde(de);
	struct telemetry_shmti *shmti;
	struct payload __iomem *payld;
	int ret;

	lockdep_assert_held(&tde->mtx);

	/* A FastChannel DE MUST return an INVALID SHMTI ID on enable */
	if (WARN_ON(de->fc_support)) {
		trace_scmi_tlm_access(de->info->id, "INVALID_DE_FC_ON_SHMTI", 0, 0);
		return -EPROTO;
	}

	/* Update SHMTI/offset while skipping non-SHMTI based DES */
	shmti = &ti->shmti[sid];
	/* Check sanity of received location... */
	payld = scmi_telemetry_payld_offset_safe_calc(shmti, de_offs);
	if (IS_ERR(payld))
		return PTR_ERR(payld);

	/*
	 * Note that here we are processing a configuration request on a DE
	 * while holding @config_mtx: in this scenario platform cannot relocate
	 * or mutate this line freely, so we can directly access the TDCF and
	 * lookup the line sitting at @de_offs to check its line type without
	 * having to worry about consistency or taking snapshots.
	 */
	if (!IS_DATA_LINE(payld))
		return -EPROTO;

	ret = scmi_telemetry_tde_linked_lines_process(ti, tde, shmti, payld,
						      bts_offs);
	if (ret)
		return ret;

	/* ...then assign once validated */
	tde->sid = sid;
	tde->base = shmti->base;
	tde->offset = de_offs;
	/* A handy reference to the Epilogue updated */
	tde->eplg = SHMTI_EPLG(shmti);

	return 0;
}

static int
scmi_telemetry_tde_state_set_resp_process(struct telemetry_info *ti,
					  struct scmi_telemetry_de *de,
					  struct scmi_msg_resp_telemetry_de_configure *r)
{
	u32 sid = le32_to_cpu(r->shmti_id);

	/*
	 * 3.12.4.8 TELEMETRY_DE_CONFIGURE - SHMTI ID
	 * This field is optional and is set to 0xFFFFFFFF if any of the
	 * following are true:
	 *  - no DE or event group is being enabled.
	 *  - No SHMTI is supported.
	 *  - SHMTI is not used for this DE or event group. This could
	 *  be the case for example, if this DE is associated with a FastChannel.
	 *  the platform does not support returning this information.
	 */
	if (IS_SHMTI_ID_VALID(sid)) {
		u32 de_offs, bts_offs;

		if (sid >= ti->num_shmti)
			return -EPROTO;

		de_offs = le32_to_cpu(r->shmti_de_offset);
		bts_offs = le32_to_cpu(r->blk_ts_offset);
		if (!IS_ALIGNED(de_offs, 4) || !IS_ALIGNED(bts_offs, 4)) {
			dev_err(ti->ph->dev,
				"Returned DE/BTS offsets are NOT 32-bit aligned - de_offs:%X  bts_offs:%X\n",
				de_offs, bts_offs);
			return -EINVAL;
		}

		return scmi_telemetry_state_set_tde_resp(ti, de, sid,
							 de_offs, bts_offs);
	} else {
		/* Unlink the related BLK_TS/UUID lines on disable */
		struct telemetry_de *tde = to_tde(de);

		lockdep_assert_held(&tde->mtx);

		tde->sid = SHMTI_ID_INVALID;
		tde->offset = 0;

		/* UUID is never unlinked once discovered */
		scmi_telemetry_blkts_unlink(tde);
	}

	return 0;
}

static int
scmi_telemetry_group_state_set_resp_process(struct telemetry_info *ti,
					    struct scmi_telemetry_group *grp,
					    struct scmi_msg_resp_telemetry_de_configure *r)
{
	u32 sid = le32_to_cpu(r->shmti_id);
	int ret;

	/*
	 * 3.12.4.8 TELEMETRY_DE_CONFIGURE - SHMTI ID
	 * This field is optional and is set to 0xFFFFFFFF if any of the
	 * following are true:
	 *  - no DE or event group is being enabled.
	 *  - No SHMTI is supported.
	 *  - SHMTI is not used for this DE or event group. This could
	 *  be the case for example, if this DE is associated with a FastChannel.
	 *  the platform does not support returning this information.
	 */
	if (IS_SHMTI_ID_VALID(sid)) {
		if (sid >= ti->num_shmti)
			return -EPROTO;

		/*
		 * A full SHMTI scan is needed when enabling a
		 * group or its timestamps in order to retrieve
		 * offsets: note that when group-timestamp is
		 * enabled for composing DEs a re-scan is needed
		 * since some DEs could have been relocated due
		 * to lack of space in the TDCF.
		 */
		ret = scmi_telemetry_shmti_scan(ti, sid, SCAN_UPDATE);
		if (ret) {
			dev_err(ti->ph->dev,
				"Failed group-scan of SHMTI ID:%d - ret:%d\n",
				sid, ret);
			return ret;
		}
	} else {
		/* Unlink the related BLK_TS/UUID lines on disable */
		scmi_telemetry_group_disable(ti, grp);
	}

	return 0;
}

static void
scmi_telemetry_state_cache_update(struct telemetry_info *ti,
				  const bool *enable, bool *enabled_state,
				  const bool *tstamp, bool *tstamp_enabled_state,
				  struct scmi_telemetry_group *grp,
				  struct scmi_telemetry_de *de)
{
	if ((!grp && !de) || (grp && de))
		return;

	if (enable) {
		if (!grp)
			scmi_telemetry_de_state_update(ti, ENA_STATE,
						       enabled_state,
						       *enable);
		else
			*enabled_state = *enable;
	}

	if (tstamp) {
		if (!grp) {
			if (de->tstamp_support)
				scmi_telemetry_de_state_update(ti, ENA_TSTAMP,
							       tstamp_enabled_state,
							       *tstamp);
		} else {
			*tstamp_enabled_state = *tstamp;
		}
	}

	if (grp)
		scmi_telemetry_group_state_update(ti, grp, enable, tstamp);
}

static inline bool
scmi_telemetry_remote_state_update_needed(struct telemetry_info *ti,
					  const bool *enable, bool *enabled_state,
					  const bool *tstamp,
					  bool *tstamp_enabled_state,
					  bool is_group, void *obj)
{
	/* Is anything to do at all on this object ? */
	if ((!enable || *enable == *enabled_state) &&
	    (!tstamp || *tstamp == *tstamp_enabled_state))
		return false;

	/*
	 * When the object is currently disabled AND no enable state change was
	 * requested, BUT timestamp is being changed, update only local state...
	 * no need to send a message now, it will be sent later on enable.
	 */
	if (!enable && !*enabled_state) {
		scmi_telemetry_state_cache_update(ti, enable,
						  enabled_state, tstamp,
						  tstamp_enabled_state,
						  is_group ? obj : NULL,
						  !is_group ? obj : NULL);

		return false;
	}

	return true;
}

static inline void
scmi_telemetry_state_message_prepare(struct scmi_msg_telemetry_de_configure *msg,
				     unsigned int id, bool is_group,
				     const bool *enable, bool *enabled_state,
				     const bool *tstamp, bool *tstamp_enabled_state)
{
	msg->identifier = cpu_to_le32(id);
	/* Default to disable mode */
	msg->flags = CFG_DISABLE_ONE;
	msg->flags |= cpu_to_le32(FIELD_PREP(GENMASK(3, 3),
					     !is_group ? CFG_EVENT_DE : CFG_EVENT_GROUP));

	if ((!enable && *enabled_state) || (enable && *enable)) {
		/* Already enabled but tstamp_enabled state changed */
		if (tstamp) {
			/* Here, tstamp cannot be NULL too */
			msg->flags |= cpu_to_le32(*tstamp ?
					CFG_ENABLE_WTH_TSTAMP : CFG_ENABLE_NO_TSTAMP);
		} else {
			msg->flags |= cpu_to_le32(*tstamp_enabled_state ?
					CFG_ENABLE_WTH_TSTAMP : CFG_ENABLE_NO_TSTAMP);
		}
	}
}

static inline void
scmi_telemetry_tde_location_update(struct telemetry_de *tde,
				   u32 *sid, u32 *offset, uuid_t *uuid)
{
	if (tde)
		lockdep_assert_held(&tde->mtx);

	if (sid)
		*sid = tde ? tde->sid : SHMTI_ID_INVALID;
	if (offset)
		*offset = tde ? tde->offset : 0;
	if (uuid) {
		if (tde && tde->uuid)
			uuid_copy(uuid, &tde->uuid->uuid);
		else
			memset(uuid, 0x0, sizeof(*uuid));
	}
}

static int scmi_telemetry_tde_state_set(const struct scmi_protocol_handle *ph,
					const bool *enable, const bool *tstamp,
					struct scmi_telemetry_de *de,
					u32 *sid, u32 *offset, uuid_t *uuid)
{
	struct scmi_msg_resp_telemetry_de_configure *resp;
	struct scmi_msg_telemetry_de_configure *msg;
	struct telemetry_info *ti = ph->get_priv(ph);
	struct telemetry_de *tde = to_tde(de);
	struct scmi_xfer *t;
	int ret;

	/* Stall concurrent configuration request */
	guard(mutex)(&ti->config_mtx);

	/*
	 * Note that the TDE lock must be taken early on, before the SCMI
	 * configuration command is even issued to avoid a de-sync between the
	 * TDE state and the effective HW state enforced by the platform in
	 * response to our request.
	 */
	guard(mutex)(&tde->mtx);

	/* Initialize return values with current TDE in case of error */
	scmi_telemetry_tde_location_update(tde, sid, offset, uuid);

	if (!scmi_telemetry_remote_state_update_needed(ti, enable, &de->enabled,
						       tstamp, &de->tstamp_enabled,
						       false, de))
		return 0;

	ret = ph->xops->xfer_get_init(ph, TELEMETRY_DE_CONFIGURE,
				      sizeof(*msg), sizeof(*resp), &t);
	if (ret)
		return ret;

	msg = t->tx.buf;
	scmi_telemetry_state_message_prepare(msg, de->info->id, false,
					     enable, &de->enabled,
					     tstamp, &de->tstamp_enabled);

	resp = t->rx.buf;
	ret = ph->xops->do_xfer(ph, t);
	if (!ret) {
		/*
		 * Update cached state on command success anyway, despite any
		 * possible later response validation issue: once the command
		 * has succedeed keep our state in sync with HW.
		 */
		scmi_telemetry_state_cache_update(ti, enable, &de->enabled,
						  tstamp, &de->tstamp_enabled, NULL, de);
		/* Process response, update DEs location tracking */
		ret = scmi_telemetry_tde_state_set_resp_process(ti, de, resp);
		if (!ret)
			scmi_telemetry_tde_location_update(tde, sid, offset, uuid);
		else
			dev_err(ph->dev,
				"Could NOT process DE ID 0x%08X state response - ret:%d\n",
				tde->de.info->id, ret);
	}

	ph->xops->xfer_put(ph, t);

	return ret;
}

static int scmi_telemetry_group_state_set(const struct scmi_protocol_handle *ph,
					  const bool *enable, const bool *tstamp,
					  struct scmi_telemetry_group *grp)
{
	struct scmi_msg_resp_telemetry_de_configure *resp;
	struct telemetry_info *ti = ph->get_priv(ph);
	struct scmi_msg_telemetry_de_configure *msg;
	struct scmi_xfer *t;
	int ret;

	/* Stall concurrent configuration request */
	guard(mutex)(&ti->config_mtx);

	if (!scmi_telemetry_remote_state_update_needed(ti, enable, &grp->enabled,
						       tstamp, &grp->tstamp_enabled,
						       true, grp))
		return 0;

	ret = ph->xops->xfer_get_init(ph, TELEMETRY_DE_CONFIGURE,
				      sizeof(*msg), sizeof(*resp), &t);
	if (ret)
		return ret;

	msg = t->tx.buf;
	scmi_telemetry_state_message_prepare(msg, grp->info->grp_id, true,
					     enable, &grp->enabled,
					     tstamp, &grp->tstamp_enabled);
	resp = t->rx.buf;
	ret = ph->xops->do_xfer(ph, t);
	if (!ret) {
		/*
		 * Update cached state on command success anyway, despite any
		 * possible later response validation issue: once the command
		 * has succedeed keep our state in sync with HW.
		 */
		scmi_telemetry_state_cache_update(ti, enable, &grp->enabled,
						  tstamp, &grp->tstamp_enabled,
						  grp, NULL);
		ret = scmi_telemetry_group_state_set_resp_process(ti, grp, resp);
		if (ret)
			dev_err(ph->dev,
				"Could NOT process GROUP %u state response - ret:%d\n",
				grp->info->grp_id, ret);
	}

	ph->xops->xfer_put(ph, t);

	return ret;
}

static int scmi_telemetry_state_get(const struct scmi_protocol_handle *ph,
				    const u32 *id, bool *enabled, bool *tstamp_enabled,
				    u32 *sid, u32 *offset, uuid_t  *uuid)
{
	struct telemetry_info *ti = ph->get_priv(ph);
	struct scmi_telemetry_de *de;
	struct telemetry_de *tde;

	if (!enabled || !tstamp_enabled)
		return -EINVAL;

	ti->res_get(ti);
	if (!id) {
		guard(mutex)(&ti->des_enabled_mtx);
		/* Returning the all_des_* state */
		*enabled =
			(atomic_read(&ti->des_enabled[ENA_STATE]) == ti->info.base.num_des);
		*tstamp_enabled =
			(atomic_read(&ti->des_enabled[ENA_TSTAMP]) == ti->num_des_tstamp);

		return 0;
	}

	de = xa_load(&ti->xa_des, *id);
	if (!de)
		return -ENODEV;

	tde = to_tde(de);
	guard(mutex)(&tde->mtx);

	*enabled = de->enabled;
	*tstamp_enabled = de->tstamp_enabled;

	scmi_telemetry_tde_location_update(tde, sid, offset, uuid);

	return 0;
}

static int scmi_telemetry_state_set(const struct scmi_protocol_handle *ph,
				    bool is_group, u32 id, const bool *enable,
				    const bool *tstamp, u32 *sid, u32 *offset,
				    uuid_t *uuid)
{
	struct telemetry_info *ti = ph->get_priv(ph);
	struct scmi_telemetry_res_info *rinfo;

	rinfo = ti->res_get(ti);
	if (!is_group) {
		struct scmi_telemetry_de *de;

		de = xa_load(&ti->xa_des, id);
		if (!de)
			return -ENODEV;

		/* Filter out unplausible timestamp requests */
		return scmi_telemetry_tde_state_set(ph, enable,
						    de->tstamp_support ? tstamp : NULL,
						    de, sid, offset, uuid);
	} else {
		struct scmi_telemetry_group *grp;

		if (id >= rinfo->num_groups)
			return -EINVAL;

		grp = &rinfo->grps[id];
		return scmi_telemetry_group_state_set(ph, enable, tstamp, grp);
	}
}

static int
scmi_telemetry_collection_configure(const struct scmi_protocol_handle *ph,
				    unsigned int res_id, const bool *enable,
				    const unsigned int *update_interval_ms,
				    const enum scmi_telemetry_collection *mode)
{
	enum scmi_telemetry_collection *current_mode, next_mode;
	struct telemetry_info *ti = ph->get_priv(ph);
	struct scmi_msg_telemetry_config_set *msg;
	bool tlm_enable, *current_state, is_group;
	struct scmi_telemetry_res_info *rinfo;
	unsigned int *active_update_interval;
	struct scmi_xfer *t;
	__le32 interval;
	u32 control;
	int ret;

	/* Stall concurrent configuration request */
	guard(mutex)(&ti->config_mtx);

	if (mode && (*mode <= SCMI_TLM_SINGLE_READ) &&
	    ((*mode == SCMI_TLM_NOTIFICATION && !ti->info.continuous_update_support) ||
	     (*mode == SCMI_TLM_SINGLE_READ && !ti->info.single_read_support)))
		return -EINVAL;

	is_group = res_id != SCMI_TLM_GRP_INVALID;
	if (is_group) {
		rinfo = ti->res_get(ti);

		if (res_id >= rinfo->num_groups ||
		    !ti->info.per_group_config_support)
			return -EINVAL;
	}

	if (!is_group) {
		active_update_interval = &ti->info.active_update_interval;
		current_mode = &ti->info.current_mode;
		current_state = &ti->info.enabled;
	} else {
		active_update_interval =
			&rinfo->grps[res_id].active_update_interval;
		current_mode = &rinfo->grps[res_id].current_mode;
		current_state = &rinfo->grps[res_id].enabled;
	}

	if (!enable && !update_interval_ms && (!mode || *mode == *current_mode))
		return 0;

	ret = ph->xops->xfer_get_init(ph, TELEMETRY_CONFIG_SET,
				      sizeof(*msg), 0, &t);
	if (ret)
		return ret;

	if (!update_interval_ms)
		interval = cpu_to_le32(*active_update_interval);
	else
		interval = cpu_to_le32(*update_interval_ms);

	tlm_enable = enable ? *enable : *current_state;
	next_mode = mode ? *mode : *current_mode;

	msg = t->tx.buf;
	msg->group_identifier = cpu_to_le32(res_id);
	control = tlm_enable ? TELEMETRY_ENABLE : 0;
	control |= !is_group ? TELEMETRY_SET_SELECTOR_ALL : TELEMETRY_SET_SELECTOR_GROUP;
	control |= TELEMETRY_MODE_SET(next_mode);
	msg->control = cpu_to_le32(control);
	msg->sampling_rate = interval;
	ret = ph->xops->do_xfer(ph, t);
	if (!ret) {
		*current_mode = next_mode;
		*current_state = tlm_enable;
		/*
		 * Enable streaming mode when notifications were explicitly
		 * requested as a global config, not on a group.
		 */
		if (!is_group)
			ti->streaming_mode = *current_mode == SCMI_TLM_NOTIFICATION;
		if (update_interval_ms)
			*active_update_interval = le32_to_cpu(interval);
	}

	ph->xops->xfer_put(ph, t);

	return ret;
}

static inline int
scmi_telemetry_de_data_fc_read(struct telemetry_de *tde,
			       struct scmi_telemetry_de_sample *sample)
{
	struct fc_tsline __iomem *fc;

	lockdep_assert_held(&tde->mtx);

	/*
	 * A FastChannel DE that was discovered as enabled at boot but later
	 * failed to be enumerated cannot be accessed.
	 */
	if (!tde->base)
		return -EPROTO;

	fc = tde->base + tde->offset;
	sample->val = LINE_DATA_GET(fc);
	sample->tstamp = IS_TDE_TS_LINE(tde) ? LINE_TSTAMP_GET(fc) : 0;

	/* Trace originally read tstamp */
	trace_scmi_tlm_collect(sample->tstamp, tde->de.info->id, sample->val,
			       "FC_READ");

	/* Cache anyway since TDE caches are on the read path anyway */
	scmi_telemetry_tde_cache_update(tde, sample, NULL);

	return 0;
}

static void scmi_telemetry_scan_update(struct telemetry_info *ti)
{
	struct telemetry_de *tde;

	/* Scan all SHMTIs ... */
	for (int id = 0; id < ti->num_shmti; id++) {
		int ret;

		ret = scmi_telemetry_shmti_scan(ti, id, SCAN_LOOKUP);
		if (ret)
			dev_warn(ti->ph->dev,
				 "Failed update-scan of SHMTI ID:%d - ret:%d\n",
				 id, ret);
	}

	if (!ti->info.fc_support)
		return;

	/* Need to enumerate resources to access fastchannels */
	ti->res_get(ti);
	list_for_each_entry(tde, &ti->fcs_des, item) {
		struct scmi_telemetry_de_sample sample = {};

		guard(mutex)(&tde->mtx);
		if (!tde->de.enabled)
			continue;

		/*
		 * Only for the sake of updating TDE cache.
		 * Ignoring errors deriving from malformed FCs.
		 */
		scmi_telemetry_de_data_fc_read(tde, &sample);
	}
}

/*
 * TDCF and TS Line Management Notes
 * ---------------------------------
 *
 * TDCF Payload Metadata notable bits:
 *  - Bit[3]: USE BLK Tstamp
 *  - Bit[2]: Line-Extension Field present (LineTstamp)
 *  - Bit[1]: Tstamp VALID
 *  - Bit[0]: Data INVALID
 *
 * CASE_1:
 * -------
 *	+ A DE is enabled with timestamp disabled, so the TS fields are
 *	  NOT present
 *	  -> BIT[3:0] = 0000b
 *
 *	  - 1/A LINE_TSTAMP
 *	  ------------------
 *	     + that DE is then 're-enabled' with TS: so it was ON, it remains
 *	       ON but using DE_CONFIGURE I now enabled also TS, so the
 *	       platform relocates it at the end of the SHMTI and return the
 *	       new offset
 *	       -> BIT[3:0] = 0110b
 *
 *	  - 1/B BLK_TSTAMP
 *	  ------------------
 *	     + that DE is then 're-enabled' with BLK TS: so it was ON, it
 *	       remains ON but using DE_CONFIGURE, we now also enabled the TS,
 *	       so the platform will:
 *	       - IF a preceding BLK_TS line exist (with same clk rate)
 *	         it relocates the DE at the end of the SHMTI and return the
 *	         new offset (if there is enough room, if not in another SHMTI)
 *	       - IF a preceding BLK_TS line DOES NOT exist (with same clk rate)
 *	         it creates a new BLK_TS line at the end of the SHMTI and then
 *	         relocates the DE after the new BLK_TS and return the
 *	         new offset (if there is enough room, if not in another SHMTI)
 *	       -> BIT[3:1] = 1010b
 *
 *	+ the hole left from the relocated DE can be reused by the platform
 *	to fit another equally sized DE. (i.e. without shuffling around any
 *	other enabled DE, since that would cause a change of the known offset)
 *	anyway it will be marked as:
 *	-> BIT[3:0] = 0101b iff it was a LINE_TSTAMP
 *	-> BIT[3:0] = 0001b iff it was a BLK_TSTAMP
 *
 * CASE_2:
 * -------
 *	+ A DE is enabled with LINE timestamp enabled, so the TS_Line is there
 *	  -> BIT[3:0] = 0110b
 *	+ that DE has its timestamp disabled: again, you can do this without
 *	  disabling it fully but just disabling the TS, so now that TS_line
 *	  fields are still physically there but NOT valid
 *	  -> BIT[3:0] = 0100b
 *	+ the hole from the timestamp remain there unused until
 *		- you enable again the TS so the hole is used again
 *		  -> BIT[3:0] = 0110b
 *			OR
 *		- you disable fully the DE and then re-enable it with the TS
 *		  -> potentially CASE_1 the DE is relocated on enable
 *	+ same kind of dynamic applies if the DE had a BLK_TS line
 */
static int scmi_telemetry_tdcf_de_payld_check(struct telemetry_de *tde,
					      struct payload *payld)
{
	u32 meta = PAYLD_META_RAW(payld);

	lockdep_assert_held(&tde->mtx);

	if (DATA_INVALID_RAW(meta)) {
		trace_scmi_tlm_access(PAYLD_ID_RAW(payld), "DE_DATA_INVALID", 0, 0);
		return -EINVAL;
	}

	if (!IS_DATA_LINE_RAW(meta)) {
		trace_scmi_tlm_access(tde->de.info->id, "BAD_DE_LINE_TYPE", 0, 0);
		return -EPROTO;
	}

	if (PAYLD_ID_RAW(payld) != tde->de.info->id) {
		trace_scmi_tlm_access(tde->de.info->id, "DE_ID_MISMATCH", 0, 0);
		return -ENODEV;
	}

	/*
	 * A valid line using BLK_TS should have been initialized with the
	 * related BLK_TS when enabled, unless is a torn read.
	 */
	if ((USE_BLK_TS_RAW(meta) && !tde->bts)) {
		trace_scmi_tlm_access(tde->de.info->id, "BAD_USE_BLK_TS", 0, 0);
		return -EPROTO;
	}

	return 0;
}

static int scmi_telemetry_de_snapshot(struct tdcf __iomem *tdcf,
				      struct telemetry_de *tde,
				      struct telemetry_de_snapshot *snap)
{
	int retries = SCMI_TLM_TDCF_MAX_RETRIES;
	u32 startm, endm;
	int err = 0;

	lockdep_assert_held(&tde->mtx);

	do {
		struct payload __iomem *payld, *bts_payld;

		/* A bit of exponential backoff between retries */
		fsleep((SCMI_TLM_TDCF_MAX_RETRIES - retries) * SCMI_TLM_TDCF_RETRY_GAP_US);

		startm = TDCF_START_SEQ_GET(tdcf);
		/* Build a default endm certainly different from startm */
		endm = startm + 1;
		if (IS_BAD_START_SEQ(startm)) {
			trace_scmi_tlm_access(tde->de.info->id, "MSEQ_BADSTART",
					      startm, 0);
			continue;
		}

		/*
		 * In this context any anomaly detected on the payload could
		 * due to a torn read, and it is worth retrying a snapshot.
		 *
		 * Note that TDE base/offset have been sanitized when
		 * initialized and cannot have changed: accessing them here
		 * is safe.
		 */
		payld = tde->base + tde->offset;
		memcpy_fromio(&snap->payld, payld, LINE_LENGTH_BYTES(payld));
		err = scmi_telemetry_tdcf_de_payld_check(tde, &snap->payld);
		if (err)
			continue;

		/*
		 * Here the associated BLK_TS line, if any, has been verified
		 * as sane when linked/bound: no need of further validation.
		 */
		if (tde->bts) {
			bts_payld = tde->base + tde->bts->line.offset;
			memcpy_fromio(&snap->bts_payld, bts_payld,
				      LINE_LENGTH_BYTES(bts_payld));
		}

		/* Assure the snapshot has been fully taken before checking seqnum */
		rmb();

		endm = TDCF_END_SEQ_GET(tde->eplg);
		if (startm != endm)
			trace_scmi_tlm_access(tde->de.info->id, "MSEQ_MISMATCH",
					      startm, endm);
	} while ((startm != endm || err) && --retries);

	if (startm != endm || err) {
		trace_scmi_tlm_access(tde->de.info->id,
				      "TDCF_SNAPSHOT_DE_FAIL", startm, endm);
		return err ?: -EPROTO;
	}

	/* Ensure any snapshot is visible before updating magic */
	smp_store_release(&snap->magic, startm);

	trace_scmi_tlm_access(tde->de.info->id, "TDCF_SNAPSHOT_DE_OK",
			      startm, endm);

	return 0;
}

static int
scmi_telemetry_tdcf_de_sample_cached(struct tdcf __iomem *tdcf,
				     struct telemetry_de *tde,
				     struct scmi_telemetry_de_sample *sample)
{
	lockdep_assert_held(&tde->mtx);

	u32 startm;

	/* If updating cannot be cached */
	startm = TDCF_START_SEQ_GET(tdcf);
	if (IS_BAD_START_SEQ(startm))
		return -EAGAIN;

	return scmi_telemetry_tde_cache_lookup(tde, sample, &startm);
}

/**
 * scmi_telemetry_tdcf_de_parse  - Helper to read one SHMTI/DE
 * @tde: A reference to the DE descriptor to read
 * @sample: A reference to the sample used as a container for output
 *
 * This helper can be used to retrieve the data value of a SHMTI based DE
 * and any related BLK_TS line: unless the values are found already available
 * and up to date in the TDE cache, a limited snapshot of the involved lines
 * is taken at first so that all the subsequent DE parsing and processing can
 * happen on a stable in RAM copy.
 *
 * Taking a limited snapshot does not carry relevant overhead and has the
 * benefit of allowing the reuse of the same RAM-baased data accessors used
 * during a full scan and related full snapshot, instead of a set of dedicated
 * __iomem helpers.
 *
 * NOTE that since each TDE has its own cache, which is accessed and updated
 * both during a single DE read and while performing a bulk read, while
 * caching consistency assures to provide always the 'freshest' value
 * retrieved, mixing single and bulk reads can lead to the values produced by
 * the bulk reads to contain 'fresher' late values derived from concurrent
 * single DE reads: IOW mixing single and bulk reads can produce a set of bulk
 * DEs values that are NOT all from the same moment in time.
 *
 * Moreover in general, since no assumption can be made about the TDCF sequence
 * numbers across different SHMTIs and related optional DE timestamps, it is NOT
 * possible to guarantee anyway that data values retrieved from DEs located in
 * distinct SHMTIs areas comes from the same platform update cycle at all.
 */
static int
scmi_telemetry_tdcf_de_parse(struct telemetry_de *tde,
			     struct scmi_telemetry_de_sample *sample)
{
	struct telemetry_de_snapshot snap = {};
	struct tdcf __iomem *tdcf;
	int ret;

	lockdep_assert_held(&tde->mtx);

	/*
	 * TDEs can be relocated by platform only during enable phase,
	 * thing that cannot happen until tde->mtx is released.
	 */
	tdcf = tde->base;
	if (!tdcf)
		return -ENODEV;

	if (!scmi_telemetry_tdcf_de_sample_cached(tdcf, tde, sample))
		return 0;

	/* Attempt a localized DE snapshot: DATA_LINE + optionally BLK_TS */
	ret = scmi_telemetry_de_snapshot(tdcf, tde, &snap);
	if (ret)
		return ret;

	/* Now parse the stable line snapshot */
	return scmi_telemetry_line_data_parse(tde, NULL, sample, &snap.payld,
					      &snap.bts_payld, snap.magic);
}

static int scmi_telemetry_de_access(struct telemetry_de *tde,
				    struct scmi_telemetry_de_sample *sample)
{
	lockdep_assert_held(&tde->mtx);

	if (!tde->de.fc_support)
		return scmi_telemetry_tdcf_de_parse(tde, sample);

	return scmi_telemetry_de_data_fc_read(tde, sample);
}

static int scmi_telemetry_de_collect(struct telemetry_info *ti,
				     struct scmi_telemetry_de *de,
				     struct scmi_telemetry_de_sample *sample)
{
	struct telemetry_de *tde = to_tde(de);

	guard(mutex)(&tde->mtx);

	if (!de->enabled)
		return -ENODATA;

	/*
	 * DE readings returns cached values when:
	 *  - DE data value was retrieved via notification/delayed_response
	 */
	if (tde->cached_msg)
		return scmi_telemetry_tde_cache_lookup(tde, sample, NULL);

	return scmi_telemetry_de_access(tde, sample);
}

static int scmi_telemetry_de_data_read(const struct scmi_protocol_handle *ph,
				       struct scmi_telemetry_de_sample *sample)
{
	struct telemetry_info *ti = ph->get_priv(ph);
	struct scmi_telemetry_de *de;

	if (!ti->info.enabled || !sample)
		return -ENODATA;

	ti->res_get(ti);
	de = xa_load(&ti->xa_des, sample->id);
	if (!de)
		return -ENOENT;

	return scmi_telemetry_de_collect(ti, de, sample);
}

static int
scmi_telemetry_samples_collect(struct telemetry_info *ti, int grp_id,
			       unsigned int *num_samples,
			       struct scmi_telemetry_de_sample *samples)
{
	struct scmi_telemetry_res_info *rinfo;
	unsigned int max_samples;

	max_samples = *num_samples;
	*num_samples = 0;

	rinfo = ti->res_get(ti);
	for (int i = 0; i < rinfo->num_des; i++) {
		struct telemetry_de *tde = to_tde(rinfo->des[i]);

		guard(mutex)(&tde->mtx);

		/* Skip disabled DEs and not belonging to the selected Group */
		if (!tde->de.enabled ||
		    (grp_id != SCMI_TLM_GRP_INVALID &&
		     (!tde->de.grp || tde->de.grp->info->grp_id != grp_id)))
			continue;

		/* Must be checked here to skip disabled and non selected */
		if (*num_samples == max_samples)
			return -ENOSPC;

		/* Note that this cannot fail when passing a NULL magic */
		scmi_telemetry_tde_cache_lookup(tde, &samples[(*num_samples)++], NULL);
	}

	return 0;
}

static int scmi_telemetry_des_bulk_read(const struct scmi_protocol_handle *ph,
					int grp_id, unsigned int *num_samples,
					struct scmi_telemetry_de_sample *samples)
{
	struct telemetry_info *ti = ph->get_priv(ph);

	if (!ti->info.enabled || !num_samples || !samples)
		return -EINVAL;

	/* Trigger a full SHMTIs & FCs scan */
	scmi_telemetry_scan_update(ti);

	/* Collect all last cached values */
	return scmi_telemetry_samples_collect(ti, grp_id, num_samples, samples);
}

static void
scmi_telemetry_msg_payld_process(struct telemetry_info *ti,
				 unsigned int num_dwords, __le32 *dwords,
				 size_t payld_bytes, bool cacheable)
{
	struct scmi_telemetry_res_info *rinfo;
	u32 next = 0;

	rinfo = ti->res_get(ti);
	if (!rinfo->fully_enumerated) {
		dev_warn_once(ti->ph->dev,
			      "Cannot process DEs in message payload. Drop.\n");
		return;
	}

	while (next < num_dwords) {
		struct payload *payld = (struct payload *)&dwords[next];
		struct scmi_telemetry_de_sample sample = {};
		u32 de_id, meta = le32_to_cpu(payld->meta);
		struct scmi_telemetry_de *de;
		struct telemetry_de *tde;
		unsigned int wlen;

		wlen = LINE_LENGTH_WORDS_RAW(meta);
		/* Check Boundary and prepare next iteration */
		if (check_add_overflow(next, wlen, &next) ||
		    next > payld_bytes / sizeof(u32)) {
			trace_scmi_tlm_access(0, "MSG_OVERFLOW", 0, 0);
			return;
		}

		de_id = le32_to_cpu(payld->id);
		if (DATA_INVALID_RAW(meta)) {
			trace_scmi_tlm_access(de_id, "MSG_INVALID", 0, 0);
			continue;
		}

		if (LINE_TYPE_RAW(meta) != TDCF_DATA_LINE) {
			trace_scmi_tlm_access(de_id, "MSG_BAD_TYPE", 0, 0);
			continue;
		}

		if (USE_BLK_TS_RAW(meta)) {
			trace_scmi_tlm_access(de_id, "MSG_BAD_USE_BLKTS", 0, 0);
			continue;
		}

		de = xa_load(&ti->xa_des, de_id);
		if (!de) {
			trace_scmi_tlm_access(de_id, "MSG_DE_UNKNOWN", 0, 0);
			continue;
		}

		tde = to_tde(de);
		guard(mutex)(&tde->mtx);
		if (!de->enabled) {
			trace_scmi_tlm_access(de_id, "MSG_DE_DISABLED", 0, 0);
			continue;
		}

		tde->cached_msg = cacheable;
		sample.val = LINE_DATA_GET_RAW(&payld->tsl);
		sample.tstamp = HAS_LINE_EXT_RAW(meta) &&
			LINE_TS_VALID_RAW(meta) ? LINE_TSTAMP_GET_RAW(&payld->tsl) : 0;

		/* Update the cache holding the TDE mutex */
		scmi_telemetry_tde_cache_update(tde, &sample, NULL);

		/* Link notifications to Primary UUID */
		if (cacheable)
			scmi_telemetry_uuid_link(tde, ti->primary_uuid);

		trace_scmi_tlm_collect(sample.tstamp, de->info->id, sample.val,
				       "MESSAGE");
	}
}

static int scmi_telemetry_des_sample_get(const struct scmi_protocol_handle *ph,
					 int grp_id, unsigned int *num_samples,
					 struct scmi_telemetry_de_sample *samples)
{
	struct telemetry_info *ti = ph->get_priv(ph);
	struct scmi_msg_telemetry_config_set *msg;
	struct scmi_xfer *t;
	bool is_group;
	u32 control;
	int ret;

	if (!ti->info.enabled || !num_samples || !samples ||
	    !ti->info.single_read_support)
		return -EINVAL;

	is_group = grp_id != SCMI_TLM_GRP_INVALID;
	if (is_group && grp_id >= ti->info.base.num_groups)
		return -EINVAL;

	ret = ph->xops->xfer_get_init(ph, TELEMETRY_CONFIG_SET,
				      sizeof(*msg), 0, &t);
	if (ret)
		return ret;

	msg = t->tx.buf;
	msg->group_identifier = cpu_to_le32(grp_id);
	control = TELEMETRY_ENABLE;
	control |= !is_group ? TELEMETRY_SET_SELECTOR_ALL :
		TELEMETRY_SET_SELECTOR_GROUP;
	control |= TELEMETRY_MODE_SINGLE;
	msg->control = cpu_to_le32(control);
	msg->sampling_rate = 0;

	ret = ph->xops->do_xfer_with_response(ph, t);
	/*
	 * PARTIAL_ERRORs are reported as -EBADMSG and related lines,
	 * marked as DATA_INVALID, will be properly skipped by
	 * scmi_telemetry_msg_payld_process.
	 */
	if (!ret || ret == -EBADMSG) {
		struct scmi_msg_resp_telemetry_reading_complete *r = t->rx.buf;
		u32 num_dwords;

		if (ret == -EBADMSG)
			trace_scmi_tlm_access(0, "BAD_SAMPLE_PARTIAL_ERROR", 0, 0);

		if (t->rx.len < sizeof(*r))
			return -EPROTO;

		num_dwords = le32_to_cpu(r->num_dwords);
		/* Update cached DEs values from payload */
		if (num_dwords) {
			size_t payld_sz = 0, dwords_sz;

			if (check_mul_overflow(num_dwords, sizeof(r->array[0]), &dwords_sz) ||
			    check_add_overflow(sizeof(*r), dwords_sz, &payld_sz) ||
			    payld_sz > t->rx.len) {
				dev_err(ph->dev,
					"Malformed Telemetry delayed response - num_dwords:%u  payld_sz:%zd  rx_len:%zd\n",
					num_dwords, payld_sz, t->rx.len);
				ret = -EPROTO;
				goto out;
			}

			scmi_telemetry_msg_payld_process(ti, num_dwords, r->array,
							 payld_sz - sizeof(*r), false);
		}

		/* Scan and update SMHTIs and FCs */
		scmi_telemetry_scan_update(ti);

		/* Collect all last cached values, override any PARTIAL_ERROR */
		ret = scmi_telemetry_samples_collect(ti, grp_id, num_samples,
						     samples);
	}

out:
	ph->xops->xfer_put(ph, t);

	return ret;
}

static void scmi_telemetry_local_resources_reset(struct telemetry_info *ti)
{
	struct scmi_telemetry_res_info *rinfo;
	unsigned int num_des;

	ti->info.enabled = false;
	ti->info.current_mode = SCMI_TLM_ONDEMAND;
	ti->streaming_mode = false;
	ti->info.active_update_interval = 0;

	/* Get rinfo without triggering an enumeration, cannot be NULL anyway */
	rinfo = __scmi_telemetry_resources_get(ti);
	/* Make sure to see the latest num_des */
	num_des = smp_load_acquire(&rinfo->num_des);
	/* Clear all local state...*/
	for (int i = 0; i < num_des; i++) {
		struct telemetry_de *tde = to_tde(rinfo->des[i]);

		scoped_guard(mutex, &tde->mtx) {
			tde->last_ts = 0;
			tde->last_val = 0;
			tde->last_magic = 0;
			tde->cached_msg = false;
			if (!tde->de.fc_support) {
				tde->sid = SHMTI_ID_INVALID;
				tde->base = NULL;
				tde->offset = 0;
				tde->eplg = NULL;
			}

			scmi_telemetry_de_state_update(ti, ENA_STATE,
						       &tde->de.enabled, false);

			if (tde->de.tstamp_support)
				scmi_telemetry_de_state_update(ti, ENA_TSTAMP,
							       &tde->de.tstamp_enabled,
							       false);

			/*
			 * Unlinking ONLY BLK_TS lines since, per the SCMI spec,
			 * the UUID/DE associations are permanent within the same
			 * session boot: after a reset has cleared the server-side
			 * configuration the next time SHMTIs will be re-populated,
			 * these same UUID/DE associations will be re-instated.
			 */
			scmi_telemetry_blkts_unlink(tde);
		}
	}

	for (int i = 0; i < rinfo->num_groups; i++) {
		rinfo->grps[i].enabled = false;
		rinfo->grps[i].tstamp_enabled = false;
		rinfo->grps[i].current_mode = SCMI_TLM_ONDEMAND;
		rinfo->grps[i].active_update_interval = 0;
	}
}

static int scmi_telemetry_reset(const struct scmi_protocol_handle *ph)
{
	struct telemetry_info *ti = ph->get_priv(ph);
	struct scmi_xfer *t;
	int ret;

	/* Stall concurrent configuration request */
	guard(mutex)(&ti->config_mtx);

	ret = ph->xops->xfer_get_init(ph, TELEMETRY_RESET, sizeof(u32), 0, &t);
	if (ret)
		return ret;

	put_unaligned_le32(0, t->tx.buf);
	ret = ph->xops->do_xfer(ph, t);
	if (!ret)
		scmi_telemetry_local_resources_reset(ti);

	ph->xops->xfer_put(ph, t);

	return ret;
}

static const struct scmi_telemetry_proto_ops tlm_proto_ops = {
	.info_get = scmi_telemetry_info_get,
	.de_lookup = scmi_telemetry_de_lookup,
	.res_get = scmi_telemetry_resources_get,
	.state_get = scmi_telemetry_state_get,
	.state_set = scmi_telemetry_state_set,
	.collection_configure = scmi_telemetry_collection_configure,
	.de_data_read = scmi_telemetry_de_data_read,
	.des_bulk_read = scmi_telemetry_des_bulk_read,
	.des_sample_get = scmi_telemetry_des_sample_get,
	.reset = scmi_telemetry_reset,
};

static bool
scmi_telemetry_notify_supported(const struct scmi_protocol_handle *ph,
				u8 evt_id, u32 src_id)
{
	struct telemetry_info *ti = ph->get_priv(ph);

	return ti->info.continuous_update_support;
}

static int
scmi_telemetry_set_notify_enabled(const struct scmi_protocol_handle *ph,
				  u8 evt_id, u32 src_id, bool enable)
{
	/*
	 * As defined by the specification, SCMI Telemetry notifications are a
	 * kind of their own: the enable process deviates slightly from usual
	 * notifications behaviour and a notifier has to be registered anyway
	 * right after protocol initialization if such notifications are
	 * supported at all by the platform.
	 * IOW, SCMI Telemetry notifications are in fact always enabled when
	 * supported, so this helper needs to do nothing but succeed.
	 */
	return 0;
}

static void *
scmi_telemetry_fill_custom_report(const struct scmi_protocol_handle *ph,
				  u8 evt_id, ktime_t timestamp,
				  const void *payld, size_t payld_sz,
				  void *report, u32 *src_id)
{
	const struct scmi_telemetry_update_notify_payld *p = payld;
	struct scmi_telemetry_update_report *r = report;
	size_t dwords_sz, msg_payld_sz;

	/* At least sized as an empty notification */
	if (payld_sz < sizeof(*p))
		return NULL;

	r->timestamp = timestamp;
	r->agent_id = le32_to_cpu(p->agent_id);
	r->status = scmi_to_linux_errno(le32_to_cpu(p->status));
	r->num_dwords = le32_to_cpu(p->num_dwords);

	/*Check boundaries and wraparounds */
	if (check_mul_overflow(r->num_dwords, sizeof(r->dwords[0]), &dwords_sz))
		return NULL;

	if (check_add_overflow(sizeof(*p), dwords_sz, &msg_payld_sz))
		return NULL;

	if (msg_payld_sz > payld_sz)
		return NULL;

	/*
	 * Allocated dwords and report are sized as max_msg_size, so as
	 * to allow for the maximum payload permitted by the configured
	 * transport. Overflow is not possible since out-of-size messages
	 * are dropped at the transport layer.
	 */
	if (r->num_dwords)
		memcpy_from_le32(r->dwords, p->array, r->num_dwords);

	*src_id = 0;

	return r;
}

static const struct scmi_event tlm_events[] = {
	{
		.id = SCMI_EVENT_TELEMETRY_UPDATE,
		.max_payld_sz = 0,
		.max_report_sz = 0,
	},
};

static const struct scmi_event_ops tlm_event_ops = {
	.is_notify_supported = scmi_telemetry_notify_supported,
	.set_notify_enabled = scmi_telemetry_set_notify_enabled,
	.fill_custom_report = scmi_telemetry_fill_custom_report,
};

static const struct scmi_protocol_events tlm_protocol_events = {
	.queue_sz = SCMI_PROTO_QUEUE_SZ,
	.ops = &tlm_event_ops,
	.evts = tlm_events,
	.num_events = ARRAY_SIZE(tlm_events),
	.num_sources = 1,
};

static int scmi_telemetry_notifier(struct notifier_block *nb,
				   unsigned long event, void *data)
{
	struct scmi_telemetry_update_report *er = data;
	struct telemetry_info *ti = telemetry_nb_to_info(nb);

	/*
	 * PARTIAL_ERRORs are reported as -EBADMSG and related lines,
	 * marked as DATA_INVALID, will be properly skipped by
	 * scmi_telemetry_msg_payld_process.
	 */
	if (er->status && er->status != -EBADMSG) {
		trace_scmi_tlm_access(0, "BAD_NOTIF_MSG", 0, 0);
		return NOTIFY_DONE;
	} else if (er->status == -EBADMSG) {
		trace_scmi_tlm_access(0, "BAD_NOTIF_PARTIAL_ERROR", 0, 0);
	}

	trace_scmi_tlm_access(0, "TLM_UPDATE_MSG", 0, 0);
	/* Lookup the embedded DEs in the notification payload ... */
	if (er->num_dwords) {
		size_t payld_bytes = sizeof(er->dwords[0]) * er->num_dwords;

		__le32 *dwords __free(kvfree) =
			kvzalloc_objs(*dwords, er->num_dwords);
		if (!dwords) {
			trace_scmi_tlm_access(0, "TLM_UPDATE_MSG_FAILED", 0, 0);
			return NOTIFY_DONE;
		}

		/* The report payload size was bound checked on rx */
		memcpy_to_le32(dwords, er->dwords, er->num_dwords);
		/*
		 * Note that the DEs received via Notifications can only be
		 * updated that way, and as such are cached at each reception
		 * and never read on-demand.
		 */
		scmi_telemetry_msg_payld_process(ti, er->num_dwords, dwords,
						 payld_bytes, true);
	}

	/*
	 * ...scan the SHMTI/FCs for any other DE updates if streaming mode
	 * is enabled since it is an indication that someone explcitly requested
	 * collection by notification.
	 */
	if (ti->streaming_mode)
		scmi_telemetry_scan_update(ti);

	return NOTIFY_OK;
}

/**
 * scmi_telemetry_resources_alloc  - Resources allocation
 * @ti: A reference to the telemetry info descriptor for this instance
 *
 * This allocates and initializes dedicated resources for the maximum possible
 * number of needed telemetry resources, based on information gathered from
 * the initial enumeration: these allocations represent an upper bound on
 * the number of discoverable telemetry resources and they will be later
 * populated during late deferred further discovery phases.
 *
 * Note that some of the allocations down below are designed to keep some
 * class of data packed together since it eases retrieval from the ABI layer.
 *
 * Return: 0 on Success, errno otherwise
 */
static int scmi_telemetry_resources_alloc(struct telemetry_info *ti)

{
	/* Array to hold SHMTIs descriptors */
	struct telemetry_shmti *shmtis __free(kfree) =
		kzalloc_objs(*shmtis, ti->num_shmti);
	if (!shmtis)
		return -ENOMEM;

	/* Array of initialized SHMTIs references */
	struct scmi_telemetry_shmti_info **shmtis_info __free(kfree) =
		kzalloc_objs(*shmtis_info, ti->num_shmti);
	if (!shmtis_info)
		return -ENOMEM;

	/* Array to hold pointers to discovered DEs */
	struct scmi_telemetry_de **des __free(kfree) =
		kzalloc_objs(*des, ti->info.base.num_des);
	if (!des)
		return -ENOMEM;

	/* The allocated DE descriptors */
	struct telemetry_de *tdes __free(kfree) =
		kzalloc_objs(*tdes, ti->info.base.num_des);
	if (!tdes)
		return -ENOMEM;

	/* Allocate a set of contiguous DE info descriptors. */
	struct scmi_telemetry_de_info *dei_store __free(kfree) =
		kzalloc_objs(*dei_store, ti->info.base.num_des);
	if (!dei_store)
		return -ENOMEM;

	/* Array to hold descriptors of discovered GROUPs */
	struct scmi_telemetry_group *grps __free(kfree) =
		kzalloc_objs(*grps, ti->info.base.num_groups);
	if (!grps)
		return -ENOMEM;

	/* Allocate a set of contiguous Group info descriptors. */
	struct scmi_telemetry_grp_info *grps_store __free(kfree) =
		kzalloc_objs(*grps_store, ti->info.base.num_groups);
	if (!grps_store)
		return -ENOMEM;

	struct scmi_telemetry_res_info *rinfo __free(kfree) =
		kzalloc_obj(*rinfo);
	if (!rinfo)
		return -ENOMEM;

	mutex_init(&ti->free_mtx);
	INIT_LIST_HEAD(&ti->free_des);
	for (int i = 0; i < ti->info.base.num_des; i++) {
		mutex_init(&tdes[i].mtx);
		/* Bind contiguous DE info structures */
		tdes[i].de.info = &dei_store[i];
		scmi_telemetry_free_tdes_add(ti, &tdes[i]);
	}

	for (int i = 0; i < ti->info.base.num_groups; i++) {
		grps_store[i].grp_id = i;
		/* Bind contiguous Group info struct */
		grps[i].info = &grps_store[i];
	}

	INIT_LIST_HEAD(&ti->fcs_des);
	hash_init(ti->uuids_ht);

	ti->shmti = no_free_ptr(shmtis);
	ti->info.shmtis = no_free_ptr(shmtis_info);

	ti->tdes = no_free_ptr(tdes);

	rinfo->des = no_free_ptr(des);
	rinfo->dei_store = no_free_ptr(dei_store);
	rinfo->grps = no_free_ptr(grps);
	rinfo->grps_store = no_free_ptr(grps_store);

	/* Ensure all of the above assignments are visible */
	smp_store_release(&ti->rinfo, no_free_ptr(rinfo));

	return 0;
}

static struct scmi_telemetry_res_info *
__scmi_telemetry_resources_get(struct telemetry_info *ti)
{
	/* Ensure rinfo descriptor is visible */
	return smp_load_acquire(&ti->rinfo);
}

static void scmi_telemetry_resources_free(struct telemetry_info *ti)
{
	struct scmi_telemetry_res_info *rinfo;

	/* Get rinfo without triggering a recursive enumeration, cannot be NULL */
	rinfo = __scmi_telemetry_resources_get(ti);
	/* Ensure rinfo is no more accessible upfront */
	smp_store_release(&ti->rinfo, NULL);

	kfree(ti->info.shmtis);
	kfree(ti->shmti);

	kfree(ti->tdes);

	kfree(rinfo->des);
	kfree(rinfo->dei_store);

	kfree(rinfo->grps);
	kfree(rinfo->grps_store);

	kfree(rinfo);

	dev_dbg(ti->ph->dev, "SCMI Telemetry resources freed for instance\n");
}

static void scmi_telemetry_lines_cleanup(struct telemetry_info *ti)
{
	for (int id = 0; id < ti->num_shmti; id++) {
		struct telemetry_shmti *shmti = &ti->shmti[id];
		struct telemetry_line *line;
		unsigned long idx;

		guard(mutex)(&shmti->lines_mtx);
		/* Drop all remaining currently unbound lines and their containers */
		xa_for_each(&shmti->xa_lines, idx, line)
			__scmi_telemetry_line_put(line);

		xa_destroy(&shmti->xa_lines);
	}
}

static void scmi_telemetry_uuids_cleanup(struct telemetry_info *ti)
{
	uuid_t **cur_uuids;

	/* Drop reference to UUID lines kept in the growable array */
	scoped_guard(mutex, &ti->uuids_mtx) {
		int num_uuids;

		/* Ensure looking up an updated counter */
		num_uuids = smp_load_acquire(&ti->info.num_uuids);
		/* Ensure zeroing is visible */
		smp_store_release(&ti->info.num_uuids, 0);
		/* Inhibit further accesses to cur_uuids */
		cur_uuids = rcu_replace_pointer(ti->info.uuids, NULL,
						lockdep_is_held(&ti->uuids_mtx));
		synchronize_rcu();

		for (int i = 0; i < num_uuids; i++) {
			struct telemetry_uuid *uuid;

			uuid = to_uuid_from_uuid_t(cur_uuids[i]);
			hash_del(&uuid->node_ht);
			kfree(uuid);

			trace_scmi_tlm_access(0, "DROP_LINE", TDCF_UUID_LINE, 0);
		}
	}

	kfree_rcu_mightsleep(cur_uuids);
}

static void scmi_telemetry_tdes_cleanup(struct telemetry_info *ti)
{
	struct scmi_telemetry_de *de;
	unsigned long idx;

	/*
	 * Unlinking all the BLK_TS/UUID lines related to a DE triggers also
	 * the deallocation of such lines when the embedded refcount hits zero.
	 * Note that the UUID lines are also referenced and refcounted by the
	 * global UUID RCU array, so they won't be deallocated here.
	 */
	xa_for_each(&ti->xa_des, idx, de) {
		struct telemetry_de *tde = to_tde(de);

		guard(mutex)(&tde->mtx);

		scmi_telemetry_de_unlink(&tde->de);
		scmi_telemetry_free_tde_put(ti, tde);
	}

	xa_destroy(&ti->xa_des);
}

static void scmi_telemetry_groups_free(struct scmi_telemetry_res_info *rinfo)
{
	/* Cannot be NULL here by construction, make sure it remains like that */
	if (WARN_ON(!rinfo))
		return;

	for (int i = 0; i < rinfo->num_groups; i++) {
		struct scmi_telemetry_group *grp = &rinfo->grps[i];

		kfree(grp->des);
		kfree(grp->des_str);
		kfree(grp->intervals);
	}
}

static void scmi_telemetry_instance_cleanup(void *arg)
{
	struct telemetry_info *ti = arg;

	scmi_telemetry_groups_free(ti->rinfo);
	scmi_telemetry_tdes_cleanup(ti);
	scmi_telemetry_uuids_cleanup(ti);
	scmi_telemetry_lines_cleanup(ti);
	scmi_telemetry_resources_free(ti);
}

/**
 * scmi_telemetry_resources_enumerate  - Enumeration helper
 * @ti: A reference to the telemetry info descriptor for this instance
 *
 * This helper is configured to be called once on the first enumeration
 * attempt, when triggered by invoking ti->res_get() from somewhere else.
 *
 * Once run it substitues itself in ti->res_get() with the simple accessor
 * __scmi_telemetry_resources_get, which returns a descriptor to the resources
 * that were possibly discovered.
 *
 * Note that, while it attempts to fully enumerate Data Events and Groups, it
 * does NOT fail when such enumerations fail, instead it simply gives up with
 * the end result that only a partially populated, but consistent, resources
 * descriptor will be returned; in such a case the incomplete descriptor will
 * be marked as NOT fully_enumerated: this design enables the kernel to deal
 * with badly implemented out-of-spec firmware support while keep on providing
 * a minimal sane, albeit possibly incomplete, set of telemetry respources.
 *
 * Return: A reference to a fully or partially populated resources descriptor
 */
static struct scmi_telemetry_res_info *
scmi_telemetry_resources_enumerate(struct telemetry_info *ti)
{
	struct scmi_telemetry_res_info *rinfo;
	struct device *dev = ti->ph->dev;
	int ret;

	/*
	 * Ensure the following initialization can be called only once
	 * from one thread of execution.
	 */
	if (atomic_cmpxchg(&ti->rinfo_initializing, 0, 1)) {
		/*
		 * When initialization is already ongoing in another thread,
		 * just wait for its completion and return the fully or partially
		 * populated rinfo.
		 */
		if (!completion_done(&ti->rinfo_initdone))
			wait_for_completion(&ti->rinfo_initdone);

		/* Ensure rinfo descriptor is visible */
		return smp_load_acquire(&ti->rinfo);
	}

	/* Note that this code below can be run only once by one thread */
	ret = scmi_telemetry_de_descriptors_get(ti);
	if (ret) {
		dev_err(dev, FW_BUG "Cannot fully enumerate DEs resources. Degraded system.\n");
		goto done;
	}

	ret = scmi_telemetry_enumerate_groups_intervals(ti);
	if (ret) {
		dev_err(dev, FW_BUG "Cannot fully enumerate group intervals. Degraded system.\n");
		goto done;
	}

	/* Get rinfo without triggering a recursive enumeration */
	rinfo = __scmi_telemetry_resources_get(ti);
	rinfo->fully_enumerated = rinfo->num_des == ti->info.base.num_des;
done:
	/* Disable initialization permanently */
	smp_store_release(&ti->res_get, __scmi_telemetry_resources_get);

	/* Unblock concurrent threads that have been stalled */
	complete_all(&ti->rinfo_initdone);

	/* Ensure local rinfo is visible before returning it */
	smp_mb();
	return ti->rinfo;
}

static int scmi_telemetry_primary_uuid_init(struct telemetry_info *ti)
{
	__be32 *dwords = (__be32 *)&ti->info.base.primary_revision.b;
	struct telemetry_uuid *uuid;

	uuid = scmi_telemetry_uuid_get_or_create(ti, dwords);
	if (!uuid) {
		dev_err(ti->ph->dev, "Failed to register Primary UUID\n");
		return -ENOMEM;
	}

	/* Ensure Primary UUID association is visible */
	smp_store_release(&ti->primary_uuid, uuid);

	return 0;
}

/**
 * scmi_telemetry_instance_init  - Instance initializer
 * @ti: A reference to the telemetry info descriptor for this instance
 *
 * Note that this allocates and initialize all the resources possibly needed
 * and then setups the @scmi_telemetry_resources_enumerate helper as the
 * default method for the first call to ti->res_get(): this mechanism enables
 * the possibility of optionally implementing deferred enumeration policies
 * which optionally delay the discovery phase and related SCMI message exchanges
 * to a later point in time.
 *
 * Return: 0 on Success, errno otherwise
 */
static int scmi_telemetry_instance_init(struct telemetry_info *ti)
{
	unsigned int uuids_len;
	uuid_t **cur_uuids;
	int ret;

	ret = scmi_telemetry_resources_alloc(ti);
	if (ret)
		return ret;

	xa_init(&ti->xa_des);
	mutex_init(&ti->config_mtx);

	/*
	 * Always allocate at least one slot for the primary and anyway at
	 * least enough to avoid immediate resizing, assuring uuids_len
	 * always greater or equal to one.
	 */
	uuids_len = max(ti->num_shmti * 2, SCMI_UUID_DB_THRESH + 1);
	cur_uuids = kzalloc_objs(*cur_uuids, uuids_len);
	if (!cur_uuids) {
		xa_destroy(&ti->xa_des);
		scmi_telemetry_resources_free(ti);
		return -ENOMEM;
	}

	mutex_init(&ti->uuids_mtx);
	/* Expose new UUID pointer */
	scoped_guard(mutex, &ti->uuids_mtx) {
		rcu_assign_pointer(ti->info.uuids, cur_uuids);
		ti->uuids_len = uuids_len;
	}

	/* Initialize the first UUIDs in the global list with the primary */
	ret = scmi_telemetry_primary_uuid_init(ti);
	if (ret) {
		scmi_telemetry_uuids_cleanup(ti);
		xa_destroy(&ti->xa_des);
		scmi_telemetry_resources_free(ti);
		return ret;
	}

	atomic_set(&ti->des_enabled[ENA_STATE], 0);
	atomic_set(&ti->des_enabled[ENA_TSTAMP], 0);
	mutex_init(&ti->des_enabled_mtx);
	/* Setup resources lazy initialization */
	atomic_set(&ti->rinfo_initializing, 0);
	init_completion(&ti->rinfo_initdone);
	/* Ensure the new res_get() operation is visible after this point */
	smp_store_mb(ti->res_get, scmi_telemetry_resources_enumerate);

	return devm_add_action_or_reset(ti->ph->dev,
					scmi_telemetry_instance_cleanup, ti);
}

static int scmi_telemetry_protocol_init(const struct scmi_protocol_handle *ph)
{
	struct device *dev = ph->dev;
	struct telemetry_info *ti;
	int ret;

	dev_dbg(dev, "Telemetry Version %d.%d\n",
		PROTOCOL_REV_MAJOR(ph->version), PROTOCOL_REV_MINOR(ph->version));

	ti = devm_kzalloc(dev, sizeof(*ti), GFP_KERNEL);
	if (!ti)
		return -ENOMEM;

	ti->ph = ph;

	ret = scmi_telemetry_protocol_attributes_get(ti);
	if (ret) {
		dev_err(dev, FW_BUG "Cannot retrieve protocol attributes. Abort.\n");
		return ret;
	}

	ret = scmi_telemetry_instance_init(ti);
	if (ret) {
		dev_err(dev, "Cannot initialize instance. Abort.\n");
		return ret;
	}

	ret = scmi_telemetry_enumerate_common_intervals(ti);
	if (ret) {
		dev_err(dev, FW_BUG "Cannot enumerate update intervals. Abort.\n");
		return ret;
	}

	ret = scmi_telemetry_enumerate_shmti(ti);
	if (ret) {
		dev_err(dev, FW_BUG "Cannot enumerate SHMTIs. Abort.\n");
		return ret;
	}

	ti->info.base.version = ph->version;

	ret = ph->set_priv(ph, ti);
	if (ret)
		return ret;

	/*
	 * Register a notifier anyway straight upon protocol initialization
	 * since there could be some DEs that are ONLY reported by notifications
	 * even though the chosen collection method was SHMTI/FCs.
	 */
	if (ti->info.continuous_update_support) {
		ti->telemetry_nb.notifier_call = &scmi_telemetry_notifier;
		ret = ph->instance_notifier_register(ph, SCMI_EVENT_TELEMETRY_UPDATE,
						     NULL, &ti->telemetry_nb);
		if (ret) {
			dev_err(ph->dev,
				"Could NOT register Telemetry notifier\n");
			return ret;
		}
	}

	return 0;
}

static const struct scmi_protocol scmi_telemetry = {
	.id = SCMI_PROTOCOL_TELEMETRY,
	.owner = THIS_MODULE,
	.instance_init = &scmi_telemetry_protocol_init,
	.ops = &tlm_proto_ops,
	.events = &tlm_protocol_events,
	.supported_version = SCMI_PROTOCOL_SUPPORTED_VERSION,
};

DEFINE_SCMI_PROTOCOL_REGISTER_UNREGISTER(telemetry, scmi_telemetry)
