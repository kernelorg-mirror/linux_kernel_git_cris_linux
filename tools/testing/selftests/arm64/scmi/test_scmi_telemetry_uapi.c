// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 ARM Limited

#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

#include "kselftest_harness.h"

#include <../../../../../include/uapi/linux/scmi.h>

#define TLM_0	"tlm_0"

struct scmi_ksft_session {
	bool initialized;
	struct scmi_tlm_abi_info info;
	struct scmi_tlm_config *original_cfg;
	struct scmi_tlm_intervals available;
	struct scmi_tlm_update_interval *intervals;
	struct scmi_tlm_de_info *de_list;
	unsigned int num_des;

} ksft_session;

static int scmi_tlm_batch_init(struct scmi_tlm_batch *batch,
			       unsigned int num_items,
			       size_t item_sz,
			       bool with_states)
{
	void *items = NULL;
	int *states = NULL;

	bzero(batch, sizeof(*batch));

	if (num_items) {
		items = malloc(item_sz * num_items);
		if (!items)
			return -1;

		bzero(items, item_sz * num_items);
	}

	if (with_states && num_items) {
		states = malloc(sizeof(*states) * num_items);
		if (!states) {
			free(items);
			return -1;
		}

		bzero(states, sizeof(*states) * num_items);
	}

	batch->num_items = num_items;
	batch->item_sz = item_sz;
	batch->items = (__u64)items;
	batch->states = (__u64)states;

	return 0;
}

static void scmi_tlm_batch_free(struct scmi_tlm_batch *batch)
{
	free((void *)batch->items);
	free((void *)batch->states);
	bzero(batch, sizeof(*batch));
}

static __attribute__((constructor)) void scmi_tlm_initialize(void)
{
	struct scmi_tlm_batch batch = {};
	int fd, ret;

	fd = open("/dev/scmi/" TLM_0, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "INIT: device not available\n");
		return;
	}

	ksft_session.info.size = sizeof(struct scmi_tlm_abi_info);
	ret = ioctl(fd, SCMI_TLM_GET_ABI_INFO, &ksft_session.info);
	if (ret) {
		fprintf(stderr, "INIT: failed to get ABI info\n");
		goto out;
	}

	if (ksft_session.info.abi_version != SCMI_TLM_ABI_VERSION_V1) {
		fprintf(stderr, "INIT: ABI Version %u NOT supported",
			ksft_session.info.abi_version);
		goto out;
	}

	if (ksft_session.info.num_des) {
		ret = scmi_tlm_batch_init(&batch, ksft_session.info.num_des,
					  sizeof(*ksft_session.de_list), false);
		if (!ret) {
			ret = ioctl(fd, SCMI_TLM_GET_DE_LIST, &batch);
			if (!ret) {
				ksft_session.de_list = (struct scmi_tlm_de_info *)batch.items;
				ksft_session.num_des = batch.num_items;
			} else {
				scmi_tlm_batch_free(&batch);
			}
		}
	}

	if (ksft_session.info.num_intervals) {
		int num_intervals = ksft_session.info.num_intervals;
		struct scmi_tlm_update_interval *intervals;

		intervals = malloc(sizeof(*intervals) * num_intervals);
		if (!intervals) {
			fprintf(stderr, "INIT: Failed to allocate intervals");
			goto out;
		}

		bzero(intervals, sizeof(*intervals) * num_intervals);

		ksft_session.intervals = intervals;
		ksft_session.available.intervals = (__u64)intervals;
		ksft_session.available.num_intervals = num_intervals;

		ret = ioctl(fd, SCMI_TLM_GET_INTRVS, &ksft_session.available);
		if (ret) {
			fprintf(stderr, "INIT: Failed to retrieve intervals");
			free(intervals);
			goto out;
		}
	}

	fprintf(stdout, "INIT: Found ABI version %u\n",
		ksft_session.info.abi_version);
	fprintf(stdout, "INIT: Discovered %u global update intervals\n",
		ksft_session.available.num_intervals);

	ksft_session.original_cfg = malloc(sizeof(*ksft_session.original_cfg));
	if (ksft_session.original_cfg) {
		bzero(ksft_session.original_cfg, sizeof(*ksft_session.original_cfg));

		ret = ioctl(fd, SCMI_TLM_GET_CFG, ksft_session.original_cfg);
		if (ret) {
			free(ksft_session.original_cfg);
			ksft_session.original_cfg = NULL;
		}
	}

	ksft_session.initialized = true;

out:
	close(fd);
}

TEST(scmi_tlm_config_struct_layout) {
	ASSERT_EQ(24, sizeof(struct scmi_tlm_config));
	ASSERT_EQ(0,  offsetof(struct scmi_tlm_config, enable));
	ASSERT_EQ(1, offsetof(struct scmi_tlm_config, t_enable));
	ASSERT_EQ(2, offsetof(struct scmi_tlm_config, flags));
	ASSERT_EQ(3, offsetof(struct scmi_tlm_config, pad));
	ASSERT_EQ(4, offsetof(struct scmi_tlm_config, grp_id));
	ASSERT_EQ(8, offsetof(struct scmi_tlm_config, active));
	ASSERT_EQ(16, offsetof(struct scmi_tlm_config, reserved));
}

TEST(scmi_tlm_abi_info_struct_layout) {
	ASSERT_EQ(56, sizeof(struct scmi_tlm_abi_info));
	ASSERT_EQ(0, offsetof(struct scmi_tlm_abi_info, size));
	ASSERT_EQ(4, offsetof(struct scmi_tlm_abi_info, abi_version));
	ASSERT_EQ(8, offsetof(struct scmi_tlm_abi_info, abi_features));
	ASSERT_EQ(12, offsetof(struct scmi_tlm_abi_info, primary_de_impl_version));
	ASSERT_EQ(28, offsetof(struct scmi_tlm_abi_info, num_des));
	ASSERT_EQ(32, offsetof(struct scmi_tlm_abi_info, num_groups));
	ASSERT_EQ(36, offsetof(struct scmi_tlm_abi_info, num_intervals));
	ASSERT_EQ(40, offsetof(struct scmi_tlm_abi_info, num_shmtis));
	ASSERT_EQ(44, offsetof(struct scmi_tlm_abi_info, features));
	ASSERT_EQ(48, offsetof(struct scmi_tlm_abi_info, reserved));
}

TEST(scmi_tlm_update_interval_struct_layout) {
	ASSERT_EQ(8, sizeof(struct scmi_tlm_update_interval));
	ASSERT_EQ(0, offsetof(struct scmi_tlm_update_interval, secs));
	ASSERT_EQ(4, offsetof(struct scmi_tlm_update_interval, exp));
}

TEST(scmi_tlm_intervals_struct_layout) {
	ASSERT_EQ(32, sizeof(struct scmi_tlm_intervals));
	ASSERT_EQ(0, offsetof(struct scmi_tlm_intervals, grp_id));
	ASSERT_EQ(4, offsetof(struct scmi_tlm_intervals, flags));
	ASSERT_EQ(5, offsetof(struct scmi_tlm_intervals, pad));
	ASSERT_EQ(8, offsetof(struct scmi_tlm_intervals, num_intervals));
	ASSERT_EQ(12, offsetof(struct scmi_tlm_intervals, pad2));
	ASSERT_EQ(16, offsetof(struct scmi_tlm_intervals, reserved));
	ASSERT_EQ(24, offsetof(struct scmi_tlm_intervals, intervals));
}

TEST(scmi_tlm_de_config_struct_layout) {
	ASSERT_EQ(48, sizeof(struct scmi_tlm_de_config));
	ASSERT_EQ(0, offsetof(struct scmi_tlm_de_config, id));
	ASSERT_EQ(4, offsetof(struct scmi_tlm_de_config, enable));
	ASSERT_EQ(8, offsetof(struct scmi_tlm_de_config, t_enable));
	ASSERT_EQ(12, offsetof(struct scmi_tlm_de_config, sid));
	ASSERT_EQ(16, offsetof(struct scmi_tlm_de_config, offset));
	ASSERT_EQ(20, offsetof(struct scmi_tlm_de_config, pad));
	ASSERT_EQ(24, offsetof(struct scmi_tlm_de_config, uuid));
	ASSERT_EQ(40, offsetof(struct scmi_tlm_de_config, reserved));
}

TEST(scmi_tlm_de_info_struct_layout) {
	ASSERT_EQ(72, sizeof(struct scmi_tlm_de_info));
	ASSERT_EQ(0, offsetof(struct scmi_tlm_de_info, id));
	ASSERT_EQ(4, offsetof(struct scmi_tlm_de_info, grp_id));
	ASSERT_EQ(8, offsetof(struct scmi_tlm_de_info, data_sz));
	ASSERT_EQ(12, offsetof(struct scmi_tlm_de_info, type));
	ASSERT_EQ(16, offsetof(struct scmi_tlm_de_info, unit));
	ASSERT_EQ(20, offsetof(struct scmi_tlm_de_info, unit_exp));
	ASSERT_EQ(24, offsetof(struct scmi_tlm_de_info, ts_rate));
	ASSERT_EQ(28, offsetof(struct scmi_tlm_de_info, instance_id));
	ASSERT_EQ(32, offsetof(struct scmi_tlm_de_info, compo_instance_id));
	ASSERT_EQ(36, offsetof(struct scmi_tlm_de_info, compo_type));
	ASSERT_EQ(40, offsetof(struct scmi_tlm_de_info, persistent));
	ASSERT_EQ(41, offsetof(struct scmi_tlm_de_info, flags));
	ASSERT_EQ(42, offsetof(struct scmi_tlm_de_info, pad));
	ASSERT_EQ(44, offsetof(struct scmi_tlm_de_info, pad2));
	ASSERT_EQ(48, offsetof(struct scmi_tlm_de_info, name));
	ASSERT_EQ(64, offsetof(struct scmi_tlm_de_info, reserved));
}

TEST(scmi_tlm_de_sample_struct_layout) {
	ASSERT_EQ(24, sizeof(struct scmi_tlm_de_sample));
	ASSERT_EQ(0, offsetof(struct scmi_tlm_de_sample, id));
	ASSERT_EQ(4, offsetof(struct scmi_tlm_de_sample, pad));
	ASSERT_EQ(8, offsetof(struct scmi_tlm_de_sample, tstamp));
	ASSERT_EQ(16, offsetof(struct scmi_tlm_de_sample, val));
}

TEST(scmi_tlm_data_read_struct_layout) {
	ASSERT_EQ(24, sizeof(struct scmi_tlm_data_read));
	ASSERT_EQ(0, offsetof(struct scmi_tlm_data_read, grp_id));
	ASSERT_EQ(4, offsetof(struct scmi_tlm_data_read, flags));
	ASSERT_EQ(5, offsetof(struct scmi_tlm_data_read, pad));
	ASSERT_EQ(8, offsetof(struct scmi_tlm_data_read, pad2));
	ASSERT_EQ(12, offsetof(struct scmi_tlm_data_read, num_samples));
	ASSERT_EQ(16, offsetof(struct scmi_tlm_data_read, samples));
}

TEST(scmi_tlm_batch_struct_layout) {
	ASSERT_EQ(32, sizeof(struct scmi_tlm_batch));
	ASSERT_EQ(0, offsetof(struct scmi_tlm_batch, num_items));
	ASSERT_EQ(4, offsetof(struct scmi_tlm_batch, item_sz));
	ASSERT_EQ(8, offsetof(struct scmi_tlm_batch, reserved));
	ASSERT_EQ(16, offsetof(struct scmi_tlm_batch, states));
	ASSERT_EQ(24, offsetof(struct scmi_tlm_batch, items));
}

TEST(scmi_tlm_grp_info_struct_layout) {
	ASSERT_EQ(24, sizeof(struct scmi_tlm_grp_info));
	ASSERT_EQ(0, offsetof(struct scmi_tlm_grp_info, grp_id));
	ASSERT_EQ(4, offsetof(struct scmi_tlm_grp_info, num_des));
	ASSERT_EQ(8, offsetof(struct scmi_tlm_grp_info, num_intervals));
	ASSERT_EQ(12, offsetof(struct scmi_tlm_grp_info, pad));
	ASSERT_EQ(16, offsetof(struct scmi_tlm_grp_info, reserved));
}

TEST(scmi_tlm_grp_desc_struct_layout) {
	ASSERT_EQ(24, sizeof(struct scmi_tlm_grp_desc));
	ASSERT_EQ(0, offsetof(struct scmi_tlm_grp_desc, grp_id));
	ASSERT_EQ(4, offsetof(struct scmi_tlm_grp_desc, num_des));
	ASSERT_EQ(8, offsetof(struct scmi_tlm_grp_desc, composing_des));
}

TEST(scmi_tlm_shmti_info_struct_layout) {
	ASSERT_EQ(24, sizeof(struct scmi_tlm_shmti_info));
	ASSERT_EQ(0, offsetof(struct scmi_tlm_shmti_info, sid));
	ASSERT_EQ(4, offsetof(struct scmi_tlm_shmti_info, fd));
	ASSERT_EQ(8, offsetof(struct scmi_tlm_shmti_info, len));
	ASSERT_EQ(12, offsetof(struct scmi_tlm_shmti_info, offset));
	ASSERT_EQ(16, offsetof(struct scmi_tlm_shmti_info, reserved));
}

TEST(scmi_tlm_uuid_struct_layout) {
	ASSERT_EQ(16, sizeof(struct scmi_tlm_uuid));
	ASSERT_EQ(0, offsetof(struct scmi_tlm_uuid, bytes));
}

TEST(scmi_tlm_event_struct_layout) {
	ASSERT_EQ(24, sizeof(struct scmi_tlm_event));
	ASSERT_EQ(0, offsetof(struct scmi_tlm_event, type));
	ASSERT_EQ(4, offsetof(struct scmi_tlm_event, efd));
	ASSERT_EQ(8, offsetof(struct scmi_tlm_event, cookie));
	ASSERT_EQ(12, offsetof(struct scmi_tlm_event, pad));
	ASSERT_EQ(16, offsetof(struct scmi_tlm_event, reserved));
}

FIXTURE(stlm) {
	int fd;
};

FIXTURE_SETUP(stlm) {
	if (!ksft_session.initialized)
		SKIP(return, "initialization failed");

	self->fd = open("/dev/scmi/" TLM_0, O_RDWR);
	if (self->fd < 0)
		SKIP(return, "device not available");

	TH_LOG("Testing ABI Version %u on device %s",
	       ksft_session.info.abi_version, TLM_0);
}

FIXTURE_TEARDOWN(stlm) {
	close(self->fd);
}

TEST_F(stlm, tlm_get_cfg) {
	struct scmi_tlm_config cfg = {};

	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_GET_CFG, &cfg));
	ASSERT_EQ(0, cfg.pad);
	ASSERT_EQ(0, cfg.reserved);
	ASSERT_EQ(0, cfg.flags & ~SCMI_TLM_CONFIG_FLAGS);

	TH_LOG("SCMI_TLM_GET_CFG - ena:%u  t_ena:%u  secs:%u  exp:%d",
	       cfg.enable, cfg.t_enable, cfg.active.secs, cfg.active.exp);

	for (int i = 0; i < ksft_session.info.num_groups; i++) {
		cfg.flags = SCMI_TLM_CONFIG_GROUP;
		cfg.grp_id = i;

		ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_GET_CFG, &cfg));
		ASSERT_EQ(0, cfg.pad);
		ASSERT_EQ(0, cfg.reserved);
		ASSERT_EQ(SCMI_TLM_CONFIG_GROUP, cfg.flags & SCMI_TLM_CONFIG_FLAGS);
		ASSERT_EQ(i, cfg.grp_id);

		TH_LOG("SCMI_TLM_GET_CFG - ena:%u  t_ena:%u  grp_id:%u  secs:%u  exp:%d",
		       cfg.enable, cfg.t_enable, cfg.grp_id, cfg.active.secs, cfg.active.exp);
	}

	/* Invalid GRP ID should be ignored when proper flags missing */
	cfg.grp_id = ksft_session.info.num_groups;
	cfg.flags = 0x0;

	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_GET_CFG, &cfg));
	ASSERT_EQ(0, cfg.pad);
	ASSERT_EQ(0, cfg.reserved);
}

TEST_F(stlm, tlm_get_cfg_bad_group) {
	struct scmi_tlm_config cfg = {};

	cfg.flags = SCMI_TLM_CONFIG_GROUP;
	cfg.grp_id = ksft_session.info.num_groups;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_CFG, &cfg));
	ASSERT_EQ(0, cfg.pad);
	ASSERT_EQ(0, cfg.reserved);
	ASSERT_EQ(0, cfg.flags & ~SCMI_TLM_CONFIG_FLAGS);
}

TEST_F(stlm, tlm_get_cfg_null_ptr_rejected) {
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_CFG, NULL));
	EXPECT_EQ(EFAULT, errno);
}

TEST_F(stlm, tlm_get_cfg_invalid_request) {
	struct scmi_tlm_config cfg = { };

	cfg.pad = 0x1;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_CFG, &cfg));
	EXPECT_EQ(EINVAL, errno);

	cfg.pad = 0x0;
	cfg.reserved = 0x1;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_CFG, &cfg));
	EXPECT_EQ(EINVAL, errno);

	cfg.reserved = 0x0;
	cfg.flags = ~SCMI_TLM_CONFIG_FLAGS;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_CFG, &cfg));
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(stlm, tlm_set_cfg) {
	struct scmi_tlm_config old_cfg = {};
	struct scmi_tlm_config new_cfg = {};
	struct scmi_tlm_config check_cfg = {};

	if (!ksft_session.original_cfg)
		SKIP(return, "original config not available");

	old_cfg = *ksft_session.original_cfg;

	new_cfg = old_cfg;
	new_cfg.enable = !old_cfg.enable;

	if (ksft_session.info.num_intervals > 1) {
		int num_intervals = ksft_session.info.num_intervals;
		struct scmi_tlm_update_interval *intervals;

		intervals = (struct scmi_tlm_update_interval *)ksft_session.available.intervals;
		for (int i = 0; i < num_intervals; i++) {
			if (intervals[i].secs == old_cfg.active.secs &&
			    intervals[i].exp == old_cfg.active.exp)
				continue;

			/* pick another valid interval */
			new_cfg.active.secs = intervals[i].secs;
			new_cfg.active.exp = intervals[i].exp;
			break;
		}
	}

	TH_LOG("SCMI_TLM_SET_CFG - ena:%u  t_ena:%u  secs:%u  exp:%d",
	       new_cfg.enable, new_cfg.t_enable, new_cfg.active.secs, new_cfg.active.exp);

	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_SET_CFG, &new_cfg));
	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_GET_CFG, &check_cfg));
	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_SET_CFG, &old_cfg));

	ASSERT_EQ(new_cfg.enable, check_cfg.enable);
	ASSERT_EQ(new_cfg.active.secs, check_cfg.active.secs);
	ASSERT_EQ(new_cfg.active.exp, check_cfg.active.exp);
	ASSERT_EQ(0, check_cfg.pad);
	ASSERT_EQ(0, check_cfg.reserved);

}

TEST_F(stlm, tlm_get_intrvs) {
	struct scmi_tlm_update_interval *intervals;
	struct scmi_tlm_intervals ivs = {};
	int num_intervals = ksft_session.info.num_intervals;

	if (!num_intervals)
		SKIP(return, "No update intervals available");

	intervals = malloc(sizeof(*intervals) * num_intervals);
	ASSERT_NE(NULL, intervals);
	bzero(intervals, sizeof(*intervals) * num_intervals);

	ivs.num_intervals = num_intervals;
	ivs.intervals = (__u64)intervals;

	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_GET_INTRVS, &ivs));

	ASSERT_EQ(num_intervals, ivs.num_intervals);
	ASSERT_EQ(0, ivs.pad[0]);
	ASSERT_EQ(0, ivs.pad[1]);
	ASSERT_EQ(0, ivs.pad[2]);
	ASSERT_EQ(0, ivs.pad2);
	ASSERT_EQ(0, ivs.reserved);
	ASSERT_EQ(0, ivs.flags & ~SCMI_TLM_INTERV_FLAGS);

	for (int i = 0; i < num_intervals; i++) {
		TH_LOG("SCMI_TLM_GET_INTRVS - [%d] secs:%u exp:%d", i,
		       intervals[i].secs, intervals[i].exp);
	}

	free(intervals);
}

TEST_F(stlm, tlm_get_intrvs_invalid_request) {
	struct scmi_tlm_update_interval interval = {};
	struct scmi_tlm_intervals ivs = {};

	ivs.num_intervals = 1;
	ivs.intervals = (__u64)&interval;
	ivs.pad[0] = 1;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_INTRVS, &ivs));
	EXPECT_EQ(EINVAL, errno);

	bzero(&ivs, sizeof(ivs));
	ivs.num_intervals = 1;
	ivs.intervals = (__u64)&interval;
	ivs.pad2 = 1;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_INTRVS, &ivs));
	EXPECT_EQ(EINVAL, errno);

	bzero(&ivs, sizeof(ivs));
	ivs.num_intervals = 1;
	ivs.intervals = (__u64)&interval;
	ivs.reserved = 1;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_INTRVS, &ivs));
	EXPECT_EQ(EINVAL, errno);

	bzero(&ivs, sizeof(ivs));
	ivs.num_intervals = 1;
	ivs.intervals = (__u64)&interval;
	ivs.flags = ~SCMI_TLM_INTERV_FLAGS;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_INTRVS, &ivs));
}

TEST_F(stlm, tlm_get_intrvs_oversized) {
	struct scmi_tlm_update_interval interval = {};
	struct scmi_tlm_intervals ivs = {};

	ivs.num_intervals = ksft_session.info.num_intervals + 1;
	ivs.intervals = (__u64)&interval;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_INTRVS, &ivs));
	EXPECT_EQ(ENOSPC, errno);
}

TEST_F(stlm, tlm_get_de_list)
{
	struct scmi_tlm_de_info *des;
	struct scmi_tlm_batch batch = {};

	if (!ksft_session.info.num_des)
		SKIP(return, "no DEs available");

	ASSERT_EQ(0, scmi_tlm_batch_init(&batch, ksft_session.info.num_des,
		  sizeof(*des), false));

	des = (struct scmi_tlm_de_info *)batch.items;

	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_GET_DE_LIST, &batch));

	ASSERT_LE(batch.num_items, ksft_session.info.num_des);

	for (int i = 0; i < batch.num_items; i++) {
		ASSERT_EQ(0, des[i].reserved);
		ASSERT_EQ(0, des[i].pad[0]);
		ASSERT_EQ(0, des[i].pad[1]);
		ASSERT_EQ(0, des[i].pad2);
		ASSERT_EQ(0, des[i].flags & ~SCMI_TLM_DEINFO_FLAGS);

		TH_LOG("SCMI_TLM_GET_DE_LIST - [%d] id:0x%x name:%s", i, des[i].id,
		       des[i].name);
	}

	scmi_tlm_batch_free(&batch);
}

TEST_F(stlm, tlm_get_de_list_zero_size_query)
{
	struct scmi_tlm_batch batch = {};

	batch.num_items = 0;
	batch.item_sz = sizeof(struct scmi_tlm_de_info);

	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_GET_DE_LIST, &batch));
	ASSERT_EQ(ksft_session.info.num_des, batch.num_items);
	ASSERT_EQ(sizeof(struct scmi_tlm_de_info), batch.item_sz);
	ASSERT_EQ(0, batch.reserved);
	ASSERT_EQ(0, batch.items);
}

TEST_F(stlm, tlm_get_de_list_zero_size_query_bad_item_sz)
{
	struct scmi_tlm_batch batch = {};

	batch.num_items = 0;
	batch.item_sz = sizeof(struct scmi_tlm_de_info) + 1;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_DE_LIST, &batch));
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(stlm, tlm_get_de_list_invalid_request)
{
	struct scmi_tlm_batch batch = {};
	struct scmi_tlm_de_info de = {};

	batch.num_items = 1;
	batch.item_sz = sizeof(de) + 1;
	batch.items = (__u64)&de;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_DE_LIST, &batch));
	EXPECT_EQ(EINVAL, errno);

	bzero(&batch, sizeof(batch));
	batch.num_items = 1;
	batch.item_sz = sizeof(de);
	batch.reserved = 1;
	batch.items = (__u64)&de;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_DE_LIST, &batch));
	EXPECT_EQ(EINVAL, errno);

	bzero(&batch, sizeof(batch));
	batch.num_items = ksft_session.info.num_des + 1;
	batch.item_sz = sizeof(de);
	batch.items = (__u64)&de;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_DE_LIST, &batch));
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(stlm, tlm_get_de_info)
{
	struct scmi_tlm_de_info info = {};

	if (!ksft_session.de_list || !ksft_session.num_des)
		SKIP(return, "no DE list available");

	info.id = ksft_session.de_list[0].id;

	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_GET_DE_INFO, &info));
	ASSERT_EQ(0, info.reserved);
	ASSERT_EQ(0, info.pad[0]);
	ASSERT_EQ(0, info.pad[1]);
	ASSERT_EQ(0, info.pad2);
	ASSERT_EQ(0, info.flags & ~SCMI_TLM_DEINFO_FLAGS);

	TH_LOG("SCMI_TLM_GET_DE_INFO - id:0x%x name:%s data_sz:%u",
	       info.id, info.name, info.data_sz);
}

TEST_F(stlm, tlm_get_de_info_invalid_request)
{
	struct scmi_tlm_de_info info = {};

	if (!ksft_session.de_list || !ksft_session.num_des)
		SKIP(return, "no DE list available");

	info.id = ksft_session.de_list[0].id;
	info.flags = 1;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_DE_INFO, &info));
	EXPECT_EQ(EINVAL, errno);

	bzero(&info, sizeof(info));
	info.id = ksft_session.de_list[0].id;
	info.pad[0] = 1;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_DE_INFO, &info));
	EXPECT_EQ(EINVAL, errno);

	bzero(&info, sizeof(info));
	info.id = ksft_session.de_list[0].id;
	info.reserved = 1;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_DE_INFO, &info));
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(stlm, tlm_get_de_info_bad_id)
{
	struct scmi_tlm_de_info info = {};

	info.id = 0xffffffff;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_DE_INFO, &info));
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(stlm, tlm_get_de_cfg)
{
	struct scmi_tlm_batch batch = {};
	struct scmi_tlm_de_config *cfg;

	if (!ksft_session.de_list || !ksft_session.num_des)
		SKIP(return, "no DE list available");

	ASSERT_EQ(0, scmi_tlm_batch_init(&batch, 1, sizeof(*cfg), false));

	cfg = (struct scmi_tlm_de_config *)batch.items;
	cfg[0].id = ksft_session.de_list[0].id;

	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_GET_DE_CFG, &batch));
	ASSERT_EQ(1, batch.num_items);
	ASSERT_EQ(ksft_session.de_list[0].id, cfg[0].id);
	ASSERT_EQ(0, cfg[0].reserved);

	TH_LOG("SCMI_TLM_GET_DE_CFG - id:0x%x ena:%u sid:%u offset:%u",
			cfg[0].id, cfg[0].enable, cfg[0].sid,
			cfg[0].offset);

	scmi_tlm_batch_free(&batch);
}

TEST_F(stlm, tlm_get_de_cfg_invalid_request)
{
	struct scmi_tlm_batch batch = {};
	struct scmi_tlm_de_config cfg = {};

	batch.num_items = 1;
	batch.item_sz = sizeof(cfg) + 1;
	batch.items = (__u64)&cfg;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_DE_CFG, &batch));
	EXPECT_EQ(EINVAL, errno);

	bzero(&batch, sizeof(batch));
	batch.num_items = ksft_session.info.num_des + 1;
	batch.item_sz = sizeof(cfg);
	batch.items = (__u64)&cfg;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_DE_CFG, &batch));
	EXPECT_EQ(EINVAL, errno);

	bzero(&batch, sizeof(batch));
	batch.num_items = 1;
	batch.item_sz = sizeof(cfg);
	batch.items = 0;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_DE_CFG, &batch));
	EXPECT_EQ(EFAULT, errno);
}

TEST_F(stlm, tlm_get_de_cfg_bad_id)
{
	struct scmi_tlm_batch batch = {};
	struct scmi_tlm_de_config *cfg;

	ASSERT_EQ(0, scmi_tlm_batch_init(&batch, 1, sizeof(*cfg), false));

	cfg = (struct scmi_tlm_de_config *)batch.items;
	cfg[0].id = 0xffffffff;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_GET_DE_CFG, &batch));
	EXPECT_EQ(ENODEV, errno);

	scmi_tlm_batch_free(&batch);
}

TEST_F(stlm, tlm_get_de_cfg_bad_id_with_states)
{
	struct scmi_tlm_batch batch = {};
	struct scmi_tlm_de_config *cfg;
	int *states;

	ASSERT_EQ(0, scmi_tlm_batch_init(&batch, 1, sizeof(*cfg), true));

	cfg = (struct scmi_tlm_de_config *)batch.items;
	states = (int *)batch.states;

	cfg[0].id = 0xffffffff;

	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_GET_DE_CFG, &batch));
	ASSERT_LT(states[0], 0);

	scmi_tlm_batch_free(&batch);
}

TEST_F(stlm, tlm_de_read)
{
	struct scmi_tlm_de_sample sample = {};
	__u32 de_id;

	if (!ksft_session.de_list || !ksft_session.num_des)
		SKIP(return, "no DE list availalbe");

	de_id = ksft_session.de_list[0].id;
	sample.id = de_id;

	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_DE_READ, &sample));
	ASSERT_EQ(de_id, sample.id);
	ASSERT_EQ(0, sample.pad);

	TH_LOG("SCMI_TLM_DE_READ - id:0x%x tstamp:%llu val:%llu", sample.id,
	       sample.tstamp, sample.val);
}

TEST_F(stlm, tlm_de_read_invalid_request)
{
	struct scmi_tlm_de_sample sample = {};

	if (!ksft_session.de_list || !ksft_session.num_des)
		SKIP(return, "no DE list available");

	sample.id = ksft_session.de_list[0].id;
	sample.pad = 1;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_DE_READ, &sample));
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(stlm, tlm_de_read_null_ptr_rejected)
{
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_DE_READ, NULL));
	EXPECT_EQ(EFAULT, errno);
}

TEST_F(stlm, tlm_de_read_bad_id)
{
	struct scmi_tlm_de_sample sample = {};

	sample.id = 0xffffffff;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_DE_READ, &sample));
	EXPECT_EQ(ENOENT, errno);
}

TEST_F(stlm, tlm_single_read)
{
	struct scmi_tlm_de_sample *samples;
	struct scmi_tlm_data_read read = {};
	int num_samples = ksft_session.num_des;

	if (!ksft_session.de_list || !ksft_session.num_des)
		SKIP(return, "no DE list available");

	samples = malloc(sizeof(*samples) * num_samples);
	ASSERT_NE(NULL, samples);
	bzero(samples, sizeof(*samples) * num_samples);

	read.num_samples = num_samples;
	read.samples = (__u64)samples;

	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_SINGLE_READ, &read));
	ASSERT_LE(read.num_samples, num_samples);
	ASSERT_EQ(0, read.pad[0]);
	ASSERT_EQ(0, read.pad[1]);
	ASSERT_EQ(0, read.pad[2]);
	ASSERT_EQ(0, read.pad2);
	ASSERT_EQ(0, read.flags & ~SCMI_TLM_READ_FLAGS);

	for (int i = 0; i < read.num_samples; i++) {
		ASSERT_EQ(0, samples[i].pad);

		TH_LOG("SCMI_TLM_SINGE_READ = [%d] id:0x%x tstamp:%llu val:%llu", i,
		       samples[i].id, samples[i].tstamp, samples[i].val);
	}

	free(samples);
}

TEST_F(stlm, tlm_single_read_invalid_request)
{
	struct scmi_tlm_de_sample sample = {};
	struct scmi_tlm_data_read read = {};

	read.num_samples = 1;
	read.samples = (__u64)&sample;
	read.pad[0] = 1;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_SINGLE_READ, &read));
	EXPECT_EQ(EINVAL, errno);

	bzero(&read, sizeof(read));
	read.num_samples = 1;
	read.samples = (__u64)&sample;
	read.pad2 = 1;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_SINGLE_READ, &read));
	EXPECT_EQ(EINVAL, errno);

	bzero(&read, sizeof(read));
	read.num_samples = 1;
	read.samples = (__u64)&sample;
	read.flags = ~SCMI_TLM_READ_FLAGS;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_SINGLE_READ, &read));
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(stlm, tlm_single_read_oversized)
{
	struct scmi_tlm_de_sample sample = {};
	struct scmi_tlm_data_read read = {};

	read.num_samples = ksft_session.info.num_des + 1;
	read.samples = (__u64)&sample;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_SINGLE_READ, &read));
	EXPECT_EQ(E2BIG, errno);
}

TEST_F(stlm, tlm_single_read_null_ptr_rejected)
{
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_SINGLE_READ, NULL));
	EXPECT_EQ(EFAULT, errno);
}

TEST_F(stlm, tlm_bulk_read)
{
	struct scmi_tlm_de_sample *samples;
	struct scmi_tlm_data_read read = {};
	int num_samples = ksft_session.num_des;
	int i;

	if (!ksft_session.de_list || !ksft_session.num_des)
		SKIP(return, "no DE list available");

	samples = malloc(sizeof(*samples) * num_samples);
	ASSERT_NE(NULL, samples);
	bzero(samples, sizeof(*samples) * num_samples);

	read.num_samples = num_samples;
	read.samples = (__u64)samples;

	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_BULK_READ, &read));
	ASSERT_LE(read.num_samples, num_samples);
	ASSERT_EQ(0, read.pad[0]);
	ASSERT_EQ(0, read.pad[1]);
	ASSERT_EQ(0, read.pad[2]);
	ASSERT_EQ(0, read.pad2);
	ASSERT_EQ(0, read.flags & ~SCMI_TLM_READ_FLAGS);

	for (i = 0; i < read.num_samples; i++) {
		ASSERT_EQ(0, samples[i].pad);

		TH_LOG("SCMI_TLM_BULK_READ - [%d] id:0x%x tstamp:%llu val:%llu", i,
		       samples[i].id, samples[i].tstamp, samples[i].val);
	}

	free(samples);
}

TEST_F(stlm, tlm_bulk_read_invalid_request)
{
	struct scmi_tlm_de_sample sample = {};
	struct scmi_tlm_data_read read = {};

	read.num_samples = 1;
	read.samples = (__u64)&sample;
	read.pad[0] = 1;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_BULK_READ, &read));
	EXPECT_EQ(EINVAL, errno);

	bzero(&read, sizeof(read));
	read.num_samples = 1;
	read.samples = (__u64)&sample;
	read.pad2 = 1;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_BULK_READ, &read));
	EXPECT_EQ(EINVAL, errno);

	bzero(&read, sizeof(read));
	read.num_samples = 1;
	read.samples = (__u64)&sample;
	read.flags = ~SCMI_TLM_READ_FLAGS;
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_BULK_READ, &read));
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(stlm, tlm_bulk_read_oversized)
{
	struct scmi_tlm_de_sample sample = {};
	struct scmi_tlm_data_read read = {};

	read.num_samples = ksft_session.info.num_des + 1;
	read.samples = (__u64)&sample;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_BULK_READ, &read));
	EXPECT_EQ(E2BIG, errno);
}

TEST_F(stlm, tlm_bulk_read_null_ptr_rejected)
{
	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_BULK_READ, NULL));
	EXPECT_EQ(EFAULT, errno);
}

TEST_F(stlm, tlm_batch_read)
{
	struct scmi_tlm_batch batch = {};
	struct scmi_tlm_de_sample *samples;

	if (!ksft_session.de_list || !ksft_session.num_des)
		SKIP(return, "no DE list available");

	ASSERT_EQ(0, scmi_tlm_batch_init(&batch, 1, sizeof(*samples),
		  false));

	samples = (struct scmi_tlm_de_sample *)batch.items;
	samples[0].id = ksft_session.de_list[0].id;

	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_BATCH_READ, &batch));

	ASSERT_EQ(1, batch.num_items);
	ASSERT_EQ(ksft_session.de_list[0].id, samples[0].id);
	ASSERT_EQ(0, samples[0].pad);

	TH_LOG("SCMI_TLM_BATCH_READ - id:0x%x tstamp:%llu val:%llu", samples[0].id,
	       samples[0].tstamp, samples[0].val);

	scmi_tlm_batch_free(&batch);
}

TEST_F(stlm, tlm_batch_read_invalid_request)
{
	struct scmi_tlm_batch batch = {};
	struct scmi_tlm_de_sample sample = {};

	batch.num_items = 1;
	batch.item_sz = sizeof(sample) + 1;
	batch.items = (__u64)&sample;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_BATCH_READ, &batch));
	EXPECT_EQ(EINVAL, errno);

	bzero(&batch, sizeof(batch));
	batch.num_items = 1;
	batch.item_sz = sizeof(sample);
	batch.reserved = 1;
	batch.items = (__u64)&sample;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_BATCH_READ, &batch));
	EXPECT_EQ(EINVAL, errno);

	bzero(&batch, sizeof(batch));
	batch.num_items = ksft_session.info.num_des + 1;
	batch.item_sz = sizeof(sample);
	batch.items = (__u64)&sample;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_BATCH_READ, &batch));
	EXPECT_EQ(EINVAL, errno);
}

TEST_F(stlm, tlm_batch_read_bad_items_ptr)
{
	struct scmi_tlm_batch batch = {};

	batch.num_items = 1;
	batch.item_sz = sizeof(struct scmi_tlm_de_sample);
	batch.items = 0;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_BATCH_READ, &batch));
	EXPECT_EQ(EFAULT, errno);
}

TEST_F(stlm, tlm_batch_read_bad_id)
{
	struct scmi_tlm_batch batch = {};
	struct scmi_tlm_de_sample *samples;

	ASSERT_EQ(0, scmi_tlm_batch_init(&batch, 1, sizeof(*samples), false));

	samples = (struct scmi_tlm_de_sample *)batch.items;
	samples[0].id = 0xffffffff;

	ASSERT_EQ(-1, ioctl(self->fd, SCMI_TLM_BATCH_READ, &batch));
	EXPECT_EQ(ENOENT, errno);

	scmi_tlm_batch_free(&batch);
}

TEST_F(stlm, tlm_batch_read_bad_id_with_states)
{
	struct scmi_tlm_batch batch = {};
	struct scmi_tlm_de_sample *samples;
	int *states;

	ASSERT_EQ(0, scmi_tlm_batch_init(&batch, 1, sizeof(*samples), true));

	samples = (struct scmi_tlm_de_sample *)batch.items;
	states = (int *)batch.states;

	samples[0].id = 0xffffffff;

	ASSERT_EQ(0, ioctl(self->fd, SCMI_TLM_BATCH_READ, &batch));
	ASSERT_EQ(-ENOENT, states[0]);

	scmi_tlm_batch_free(&batch);
}

TEST_HARNESS_MAIN   /* generates main() */
