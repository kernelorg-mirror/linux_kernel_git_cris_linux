// SPDX-License-Identifier: GPL-2.0
/*
 * SCMI - System Telemetry Driver
 *
 * Copyright (C) 2026 ARM Ltd.
 */

#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/ctype.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/scmi_protocol.h>
#include <linux/slab.h>
#include <linux/sprintf.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uuid.h>
#include <linux/wait.h>
#include <linux/xarray.h>

#include <uapi/linux/scmi.h>

#define SCMI_TLM_DRIVER		"scmi-telemetry-driver"
#define SCMI_TLM_NUM_DEVS	256

#define MAX_BULK_LINE_CHAR_LENGTH		64

/*
 * Break if inadvertently struct scmi_telemetry_de_sample deviates from the
 * UAPI counterpart struct scmi_tlm_de_sample: this allows more performant
 * single DE reads.
 */
#define SCMI_DE_SAMPLE_BUILD_SANITY_CHECK				  \
({									  \
	BUILD_BUG_ON_MSG(sizeof(struct scmi_telemetry_de_sample) !=	  \
			 sizeof(struct scmi_tlm_de_sample),		  \
			 "UAPI DE sample mismatch !");			  \
	ASSERT_STRUCT_OFFSET(struct scmi_telemetry_de_sample, id,	  \
			     offsetof(struct scmi_tlm_de_sample, id));	  \
	ASSERT_STRUCT_OFFSET(struct scmi_telemetry_de_sample, pad,	  \
			     offsetof(struct scmi_tlm_de_sample, pad));	  \
	ASSERT_STRUCT_OFFSET(struct scmi_telemetry_de_sample, tstamp,	  \
			     offsetof(struct scmi_tlm_de_sample, tstamp));\
	ASSERT_STRUCT_OFFSET(struct scmi_telemetry_de_sample, val,	  \
			     offsetof(struct scmi_tlm_de_sample, val));	  \
})

static dev_t stlm_devt;

/**
 * struct scmi_tlm_setup  - Telemetry setup descriptor
 * @sdev: A reference to the related SCMI device
 * @ph: A reference to the protocol handle to be used with the ops
 * @ops: A reference to the protocol ops
 * @rinfo: A reference to the resource info descriptor
 */
struct scmi_tlm_setup {
	struct scmi_device *sdev;
	struct scmi_protocol_handle *ph;
	const struct scmi_telemetry_proto_ops *ops;
	const struct scmi_telemetry_res_info *rinfo;
};

/**
 * struct scmi_tlm_instance  - Telemetry instance descriptor
 * @id: Progressive number identifying this probed instance.
 * @devt: The dev_t descriptor attached to this instance.
 * @dev: An embedded device structure.
 * @cdev: An embedded CDEV structure.
 * @node: A node to link this in the list of all instances.
 * @tsp: A reference to the telemetry instance setup
 * @info: A reference to this instance SCMI Telemetry info data.
 * @sessions_xa: An XArray holding sessions descriptors, indexed by per-process
 *		 keys (@filp), that in turn contain the Telemetry events
 *		 currently subscribed by this instance of the driver.
 * @sessions_mtx: A mutex to protect sessions_xa
 * @dead_mtx: A mutex to protect @dead
 * @dead: A boolean to indicate when the device has been unboud
 */
struct scmi_tlm_instance {
	unsigned int id;
	dev_t devt;
	struct device dev;
	struct cdev cdev;
	struct list_head node;
	struct scmi_tlm_setup *tsp;
	const struct scmi_telemetry_info *info;
#define SCMI_TLM_EVT_XA_MIN	1
#define scmi_evt_xa_limit	XA_LIMIT(SCMI_TLM_EVT_XA_MIN, UINT_MAX)
	struct xarray sessions_xa;
	/* Protect sessions_xa */
	struct mutex sessions_mtx;
	/* Protect dead */
	struct mutex dead_mtx;
	bool dead;
};

#define cdev_to_instance(c)	container_of(c, struct scmi_tlm_instance, cdev)
#define dev_to_instance(c)	container_of(c, struct scmi_tlm_instance, dev)

struct scmi_tlm_shmti_ctx {
	struct scmi_tlm_instance *ti;
	struct scmi_telemetry_shmti_info *shmti;
	struct kref ref;
};

#define to_shmti_ctx(c)	container_of(c, struct scmi_tlm_shmti_ctx, ref)

struct scmi_tlm_registered_event {
	enum scmi_telemetry_event type;
	struct eventfd_ctx *ctx;
};

struct scmi_tlm_events_session {
	struct xarray events_xa;
	/* Protect events_xa */
	struct mutex events_mtx;
};

static inline void scmi_tlm_to_uapi_abi_info(struct scmi_tlm_abi_info *out,
					     const struct scmi_telemetry_info *in)
{
	out->size = sizeof(*out);
	out->abi_version = SCMI_TLM_CURRENT_ABI_VERSION;
	out->abi_features = SCMI_TLM_ABI_FEAT_RESET | SCMI_TLM_ABI_FEAT_EVENT |
		SCMI_TLM_ABI_FEAT_UUID_LIST | SCMI_TLM_ABI_FEAT_BATCH_STATE |
		SCMI_TLM_ABI_FEAT_BATCHED_CFG | SCMI_TLM_ABI_FEAT_DE_TRACKING;
	export_uuid(out->primary_de_impl_version, &in->base.primary_revision);
	out->num_des = in->base.num_des;
	out->num_groups = in->base.num_groups;
	out->num_intervals = in->base.num_intervals;
	out->num_shmtis = in->base.num_shmtis;
	out->features = in->reset_support ? SCMI_TLM_SCMI_SUPPORT_RESET : 0;
	out->features |= in->single_read_support ?
		SCMI_TLM_SCMI_SUPPORT_SINGLE_SAMPLE : 0;
	out->features |= in->per_group_config_support ?
		SCMI_TLM_SCMI_SUPPORT_GROUP_CONFIG : 0;
	out->features |= in->continuous_update_support ?
		SCMI_TLM_SCMI_SUPPORT_UPDATE_NOTIFICATION : 0;
}

static inline void
scmi_tlm_to_uapi_intervals(struct scmi_tlm_intervals *out,
			   struct scmi_telemetry_intervals *in,
			   struct scmi_tlm_update_interval *out_interv)
{
	unsigned int *in_interv = in->update_intervals;

	out->flags |= in->discrete ? SCMI_TLM_INTERV_DISCRETE : 0;
	for (int i = 0; i < out->num_intervals; i++) {
		out_interv[i].secs =
			SCMI_TLM_GET_UPDATE_INTERVAL_SECS(in_interv[i]);
		out_interv[i].exp =
			SCMI_TLM_GET_UPDATE_INTERVAL_EXP(in_interv[i]);
	}
}

static inline void scmi_tlm_to_uapi_de_info(struct scmi_tlm_de_info *out,
					    struct scmi_telemetry_de_info *in)
{
	out->id = in->id;
	out->grp_id = in->grp_id;
	out->data_sz = in->data_sz;
	out->type = in->type;
	out->unit = in->unit;
	out->unit_exp = in->unit_exp;
	out->ts_rate = in->ts_rate;
	out->instance_id = in->instance_id;
	out->compo_instance_id = in->compo_instance_id;
	out->compo_type = in->compo_type;
	out->persistent = !!in->persistent;
	out->flags = in->grp_id != SCMI_TLM_GRP_INVALID ?
		SCMI_TLM_DEINFO_GROUP : 0;
	out->pad[0] = 0;
	out->pad[1] = 0;
	out->pad2 = 0;
	memcpy(out->name, in->name, 16);
}

static inline void
scmi_tlm_to_uapi_des_items(unsigned int num_des,
			   const struct scmi_telemetry_res_info *in,
			   struct scmi_tlm_de_info *des)
{
	for (int i = 0; i < num_des; i++)
		scmi_tlm_to_uapi_de_info(&des[i], &in->dei_store[i]);
}

static inline void scmi_tlm_to_uapi_grp_info(struct scmi_tlm_grp_info *out,
					     struct scmi_telemetry_grp_info *in)
{
	out->grp_id = in->grp_id;
	out->num_des = in->num_des;
	out->num_intervals = in->num_intervals;
	out->pad = 0;
}

static inline void
scmi_tlm_to_uapi_grps_list(unsigned int num_groups,
			   const struct scmi_telemetry_res_info *in,
			   struct scmi_tlm_grp_info *ginfo)
{
	struct scmi_tlm_grp_info *out_ginfo = ginfo;

	for (int i = 0; i < num_groups; i++)
		scmi_tlm_to_uapi_grp_info(&out_ginfo[i], &in->grps_store[i]);
}

static inline void
scmi_tlm_to_uapi_composing_des(struct scmi_tlm_grp_desc *out,
			       const struct scmi_telemetry_res_info *in,
			       u32 *composing_des)
{
	struct scmi_telemetry_group *grp = &in->grps[out->grp_id];

	for (int i = 0; i < out->num_des; i++)
		composing_des[i] = in->des[grp->des[i]]->info->id;
}

/**
 * scmi_telemetry_res_info_get  - Resources info getter
 * @tsp: A reference to the telemetry instance setup
 *
 * On first call this helper takes care to retrieve and cache all the resources
 * descriptor from the platform, then, on the following invocations it will
 * always return the cached value.
 */
static inline const struct scmi_telemetry_res_info *
scmi_telemetry_res_info_get(struct scmi_tlm_setup *tsp)
{
	const struct scmi_telemetry_res_info *rinfo;

	if (READ_ONCE(tsp->rinfo))
		return tsp->rinfo;

	rinfo = tsp->ops->res_get(tsp->ph);
	/* Cache the retrieved resource info value */
	smp_store_mb(tsp->rinfo, rinfo);

	return rinfo;
}

static long
scmi_tlm_abi_info_get_ioctl(const struct scmi_tlm_instance *ti, unsigned long arg)
{
	struct scmi_tlm_abi_info base = {};
	void __user *uptr = (void __user *)arg;
	bool ignored_trailing;
	u32 usize;
	int err;

	if (get_user(usize, (u32 __user *)arg))
		return -EFAULT;

	if (usize < offsetofend(struct scmi_tlm_abi_info, reserved))
		return -EINVAL;

	err = copy_struct_from_user(&base, sizeof(base), uptr, usize);
	if (err)
		return err;

	if (base.reserved)
		return -EINVAL;

	scmi_tlm_to_uapi_abi_info(&base, ti->info);
	err = copy_struct_to_user(uptr, usize, &base, sizeof(base),
				  &ignored_trailing);
	if (err)
		return err;

	if (ignored_trailing)
		return -EMSGSIZE;

	return 0;
}

static long
scmi_tlm_config_get_ioctl(const struct scmi_tlm_instance *ti, unsigned long arg)
{
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_config cfg;

	if (copy_from_user(&cfg, uptr, sizeof(cfg)))
		return -EFAULT;

	if (cfg.pad || cfg.reserved || cfg.flags & ~SCMI_TLM_CONFIG_FLAGS)
		return -EINVAL;

	if (!(SCMI_TLM_CONFIG_IS_GROUP(cfg.flags))) {
		unsigned int active = ti->info->active_update_interval;

		cfg.enable = !!ti->info->enabled;
		cfg.active.secs = SCMI_TLM_GET_UPDATE_INTERVAL_SECS(active);
		cfg.active.exp = SCMI_TLM_GET_UPDATE_INTERVAL_EXP(active);
	} else {
		const struct scmi_telemetry_res_info *rinfo;
		struct scmi_telemetry_group *grp;
		unsigned int active;

		rinfo = scmi_telemetry_res_info_get(ti->tsp);
		if (cfg.grp_id >= rinfo->num_groups)
			return -EINVAL;

		grp = &rinfo->grps[cfg.grp_id];
		active = grp->active_update_interval;

		cfg.enable = grp->enabled;
		cfg.t_enable = grp->tstamp_enabled;
		cfg.active.secs = SCMI_TLM_GET_UPDATE_INTERVAL_SECS(active);
		cfg.active.exp = SCMI_TLM_GET_UPDATE_INTERVAL_EXP(active);
	}

	if (copy_to_user(uptr, &cfg, sizeof(cfg)))
		return -EFAULT;

	return 0;
}

static long
scmi_tlm_config_set_ioctl(const struct scmi_tlm_instance *ti, unsigned long arg)
{
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_setup *tsp = ti->tsp;
	struct scmi_tlm_config cfg;
	unsigned int active;
	bool ena, t_ena;

	if (copy_from_user(&cfg, uptr, sizeof(cfg)))
		return -EFAULT;

	if (cfg.pad || cfg.reserved || cfg.flags & ~SCMI_TLM_CONFIG_FLAGS)
		return -EINVAL;

	ena = !!cfg.enable;
	t_ena = !!cfg.t_enable;
	if (!SCMI_TLM_CONFIG_IS_GROUP(cfg.flags)) {
		cfg.grp_id = SCMI_TLM_GRP_INVALID;
	} else {
		int ret;

		ret = tsp->ops->state_set(tsp->ph, true, cfg.grp_id, &ena, &t_ena,
					  NULL, NULL, NULL);
		if (ret)
			return ret;
	}

	active = SCMI_TLM_BUILD_UPDATE_INTERVAL(cfg.active.secs, cfg.active.exp);

	return tsp->ops->collection_configure(tsp->ph, cfg.grp_id, &ena, &active, NULL);
}

static long
scmi_tlm_intervals_get_ioctl(const struct scmi_tlm_instance *ti,
			     unsigned long arg)
{
	struct scmi_telemetry_intervals *tlm_ivs;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_intervals ivs;
	size_t ivs_intrv_sz;

	if (copy_from_user(&ivs, uptr, sizeof(ivs)))
		return -EFAULT;

	if (ivs.pad[0] || ivs.pad[1] || ivs.pad[2] || ivs.pad2 ||
	    ivs.reserved || ivs.flags & ~SCMI_TLM_INTERV_FLAGS)
		return -EINVAL;

	if (!SCMI_TLM_INTERV_IS_GROUP(ivs.flags)) {
		tlm_ivs = ti->info->intervals;
	} else {
		const struct scmi_telemetry_res_info *rinfo;

		rinfo = scmi_telemetry_res_info_get(ti->tsp);
		if (ivs.grp_id >= rinfo->num_groups)
			return -EINVAL;

		tlm_ivs = rinfo->grps[ivs.grp_id].intervals;
	}

	/* Return max interval on zero-query */
	if (!ivs.num_intervals) {
		ivs.num_intervals = tlm_ivs->num_intervals;

		if (copy_to_user(uptr, &ivs, sizeof(ivs)))
			return -EFAULT;

		return 0;
	}

	/* Reject only oversized output buffers */
	if (ivs.num_intervals > tlm_ivs->num_intervals)
		return -ENOSPC;

	ivs_intrv_sz = array_size(ivs.num_intervals,
				  sizeof(struct scmi_tlm_update_interval));
	if (ivs_intrv_sz == SIZE_MAX)
		return -EOVERFLOW;

	/* A local scratch buffer... */
	struct scmi_tlm_update_interval *ivs_intrv __free(kvfree) =
		kvzalloc(ivs_intrv_sz, GFP_KERNEL);
	if (!ivs_intrv)
		return -ENOMEM;

	/* Passing the array as a param avoids dancing with uptr->intervals */
	scmi_tlm_to_uapi_intervals(&ivs, tlm_ivs, ivs_intrv);
	if (copy_to_user(u64_to_user_ptr(ivs.intervals),
			 (void *)ivs_intrv, ivs_intrv_sz))
		return -EFAULT;

	if (copy_to_user(uptr, &ivs, sizeof(ivs)))
		return -EFAULT;

	return 0;
}

static int
scmi_tlm_batch_initialize(void __user *uptr, struct scmi_tlm_batch *batch,
			  size_t item_sz, unsigned int max_items,
			  void **out_items, size_t *out_batch_sz,
			  int **out_states, size_t *out_states_sz)
{
	size_t batch_sz;

	if (copy_from_user(batch, uptr, sizeof(*batch)))
		return -EFAULT;

	if (batch->reserved || batch->item_sz != item_sz ||
	    batch->num_items > max_items)
		return -EINVAL;

	/* Sanity check on user invocation */
	if (!out_items || !out_batch_sz)
		return -EINVAL;

	/* Was a size query ? */
	if (batch->num_items == 0) {
		*out_items = NULL;
		*out_batch_sz = 0;
		return 0;
	}

	batch_sz = array_size(batch->num_items, batch->item_sz);
	if (batch_sz == SIZE_MAX)
		return -EOVERFLOW;

	void *items __free(kvfree) = kvzalloc(batch_sz, GFP_KERNEL);
	if (!items)
		return -ENOMEM;

	/* Read all the requested configs */
	if (copy_from_user(items, u64_to_user_ptr(batch->items), batch_sz))
		return -EFAULT;

	/* Is per-item status required ? */
	if (batch->states) {
		size_t states_sz;

		states_sz = array_size(batch->num_items, sizeof(int));
		if (states_sz == SIZE_MAX)
			return -EOVERFLOW;

		int *states_arr __free(kvfree) = kvzalloc(states_sz, GFP_KERNEL);
		if (!states_arr)
			return -ENOMEM;

		if (out_states)
			*out_states = no_free_ptr(states_arr);
		if (out_states_sz)
			*out_states_sz = states_sz;
	} else {
		if (out_states)
			*out_states = NULL;
		if (out_states_sz)
			*out_states_sz = 0;
	}

	*out_items = no_free_ptr(items);
	*out_batch_sz = batch_sz;

	return 0;
}

static int
scmi_tlm_batch_finalize(void __user *uptr, struct scmi_tlm_batch *batch,
			void *items, int *states, size_t batch_sz,
			size_t states_sz)
{
	if (batch_sz) {
		if (copy_to_user(u64_to_user_ptr(batch->items), items, batch_sz))
			return -EFAULT;

		if (batch->states) {
			if (copy_to_user(u64_to_user_ptr(batch->states),
					 states, states_sz))
				return -EFAULT;
		}
	}

	if (copy_to_user(uptr, batch, sizeof(*batch)))
		return -EFAULT;

	return 0;
}

static long
scmi_tlm_all_de_config_set_ioctl(const struct scmi_tlm_instance *ti,
				 unsigned long arg)
{
	const struct scmi_telemetry_res_info *rinfo;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_de_config tcfg = {};
	bool ena, t_ena;
	int ret = 0;

	if (copy_from_user(&tcfg, uptr, sizeof(tcfg)))
		return -EFAULT;

	if (tcfg.reserved)
		return -EINVAL;

	ena = !!tcfg.enable;
	t_ena = !!tcfg.t_enable;
	rinfo = scmi_telemetry_res_info_get(ti->tsp);
	for (int i = 0; i < rinfo->num_des; i++) {
		int err;

		err = ti->tsp->ops->state_set(ti->tsp->ph, false,
					      rinfo->des[i]->info->id,
					      &ena, &t_ena, NULL, NULL, NULL);
		if (err) {
			/* Carry on BUT report last error */
			ret = err;
			continue;
		}
	}

	return ret;
}

static long
scmi_tlm_all_de_config_get_ioctl(const struct scmi_tlm_instance *ti,
				 unsigned long arg)
{
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_de_config tcfg = {};
	bool ena, t_ena;
	int ret;

	if (copy_from_user(&tcfg, uptr, sizeof(tcfg)))
		return -EFAULT;

	if (tcfg.reserved)
		return -EINVAL;

	ena = !!tcfg.enable;
	t_ena = !!tcfg.t_enable;
	ret = ti->tsp->ops->state_get(ti->tsp->ph, NULL, &ena, &t_ena,
				      NULL, NULL, NULL);
	if (ret)
		return ret;

	tcfg.enable = !!ena;
	tcfg.t_enable = !!t_ena;
	if (copy_to_user(uptr, &tcfg, sizeof(tcfg)))
		return -EFAULT;

	return 0;
}

static long
scmi_tlm_de_config_set_ioctl(const struct scmi_tlm_instance *ti,
			     unsigned long arg)
{
	struct scmi_tlm_de_config *tcfg __free(kvfree) = NULL;
	int ret, *states __free(kvfree) = NULL;
	const struct scmi_telemetry_res_info *rinfo;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_batch batch = {};
	size_t batch_sz, states_sz;

	rinfo = scmi_telemetry_res_info_get(ti->tsp);
	ret = scmi_tlm_batch_initialize(uptr, &batch, sizeof(*tcfg),
					rinfo->num_des, (void **)&tcfg, &batch_sz,
					&states, &states_sz);
	if (ret)
		return ret;

	for (int i = 0; i < batch.num_items; i++) {
		unsigned int sid, offset;
		bool ena, t_ena;
		uuid_t uuid;
		int ret;

		ena = !!tcfg[i].enable;
		t_ena = !!tcfg[i].t_enable;

		ret = ti->tsp->ops->state_set(ti->tsp->ph, false,
					      tcfg[i].id, &ena, &t_ena,
					      &sid, &offset, &uuid);
		if (ret) {
			if (!states)
				return ret;

			states[i] = ret;
			continue;
		}

		tcfg[i].sid = sid;
		tcfg[i].offset = offset;
		export_uuid(tcfg[i].uuid, &uuid);
	}

	/* Return max batch size on zero query */
	if (!batch.num_items)
		batch.num_items = rinfo->num_des;

	return scmi_tlm_batch_finalize(uptr, &batch, tcfg, states, batch_sz,
				       states_sz);
}

static long
scmi_tlm_de_config_get_ioctl(const struct scmi_tlm_instance *ti,
			     unsigned long arg)
{
	struct scmi_tlm_de_config *tcfg __free(kvfree) = NULL;
	int ret, *states __free(kvfree) = NULL;
	const struct scmi_telemetry_res_info *rinfo;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_batch batch = {};
	size_t batch_sz, states_sz;

	rinfo = scmi_telemetry_res_info_get(ti->tsp);
	ret = scmi_tlm_batch_initialize(uptr, &batch, sizeof(*tcfg),
					rinfo->num_des, (void **)&tcfg,
					&batch_sz, &states, &states_sz);
	if (ret)
		return ret;

	for (int i = 0; i < batch.num_items; i++) {
		unsigned int sid = SCMI_TLM_SHMTI_ID_INVALID, offset = 0;
		bool ena, t_ena;
		uuid_t uuid = {};

		ena = !!tcfg[i].enable;
		t_ena = !!tcfg[i].t_enable;
		ret = ti->tsp->ops->state_get(ti->tsp->ph, &tcfg[i].id,
					      &ena, &t_ena, &sid, &offset, &uuid);

		if (ret) {
			if (!states)
				return ret;

			states[i] = ret;
			continue;
		}

		tcfg[i].enable = ena;
		tcfg[i].t_enable = t_ena;
		tcfg[i].sid = sid;
		tcfg[i].offset = offset;
		export_uuid(tcfg[i].uuid, &uuid);
	}

	/* Return max batch size on zero query */
	if (!batch.num_items)
		batch.num_items = rinfo->num_des;

	return scmi_tlm_batch_finalize(uptr, &batch, tcfg, states, batch_sz,
				       states_sz);
}

static long
scmi_tlm_de_info_get_ioctl(const struct scmi_tlm_instance *ti, unsigned long arg)
{
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_setup *tsp = ti->tsp;
	const struct scmi_telemetry_de *de;
	struct scmi_tlm_de_info dei;

	if (copy_from_user(&dei, uptr, sizeof(dei)))
		return -EFAULT;

	/* Flags does NOT make sense in the input param */
	if (dei.pad[0] || dei.pad[1] || dei.flags || dei.reserved)
		return -EINVAL;

	de = tsp->ops->de_lookup(tsp->ph, dei.id);
	if (!de)
		return -EINVAL;

	scmi_tlm_to_uapi_de_info(&dei, de->info);
	if (copy_to_user(uptr, &dei, sizeof(dei)))
		return -EFAULT;

	return 0;
}

static long
scmi_tlm_des_list_get_ioctl(const struct scmi_tlm_instance *ti, unsigned long arg)
{
	struct scmi_tlm_de_info *dei __free(kvfree) = NULL;
	const struct scmi_telemetry_res_info *rinfo;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_batch batch = {};
	size_t batch_sz;
	int ret;

	rinfo = scmi_telemetry_res_info_get(ti->tsp);
	ret = scmi_tlm_batch_initialize(uptr, &batch, sizeof(*dei),
					rinfo->num_des, (void **)&dei, &batch_sz,
					NULL, NULL);
	if (ret)
		return ret;

	/* Passing the array as a param avoids dancing with uptr->intervals */
	if (batch.num_items)
		scmi_tlm_to_uapi_des_items(batch.num_items, rinfo, dei);
	else
		batch.num_items = rinfo->num_des;

	return scmi_tlm_batch_finalize(uptr, &batch, dei, NULL, batch_sz, 0);
}

static long
scmi_tlm_de_value_get_ioctl(const struct scmi_tlm_instance *ti, unsigned long arg)
{
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_setup *tsp = ti->tsp;
	struct scmi_tlm_de_sample sample;
	int ret;

	SCMI_DE_SAMPLE_BUILD_SANITY_CHECK;

	if (copy_from_user(&sample, uptr, sizeof(sample)))
		return -EFAULT;

	if (sample.pad)
		return -EINVAL;

	ret = tsp->ops->de_data_read(tsp->ph,
				     (struct scmi_telemetry_de_sample *)&sample);
	if (ret)
		return ret;

	if (copy_to_user(uptr, &sample, sizeof(sample)))
		return -EFAULT;

	return 0;
}

static long
scmi_tlm_grp_info_get_ioctl(const struct scmi_tlm_instance *ti, unsigned long arg)
{
	const struct scmi_telemetry_res_info *rinfo;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_grp_info ginfo;

	if (copy_from_user(&ginfo, uptr, sizeof(ginfo)))
		return -EFAULT;

	if (ginfo.pad || ginfo.reserved)
		return -EINVAL;

	rinfo = scmi_telemetry_res_info_get(ti->tsp);
	if (ginfo.grp_id >= rinfo->num_groups)
		return -EINVAL;

	scmi_tlm_to_uapi_grp_info(&ginfo, &rinfo->grps_store[ginfo.grp_id]);
	if (copy_to_user(uptr, &ginfo, sizeof(ginfo)))
		return -EFAULT;

	return 0;
}

static long
scmi_tlm_grp_desc_get_ioctl(const struct scmi_tlm_instance *ti, unsigned long arg)
{
	const struct scmi_telemetry_res_info *rinfo;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_grp_desc gdesc;
	size_t composing_sz;

	if (copy_from_user(&gdesc, uptr, sizeof(gdesc)))
		return -EFAULT;

	if (gdesc.reserved)
		return -EINVAL;

	rinfo = scmi_telemetry_res_info_get(ti->tsp);
	if (gdesc.grp_id >= rinfo->num_groups)
		return -EINVAL;

	/* Reject only oversized output buffers */
	if (gdesc.num_des > rinfo->grps_store[gdesc.grp_id].num_des)
		return -ENOSPC;

	composing_sz = array_size(gdesc.num_des, sizeof(u32));
	if (composing_sz == SIZE_MAX)
		return -EOVERFLOW;

	/* A local scratch buffer... */
	u32 *composing_des __free(kvfree) = kvzalloc(composing_sz, GFP_KERNEL);
	if (!composing_des)
		return -ENOMEM;

	/* Passing the array as a param avoids dancing with uptr->intervals */
	scmi_tlm_to_uapi_composing_des(&gdesc, rinfo, composing_des);
	if (copy_to_user(u64_to_user_ptr(gdesc.composing_des), composing_des,
			 composing_sz))
		return -EFAULT;

	if (copy_to_user(uptr, &gdesc, sizeof(gdesc)))
		return -EFAULT;

	return 0;
}

static long
scmi_tlm_grps_list_get_ioctl(const struct scmi_tlm_instance *ti, unsigned long arg)
{
	struct scmi_tlm_grp_info *ginfo __free(kvfree) = NULL;
	const struct scmi_telemetry_res_info *rinfo;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_batch batch = {};
	size_t batch_sz;
	int ret;

	rinfo = scmi_telemetry_res_info_get(ti->tsp);
	ret = scmi_tlm_batch_initialize(uptr, &batch, sizeof(*ginfo),
					rinfo->num_groups, (void **)&ginfo,
					&batch_sz, NULL, NULL);
	if (ret)
		return ret;

	/* Passing the array as a param avoids dancing with uptr->intervals */
	if (batch.num_items)
		scmi_tlm_to_uapi_grps_list(batch.num_items, rinfo, ginfo);
	else
		batch.num_items = rinfo->num_groups;

	return scmi_tlm_batch_finalize(uptr, &batch, ginfo, NULL, batch_sz, 0);
}

static long scmi_tlm_des_read_ioctl(const struct scmi_tlm_instance *ti,
				    unsigned long arg, bool single)
{
	const struct scmi_telemetry_res_info *rinfo;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_setup *tsp = ti->tsp;
	struct scmi_tlm_data_read bulk;
	unsigned int grp_id;
	int ret;

	if (copy_from_user(&bulk, uptr, sizeof(bulk)))
		return -EFAULT;

	if (bulk.pad[0] || bulk.pad[1] || bulk.pad[2] || bulk.pad2 ||
	    bulk.flags & ~SCMI_TLM_READ_FLAGS)
		return -EINVAL;

	/* Check that a reasonably sized buffer has been requested */
	rinfo = scmi_telemetry_res_info_get(tsp);
	if (bulk.num_samples > rinfo->num_des)
		return -E2BIG;

	if (!SCMI_TLM_READ_IS_GROUP(bulk.flags)) {
		grp_id = SCMI_TLM_GRP_INVALID;
	} else {
		if (bulk.grp_id >= rinfo->num_groups)
			return -EINVAL;

		grp_id = bulk.grp_id;
	}

	/* Return max samples on zero-query */
	if (!bulk.num_samples) {
		if (!SCMI_TLM_READ_IS_GROUP(bulk.flags))
			bulk.num_samples = rinfo->num_des;
		else
			bulk.num_samples = rinfo->grps[grp_id].info->num_des;

		if (copy_to_user(uptr, &bulk, sizeof(bulk)))
			return -EFAULT;

		return 0;
	}

	struct scmi_telemetry_de_sample *samples __free(kvfree) =
		kvzalloc_objs(*samples, bulk.num_samples);
	if (!samples)
		return -ENOMEM;

	if (!single)
		ret = tsp->ops->des_bulk_read(tsp->ph, grp_id,
					      &bulk.num_samples, samples);
	else
		ret = tsp->ops->des_sample_get(tsp->ph, grp_id,
					       &bulk.num_samples, samples);
	if (ret)
		return ret;

	if (copy_to_user(u64_to_user_ptr(bulk.samples), samples,
			 bulk.num_samples * sizeof(*samples)))
		return -EFAULT;

	if (copy_to_user(uptr, &bulk, sizeof(bulk)))
		return -EFAULT;

	return 0;
}

static long scmi_tlm_des_batch_read_ioctl(const struct scmi_tlm_instance *ti,
					  unsigned long arg)
{
	struct scmi_telemetry_de_sample *samples __free(kvfree) = NULL;
	int ret, *states __free(kvfree) = NULL;
	const struct scmi_telemetry_res_info *rinfo;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_batch batch = {};
	size_t batch_sz, states_sz;

	rinfo = scmi_telemetry_res_info_get(ti->tsp);
	ret = scmi_tlm_batch_initialize(uptr, &batch, sizeof(*samples),
					rinfo->num_des, (void **)&samples,
					&batch_sz, &states, &states_sz);
	if (ret)
		return ret;

	for (int i = 0; i < batch.num_items; i++) {
		int ret;

		ret = ti->tsp->ops->de_data_read(ti->tsp->ph, &samples[i]);
		if (ret) {
			if (!states)
				return ret;

			states[i] = ret;
			continue;
		}
	}

	/* Return max batch size on zero query */
	if (!batch.num_items)
		batch.num_items = rinfo->num_des;

	return scmi_tlm_batch_finalize(uptr, &batch, samples, states, batch_sz,
				       states_sz);
}

static struct scmi_tlm_shmti_ctx *
scmi_tlm_shmti_ctx_alloc(struct scmi_tlm_instance *ti,
			 struct scmi_telemetry_shmti_info *shmti)
{
	struct scmi_tlm_shmti_ctx *ctx;

	ctx = kzalloc_obj(*ctx);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->shmti = shmti;
	kref_init(&ctx->ref);

	/* Get hold of the Telemetry instance when mmapping */
	get_device(&ti->dev);
	ctx->ti = ti;

	return ctx;
}

static void scmi_tlm_shmti_ctx_release(struct kref *kref)
{
	struct scmi_tlm_shmti_ctx *ctx = to_shmti_ctx(kref);

	put_device(&ctx->ti->dev);

	kfree(ctx);
}

static struct scmi_tlm_shmti_ctx *
scmi_tlm_shmti_ctx_get(struct scmi_tlm_shmti_ctx *ctx)
{
	kref_get(&ctx->ref);

	return ctx;
}

static void scmi_tlm_shmti_ctx_put(struct scmi_tlm_shmti_ctx *ctx)
{
	kref_put(&ctx->ref, scmi_tlm_shmti_ctx_release);
}

static void scmi_tlm_shmti_vma_open(struct vm_area_struct *vma)
{
	scmi_tlm_shmti_ctx_get(vma->vm_private_data);
}

static void scmi_tlm_shmti_vma_close(struct vm_area_struct *vma)
{
	scmi_tlm_shmti_ctx_put(vma->vm_private_data);
}

static const struct vm_operations_struct scmi_tlm_shmti_vm_ops = {
	.open = scmi_tlm_shmti_vma_open,
	.close = scmi_tlm_shmti_vma_close,
};

static int scmi_tlm_shmti_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct scmi_tlm_shmti_ctx *ctx = filp->private_data;
	unsigned long npages, expect, needed, req = vma->vm_end - vma->vm_start;
	phys_addr_t base;
	size_t map_sz;
	int ret;

	if (vma->vm_flags & VM_WRITE)
		return -EPERM;

	if (req < ctx->shmti->len)
		return -EINVAL;

	/* Align & reject oversized requests */
	base = ctx->shmti->phys & PAGE_MASK;
	needed = ctx->shmti->len + ctx->shmti->offset;
	expect = DIV_ROUND_UP(needed, PAGE_SIZE);
	npages = req >> PAGE_SHIFT;
	if (npages > expect)
		return -EINVAL;

	map_sz = PAGE_ALIGN(needed);
	vma->vm_private_data = scmi_tlm_shmti_ctx_get(ctx);
	vma->vm_ops = &scmi_tlm_shmti_vm_ops;
	/* Set appropriate caching attributes */
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	/* Map physical address range into user space */
	ret = vm_iomap_memory(vma, base, map_sz);
	if (ret) {
		scmi_tlm_shmti_ctx_put(ctx);
		return ret;
	}

	return 0;
}

static int scmi_tlm_shmti_release(struct inode *ino, struct file *filp)
{
	scmi_tlm_shmti_ctx_put(filp->private_data);

	return 0;
}

static const struct file_operations scmi_tlm_shmti_fops = {
	.owner = THIS_MODULE,
	.mmap = scmi_tlm_shmti_mmap,
	.release = scmi_tlm_shmti_release,
};

static void
scmi_tlm_allocate_anon_fds(struct scmi_tlm_instance *ti, unsigned int *num_shmtis,
			   struct scmi_tlm_shmti_info *shinfo,
			   struct file **filps)
{
	const struct scmi_telemetry_info *info = ti->info;
	struct device *dev = &ti->tsp->sdev->dev;
	int idx = 0;

	for (int i = 0; i < *num_shmtis; i++) {
		struct scmi_telemetry_shmti_info *shmti = info->shmtis[i];
		struct scmi_tlm_shmti_ctx *ctx;
		struct file *filp;
		int fd;

		fd = get_unused_fd_flags(O_CLOEXEC);
		if (fd < 0) {
			dev_err(dev, "Failed GET_UNUSED_FD for SID: %u\n",
				shmti->sid);
			continue;
		}

		ctx = scmi_tlm_shmti_ctx_alloc(ti, shmti);
		if (IS_ERR(ctx)) {
			dev_err(dev, "Failed CTX_ALLOC for SID: %u\n", shmti->sid);
			put_unused_fd(fd);
			continue;
		}

		filp = anon_inode_getfile(SCMI_TLM_DRIVER, &scmi_tlm_shmti_fops,
					  ctx, O_RDONLY | O_CLOEXEC);
		if (IS_ERR(filp)) {
			scmi_tlm_shmti_ctx_put(ctx);
			put_unused_fd(fd);
			dev_err(dev, "Failed ANON GET_FILE for SID: %u\n",
				shmti->sid);
			continue;
		}

		shinfo[idx].sid = shmti->sid;
		shinfo[idx].fd = fd;
		shinfo[idx].len = shmti->len;
		shinfo[idx].offset = shmti->offset;

		filps[idx++] = filp;
	}

	/* Return effective initialized items */
	*num_shmtis = idx;
}

static inline void
scmi_tlm_anon_fds_free(int num_shmtis, struct scmi_tlm_shmti_info *shinfo,
		       struct file **filps)
{
	for (int i = 0; i < num_shmtis; i++) {
		put_unused_fd(shinfo[i].fd);
		fput(filps[i]);
	}
}

static inline void
scmi_tlm_anon_fds_install(int num_shmtis, struct scmi_tlm_shmti_info *shinfo,
			  struct file **filps)
{
	for (int i = 0; i < num_shmtis; i++)
		fd_install(shinfo[i].fd, filps[i]);
}

static long
scmi_tlm_shmtis_list_get_ioctl(struct scmi_tlm_instance *ti, unsigned long arg)
{
	struct scmi_tlm_shmti_info *shinfo __free(kvfree) = NULL;
	unsigned int max_shmtis = ti->info->base.num_shmtis;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_batch batch = {};
	size_t batch_sz;
	int ret;

	ret = scmi_tlm_batch_initialize(uptr, &batch, sizeof(*shinfo), max_shmtis,
					(void **)&shinfo, &batch_sz, NULL, NULL);
	if (ret)
		return ret;

	if (batch.num_items == 0) {
		batch.num_items = max_shmtis;

		return scmi_tlm_batch_finalize(uptr, &batch, shinfo, NULL,
					       batch_sz, 0);
	}

	struct file **filps __free(kfree) = kzalloc_objs(*filps, batch.num_items);
	if (!filps)
		return -ENOMEM;

	/* Passing the array as a param avoids dancing with uptr->items */
	scmi_tlm_allocate_anon_fds(ti, &batch.num_items, shinfo, filps);
	ret = scmi_tlm_batch_finalize(uptr, &batch, shinfo, NULL, batch_sz, 0);
	if (ret) {
		scmi_tlm_anon_fds_free(batch.num_items, shinfo, filps);
		return ret;
	}

	scmi_tlm_anon_fds_install(batch.num_items, shinfo, filps);

	return 0;
}

static long scmi_tlm_reset_ioctl(const struct scmi_tlm_instance *ti,
				 unsigned long arg)
{
	return ti->tsp->ops->reset(ti->tsp->ph);
}

static long
scmi_tlm_uuid_list_get_ioctl(const struct scmi_tlm_instance *ti,
			     unsigned long arg)
{
	struct scmi_tlm_uuid *uuids __free(kvfree) = NULL;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_batch batch = {};
	unsigned int num_uuids;
	uuid_t **cur_uuids;
	size_t batch_sz;
	int ret;

	/*
	 * Note that UUID array can ONLY grow and it has NOT a known upper
	 * bound, so it does not matter if by the time we grab the cur_uuids
	 * via rcu_dereference() the array has grown in size and we end up
	 * here reading a stale/incomplete set of UUIDs, we will simply
	 * read the new UUIDs next-time: this simplifies allocation.
	 */
	num_uuids = smp_load_acquire(&ti->info->num_uuids);
	ret = scmi_tlm_batch_initialize(uptr, &batch, sizeof(*uuids),
					num_uuids, (void **)&uuids, &batch_sz,
					NULL, NULL);
	if (ret)
		return ret;

	rcu_read_lock();
	cur_uuids = rcu_dereference(ti->info->uuids);
	for (int j = 0; j < batch.num_items; j++)
		export_uuid(uuids[j].bytes, cur_uuids[j]);
	rcu_read_unlock();

	/* Return max batch size on zero query */
	if (!batch.num_items)
		batch.num_items = num_uuids;

	return scmi_tlm_batch_finalize(uptr, &batch, uuids, NULL, batch_sz, 0);
}

static int scmi_tlm_event_subscribe(struct scmi_tlm_instance *ti,
				    struct scmi_tlm_event *evt, void *key)
{
	struct scmi_tlm_events_session *session;
	struct scmi_tlm_registered_event *revt;
	struct eventfd_ctx *ctx;
	u32 cookie;
	int ret;

	scoped_guard(mutex, &ti->sessions_mtx) {
		session = xa_load(&ti->sessions_xa, (unsigned long)key);
		if (!session) {
			/*
			 * Initialize a new session on first call.
			 * Once created successfully initialized sessions are
			 * freed only on final release.
			 */
			session = kzalloc_obj(*session);
			if (!session)
				return -ENOMEM;

			/* Initialize inner with proper flags to support xa_alloc */
			xa_init_flags(&session->events_xa, XA_FLAGS_ALLOC);
			mutex_init(&session->events_mtx);
			ret = xa_insert(&ti->sessions_xa, (unsigned long)key,
					session, GFP_KERNEL);
			if (ret) {
				xa_destroy(&session->events_xa);
				kfree(session);
				return ret;
			}
		}
	}

	ctx = eventfd_ctx_fdget(evt->efd);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	revt = kzalloc_obj(*revt);
	if (!revt) {
		eventfd_ctx_put(ctx);
		return -ENOMEM;
	}

	guard(mutex)(&session->events_mtx);
	revt->ctx = ctx;
	revt->type = evt->type;
	ret = xa_alloc(&session->events_xa, &cookie, revt,
		       scmi_evt_xa_limit, GFP_KERNEL);
	if (ret) {
		eventfd_ctx_put(revt->ctx);
		kfree(revt);
		return ret;
	}

	ret = ti->tsp->ops->event_subscribe(ti->tsp->ph, revt->type, revt->ctx);
	if (ret) {
		xa_erase(&session->events_xa, cookie);
		eventfd_ctx_put(revt->ctx);
		kfree(revt);
		return ret;
	}

	/* Return the allocated cookie */
	evt->cookie = cookie;

	/* Get hold of the instance */
	get_device(&ti->dev);

	return 0;
}

static int scmi_tlm_event_unsubscribe(struct scmi_tlm_instance *ti,
				      struct scmi_tlm_event *evt, void *key)
{
	struct scmi_tlm_events_session *session;
	struct scmi_tlm_registered_event *revt;
	int ret;

	if (!evt->cookie)
		return -EINVAL;

	scoped_guard(mutex, &ti->sessions_mtx) {
		session = xa_load(&ti->sessions_xa, (unsigned long)key);
		if (!session)
			return -ENODEV;
	}

	guard(mutex)(&session->events_mtx);
	revt = xa_load(&session->events_xa, evt->cookie);
	if (!revt)
		return -ENODEV;

	if (revt->type != evt->type)
		return -EINVAL;

	ret = ti->tsp->ops->event_unsubscribe(ti->tsp->ph, revt->type, revt->ctx);
	if (ret)
		return ret;

	/* Clean up the registered event ONLY once successfully unsubscribed */
	xa_erase(&session->events_xa, evt->cookie);
	eventfd_ctx_put(revt->ctx);
	kfree(revt);

	put_device(&ti->dev);

	return 0;
}

static long scmi_tlm_event_subscribe_ioctl(struct scmi_tlm_instance *ti,
					   unsigned long arg, void *session)
{
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_event evt = {};
	int ret;

	if (copy_from_user(&evt, uptr, sizeof(evt)))
		return -EFAULT;

	if (evt.pad || evt.reserved)
		return -EINVAL;

	/* Reject unknown event types */
	if (evt.type > SCMI_TLM_EVT_LAST)
		return -ENODEV;

	if (!evt.cookie) {
		/* Register a per-session new event, returning new cookie */
		ret = scmi_tlm_event_subscribe(ti, &evt, session);
		if (ret)
			return ret;

		if (copy_to_user(uptr, &evt, sizeof(evt))) {
			scmi_tlm_event_unsubscribe(ti, &evt, session);
			return -EFAULT;
		}
	} else {
		/* DE-Register if existent, put context */
		ret = scmi_tlm_event_unsubscribe(ti, &evt, session);
		if (ret)
			return ret;
	}

	return 0;
}

static long scmi_tlm_unlocked_ioctl(struct file *filp, unsigned int cmd,
				    unsigned long arg)
{
	struct scmi_tlm_instance *ti = filp->private_data;
	bool writable = filp->f_mode & FMODE_WRITE;

	guard(mutex)(&ti->dead_mtx);
	if (ti->dead)
		return -ENODEV;

	switch (cmd) {
	case SCMI_TLM_GET_ABI_INFO:
		return scmi_tlm_abi_info_get_ioctl(ti, arg);
	case SCMI_TLM_GET_CFG:
		return scmi_tlm_config_get_ioctl(ti, arg);
	case SCMI_TLM_SET_CFG:
		if (writable)
			return scmi_tlm_config_set_ioctl(ti, arg);
		break;
	case SCMI_TLM_GET_INTRVS:
		return scmi_tlm_intervals_get_ioctl(ti, arg);
	case SCMI_TLM_GET_DE_CFG:
		return scmi_tlm_de_config_get_ioctl(ti, arg);
	case SCMI_TLM_SET_DE_CFG:
		if (writable)
			return scmi_tlm_de_config_set_ioctl(ti, arg);
		break;
	case SCMI_TLM_GET_DE_INFO:
		return scmi_tlm_de_info_get_ioctl(ti, arg);
	case SCMI_TLM_GET_DE_LIST:
		return scmi_tlm_des_list_get_ioctl(ti, arg);
	case SCMI_TLM_DE_READ:
		return scmi_tlm_de_value_get_ioctl(ti, arg);
	case SCMI_TLM_GET_ALL_CFG:
		return scmi_tlm_all_de_config_get_ioctl(ti, arg);
	case SCMI_TLM_SET_ALL_CFG:
		if (writable)
			return scmi_tlm_all_de_config_set_ioctl(ti, arg);
		break;
	case SCMI_TLM_GET_GRP_LIST:
		return scmi_tlm_grps_list_get_ioctl(ti, arg);
	case SCMI_TLM_GET_GRP_INFO:
		return scmi_tlm_grp_info_get_ioctl(ti, arg);
	case SCMI_TLM_GET_GRP_DESC:
		return scmi_tlm_grp_desc_get_ioctl(ti, arg);
	case SCMI_TLM_SINGLE_READ:
		return scmi_tlm_des_read_ioctl(ti, arg, true);
	case SCMI_TLM_BULK_READ:
		return scmi_tlm_des_read_ioctl(ti, arg, false);
	case SCMI_TLM_BATCH_READ:
		return scmi_tlm_des_batch_read_ioctl(ti, arg);
	case SCMI_TLM_GET_SHMTI_LIST:
		return scmi_tlm_shmtis_list_get_ioctl(ti, arg);
	case SCMI_TLM_RESET:
		if (writable)
			return scmi_tlm_reset_ioctl(ti, arg);
		break;
	case SCMI_TLM_GET_UUID_LIST:
		return scmi_tlm_uuid_list_get_ioctl(ti, arg);
	case SCMI_TLM_EVENT_SUBSCRIBE:
		return scmi_tlm_event_subscribe_ioctl(ti, arg, filp);
	default:
		return -ENOTTY;
	}

	return -EPERM;
}

static int scmi_tlm_open(struct inode *ino, struct file *filp)
{
	struct scmi_tlm_instance *ti = cdev_to_instance(ino->i_cdev);

	guard(mutex)(&ti->dead_mtx);
	if (ti->dead)
		return -ENODEV;

	get_device(&ti->dev);

	filp->private_data = ti;

	return nonseekable_open(ino, filp);
}

static void
scmi_tlm_events_session_unsubscribe(struct scmi_tlm_instance *ti,
				    struct scmi_tlm_events_session *session)
{
	unsigned long cookie = SCMI_TLM_EVT_XA_MIN;
	struct device *dev = &ti->tsp->sdev->dev;
	struct scmi_tlm_registered_event *revt;

	lockdep_assert_held(&ti->dead_mtx);

	mutex_lock(&session->events_mtx);

	/* Walk any still registered events and unsubscribe */
	xa_for_each(&session->events_xa, cookie, revt) {
		xa_erase(&session->events_xa, cookie);

		/*
		 * Unsubscribe if still alive...this cleans up the pending
		 * events when a process has not cleaned up properly on its
		 * own on exit. (or died)
		 */
		if (!ti->dead) {
			int ret;

			ret = ti->tsp->ops->event_unsubscribe(ti->tsp->ph,
							      revt->type,
							      revt->ctx);
			if (ret)
				dev_warn(dev,
					 "Failed to unsubscribe event type:%u cookie:%lu\n",
					 revt->type, cookie);
		}

		dev_dbg(dev,
			"Forcibly unsubscribed event type:%u cookie:%lu\n",
			revt->type, cookie);

		eventfd_ctx_put(revt->ctx);
		kfree(revt);

		/* Drop the per-subscribe reference */
		put_device(&ti->dev);
	}

	xa_destroy(&session->events_xa);

	mutex_unlock(&session->events_mtx);

	kfree(session);
}

static int scmi_tlm_release(struct inode *ino, struct file *filp)
{
	struct scmi_tlm_instance *ti = filp->private_data;
	struct scmi_tlm_events_session *session;

	/* Any events at all for this session ?*/
	mutex_lock(&ti->sessions_mtx);
	session = xa_erase(&ti->sessions_xa, (unsigned long)filp);
	mutex_unlock(&ti->sessions_mtx);
	/*
	 * Any STILL subscribed event is cleaned-up here at the final release:
	 * this adddresses the case in which a userspace application had not
	 * properly unsubscribed OR died unexpectedly.
	 */
	if (session) {
		mutex_lock(&ti->dead_mtx);
		scmi_tlm_events_session_unsubscribe(ti, session);
		mutex_unlock(&ti->dead_mtx);
	}

	put_device(&ti->dev);

	return 0;
}

static const struct file_operations stlm_fops = {
	.owner = THIS_MODULE,
	.open = scmi_tlm_open,
	.release = scmi_tlm_release,
	.unlocked_ioctl = scmi_tlm_unlocked_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

static struct scmi_tlm_instance *
scmi_tlm_instance_init(struct scmi_device *sdev,
		       const struct scmi_telemetry_proto_ops *ops,
		       struct scmi_protocol_handle *ph, unsigned int instance_id)
{
	struct scmi_tlm_instance *ti __free(kfree) = kzalloc_obj(*ti);
	if (!ti)
		return ERR_PTR(-ENOMEM);

	struct scmi_tlm_setup *tsp __free(kfree) = kzalloc_obj(*tsp);
	if (!tsp)
		return ERR_PTR(-ENOMEM);

	ti->info = ops->info_get(ph);
	if (!ti->info)
		return dev_err_ptr_probe(&sdev->dev,
					 -EINVAL, "invalid Telemetry info !\n");

	tsp->sdev = sdev;
	tsp->ops = ops;
	tsp->ph = ph;
	ti->tsp = no_free_ptr(tsp);

	ti->id = instance_id;
	/* Keep track of events via per-process sessions */
	xa_init(&ti->sessions_xa);
	mutex_init(&ti->sessions_mtx);

	mutex_init(&ti->dead_mtx);

	return no_free_ptr(ti);
}

static char *scmi_tlm_devnode(const struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0664;

	return kasprintf(GFP_KERNEL, "scmi/%s", dev_name(dev));
}

static struct class stlm_class = {
	.name    = "stlm",
	.devnode = scmi_tlm_devnode,
};

static void scmi_tlm_device_release(struct device *dev)
{
	struct scmi_tlm_instance *ti = dev_to_instance(dev);
	struct scmi_device *sdev = ti->tsp->sdev;

	dev_dbg(&sdev->dev, "Finalizing Telemetry instance %u\n", ti->id);

	kfree(ti->tsp);
	kfree(ti);
}

static int scmi_telemetry_probe(struct scmi_device *sdev)
{
	const struct scmi_handle *handle = sdev->handle;
	struct scmi_protocol_handle *ph;
	struct scmi_tlm_instance *ti;
	unsigned int instance;
	const void *ops;
	int ret;

	if (!handle)
		return -ENODEV;

	instance = handle->id;
	if (instance >= SCMI_TLM_NUM_DEVS)
		return -ENOSPC;

	ops = handle->devm_protocol_get(sdev, sdev->protocol_id, &ph);
	if (IS_ERR(ops))
		return dev_err_probe(&sdev->dev, PTR_ERR(ops),
				     "Cannot access protocol:0x%X\n",
				     sdev->protocol_id);

	ti = scmi_tlm_instance_init(sdev, ops, ph, instance);
	if (IS_ERR(ti))
		return PTR_ERR(ti);

	/*
	 * Setting the platform device as parent to enforce proper ordering
	 * at shutdown and to avoid the need for explicit get/put_device
	 */
	ti->dev.parent = &sdev->dev;
	ti->dev.devt = MKDEV(MAJOR(stlm_devt), MINOR(stlm_devt) + instance);
	ti->dev.class = &stlm_class;
	ti->dev.release = scmi_tlm_device_release;
	device_initialize(&ti->dev);

	ret = dev_set_name(&ti->dev, "tlm_%d", ti->id);
	if (ret)
		goto err_dev;

	cdev_init(&ti->cdev, &stlm_fops);
	ti->cdev.owner = THIS_MODULE;

	ret = cdev_device_add(&ti->cdev, &ti->dev);
	if (ret)
		goto err_dev;

	dev_set_drvdata(&sdev->dev, ti);

	return 0;

err_dev:
	put_device(&ti->dev);

	kfree(ti->tsp);
	kfree(ti);

	return ret;
}

static void scmi_telemetry_remove(struct scmi_device *sdev)
{
	struct scmi_tlm_events_session *session;
	struct scmi_tlm_instance *ti;
	unsigned long index;

	ti = dev_get_drvdata(&sdev->dev);
	if (!ti)
		return;

	scoped_guard(mutex, &ti->dead_mtx) {
		/* Inhibit future opens */
		cdev_device_del(&ti->cdev, &ti->dev);
		/*
		 * Drop any residual session and related events if unbind
		 * happened with some still open event fds.
		 */
		mutex_lock(&ti->sessions_mtx);
		xa_for_each(&ti->sessions_xa, index, session) {
			xa_erase(&ti->sessions_xa, index);
			scmi_tlm_events_session_unsubscribe(ti, session);
		}
		mutex_unlock(&ti->sessions_mtx);
		/* Stop ongoing opens */
		ti->dead = true;
	}

	put_device(&ti->dev);
}

static const struct scmi_device_id scmi_id_table[] = {
	{ SCMI_PROTOCOL_TELEMETRY, "telemetry" },
	{ }
};
MODULE_DEVICE_TABLE(scmi, scmi_id_table);

static struct scmi_driver scmi_telemetry_driver = {
	.name = SCMI_TLM_DRIVER,
	.probe = scmi_telemetry_probe,
	.remove = scmi_telemetry_remove,
	.id_table = scmi_id_table,
};

static int __init scmi_telemetry_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&stlm_devt, 0, SCMI_TLM_NUM_DEVS,
				  SCMI_TLM_DRIVER);
	if (ret)
		return ret;

	ret = class_register(&stlm_class);
	if (ret)
		goto err_class;

	ret = scmi_register(&scmi_telemetry_driver);
	if (ret)
		goto err_scmi;

	return 0;

err_scmi:
	class_unregister(&stlm_class);

err_class:
	unregister_chrdev_region(stlm_devt, SCMI_TLM_NUM_DEVS);

	return ret;
}
module_init(scmi_telemetry_init);

static void __exit scmi_telemetry_exit(void)
{
	scmi_unregister(&scmi_telemetry_driver);
	unregister_chrdev_region(stlm_devt, SCMI_TLM_NUM_DEVS);
	class_unregister(&stlm_class);
}
module_exit(scmi_telemetry_exit);

MODULE_AUTHOR("Cristian Marussi <cristian.marussi@arm.com>");
MODULE_DESCRIPTION("ARM SCMI Telemetry Driver");
MODULE_LICENSE("GPL");
