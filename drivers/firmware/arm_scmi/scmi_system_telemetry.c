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
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/scmi_protocol.h>
#include <linux/slab.h>
#include <linux/sprintf.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include <uapi/linux/scmi.h>

#define SCMI_TLM_DRIVER		"scmi-telemetry-driver"
#define SCMI_TLM_NUM_DEVS	256

#define MAX_BULK_LINE_CHAR_LENGTH		64

/*
 * Break if inadvertently struct scmi_telemetry_de_sample deviates from the
 * UAPI counterpart struct scmi_tlm_de_sample: this allows more performant
 * single DE reads.
 */
#define SCMI_DE_SAMPLE_SANITY_CHECK					\
({									\
	BUILD_BUG_ON_MSG(sizeof(struct scmi_telemetry_de_sample) !=	\
			 sizeof(struct scmi_tlm_de_sample),		\
			 "UAPI DE sample mismatch !");			\
	ASSERT_STRUCT_OFFSET(struct scmi_telemetry_de_sample, id,	\
			     offsetof(struct scmi_tlm_de_sample, id));	\
	ASSERT_STRUCT_OFFSET(struct scmi_telemetry_de_sample, pad,	\
			     offsetof(struct scmi_tlm_de_sample, pad));	\
	ASSERT_STRUCT_OFFSET(struct scmi_telemetry_de_sample, tstamp,	\
			     offsetof(struct scmi_tlm_de_sample, tstamp));\
	ASSERT_STRUCT_OFFSET(struct scmi_telemetry_de_sample, val,	\
			     offsetof(struct scmi_tlm_de_sample, val));	\
})

static dev_t stlm_devt;

struct scmi_tlm_setup;

struct scmi_tlm_priv {
	char *buf;
	size_t buf_sz;
	int buf_len;
	unsigned int num_samples;
	struct scmi_tlm_setup *tsp;
};

/**
 * struct scmi_tlm_setup  - Telemetry setup descriptor
 * @dev: A reference to the related device
 * @ph: A reference to the protocol handle to be used with the ops
 * @rinfo: A reference to the resource info descriptor
 * @ops: A reference to the protocol ops
 */
struct scmi_tlm_setup {
	struct device *dev;
	struct scmi_protocol_handle *ph;
	const struct scmi_telemetry_res_info *rinfo;
	const struct scmi_telemetry_proto_ops *ops;
};

/**
 * struct scmi_tlm_instance  - Telemetry instance descriptor
 * @id: Progressive number identifying this probed instance.
 * @devt: The dev_t descriptor attached to this instance
 * @cdev:
 * @node: A node to link this in the list of all instances.
 * @tsp: A reference to the SCMI instance data.
 * @info: A reference to this instance SCMI Telemetry info data.
 */
struct scmi_tlm_instance {
	unsigned int id;
	dev_t devt;
	struct cdev cdev;
	struct list_head node;
	struct scmi_tlm_setup *tsp;
	const struct scmi_telemetry_info *info;
};

#define to_instance(c)	container_of(c, struct scmi_tlm_instance, cdev)

struct scmi_tlm_shmti_ctx {
	struct scmi_telemetry_shmti_info *shmti;
	struct kref kref;
};

#define to_shmti_ctx(c)	container_of(c, struct scmi_tlm_shmti_ctx, kref)

static int scmi_tlm_buffer_fill(struct device *dev, char *buf, size_t size,
				unsigned int *len, unsigned int num,
				struct scmi_telemetry_de_sample *samples)
{
	unsigned int idx, bytes = 0;

	/* Loop till there space for the next line */
	for (idx = 0; idx < num && size - bytes >= MAX_BULK_LINE_CHAR_LENGTH; idx++) {
		bytes += scnprintf(buf + bytes, size - bytes,
				   "0x%08X %llu %016llX\n", samples[idx].id,
				   samples[idx].tstamp, samples[idx].val);
	}

	if (idx < num) {
		dev_err(dev, "Bulk buffer truncated !\n");
		return -ENOSPC;
	}

	if (len)
		*len = bytes;

	return 0;
}

static int scmi_tlm_bulk_buffer_fill(struct scmi_tlm_priv *tp)
{
	struct scmi_tlm_setup *tsp = tp->tsp;
	int ret;

	struct scmi_telemetry_de_sample *samples __free(kfree) =
		kcalloc(tp->num_samples, sizeof(*samples), GFP_KERNEL);
	if (!samples)
		return -ENOMEM;

	ret = tsp->ops->des_bulk_read(tsp->ph, SCMI_TLM_GRP_INVALID,
				      &tp->num_samples, samples);
	if (ret)
		return ret;

	return scmi_tlm_buffer_fill(tsp->dev, tp->buf, tp->buf_sz, &tp->buf_len,
				    tp->num_samples, samples);
}

static int scmi_tlm_priv_data_open(struct inode *ino, struct file *filp)
{
	struct scmi_tlm_instance *ti = to_instance(ino->i_cdev);

	if (!ti)
		return -ENODEV;

	struct scmi_tlm_priv *tp __free(kfree) = kzalloc_obj(*tp);
	if (!tp)
		return -ENOMEM;

	/* Allocate and empty buffer bug enough to contain all possible DEs */
	tp->num_samples = ti->info->base.num_des;
	tp->buf_sz = tp->num_samples * MAX_BULK_LINE_CHAR_LENGTH;

	/*
	 * Note that tp->buf is a scratch buffer, filled once, used to
	 * support multiple chunked read and freed in
	 * scmi_tlm_priv_release.
	 */
	tp->buf = kzalloc(tp->buf_sz, GFP_KERNEL);
	if (!tp->buf)
		return -ENOMEM;

	tp->tsp = ti->tsp;
	filp->private_data = no_free_ptr(tp);

	return 0;
}

static ssize_t scmi_tlm_priv_read(struct file *filp, char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct scmi_tlm_priv *tp = filp->private_data;

	/*
	 * Retrieve fresh data snapshot on the first read and on each
	 * subsequent seek to zero
	 */
	if (!tp->buf_len || *ppos == 0) {
		int ret;

		ret = scmi_tlm_bulk_buffer_fill(tp);
		if (ret)
			return ret;

		/* update inode timestamps */
		simple_inode_init_ts(file_inode(filp));
	}

	return simple_read_from_buffer(buf, count, ppos, tp->buf, tp->buf_len);
}

static int scmi_tlm_priv_release(struct inode *ino, struct file *filp)
{
	struct scmi_tlm_priv *tp = filp->private_data;

	kfree(tp->buf);
	kfree(tp);

	return 0;
}

static inline void scmi_tlm_to_uapi_base_info(struct scmi_tlm_base_info *out,
					      const struct scmi_telemetry_info *in)
{
	/* This is a trivial copy */
	out->version = in->base.version;
	memcpy(out->de_impl_version, in->base.de_impl_version,
	       sizeof(out->de_impl_version));
	out->num_des = in->base.num_des;
	out->num_groups = in->base.num_groups;
	out->num_intervals = in->base.num_intervals;
	out->num_shmtis = in->base.num_shmtis;
	out->flags |= in->reset_support ? SCMI_TLM_BASE_CAN_RESET : 0;
}

static inline int
scmi_tlm_to_uapi_intervals(struct scmi_tlm_intervals *out,
			   struct scmi_telemetry_intervals *in,
			   struct scmi_tlm_update_interval *out_interv)
{
	unsigned int *in_interv = in->update_intervals;

	/* Does it fit provided param ? */
	if (out->num_intervals < in->num_intervals)
		return -EINVAL;

	for (int i = 0; i < in->num_intervals; i++) {
		out_interv[i].secs =
			SCMI_TLM_GET_UPDATE_INTERVAL_SECS(in_interv[i]);
		out_interv[i].exp =
			SCMI_TLM_GET_UPDATE_INTERVAL_EXP(in_interv[i]);
	}

	/* Just in case less elements where provided */
	out->num_intervals = in->num_intervals;

	return 0;
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

static inline int
scmi_tlm_to_uapi_des_list(struct scmi_tlm_des_list *out,
			  const struct scmi_telemetry_res_info *in,
			  struct scmi_tlm_de_info *des)
{
	struct scmi_tlm_de_info *out_des = des;

	/* Does it fit provided param ? */
	if (out->num_des < in->num_des)
		return -EINVAL;

	for (int i = 0; i < in->num_des; i++)
		scmi_tlm_to_uapi_de_info(&out_des[i], &in->dei_store[i]);

	/* Just in case less elements where provided */
	out->num_des = in->num_des;

	return 0;
}

static inline void scmi_tlm_to_uapi_grp_info(struct scmi_tlm_grp_info *out,
					     struct scmi_telemetry_grp_info *in)
{
	out->grp_id = in->grp_id;
	out->num_des = in->num_des;
	out->num_intervals = in->num_intervals;
	out->pad = 0;
}

static inline int
scmi_tlm_to_uapi_grps_list(struct scmi_tlm_grps_list *out,
			   const struct scmi_telemetry_res_info *in,
			   struct scmi_tlm_grp_info *ginfo)
{
	struct scmi_tlm_grp_info *out_ginfo = ginfo;

	/* Does it fit provided param ? */
	if (out->num_grps < in->num_groups)
		return -EINVAL;

	for (int i = 0; i < in->num_groups; i++)
		scmi_tlm_to_uapi_grp_info(&out_ginfo[i], &in->grps_store[i]);

	/* Just in case less elements where provided */
	out->num_grps = in->num_groups;

	return 0;
}

static inline int
scmi_tlm_to_uapi_composing_des(struct scmi_tlm_grp_desc *out,
			       const struct scmi_telemetry_res_info *in,
			       u32 *composing_des)
{
	struct scmi_telemetry_grp_info *ginfo = &in->grps_store[out->grp_id];
	struct scmi_telemetry_group *grp = &in->grps[out->grp_id];

	/* Does it fit provided param ? */
	if (out->num_des < ginfo->num_des)
		return -EINVAL;

	for (int i = 0; i < ginfo->num_des; i++)
		composing_des[i] = in->des[grp->des[i]]->info->id;

	/* Just in case less elements where provided */
	out->num_des = ginfo->num_des;

	return 0;
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

	if (tsp->rinfo)
		return tsp->rinfo;

	rinfo = tsp->ops->res_get(tsp->ph);
	/* Cache the retrieved resource info value */
	smp_store_mb(tsp->rinfo, rinfo);

	return rinfo;
}

static long
scmi_tlm_info_get_ioctl(const struct scmi_tlm_instance *ti, unsigned long arg)
{
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_base_info base;

	scmi_tlm_to_uapi_base_info(&base, ti->info);
	if (copy_to_user(uptr, &base, sizeof(base)))
		return -EFAULT;

	return 0;
}

static long
scmi_tlm_config_get_ioctl(const struct scmi_tlm_instance *ti, unsigned long arg)
{
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_config cfg;

	if (copy_from_user(&cfg, uptr, sizeof(cfg)))
		return -EFAULT;

	if (cfg.pad || cfg.flags & ~SCMI_TLM_CONFIG_FLAGS)
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

	if (copy_from_user(&cfg, uptr, sizeof(cfg)))
		return -EFAULT;

	if (cfg.pad || cfg.flags & ~SCMI_TLM_CONFIG_FLAGS)
		return -EINVAL;

	if (!SCMI_TLM_CONFIG_IS_GROUP(cfg.flags)) {
		cfg.grp_id = SCMI_TLM_GRP_INVALID;
	} else {
		int ret;

		ret = tsp->ops->state_set(tsp->ph, true, cfg.grp_id,
					  (bool *)&cfg.enable,
					  (bool *)&cfg.t_enable);
		if (ret)
			return ret;
	}

	active = SCMI_TLM_BUILD_UPDATE_INTERVAL(cfg.active.secs, cfg.active.exp);

	return tsp->ops->collection_configure(tsp->ph, cfg.grp_id,
					      (bool *)&cfg.enable, &active, NULL);
}

static long
scmi_tlm_intervals_get_ioctl(const struct scmi_tlm_instance *ti,
			     unsigned long arg)
{
	struct scmi_telemetry_intervals *tlm_ivs;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_intervals ivs;
	size_t ivs_intrv_sz;
	int ret;

	if (copy_from_user(&ivs, uptr, sizeof(ivs)))
		return -EFAULT;

	if (ivs.pad[0] || ivs.pad[1] || ivs.pad[2] || ivs.pad2 ||
	    ivs.flags & ~SCMI_TLM_INTERV_FLAGS)
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

	/* A local scratch buffer... */
	ivs_intrv_sz = ivs.num_intervals * sizeof(struct scmi_tlm_update_interval);
	struct scmi_tlm_update_interval *ivs_intrv __free(kfree) =
		kzalloc(ivs_intrv_sz, GFP_KERNEL);
	if (!ivs_intrv)
		return -ENOMEM;

	if (copy_from_user(ivs_intrv, u64_to_user_ptr(ivs.intervals),
			   ivs_intrv_sz))
		return -EFAULT;

	/* Passing the array as a param avoids dancing with uptr->intervals */
	ret = scmi_tlm_to_uapi_intervals(&ivs, tlm_ivs, ivs_intrv);
	if (ret)
		return ret;

	if (copy_to_user(u64_to_user_ptr(ivs.intervals),
			 (void *)ivs_intrv, ivs_intrv_sz))
		return -EFAULT;

	if (copy_to_user(uptr, &ivs, sizeof(ivs)))
		return -EFAULT;

	return 0;
}

static long
scmi_tlm_de_config_set_ioctl(const struct scmi_tlm_instance *ti,
			     unsigned long arg, bool all)
{
	const struct scmi_telemetry_res_info *rinfo;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_setup *tsp = ti->tsp;
	struct scmi_tlm_de_config tcfg = {};
	int ret;

	if (copy_from_user(&tcfg, uptr, sizeof(tcfg)))
		return -EFAULT;

	if (tcfg.pad)
		return -EINVAL;

	if (!all)
		return tsp->ops->state_set(tsp->ph, false, tcfg.id,
					   (bool *)&tcfg.enable,
					   (bool *)&tcfg.t_enable);

	rinfo = scmi_telemetry_res_info_get(tsp);
	for (int i = 0; i < rinfo->num_des; i++) {
		ret = tsp->ops->state_set(tsp->ph, false,
					  rinfo->des[i]->info->id,
					  (bool *)&tcfg.enable,
					  (bool *)&tcfg.t_enable);
		if (ret)
			return ret;
	}

	return 0;
}

static long
scmi_tlm_de_config_get_ioctl(const struct scmi_tlm_instance *ti,
			     unsigned long arg, bool all)
{
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_setup *tsp = ti->tsp;
	struct scmi_tlm_de_config tcfg;
	int ret;

	if (copy_from_user(&tcfg, uptr, sizeof(tcfg)))
		return -EFAULT;

	if (tcfg.pad)
		return -EINVAL;

	ret = tsp->ops->state_get(tsp->ph, all ? NULL : &tcfg.id,
				  (bool *)&tcfg.enable, (bool *)&tcfg.t_enable);
	if (ret)
		return ret;

	if (copy_to_user(uptr, &tcfg, sizeof(tcfg)))
		return -EFAULT;

	return 0;
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
	if (dei.pad[0] || dei.pad[1] || dei.pad[2] || dei.flags)
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
	const struct scmi_telemetry_res_info *rinfo;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_des_list dsl;
	size_t dsl_des_sz;
	int ret;

	rinfo = scmi_telemetry_res_info_get(ti->tsp);
	if (copy_from_user(&dsl, uptr, sizeof(dsl)))
		return -EFAULT;

	if (dsl.pad || dsl.num_des < rinfo->num_des)
		return -EINVAL;

	/* A local scratch buffer... */
	dsl_des_sz = dsl.num_des * sizeof(struct scmi_tlm_de_info);
	struct scmi_tlm_de_info *dsl_des __free(kfree) =
		kzalloc(dsl_des_sz, GFP_KERNEL);
	if (!dsl_des)
		return -ENOMEM;

	if (copy_from_user(dsl_des, u64_to_user_ptr(dsl.des), dsl_des_sz))
		return -EFAULT;

	/* Passing the array as a param avoids dancing with uptr->intervals */
	ret = scmi_tlm_to_uapi_des_list(&dsl, rinfo, dsl_des);
	if (ret)
		return ret;

	if (copy_to_user(u64_to_user_ptr(dsl.des), (void *)dsl_des, dsl_des_sz))
		return -EFAULT;

	if (copy_to_user(uptr, &dsl, sizeof(dsl)))
		return -EFAULT;

	return 0;
}

static long
scmi_tlm_de_value_get_ioctl(const struct scmi_tlm_instance *ti, unsigned long arg)
{
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_setup *tsp = ti->tsp;
	struct scmi_tlm_de_sample sample;
	int ret;

	SCMI_DE_SAMPLE_SANITY_CHECK;

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

	if (ginfo.pad)
		return -EINVAL;

	rinfo = scmi_telemetry_res_info_get(ti->tsp);
	if (ginfo.grp_id > rinfo->num_groups)
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
	int ret;

	if (copy_from_user(&gdesc, uptr, sizeof(gdesc)))
		return -EFAULT;

	rinfo = scmi_telemetry_res_info_get(ti->tsp);
	if (gdesc.grp_id > rinfo->num_groups)
		return -EINVAL;

	/* A local scratch buffer... */
	composing_sz = gdesc.num_des * sizeof(u32);
	u32 *composing_des __free(kfree) = kzalloc(composing_sz, GFP_KERNEL);
	if (!composing_des)
		return -ENOMEM;

	if (copy_from_user(composing_des, u64_to_user_ptr(gdesc.composing_des),
			   composing_sz))
		return -EFAULT;

	/* Passing the array as a param avoids dancing with uptr->intervals */
	ret = scmi_tlm_to_uapi_composing_des(&gdesc, rinfo, composing_des);
	if (ret)
		return ret;

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
	const struct scmi_telemetry_res_info *rinfo;
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_grps_list gsl;
	size_t ginfo_sz;
	int ret;

	if (copy_from_user(&gsl, uptr, sizeof(gsl)))
		return -EFAULT;

	if (gsl.pad)
		return -EINVAL;

	rinfo = scmi_telemetry_res_info_get(ti->tsp);
	if (gsl.num_grps < rinfo->num_groups)
		return -EINVAL;

	/* A local scratch buffer... */
	ginfo_sz = gsl.num_grps * sizeof(struct scmi_tlm_grp_info);
	struct scmi_tlm_grp_info *ginfo __free(kfree) =
		kzalloc(ginfo_sz, GFP_KERNEL);
	if (!ginfo)
		return -ENOMEM;

	if (copy_from_user(ginfo, u64_to_user_ptr(gsl.grps), ginfo_sz))
		return -EFAULT;

	ret = scmi_tlm_to_uapi_grps_list(&gsl, rinfo, ginfo);
	if (ret)
		return ret;

	if (copy_to_user(u64_to_user_ptr(gsl.grps), ginfo, ginfo_sz))
		return -EFAULT;

	if (copy_to_user(uptr, &gsl, sizeof(gsl)))
		return -EFAULT;

	return 0;
}

static long scmi_tlm_des_read_ioctl(const struct scmi_tlm_instance *ti,
				    unsigned long arg, bool single)
{
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

	if (!SCMI_TLM_READ_IS_GROUP(bulk.flags)) {
		grp_id = SCMI_TLM_GRP_INVALID;
	} else {
		const struct scmi_telemetry_res_info *rinfo;

		rinfo = scmi_telemetry_res_info_get(tsp);
		if (bulk.grp_id >= rinfo->num_groups)
			return -EINVAL;

		grp_id = bulk.grp_id;
	}

	struct scmi_telemetry_de_sample *samples __free(kfree) =
		kcalloc(bulk.num_samples, sizeof(*samples), GFP_KERNEL);
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
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_setup *tsp = ti->tsp;
	struct scmi_tlm_data_read batch;
	int ret;

	if (copy_from_user(&batch, uptr, sizeof(batch)))
		return -EFAULT;

	if (batch.pad[0] || batch.pad[1] || batch.pad[2] || batch.pad2 ||
	    batch.flags & ~SCMI_TLM_READ_FLAGS)
		return -EINVAL;

	struct scmi_telemetry_de_sample *samples __free(kfree) =
		kcalloc(batch.num_samples, sizeof(*samples), GFP_KERNEL);
	if (!samples)
		return -ENOMEM;

	/* Read all the requested samples */
	if (copy_from_user(samples, u64_to_user_ptr(batch.samples),
			   batch.num_samples * sizeof(*samples)))
		return -EFAULT;

	for (int i = 0; i < batch.num_samples; i++) {
		ret = tsp->ops->de_data_read(tsp->ph, &samples[i]);
		if (ret)
			return -EINVAL;
	}

	if (copy_to_user(u64_to_user_ptr(batch.samples), samples,
			 batch.num_samples * sizeof(*samples)))
		return -EFAULT;

	if (copy_to_user(uptr, &batch, sizeof(batch)))
		return -EFAULT;

	return 0;
}

static struct scmi_tlm_shmti_ctx *
scmi_tlm_shmti_ctx_alloc(struct scmi_telemetry_shmti_info *shmti)
{
	struct scmi_tlm_shmti_ctx *ctx;

	ctx = kzalloc_obj(*ctx);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->shmti = shmti;
	kref_init(&ctx->kref);

	return ctx;
}

static void scmi_tlm_shmti_ctx_release(struct kref *kref)
{
	struct scmi_tlm_shmti_ctx *ctx = to_shmti_ctx(kref);

	kfree(ctx);
}

static struct scmi_tlm_shmti_ctx *
scmi_tlm_shmti_ctx_get(struct scmi_tlm_shmti_ctx *ctx)
{
	kref_get(&ctx->kref);

	return ctx;
}

static void scmi_tlm_shmti_ctx_put(struct scmi_tlm_shmti_ctx *ctx)
{
	kref_put(&ctx->kref, scmi_tlm_shmti_ctx_release);
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
	unsigned long req = vma->vm_end - vma->vm_start;
	phys_addr_t base;
	size_t map_sz;
	int ret;

	if (vma->vm_flags & VM_WRITE)
		return -EPERM;

	if (req < ctx->shmti->len)
		return -EINVAL;

	/* Align */
	base = ctx->shmti->phys & PAGE_MASK;
	map_sz = PAGE_ALIGN(ctx->shmti->offset + req);

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

static int
scmi_tlm_allocate_anon_fds(const struct scmi_telemetry_info *in,
			   struct scmi_tlm_shmtis_list *out,
			   struct scmi_tlm_shmti_info *shinfo)
{
	unsigned int num_shmtis;

	if (out->num_shmtis < in->base.num_shmtis)
		return -EINVAL;

	/* Count effectively returned ... */
	num_shmtis = out->num_shmtis;
	out->num_shmtis = 0;

	for (int i = 0; i < num_shmtis; i++) {
		struct scmi_telemetry_shmti_info *shmti = in->shmtis[i];
		struct scmi_tlm_shmti_ctx *ctx;
		int fd;

		ctx = scmi_tlm_shmti_ctx_alloc(shmti);
		if (IS_ERR(ctx)) {
			pr_err("ERR CTX_ALLOC on SID: %u\n", shmti->sid);
			continue;
		}

		fd = anon_inode_getfd(SCMI_TLM_DRIVER, &scmi_tlm_shmti_fops, ctx,
				      O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			scmi_tlm_shmti_ctx_put(ctx);
			pr_err("ERR ANON INODE on SID: %u\n", shmti->sid);
			continue;
		}

		shinfo[i].sid = shmti->sid;
		shinfo[i].fd = fd;
		shinfo[i].len = shmti->len;
		shinfo[i].offset = shmti->offset;

		out->num_shmtis++;
	}

	return 0;
}

static long
scmi_tlm_shmtis_list_get_ioctl(const struct scmi_tlm_instance *ti,
			       unsigned long arg)
{
	void __user *uptr = (void __user *)arg;
	struct scmi_tlm_shmtis_list ssl;
	size_t shinfo_sz;
	int ret;

	if (copy_from_user(&ssl, uptr, sizeof(ssl)))
		return -EFAULT;

	if (ssl.pad)
		return -EINVAL;

	/* A local scratch buffer... */
	shinfo_sz = ssl.num_shmtis * sizeof(struct scmi_tlm_shmti_info);
	struct scmi_tlm_shmti_info *shinfo __free(kfree) =
		kzalloc(shinfo_sz, GFP_KERNEL);
	if (!shinfo)
		return -ENOMEM;

	if (copy_from_user(shinfo, u64_to_user_ptr(ssl.shmtis), shinfo_sz))
		return -EFAULT;

	ret = scmi_tlm_allocate_anon_fds(ti->info, &ssl, shinfo);
	if (ret)
		return ret;

	if (copy_to_user(u64_to_user_ptr(ssl.shmtis), shinfo, shinfo_sz))
		return -EFAULT;

	if (copy_to_user(uptr, &ssl, sizeof(ssl)))
		return -EFAULT;

	return 0;
}

static long scmi_tlm_unlocked_ioctl(struct file *filp, unsigned int cmd,
				    unsigned long arg)
{
	struct inode *ino = file_inode(filp);
	struct scmi_tlm_instance *ti = to_instance(ino->i_cdev);

	switch (cmd) {
	case SCMI_TLM_GET_INFO:
		return scmi_tlm_info_get_ioctl(ti, arg);
	case SCMI_TLM_GET_CFG:
		return scmi_tlm_config_get_ioctl(ti, arg);
	case SCMI_TLM_SET_CFG:
		return scmi_tlm_config_set_ioctl(ti, arg);
	case SCMI_TLM_GET_INTRVS:
		return scmi_tlm_intervals_get_ioctl(ti, arg);
	case SCMI_TLM_GET_DE_CFG:
		return scmi_tlm_de_config_get_ioctl(ti, arg, false);
	case SCMI_TLM_SET_DE_CFG:
		return scmi_tlm_de_config_set_ioctl(ti, arg, false);
	case SCMI_TLM_GET_DE_INFO:
		return scmi_tlm_de_info_get_ioctl(ti, arg);
	case SCMI_TLM_GET_DE_LIST:
		return scmi_tlm_des_list_get_ioctl(ti, arg);
	case SCMI_TLM_GET_DE_VALUE:
		return scmi_tlm_de_value_get_ioctl(ti, arg);
	case SCMI_TLM_GET_ALL_CFG:
		return scmi_tlm_de_config_get_ioctl(ti, arg, true);
	case SCMI_TLM_SET_ALL_CFG:
		return scmi_tlm_de_config_set_ioctl(ti, arg, true);
	case SCMI_TLM_GET_GRP_LIST:
		return scmi_tlm_grps_list_get_ioctl(ti, arg);
	case SCMI_TLM_GET_GRP_INFO:
		return scmi_tlm_grp_info_get_ioctl(ti, arg);
	case SCMI_TLM_GET_GRP_DESC:
		return scmi_tlm_grp_desc_get_ioctl(ti, arg);
	case SCMI_TLM_SINGLE_SAMPLE:
		return scmi_tlm_des_read_ioctl(ti, arg, true);
	case SCMI_TLM_BULK_READ:
		return scmi_tlm_des_read_ioctl(ti, arg, false);
	case SCMI_TLM_BATCH_READ:
		return scmi_tlm_des_batch_read_ioctl(ti, arg);
	case SCMI_TLM_GET_SHMTI_LIST:
		return scmi_tlm_shmtis_list_get_ioctl(ti, arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations stlm_fops = {
	.owner = THIS_MODULE,
	.open = scmi_tlm_priv_data_open,
	.read = scmi_tlm_priv_read,
	.llseek = generic_file_llseek,
	.unlocked_ioctl = scmi_tlm_unlocked_ioctl,
	.release = scmi_tlm_priv_release,
};

static struct scmi_tlm_instance *scmi_tlm_init(struct scmi_tlm_setup *tsp,
					       unsigned int instance_id)
{
	struct device *dev = tsp->dev;
	struct scmi_tlm_instance *ti;

	ti = devm_kzalloc(dev, sizeof(*ti), GFP_KERNEL);
	if (!ti)
		return ERR_PTR(-ENOMEM);

	ti->info = tsp->ops->info_get(tsp->ph);
	if (!ti->info)
		return dev_err_ptr_probe(dev,
					 -EINVAL, "invalid Telemetry info !\n");

	ti->id = instance_id;
	ti->tsp = tsp;

	return ti;
}

static char *scmi_tlm_devnode(const struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "scmi/%s", dev_name(dev));
}

static struct class stlm_class = {
	.name    = "stlm",
	.devnode = scmi_tlm_devnode,
};

static int scmi_telemetry_probe(struct scmi_device *sdev)
{
	const struct scmi_handle *handle = sdev->handle;
	struct device *tdev, *dev = &sdev->dev;
	struct scmi_protocol_handle *ph;
	struct scmi_tlm_instance *ti;
	struct scmi_tlm_setup *tsp;
	unsigned int instance;
	const void *ops;
	int ret;

	if (!handle)
		return -ENODEV;

	ops = handle->devm_protocol_get(sdev, sdev->protocol_id, &ph);
	if (IS_ERR(ops))
		return dev_err_probe(dev, PTR_ERR(ops),
				     "Cannot access protocol:0x%X\n",
				     sdev->protocol_id);

	tsp = devm_kzalloc(dev, sizeof(*tsp), GFP_KERNEL);
	if (!tsp)
		return -ENOMEM;

	tsp->dev = dev;
	tsp->ops = ops;
	tsp->ph = ph;

	instance = handle->id;
	if (instance >= SCMI_TLM_NUM_DEVS)
		return -ENOSPC;

	ti = scmi_tlm_init(tsp, instance);
	if (IS_ERR(ti))
		return PTR_ERR(ti);

	cdev_init(&ti->cdev, &stlm_fops);
	ti->cdev.owner = THIS_MODULE;
	ti->devt = MKDEV(MAJOR(stlm_devt), MINOR(stlm_devt) + instance);
	ret = cdev_add(&ti->cdev, ti->devt, 1);
	if (ret)
		return ret;

	tdev = device_create(&stlm_class, NULL, ti->devt, ti, "tlm_%d", ti->id);
	if (IS_ERR(tdev)) {
		cdev_del(&ti->cdev);
		return  PTR_ERR(tdev);
	}

	dev_set_drvdata(&sdev->dev, ti);

	return 0;
}

static void scmi_telemetry_remove(struct scmi_device *sdev)
{
	struct scmi_tlm_instance *ti;

	ti = dev_get_drvdata(&sdev->dev);
	if (!ti)
		return;

	device_destroy(&stlm_class, ti->devt);
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
		return ret;

	return scmi_register(&scmi_telemetry_driver);
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
