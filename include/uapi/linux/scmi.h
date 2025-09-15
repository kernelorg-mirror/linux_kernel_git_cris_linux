/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2026 ARM Ltd.
 */
#ifndef _UAPI_LINUX_SCMI_H
#define _UAPI_LINUX_SCMI_H

/*
 * Userspace interface SCMI Telemetry
 */

#include <linux/ioctl.h>
#include <linux/types.h>

#define SCMI_TLM_ABI_VERSION_V1			1
#define SCMI_TLM_CURRENT_ABI_VERSION		SCMI_TLM_ABI_VERSION_V1
#define SCMI_TLM_DE_IMPL_UUID_SZ		16

#define SCMI_TLM_SHMTI_ID_INVALID		0xFFFFFFFF

/**
 * struct scmi_tlm_abi_info - Basic information on the ABI/instance
 *
 * SCMI Telemetry characteristics like number of DEs, Groups, Intervals and
 * SHMTIs are statically determined by the platform and do not change within
 * one boot/session; they are reported here so that they can be used to properly
 * size the requests on other IOCTLs, without having to discover dynamically
 * those sizes by issuing a zero-sized IOCTL request at first.
 *
 * @size: sizeof this structure - IN
 * @abi_version: ABI Version - OUT
 * @abi_features: ABI capabilities bitmap - OUT
 * @de_impl_version: SCMI Telemetry DE implementation revision - OUT
 * @num_des: Number of defined DEs - OUT
 * @num_groups: Number of defined DEs groups - OUT
 * @num_intervals: Number of available update intervals (instance-level) - OUT
 * @num_shmtis: Number of discovered SHMTI areas - OUT
 * @features: Instance specific SCMI feature-support bitmap - OUT
 * @reserved: Some room for future expansion without the need to resize.
 *	      Must be zero.
 *
 * Used by:
 *	RW - SCMI_TLM_GET_ABI_INFO
 */
struct scmi_tlm_abi_info {
	__u32 size;
	__u32 abi_version;
	__u32 abi_features;
#define SCMI_TLM_ABI_FEAT_RESET				(1 << 0)
#define SCMI_TLM_ABI_FEAT_EVENT				(1 << 1)
#define SCMI_TLM_ABI_FEAT_UUID_LIST			(1 << 2)
#define SCMI_TLM_ABI_FEAT_BATCH_STATE			(1 << 3)
#define SCMI_TLM_ABI_FEAT_BATCHED_CFG			(1 << 4)
#define SCMI_TLM_ABI_FEAT_DE_TRACKING			(1 << 5)
	__u8 primary_de_impl_version[SCMI_TLM_DE_IMPL_UUID_SZ];
	__u32 num_des;
	__u32 num_groups;
	__u32 num_intervals;
	__u32 num_shmtis;
	__u32 features;
#define SCMI_TLM_SCMI_SUPPORT_RESET			(1 << 0)
#define SCMI_TLM_SCMI_SUPPORT_SINGLE_SAMPLE		(1 << 1)
#define SCMI_TLM_SCMI_SUPPORT_GROUP_CONFIG		(1 << 2)
#define SCMI_TLM_SCMI_SUPPORT_UPDATE_NOTIFICATION	(1 << 3)
	__u64 reserved;
};

/**
 * struct scmi_tlm_update_interval  - Update interval descriptor
 *
 * @secs: integer representing seconds - OUT
 * @exp: signed integer representing the base 10 exponent used as a multiplier
 *	 with @secs to represent the interval - OUT
 *
 * The resulting update interval is calculated as: <secs> * 10 ^ <exp>
 */
struct scmi_tlm_update_interval {
	__u32 secs;
	__s32 exp;
};

/**
 * struct scmi_tlm_config  - Whole instance or group configuration
 *
 * @enable: Get/Set Telemetry enabled state for the whole instance or the
 *	    group specified in @grp_id - IN/OUT
 * @t_enable: Get/Set timestamp state for the group specified in @grp_id - IN/OUT
 * @flags: Bitmask to represent special characteristics - IN
 * @pad: Padding fields to enforce alignment
 * @grp_id: Identifier of the target group upon which this configuration will
 *	    be applied: ignored if not marked as a group in @flags - IN/OUT
 * @active: Get/Set currently active update interval for the whole instance
 *	    or the group specified in @grp_id - IN/OUT
 * @reserved: Some room for future expansion. Must be zero.
 *
 * Used by:
 *	RW - SCMI_TLM_GET_CFG
 *	WO - SCMI_TLM_SET_CFG
 */
struct scmi_tlm_config {
	__u8 enable;
	__u8 t_enable;
	__u8 flags;
#define SCMI_TLM_CONFIG_GROUP		(1 << 0)
#define SCMI_TLM_CONFIG_FLAGS		(SCMI_TLM_CONFIG_GROUP)
#define SCMI_TLM_CONFIG_IS_GROUP(f)	((f) & SCMI_TLM_CONFIG_GROUP)
	__u8 pad;
	__u32 grp_id;
	struct scmi_tlm_update_interval active;
	__u64 reserved;
};

/**
 * struct scmi_tlm_intervals  - Update intervals descriptor
 *
 * @grp_id: Identifier of the target group upon which this configuration
 *	    will be applied: ignored if not marked as a group in @flags - IN
 * @flags: Bitmask to represent special characteristics. When the interval
 *	   is NOT marked as SCMI_TLM_INTERV_DISCRETE, @intervals will
 *	   contain a triplet: min/max/step - OUT
 * @pad: Padding fields to enforce alignment
 * @num_intervals: Number of entries of @intervals. On input this represents the
 *		   size of @intervals, while on output carries the effective
 *		   number of entries filled-in - IN/OUT
 * @pad2: Padding fields to enforce alignment
 * @reserved: Some room for future expansion. Must be zero.
 * @intervals: A pointer to an array of struct scmi_tlm_update_interval - IN/OUT
 *
 * Used by:
 *	RW - SCMI_TLM_GET_INTRVS
 */
struct scmi_tlm_intervals {
	__u32 grp_id;
	__u8 flags;
#define SCMI_TLM_INTERV_GROUP		(1 << 0)
#define SCMI_TLM_INTERV_DISCRETE	(1 << 1)
#define SCMI_TLM_INTERV_FLAGS					\
	(SCMI_TLM_INTERV_GROUP | SCMI_TLM_INTERV_DISCRETE)
#define SCMI_TLM_INTERV_IS_GROUP(f)	((f) & SCMI_TLM_INTERV_GROUP)
	__u8 pad[3];
	__u32 num_intervals;
	__u32 pad2;
	__u64 reserved;
#define SCMI_TLM_UPDATE_INTVL_SEGMENT_LOW	0
#define SCMI_TLM_UPDATE_INTVL_SEGMENT_HIGH	1
#define SCMI_TLM_UPDATE_INTVL_SEGMENT_STEP	2
	__u64 intervals;
};

/**
 * struct scmi_tlm_de_config  - DE configuration
 *
 * This descriptor is used directly by the aggregate SCMI_TLM_GET_ALL_CFG and
 * SCMI_TLM_SET_ALL_CFG IOCTLs, or embedded into an @scmi_tlm_batch request for
 * SCMI_TLM_GET_DE_CFG and SCMI_TLM_GET_DE_CFG IOCTLs.
 *
 * @id: Identifier of the DE, ignored by SCMI_TLM_GET/SET_ALL_CFG - IN
 * @enable: Get/Set the enabled state of this single DE or the cumulative ALL
 *	    state - IN/OUT
 * @t_enable: Get/Set the timestamp state of this single DE (if supported) or
 *	      the cumulative ALL state - IN/OUT
 * @sid: An integer representing the SHMTI ID that contains this DE. Valid
 *	 ONLY when the related DE is enabled - OUT
 * @oofset: An integer representing the offset in the SHMTI @sid that identifies
 *	    the start of the TDCF DataLine containing this DE.
 *	    Valid ONLY when the related DE is enabled - OUT
 * @pad: Padding fields to enforce alignment
 * @uuid: An arrray containing the UUID, in BigEndian format, associated to
 *	  this DE. Valid ONLY when the related DE is enabled: this UUID can
 *	  be the primary UUID or one of the secondary UUIDs if any exist.
 *	  Note that this UUID/DE association is permanent within the same
 *	  boot/session - OUT
 * @reserved: Some room for future expansion. Must be zero.
 *
 * Used by:
 *	RW - SCMI_TLM_GET_ALL_CFG
 *	RW - SCMI_TLM_SET_ALL_CFG
 *	RW - SCMI_TLM_GET_DE_CFG (within a BATCH)
 *	RW - SCMI_TLM_SET_DE_CFG (within a BATCH)
 */
struct scmi_tlm_de_config {
	__u32 id;
	__u32 enable;
	__u32 t_enable;
	__u32 sid;
	__u32 offset;
	__u32 pad;
	__u8 uuid[SCMI_TLM_DE_IMPL_UUID_SZ];
	__u64 reserved;
};

/**
 * struct scmi_tlm_de_info  - DataEvent Descriptor
 *
 * @id: DE identifier - IN/OUT
 * @grp_id: Identifier of the group which this DE belongs to; valid only if
 *	    this DE is marked as belonging to a group in @flags - IN/OUT
 * @data_sz: DE data size in bytes - OUT
 * @type: DE type - OUT
 * @unit: DE unit of measurements - OUT
 * @unit_exp: Power-of-10 multiplier for DE unit - OUT
 * @ts_rate: Clock rate in kHz used to generate the DE timestamp - OUT
 * @instance_id: DE instance ID - OUT
 * @compo_instance_id: DE component instance ID - OUT
 * @compo_type: Type of component which is associated to this DE - OUT
 * @persistent: Data value for this DE survives reboot (non-cold ones) - OUT
 * @flags: Bitmask to represent special characteristics - IN
 * @pad: Padding fields to enforce alignment
 * @pad2: Padding fields to enforce alignment
 * @name: Name of this DE - OUT
 * @reserved: Some room for future expansion. Must be zero.
 *
 * Used to get the full description of a DE: it reflects DE Descriptors
 * definitions in SCMI V4.0 specification at 3.12.4.6.
 *
 * Used by:
 *	RW - SCMI_TLM_GET_DE_INFO
 */
struct scmi_tlm_de_info {
	__u32 id;
	__u32 grp_id;
	__u32 data_sz;
	__u32 type;
	__u32 unit;
	__s32 unit_exp;
	__u32 ts_rate;
	__u32 instance_id;
	__u32 compo_instance_id;
	__u32 compo_type;
	__u8 persistent;
	__u8 flags;
#define SCMI_TLM_DEINFO_GROUP		(1 << 0)
#define SCMI_TLM_DEINFO_FLAGS		(SCMI_TLM_DEINFO_GROUP)
#define SCMI_TLM_DEINFO_HAS_GROUP(f)	((f) & SCMI_TLM_DEINFO_GROUP)
	__u8 pad[2];
	__u32 pad2;
	__u8 name[16];
	__u64 reserved;
};

/**
 * struct scmi_tlm_des_list  - List of all defined DEs
 *
 * @num_des: Number of entries in @des. In input represents the size of
 *	     @des, while in output carries the effective number of items
 *	     filled-in - IN/OUT
 * @pad: Padding fields to enforce alignment
 * @des: A reference to an array containing struct scmi_tlm_de_info
 *	 descriptors for all the existent DEs - IN/OUT
 *
 * Used by:
 *	RW - SCMI_TLM_GET_DE_LIST
 */
struct scmi_tlm_des_list {
	__u32 num_des;
	__u32 pad;
	__u64 des;
};

/**
 * struct scmi_tlm_de_sample - A DataEvent reading
 *
 * @id: DE identifier - IN
 * @pad: Padding fields to enforce alignment.
 * @tstamp: DE reading timestamp (0 if timestamp NOT supported) - OUT
 * @val: Reading of the DE data value - OUT
 *
 * Used by:
 *	RW - SCMI_TLM_DE_READ
 */
struct scmi_tlm_de_sample {
	__u32 id;
	__u32 pad;
	__u64 tstamp;
	__u64 val;
};

/**
 * struct scmi_tlm_data_read - Bulk read of a number of DataEvents
 *
 * @grp_id: Optional group ID number, ignored if not marked as a group request
 *	    in @flags and not supported by SCMI_TLM_BATCH_READ - IN
 * @flags: Bitmask to represent special characteristics - IN
 * @pad: Padding fields to enforce alignment
 * @pad2: Padding fields to enforce alignment
 * @num_samples: Number of entries in @samples. In input represents the size of
 *		 @samples, while in output carries the effective number of items
 *		 filled-in  - IN/OUT
 * @samples: A reference to an array of struct scmi_tlm_de_sample containing
 *	     an entry for each DE - IN/OUT
 *
 * Used by:
 *	RW - SCMI_TLM_SINGLE_READ
 *	RW - SCMI_TLM_BULK_READ
 */
struct scmi_tlm_data_read {
	__u32 grp_id;
	__u8 flags;
#define SCMI_TLM_READ_GROUP		(1 << 0)
#define SCMI_TLM_READ_FLAGS		(SCMI_TLM_READ_GROUP)
#define SCMI_TLM_READ_IS_GROUP(f)	((f) & SCMI_TLM_READ_GROUP)
	__u8 pad[3];
	__u32 pad2;
	__u32 num_samples;
	__u64 samples;
};

/**
 * struct scmi_tlm_batch  - A wrapper structure for BATCH operations
 *
 * @num_items: Number of items in @items and @states - IN
 * @items_sz: Size of a single item contained in @items - IN
 * @reserved: Some room for future expansion. Must be zero.
 * @states: A reference to an arrays of u32 items representing the outcome of
 *	    the requests for each single item in @items: these are ordered in
 *	    the same order as the @items. - OUT
 * @items: A reference to an array of batched requests - IN/OUT
 *
 * Used by:
 *	RW - SCMI_TLM_BATCH_READ
 *	RW - SCMI_TLM_GET_DE_CFG
 *	RW - SCMI_TLM_SET_DE_CFG
 *
 */
struct scmi_tlm_batch {
	__u32 num_items;
	__u32 item_sz;
	__u64 reserved;
	__u64 states;
	__u64 items;
};

/**
 * struct scmi_tlm_grp_info  - Group info descriptor
 *
 * @grp_id: Group ID number - IN
 * @num_des: Number of DEs part of this group - OUT
 * @num_intervals: Number of update intervals supported. Zero if group does not
 *		   support per-group update interval configuration. - OUT
 * @pad: Padding fields to enforce alignment
 * @reserved: Some room for future expansion. Must be zero.
 *
 * Used by:
 *	RW - SCMI_TLM_GET_GRP_INFO
 */
struct scmi_tlm_grp_info {
	__u32 grp_id;
	__u32 num_des;
	__u32 num_intervals;
	__u32 pad;
	__u64 reserved;
};

/**
 * struct scmi_tlm_grps_list  - Group info descriptor list
 *
 * @num_grps: Number of entries returned in @grps. In input represents the size
 *	      of @grps, while in output carries the effective number of items
 *	     filled-in - IN/OUT
 * @pad: Padding fields to enforce alignment
 * @grps: A reference to an array of struct scmi_tlm_grp_info containing an
 *	  entry for each defined group - IN/OUT
 *
 * Used by:
 *	RW - SCMI_TLM_GET_GRP_LIST
 */
struct scmi_tlm_grps_list {
	__u32 num_grps;
	__u32 pad;
	__u64 grps;
};

/**
 * struct scmi_tlm_grp_desc  - Group descriptor
 *
 * @grp_id: Group ID number - IN
 * @num_des: Number of DEs composing this group. In input represents the size
 *	      of @composing_des, while in output carries the effective number
 *	      of items filled-in - IN/OUT
 * @composing_des: A reference to an array of __u32 elements containing the
 *		   DataEvent IDs composing this group. - IN/OUT
 * @reserved: Some room for future expansion. Must be zero.
 *
 * Used by:
 *	RW - SCMI_TLM_GET_GRP_DESC
 */
struct scmi_tlm_grp_desc {
	__u32 grp_id;
	__u32 num_des;
	__u64 composing_des;
	__u64 reserved;
};

/**
 * struct scmi_tlm_shmti_info  - SHMTI descriptor
 *
 * @sid: SHMTI ID - IN
 * @fd: Associated opened file descriptor to use for mmap - OUT
 * @len: Size of the SHMTI to be used with mmap on this SHMTI - OUT
 * @offset: Offset in the mmap where the specified SHMTI start - OUT
 * @reserved: Some room for future expansion. Must be zero.
 *
 * Used by:
 *	RW - SCMI_TLM_GET_SHMTI_LIST
 */
struct scmi_tlm_shmti_info {
	__u32 sid;
	__u32 fd;
	__u32 len;
	__u32 offset;
	__u64 reserved;
};

/**
 * struct scmi_tlm_shmtis_list  - SHMTIs List
 *
 * @num_shmtis: Number of SHMTIs. In input represents the size of @shmtis, while
 *		in output carries the effective number of items filled-in - IN/OUT
 * @pad: Padding fields to enforce alignment
 * @shmtis: A reference to an array of struct scmi_tlm_shmti_info containing
 *	    an entry for each defined SHMTI - IN/OUT
 *
 * Used by:
 *	RW - SCMI_TLM_GET_SHMTI_LIST
 */
struct scmi_tlm_shmtis_list {
	__u32 num_shmtis;
	__u32 pad;
	__u64 shmtis;
};

/**
 * struct scmi_tlm_uuid  - UUID descriptor
 *
 * @byte: An array of bytes containing the UUDI in BigEndian order as
 *	  per RFC 9562. - OUT
 */
struct scmi_tlm_uuid {
	__u8 bytes[SCMI_TLM_DE_IMPL_UUID_SZ];
};

/**
 * struct scmi_tlm_uuid_list  - UUIDs List
 *
 * @num_uuids: Number of UUIDs. If set to zero on input it will contain the
 *	       number of existing UUIDs on output; otherwise, in input it
 *	       represents the number of entries in @uuids, while  in output
 *	       will carries the effective number of items filled-in. - IN/OUT
 * @pad: Padding fields to enforce alignment
 * @uuids: A reference to an array of struct scmi_tlm_uuid containing an entry
 *	   for each defined UUID - IN/OUT
 *
 * Used by:
 *	RW - SCMI_TLM_GET_UUID_LIST
 */
struct scmi_tlm_uuid_list {
	__u32 num_uuids;
	__u32 pad;
	__u64 uuids;
};

/**
 * struct scmi_tlm_event  - Event descriptor
 *
 * @type: Type of Telemetry event to subscribe/unsubscribe - IN
 * @efd: An integer representing an open eventfd file descriptor, which will
 *	 be used to signal the subscribed event. - IN
 * @cookie: An integer used to represent a subscrition request: ONLY positive
 *          values represents valid subscription.
 *          On a new subscription this must be set to zero in input, to signify
 *          that a new request is being made: if the subscription was
 *          successful a positive integer is returned.
 *          When, instead, @cookie is set to a positive integer in input, it
 *          is interpreted as a reference to an existing subscription to be
 *          cancelled.
 * @pad: Padding fields to enforce alignment
 * @reserved: Some room for future expansion. Must be zero.
 *
 * Used by:
 *	SCMI_TLM_EVENT_SUBSCRIBE
 */
struct scmi_tlm_event {
#define SCMI_TLM_EVT_GENERATION		0x0U
#define SCMI_TLM_EVT_LAST		(SCMI_TLM_EVT_GENERATION)
	__u32 type;
	__u32 efd;
	__u32 cookie;
	__u32 pad;
	__u64 reserved;
};

#define SCMI_TLM_IOCTL_MAGIC 0xF1

#define SCMI_TLM_GET_ABI_INFO	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x00, struct scmi_tlm_abi_info)
#define SCMI_TLM_GET_CFG	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x01, struct scmi_tlm_config)
#define SCMI_TLM_SET_CFG	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x02, struct scmi_tlm_config)
#define SCMI_TLM_GET_INTRVS	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x03, struct scmi_tlm_intervals)
#define SCMI_TLM_GET_DE_CFG	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x04, struct scmi_tlm_batch)
#define SCMI_TLM_SET_DE_CFG	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x05, struct scmi_tlm_batch)
#define SCMI_TLM_GET_DE_INFO	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x06, struct scmi_tlm_de_info)
#define SCMI_TLM_GET_DE_LIST	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x07, struct scmi_tlm_des_list)
#define SCMI_TLM_DE_READ	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x08, struct scmi_tlm_de_sample)
#define SCMI_TLM_GET_ALL_CFG	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x09, struct scmi_tlm_de_config)
#define SCMI_TLM_SET_ALL_CFG	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x0A, struct scmi_tlm_de_config)
#define SCMI_TLM_GET_GRP_LIST	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x0B, struct scmi_tlm_grps_list)
#define SCMI_TLM_GET_GRP_INFO	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x0C, struct scmi_tlm_grp_info)
#define SCMI_TLM_GET_GRP_DESC	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x0D, struct scmi_tlm_grp_desc)
#define SCMI_TLM_SINGLE_READ	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x0E, struct scmi_tlm_data_read)
#define SCMI_TLM_BULK_READ	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x0F, struct scmi_tlm_data_read)
#define SCMI_TLM_BATCH_READ	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x10, struct scmi_tlm_data_read)
#define SCMI_TLM_GET_SHMTI_LIST	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x11, struct scmi_tlm_shmtis_list)
#define SCMI_TLM_RESET		_IO(SCMI_TLM_IOCTL_MAGIC,   0x12)
#define SCMI_TLM_GET_UUID_LIST	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x13, struct scmi_tlm_uuid_list)
#define SCMI_TLM_EVENT_SUBSCRIBE	\
	_IOWR(SCMI_TLM_IOCTL_MAGIC, 0x14, struct scmi_tlm_event)

#endif /* _UAPI_LINUX_SCMI_H */
