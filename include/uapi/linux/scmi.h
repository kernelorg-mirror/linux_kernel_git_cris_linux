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

#define SCMI_TLM_DE_IMPL_MAX_DWORDS	4

/**
 * struct scmi_tlm_base_info - Basic information about an instance
 *
 * @version: SCMI Telemetry protocol version
 * @de_impl_version: SCMI Telemetry DE implementation revision
 * @num_de: Number of defined DEs
 * @num_groups: Number of defined DEs groups
 * @num_intervals: Number of available update intervals (instance-level)
 * @num_shmtis: Number of discovered SHMTI areas
 * @flags: Instance specific feature-support bitmap
 *
 * Used by:
 *	RO - SCMI_TLM_GET_INFO
 */
struct scmi_tlm_base_info {
	__u32 version;
	__u32 de_impl_version[SCMI_TLM_DE_IMPL_MAX_DWORDS];
	__u32 num_des;
	__u32 num_groups;
	__u32 num_intervals;
	__u32 num_shmtis;
	__u32 flags;
#define SCMI_TLM_BASE_CAN_RESET		(1 << 0)
};

/**
 * struct scmi_tlm_update_interval  - Update interval descriptor
 *
 * @secs: integer representing seconds
 * @exp: signed integer representing the base 10 exponent used as a multiplier
 *	 with @secs to represent the interval
 *
 * The resulting update interval is calculated as: <secs> * 10 ^ <exp>
 */
struct scmi_tlm_update_interval {
	__u32 secs;
	__u32 exp;
};

/**
 * struct scmi_tlm_config  - Whole instance or group configuration
 *
 * @enable: Enable/Disable Telemetry for the whole instance or the group
 * @t_enable: Enable/Disable timestamping for all the DEs belonging to a group
 * @flags: Bitmask to represent special characteristics
 * @pad: Padding fields to enforce alignment
 * @grp_id: Identifier of the target group upon which this configuration will
 *	    be applied: ignored if not marked as a group in @flags
 * @active: Get/Set currently active update interval for the whole instance or
 *	    a group
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
};

/**
 * struct scmi_tlm_intervals  - Update intervals descriptor
 *
 * @grp_id: Identifier of the target group upon which this configuration
 *	    will be applied: ignored if not marked as a group in @flags
 * @flags: Bitmask to represent special characteristics. When the interval
 *	   is NOT marked as SCMI_TLM_INTERV_DISCRETE, @intervals will
 *	   contain a triplet: min/max/step
 * @pad: Padding fields to enforce alignment
 * @num_intervals: Number of entries of @intervals
 * @pad2: Padding fields to enforce alignment
 * @intervals: A pointer to an array of struct scmi_tlm_update_interval
 *
 * Used by:
 *	RW - SCMI_TLM_GET_INTRVS
 */
struct scmi_tlm_intervals {
	__u32 grp_id;
	__u8 flags;
#define SCMI_TLM_INTERV_GROUP	(1 << 0)
#define SCMI_TLM_INTERV_DISCRETE	(1 << 1)
#define SCMI_TLM_INTERV_FLAGS					\
	(SCMI_TLM_INTERV_GROUP | SCMI_TLM_INTERV_DISCRETE)
#define SCMI_TLM_INTERV_IS_GROUP(f)	((f) & SCMI_TLM_INTERV_GROUP)
	__u8 pad[3];
	__u32 num_intervals;
	__u32 pad2;
#define SCMI_TLM_UPDATE_INTVL_SEGMENT_LOW	0
#define SCMI_TLM_UPDATE_INTVL_SEGMENT_HIGH	1
#define SCMI_TLM_UPDATE_INTVL_SEGMENT_STEP	2
	__u64 intervals;
};

/**
 * struct scmi_tlm_de_config  - DE configuration
 *
 * @id: Identifier of the DE to act upon (ignored by SCMI_TLM_GET/SET_ALL_CFG)
 * @enable: A boolean to enable/disable the DE
 * @t_enable: A boolean to enable/disable the timestamp for this DE
 *	      (if supported)
 * @pad: Padding fields to enforce alignment
 *
 * Used by:
 *	RW - SCMI_TLM_GET_DE_CFG
 *	RW - SCMI_TLM_SET_DE_CFG
 *	RW - SCMI_TLM_GET_ALL_CFG
 *	RW - SCMI_TLM_SET_ALL_CFG
 */
struct scmi_tlm_de_config {
	__u32 id;
	__u32 enable;
	__u32 t_enable;
	__u32 pad;
};

/**
 * struct scmi_tlm_de_info  - DataEvent Descriptor
 *
 * @id: DE identifier
 * @grp_id: Identifier of the group which this DE belongs to; valid only if
 *	    this DE is marked as belonging to a group in @flags.
 * @data_sz: DE data size in bytes
 * @type: DE type
 * @unit: DE unit of measurements
 * @unit_exp: Power-of-10 multiplier for DE unit
 * @ts_rate: Clock rate in kHz used to generate the DE timestamp
 * @instance_id: DE instance ID
 * @compo_instance_id: DE component instance ID
 * @compo_type: Type of component which is associated to this DE
 * @persistent: Data value for this DE survives reboot (non-cold ones)
 * @flags: Bitmask to represent special characteristics
 * @pad: Padding fields to enforce alignment
 * @pad2: Padding fields to enforce alignment
 * @name: Name of this DE
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
};

/**
 * struct scmi_tlm_des_list  - List of all defined DEs
 *
 * @num_des: Number of entries in @des
 * @pad: Padding fields to enforce alignment
 * @des: A reference to an array containing struct scmi_tlm_de_info
 *	 descriptors for all the existent DEs
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
 * @id: DE identifier
 * @pad: Padding fields to enforce alignment.
 * @tstamp: DE reading timestamp (0 if timestamp NOT supported)
 * @val: Reading of the DE data value
 *
 * Used by:
 *	RW - SCMI_TLM_GET_DE_VALUE
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
 *	    in @flags and not supported by SCMI_TLM_BATCH_READ
 * @flags: Bitmask to represent special characteristics
 * @pad: Padding fields to enforce alignment
 * @pad2: Padding fields to enforce alignment
 * @num_samples: Number of entries returned in @samples
 * @samples: A reference to an array of struct scmi_tlm_de_sample containing
 *	     an entry for each DE
 *
 * Used by:
 *	RW - SCMI_TLM_SINGLE_SAMPLE
 *	RW - SCMI_TLM_BULK_READ
 *	RW - SCMI_TLM_BATCH_READ
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
 * struct scmi_tlm_grp_info  - Group info descriptor
 *
 * @grp_id: Group ID number
 * @num_des: Number of DEs part of this group
 * @num_intervals: Number of update intervals supported. Zero if group does not
 *		   support per-group update interval configuration.
 * @pad: Padding fields to enforce alignment
 *
 * Used by:
 *	RW - SCMI_TLM_GET_GRP_INFO
 */
struct scmi_tlm_grp_info {
	__u32 grp_id;
	__u32 num_des;
	__u32 num_intervals;
	__u32 pad;
};

/**
 * struct scmi_tlm_grps_list  - Group info descriptor list
 *
 * @num_grps: Number of entries returned in @grps
 * @pad: Padding fields to enforce alignment
 * @grps: A reference to an array of struct scmi_tlm_grp_info containing an
 *	  entry for each defined group
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
 * @grp_id: Group ID number
 * @num_des: Number of DEs composing this group
 * @composing_des: A reference to an array of __u32 elements containing the
 *		   DataEvent IDs composing this group.
 *
 * Used by:
 *	RW - SCMI_TLM_GET_GRP_DESC
 */
struct scmi_tlm_grp_desc {
	__u32 grp_id;
	__u32 num_des;
	__u64 composing_des;
};

/**
 * struct scmi_tlm_shmti_info  - SHMTI descriptor
 *
 * @sid: SHMTI ID
 * @fd: Associated opened file descriptor to use for mmap
 * @len: Size of the SHMTI to be used with mmap on this SHMTI
 * @offset: Offset in the mmap where the specified SHMTI start
 *
 * Used by:
 *	RW - SCMI_TLM_GET_SHMTI_LIST
 */
struct scmi_tlm_shmti_info {
	__u32 sid;
	__u32 fd;
	__u32 len;
	__u32 offset;
};

/**
 * struct scmi_tlm_shmtis_list  - SHMTIs List
 *
 * @num_shmtis: Number of entries returned in @shmtis
 * @pad: Padding fields to enforce alignment
 * @shmtis: A reference to an array of struct scmi_tlm_shmti_info containing
 *	    an entry for each defined SHMTI
 *
 * Used by:
 *	RW - SCMI_TLM_GET_SHMTI_LIST
 */
struct scmi_tlm_shmtis_list {
	__u32 num_shmtis;
	__u32 pad;
	__u64 shmtis;
};

#define SCMI 0xF1

#define SCMI_TLM_GET_INFO	_IOR(SCMI,  0x00, struct scmi_tlm_base_info)
#define SCMI_TLM_GET_CFG	_IOWR(SCMI, 0x01, struct scmi_tlm_config)
#define SCMI_TLM_SET_CFG	_IOWR(SCMI, 0x02, struct scmi_tlm_config)
#define SCMI_TLM_GET_INTRVS	_IOWR(SCMI, 0x03, struct scmi_tlm_intervals)
#define SCMI_TLM_GET_DE_CFG	_IOWR(SCMI, 0x04, struct scmi_tlm_de_config)
#define SCMI_TLM_SET_DE_CFG	_IOWR(SCMI, 0x05, struct scmi_tlm_de_config)
#define SCMI_TLM_GET_DE_INFO	_IOWR(SCMI, 0x06, struct scmi_tlm_de_info)
#define SCMI_TLM_GET_DE_LIST	_IOWR(SCMI, 0x07, struct scmi_tlm_des_list)
#define SCMI_TLM_GET_DE_VALUE	_IOWR(SCMI, 0x08, struct scmi_tlm_de_sample)
#define SCMI_TLM_GET_ALL_CFG	_IOWR(SCMI, 0x09, struct scmi_tlm_de_config)
#define SCMI_TLM_SET_ALL_CFG	_IOWR(SCMI, 0x0A, struct scmi_tlm_de_config)
#define SCMI_TLM_GET_GRP_LIST	_IOWR(SCMI, 0x0B, struct scmi_tlm_grps_list)
#define SCMI_TLM_GET_GRP_INFO	_IOWR(SCMI, 0x0C, struct scmi_tlm_grp_info)
#define SCMI_TLM_GET_GRP_DESC	_IOWR(SCMI, 0x0D, struct scmi_tlm_grp_desc)
#define SCMI_TLM_SINGLE_SAMPLE	_IOWR(SCMI, 0x0E, struct scmi_tlm_data_read)
#define SCMI_TLM_BULK_READ	_IOWR(SCMI, 0x0F, struct scmi_tlm_data_read)
#define SCMI_TLM_BATCH_READ	_IOWR(SCMI, 0x10, struct scmi_tlm_data_read)
#define SCMI_TLM_GET_SHMTI_LIST	_IOWR(SCMI, 0x11, struct scmi_tlm_shmtis_list)

#endif /* _UAPI_LINUX_SCMI_H */
