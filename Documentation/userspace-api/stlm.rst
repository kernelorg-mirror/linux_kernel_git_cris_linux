.. SPDX-License-Identifier: GPL-2.0

=======================================
STLM - ARM SCMI Telemetry Userspace API
=======================================

.. contents::

Overview
========

ARM SCMI is a System and Configuration Management protocol, based on a
client-server model, that defines a number of messages that allows a
client/agent like Linux to discover, configure and make use of services
provided by the server/platform firmware.

SCMI v4.0 [1] introduced support for System Telemetry, through which an
agent can dynamically enumerate, configure and collect Telemetry Data
Events (DE) exposed by the platform.

The SCMI System Telemetry driver exposes one or more dedicated devices,
named as tlm_<N>, grouped under /dev/scmi/, one for each discovered SCMI
instance.

An IOCTL based interface is defined in order to enumerate, configure and
read telemetry data, as succinctly described in the following.

For more details on the uAPI, please see include/uapi/linux/scmi.h

Resources Enumeration
=====================

 - SCMI_TLM_GET_ABI_INFO: Gather ABI versioning detail and basic SCMI
   Telemetry features like number of resources and supported features.

 - SCMI_TLM_GET_INTRVS: Enumerate available update intervals.

 - SCMI_TLM_GET_DE_INFO: Retrieve DataEvent description.

 - SCMI_TLM_GET_DE_LIST: Retrieve the list of all the existent DataEvent
   descriptors.

 - SCMI_TLM_GET_GRP_LIST: Gather a list of descriptors for all defined Groups.

 - SCMI_TLM_GET_GRP_INFO: Gather information for a specific Group.

 - SCMI_TLM_GET_GRP_DESC: Gather detailed group composition information for
   the specified Group.

 - SCMI_TLM_GET_UUID_LIST: Gather a list of descriptors for all the SCMI
   Telemetry UUIDs defined on this system.

Configuration
=============

 - SCMI_TLM_GET_CFG / SCMI_TLM_SET_CFG: Get or set the whole instance, or a
   specific group, configuration.

 - SCMI_TLM_GET_DE_CFG / SCMI_TLM_SET_DE_CFG: Get or set the configuration
   of a specific DataEvent.

 - SCMI_TLM_GET_ALL_CFG / SCMI_TLM_SET_ALL_CFG: Get or set the cumulative
   configuration of ALL the DataEvents defined on the platform.

 - SCMI_TLM_RESET: Reset the whole Telemetry configuration server side.

 - SCMI_TLM_EVENT_SUBSCRIBE: Subscribe/unsubscribe to a Telemetry event.

Data Collection
===============

 - SCMI_TLM_DE_READ: Report the last updated sample for the specified
   DataEvent.

 - SCMI_TLM_BULK_READ: Report the last samples for all the currently enabled
   DataEvents.

 - SCMI_TLM_BATCH_READ: Report the last samples for the DataEvents IDs
   specified within the samples input params.

 - SCMI_TLM_SINGLE_READ: Trigger an immediate platform-side DataEvent
   update and report the collected samples.

Memory Mapped Raw Access
------------------------

 - SCMI_TLM_GET_SHMTI_LIST: Gather a list of open file descriptors, one for
   each SHMTI memory area defined for this instance, that can be used to
   memory-map such areas in the calling process address space so as to be
   able to directly access the SCMI Telemetry SHMTI areas shared by the
   platform firmware, and parse the TDCF format.
   The SCMI Telemetry TDCF format is defined in the specification at [1].


Example
=======

.. code-block:: c

	int main(int argc, char **argv)
	{
		struct scmi_tlm_de_config des_cfg = {};
		struct scmi_tlm_config cfg = {};
		struct scmi_tlm_de_sample samples[3] = {};
		struct scmi_tlm_data_read data = {};
		int fd, ret;

		fd = open("/dev/scmi/tlm_0", O_RDWR);
		if (fd < 0)
			return fd;

		/* Enable ALL Data Events with timestamps*/
		des_cfg.enable = 1;
		des_cfg.t_enable = 1;
		ret = ioctl(fd, SCMI_TLM_SET_ALL_CFG, &des_cfg);
		if (ret)
			return ret;

		/* Enable Telemetry as a whole, set a 400ms update interval */
		cfg.enable = 1;
		cfg.active.secs = 400;
		cfg.active.exp = -3;

		ret = ioctl(fd, SCMI_TLM_SET_CFG, &cfg);
		if (ret)
			return ret;

		/* Read a selection of DEs */
		samples[0].id = 0xA001;
		samples[1].id = 0x0002;
		samples[2].id = 0x1010;
		data.num_samples = 3;
		data.samples = (unsigned long)samples;

		ret = ioctl(fd, SCMI_TLM_BATCH_READ, &data);
		if (ret)
			return ret;

		for (int i = 0; i < 3; i++)
			fprintf(stdout, "%llu: 0x%08X -> %llu\n",
					samples[i].tstamp, samples[i].id, samples[i].val);

		return 0;
	}

References
==========
[1]: https://developer.arm.com/documentation/den0056/latest/
