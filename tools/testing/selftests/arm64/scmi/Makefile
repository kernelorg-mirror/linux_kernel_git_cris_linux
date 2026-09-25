# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 ARM Limited

# Additional include paths needed by kselftest.h and local headers
CFLAGS += -std=gnu99 -I.
LDFLAGS += -static

# Generated binaries to be installed by top KSFT script
TEST_GEN_PROGS := test_scmi_telemetry_uapi

# Include KSFT lib.mk.
include ../../lib.mk
