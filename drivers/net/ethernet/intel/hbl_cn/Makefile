# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for HabanaLabs (an Intel Company) core network driver
#

obj-$(CONFIG_HABANA_CN) := habanalabs_cn.o

include $(src)/common/Makefile
habanalabs_cn-y += $(HBL_CN_COMMON_FILES)

habanalabs_cn-$(CONFIG_DEBUG_FS) += common/hbl_cn_debugfs.o
