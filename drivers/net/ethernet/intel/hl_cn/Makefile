# SPDX-License-Identifier: GPL-2.0-only
#
# HabanaLabs (an Intel Company) core network driver
#

obj-$(CONFIG_HABANA_CN) := habanalabs_cn.o

include $(src)/common/Makefile
habanalabs_cn-y += $(HL_CN_COMMON_FILES)

include $(src)/gaudi2/Makefile
habanalabs_cn-y += $(HL_CN_GAUDI2_FILES)

habanalabs_cn-$(CONFIG_DEBUG_FS) += common/hl_cn_debugfs.o
