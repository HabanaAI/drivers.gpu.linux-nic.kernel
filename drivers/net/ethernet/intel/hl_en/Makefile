# SPDX-License-Identifier: GPL-2.0-only
#
# HabanaLabs (an Intel Company) network driver
#

obj-$(CONFIG_HABANA_EN) := habanalabs_en.o

include $(src)/common/Makefile
habanalabs_en-y += $(HL_EN_COMMON_FILES)

include $(src)/gaudi2/Makefile
habanalabs_en-y += $(HL_EN_GAUDI2_FILES)
