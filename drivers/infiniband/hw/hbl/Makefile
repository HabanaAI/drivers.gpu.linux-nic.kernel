# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for HabanaLabs (an Intel Company) Infiniband driver
#

obj-$(CONFIG_INFINIBAND_HBL) := habanalabs_ib.o

habanalabs_ib-y += hbl_main.o hbl_verbs.o

habanalabs_ib-$(CONFIG_INFINIBAND_USER_ACCESS) += hbl_encap.o hbl_query_port.o \
                                                  hbl_set_port_ex.o \
                                                  hbl_usr_fifo.o
