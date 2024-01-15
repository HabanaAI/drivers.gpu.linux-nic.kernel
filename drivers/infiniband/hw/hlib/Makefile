# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_INFINIBAND_HLIB) := habanalabs_ib.o

habanalabs_ib-y += hlib_main.o hlib_verbs.o hlib_sysfs.o
habanalabs_ib-$(CONFIG_INFINIBAND_USER_ACCESS) += hlib_usr_fifo.o \
						  hlib_query_port.o \
						  hlib_coll_qp.o \
						  hlib_encap.o \
						  hlib_set_port_ex.o