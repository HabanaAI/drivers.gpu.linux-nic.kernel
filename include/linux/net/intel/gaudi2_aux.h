/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#ifndef HBL_GAUDI2_AUX_H_
#define HBL_GAUDI2_AUX_H_

#include <linux/types.h>
#include <linux/net/intel/cn_aux.h>

enum gaudi2_setup_type {
	GAUDI2_SETUP_TYPE_HLS2,
};

/**
 * struct gaudi2_cn_aux_data - Gaudi2 CN driver data.
 * @setup_type: type of setup connectivity.
 * @cfg_base: configuration space base address.
 * @irq_num_port_base: base IRQ number for port EQ.
 * @sob_id_base: first reserved SOB ID.
 * @sob_inc_cfg_val: configuration value for incrementing SOB by one.
 * @fw_security_enabled: FW security enabled.
 * @msix_enabled: MSI-X enabled.
 */
struct gaudi2_cn_aux_data {
	enum gaudi2_setup_type setup_type;
	u64 cfg_base;
	u32 irq_num_port_base;
	u32 sob_id_base;
	u32 sob_inc_cfg_val;
	u8 fw_security_enabled;
	u8 msix_enabled;
};

/**
 * struct gaudi2_cn_aux_ops - ASIC specific functions for cn <-> compute drivers communication.
 * @get_event_name: Translate event type to name.
 * @poll_mem: Poll on a memory address until a given condition is fulfilled or timeout.
 * @dma_alloc_coherent: Allocate coherent DMA memory.
 * @dma_free_coherent: Free coherent DMA memory.
 * @dma_pool_zalloc: Allocate small size DMA memory from the pool.
 * @dma_pool_free: Free small size DMA memory from the pool.
 * @spmu_get_stats_info: get SPMU statistics information.
 * @spmu_config: config the SPMU.
 * @spmu_sample: read SPMU counters.
 * @poll_reg: Poll on a register until a given condition is fulfilled or timeout.
 * @send_cpu_message: send message to F/W. If the message is timedout, the driver will eventually
 *                    reset the device. The timeout is passed as an argument. If it is 0 the
 *                    timeout set is the default timeout for the specific ASIC.
 * @post_send_status: handler for post sending status packet to FW.
 * @reset_prepare: Prepare to reset.
 * @reset_late_init: Notify that compute device finished reset.
 * @sw_err_event_handler: Handle SW error event.
 * @axi_error_response_event_handler: Handle AXI error.
 * @ports_stop_prepare: prepare the ports for a stop.
 * @send_port_cpucp_status: Send port status to FW.
 */
struct gaudi2_cn_aux_ops {
	/* cn2compute */
	char *(*get_event_name)(struct hbl_aux_dev *aux_dev, u16 event_type);
	int (*poll_mem)(struct hbl_aux_dev *aux_dev, u32 *addr, u32 *val,
			hbl_cn_poll_cond_func func);
	void *(*dma_alloc_coherent)(struct hbl_aux_dev *aux_dev, size_t size,
				    dma_addr_t *dma_handle, gfp_t flag);
	void (*dma_free_coherent)(struct hbl_aux_dev *aux_dev, size_t size, void *cpu_addr,
				  dma_addr_t dma_handle);
	void *(*dma_pool_zalloc)(struct hbl_aux_dev *aux_dev, size_t size, gfp_t mem_flags,
				 dma_addr_t *dma_handle);
	void (*dma_pool_free)(struct hbl_aux_dev *aux_dev, void *vaddr, dma_addr_t dma_addr);
	void (*spmu_get_stats_info)(struct hbl_aux_dev *aux_dev, u32 port,
				    struct hbl_cn_stat **stats, u32 *n_stats);
	int (*spmu_config)(struct hbl_aux_dev *aux_dev, u32 port, u32 num_event_types,
			   u32 event_types[], bool enable);
	int (*spmu_sample)(struct hbl_aux_dev *aux_dev, u32 port, u32 num_out_data, u64 out_data[]);
	int (*poll_reg)(struct hbl_aux_dev *aux_dev, u32 reg, u64 timeout_us,
			hbl_cn_poll_cond_func func, void *arg);
	int (*send_cpu_message)(struct hbl_aux_dev *aux_dev, u32 *msg, u16 len, u32 timeout,
				u64 *result);
	void (*post_send_status)(struct hbl_aux_dev *aux_dev, u32 port);
	/* compute2cn */
	void (*reset_prepare)(struct hbl_aux_dev *aux_dev);
	void (*reset_late_init)(struct hbl_aux_dev *aux_dev);
	int (*sw_err_event_handler)(struct hbl_aux_dev *aux_dev, u16 event_type, u8 macro_index,
				    struct hl_eq_nic_intr_cause *intr_cause_cpucp);
	int (*axi_error_response_event_handler)(struct hbl_aux_dev *aux_dev, u16 event_type,
						u8 macro_index,
						struct hl_eq_nic_intr_cause *intr_cause_cpucp);
	void (*ports_stop_prepare)(struct hbl_aux_dev *aux_dev, bool fw_reset, bool in_teardown);
	int (*send_port_cpucp_status)(struct hbl_aux_dev *aux_dev, u32 port, u8 cmd, u8 period);
};

#endif /* HBL_GAUDI2_AUX_H_ */
