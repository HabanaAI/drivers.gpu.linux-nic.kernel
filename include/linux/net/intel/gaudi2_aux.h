/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2023-2024, Intel Corporation.
 * Copyright 2021-2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef HL_GAUDI2_AUX_H_
#define HL_GAUDI2_AUX_H_

#include <linux/types.h>
#include <linux/net/intel/cn_aux.h>

/**
 * struct gaudi2_cn_aux_data - Gaudi2 CN driver data.
 * @cfg_base: configuration space base address.
 * @irq_num_port_base: base IRQ number for port EQ.
 * @sob_id_base: first reserved SOB ID.
 * @sob_inc_cfg_val: configuration value for incrementing SOB by one.
 * @fw_security_enabled: FW security enabled.
 * @msix_enabled: MSI-X enabled.
 */
struct gaudi2_cn_aux_data {
	u64 cfg_base;
	u32 irq_num_port_base;
	u32 sob_id_base;
	u32 sob_inc_cfg_val;
	u8 fw_security_enabled;
	u8 msix_enabled;
};

/**
 * struct gaudi2_cn_aux_ops - ASIC specific functions for cn <-> accel drivers communication.
 * @get_event_name: Translate event type to name.
 * @poll_mem: Poll on a memory address until a given condition is fulfilled or timeout.
 * @reset_prepare: Prepare to reset.
 * @reset_late_init: Notify that compute device finished reset.
 * @eq_irq_handler: EQ interrupt handler (used for simulator only).
 * @sw_err_event_handler: Handle SW error event.
 * @axi_error_response_event_handler: Handle AXI error.
 */
struct gaudi2_cn_aux_ops {
	/* cn2accel */
	char *(*get_event_name)(struct hl_aux_dev *aux_dev, u16 event_type);
	int (*poll_mem)(struct hl_aux_dev *aux_dev, u32 *addr, u32 *val,
			hl_cn_poll_cond_func func);
	/* accel2cn */
	void (*reset_prepare)(struct hl_aux_dev *aux_dev);
	void (*reset_late_init)(struct hl_aux_dev *aux_dev);
	irqreturn_t (*eq_irq_handler)(struct hl_aux_dev *aux_dev, int irq);
	int (*sw_err_event_handler)(struct hl_aux_dev *aux_dev, u16 event_type, u8 macro_index,
					struct hl_eq_nic_intr_cause *intr_cause_cpucp);
	int (*axi_error_response_event_handler)(struct hl_aux_dev *aux_dev, u16 event_type,
					u8 macro_index,
					struct hl_eq_nic_intr_cause *intr_cause_cpucp);
};

#endif /* HL_GAUDI2_AUX_H_ */
