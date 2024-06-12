/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 *
 */

#ifndef CN_H_
#define CN_H_

#include <uapi/drm/habanalabs_accel.h>
#include <linux/net/intel/cn_aux.h>

#include <linux/kfifo.h>
#include <linux/hashtable.h>
#include <linux/ctype.h>

#include <linux/habanalabs/cpucp_if.h>

struct hl_device;
struct hl_ctx;

#define NIC_MACRO_CFG_SIZE		hdev->asic_prop.macro_cfg_size
#define NIC_MACRO_CFG_BASE(port)	(NIC_MACRO_CFG_SIZE * ((port) >> 1))
#define NIC_MACRO_WREG32(reg, val)	WREG32(NIC_MACRO_CFG_BASE(port) + (reg), (val))

/**
 * struct hl_cn - habanalabs CN common structure.
 * @cn_aux_dev: pointer to CN auxiliary device structure.
 * @ctx: compute user context.
 * @hw_access_lock: protects the HW access from CN flows.
 * @ports_mask: contains mask of the CN ports that are enabled, as received from the f/w. This
 *              field can contain different values based on the server type
 * @ports_ext_mask: contains mask of the CN ports that are external (used for scale-out), as
 *                  received from the f/w. This field can contain different values based on the
 *                  server type.
 * @auto_neg_mask: mask of ports with Autonegotiation enabled.
 * @eth_ports_mask: Ethernet ports enable mask.
 * @ctx_registered: is user context registered.
 * @card_location: the OAM number in the HLS (relevant for PMC card type).
 * @lanes_per_port: number of physical lanes per port.
 * @use_fw_serdes_info: true if NIC should use serdes values from F/W, false if CN should use hard
 *                      coded values.
 * @is_cn_aux_dev_initialized: true if the CN auxiliary device is initialized.
 * @is_initialized: is device initialized.
 * @load_fw: load PHY FW from ASIC path.
 * @skip_phy_init: skip PHY init phase.
 * @eth_on_internal: set internal ports as Ethernet ports.
 */
struct hl_cn {
	struct hbl_aux_dev	cn_aux_dev;
	struct hl_ctx		*ctx;
	struct mutex		hw_access_lock;
	u64			ports_mask;
	u64			ports_ext_mask;
	u64			auto_neg_mask;
	u64			eth_ports_mask;
	atomic_t		ctx_registered;
	u32			card_location;
	u8			lanes_per_port;
	u8			use_fw_serdes_info;
	u8			is_cn_aux_dev_initialized;
	u8			is_initialized;
	u8			load_fw;
	u8			skip_phy_init;
	u8			eth_on_internal;
};

/**
 * struct hl_cn_port_funcs - ASIC specific CN functions that are called from common code for a
 *                            specific port.
 * @spmu_get_stats_info: get SPMU statistics information.
 * @spmu_config: config the SPMU.
 * @spmu_sample: read the SPMU counters.
 * @post_send_status: ASIC-specific handler for post sending status packet to FW.
 * @ports_stop_prepare: prepare the ports for a stop.
 * @send_port_cpucp_status: Send port status to FW.
 */
struct hl_cn_port_funcs {
	void (*spmu_get_stats_info)(struct hl_device *hdev, u32 port, struct hbl_cn_stat **stats,
					u32 *n_stats);
	int (*spmu_config)(struct hl_device *hdev, u32 port, u32 num_event_types, u32 event_types[],
				bool enable);
	int (*spmu_sample)(struct hl_device *hdev, u32 port, u32 num_out_data, u64 out_data[]);
	void (*post_send_status)(struct hl_device *hdev, u32 port);
	void (*ports_stop_prepare)(struct hl_device *hdev, bool fw_reset, bool in_teardown);
	int (*send_port_cpucp_status)(struct hl_device *hdev, u32 port, u8 cmd, u8 period);
};

/**
 * struct hl_cn_funcs - ASIC specific CN functions that are called from common code.
 * @pre_core_init: NIC initializations to be done only once on device probe.
 * @get_hw_cap: check rather HW capability bitmap is set for NIC.
 * @set_hw_cap: set HW capability (on/off).
 * @set_cn_data: ASIC data to be used by the CN driver.
 * @port_funcs: functions called from common code for a specific NIC port.
 */
struct hl_cn_funcs {
	int (*pre_core_init)(struct hl_device *hdev);
	bool (*get_hw_cap)(struct hl_device *hdev);
	void (*set_hw_cap)(struct hl_device *hdev, bool enable);
	void (*set_cn_data)(struct hl_device *hdev);
	struct hl_cn_port_funcs *port_funcs;
};

int hl_cn_init(struct hl_device *hdev);
void hl_cn_fini(struct hl_device *hdev);
void hl_cn_stop(struct hl_device *hdev);
int hl_cn_reopen(struct hl_device *hdev);
int hl_cn_send_status(struct hl_device *hdev, int port, u8 cmd, u8 period);
void hl_cn_hard_reset_prepare(struct hl_device *hdev, bool fw_reset);
void hl_cn_synchronize_irqs(struct hl_device *hdev);
int hl_cn_cpucp_info_get(struct hl_device *hdev);
void *hl_cn_dma_alloc_coherent(struct hbl_aux_dev *aux_dev, size_t size, dma_addr_t *dma_handle,
			       gfp_t flag);
void hl_cn_dma_free_coherent(struct hbl_aux_dev *aux_dev, size_t size, void *cpu_addr,
			     dma_addr_t dma_handle);
void *hl_cn_dma_pool_zalloc(struct hbl_aux_dev *aux_dev, size_t size, gfp_t mem_flags,
			    dma_addr_t *dma_handle);
void hl_cn_dma_pool_free(struct hbl_aux_dev *aux_dev, void *vaddr, dma_addr_t dma_addr);
void hl_cn_spmu_get_stats_info(struct hbl_aux_dev *aux_dev, u32 port, struct hbl_cn_stat **stats,
				u32 *n_stats);
int hl_cn_spmu_config(struct hbl_aux_dev *aux_dev, u32 port, u32 num_event_types, u32 event_types[],
			bool enable);
int hl_cn_spmu_sample(struct hbl_aux_dev *aux_dev, u32 port, u32 num_out_data, u64 out_data[]);
int hl_cn_poll_reg(struct hbl_aux_dev *aux_dev, u32 reg, u64 timeout_us, hbl_cn_poll_cond_func func,
			void *arg);
int hl_cn_send_cpu_message(struct hbl_aux_dev *aux_dev, u32 *msg, u16 len, u32 timeout,
				u64 *result);
void hl_cn_post_send_status(struct hbl_aux_dev *aux_dev, u32 port);

#endif /* CN_H_ */
