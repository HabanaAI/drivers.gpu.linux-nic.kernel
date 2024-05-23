/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2022-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#ifndef _HBL_H_
#define _HBL_H_

#include <linux/net/intel/cn.h>

#include <uapi/rdma/hbl-abi.h>
#include <uapi/rdma/hbl_user_ioctl_cmds.h>
#include <uapi/rdma/hbl_user_ioctl_verbs.h>
#include <rdma/ib_verbs.h>
#include <linux/pci.h>
#include <rdma/uverbs_ioctl.h>
#include <linux/xarray.h>

#define HBL_IB_MAX_PORT_GIDS 13

/* For internal ports, only one GID is required and that is based on the MAC address. */
#define HBL_IB_MAX_PORT_GIDS_INTERNAL 1

/* define maximum supported send and receive SGEs */
#define HBL_IB_MAX_SEND_SGE 2
#define HBL_IB_MAX_RECV_SGE 2

#define HBL_IB_EQ_PORT_FIELD_MASK 0xFFFF
#define HBL_IB_EQ_PORT_FIELD_SIZE 16

/**
 * struct hbl_ib_user_mmap_entry - Mmap information.
 * @rdma_entry: IB core rdma mmap entry.
 * @info: Information for performing mmap.
 */
struct hbl_ib_user_mmap_entry {
	struct rdma_user_mmap_entry rdma_entry;
	struct hbl_ib_mem_info info;
};

/**
 * struct hbl_ib_pd - Habanalabs IB PD.
 * @ibpd: IB core PD.
 * @pdn: PD ID.
 */
struct hbl_ib_pd {
	struct ib_pd ibpd;
	u32 pdn;
};

/**
 * struct hbl_ib_ucontext - Habanalabs IB user context.
 * @ibucontext: IB core user context.
 * @qp_xarray: QP handle.
 * @cn_ctx: CN context private data.
 * @pd_allocated: is PD allocated.
 * @ports_mask: Mask of ports associated with this context.
 */
struct hbl_ib_ucontext {
	struct ib_ucontext ibucontext;
	struct xarray qp_xarray;
	void *cn_ctx;
	atomic_t pd_allocated;
	u64 ports_mask;
};

/**
 * struct hbl_ib_cq - Habanalabs IB CQ.
 * @ibcq: IB core CQ.
 * @hctx: HBL IB context.
 * @mem_handle_entry: Mmap entry for the mem handle.
 * @pi_handle_entry: Mmap entry for the pi handle.
 * @regs_handle_entry: Mmap entry for the regs handle.
 * @port_cq: contains the hbl_ib_cq structure per port.
 * @cq_type: Type of CQ resource
 * @cq_num: CQ number that was allocated.
 * @hbl_port_num: hbl port number that matches with the core code's port number.
 * @is_native: If this is native create cq call or dv create cq call.
 */
struct hbl_ib_cq {
	struct ib_cq ibcq;
	struct hbl_ib_ucontext *hctx;
	struct rdma_user_mmap_entry *mem_handle_entry;
	struct rdma_user_mmap_entry *pi_handle_entry;
	struct rdma_user_mmap_entry *regs_handle_entry;
	struct hbl_ib_cq *port_cq;
	enum hbl_ibv_cq_type cq_type;
	u32 cq_num;
	u8 hbl_port_num;
	u8 is_native;
};

/**
 * struct hbl_ib_qp - Habanalabs IB QP.
 * @ibqp: IB core QP.
 * @hctx: hbl IB context.
 * @swq_mem_handle_entry: Mmap entry for the swq mem handle.
 * @rwq_mem_handle_entry: Mmap entry for the rwq mem handle.
 * @qp_state: Current QP state.
 * @wq_type: WQ type.
 * @qp_id: hbl core QP ID.
 * @dest_qp_num: destination qp number.
 * @max_send_wr: maximum send work requests supported.
 * @max_recv_wr: maximum receive work requests supported.
 * @mtu: QP mtu.
 * @dst_ip_addr: destination IPv4 address.
 * @dst_mac_addr: destination MAC address.
 * @wq_granularity: send WQE granularity.
 */
struct hbl_ib_qp {
	struct ib_qp ibqp;
	struct hbl_ib_ucontext *hctx;
	struct rdma_user_mmap_entry *swq_mem_handle_entry;
	struct rdma_user_mmap_entry *rwq_mem_handle_entry;
	enum ib_qp_state qp_state;
	enum qpc_req_wq_type wq_type;
	u32 qp_id;
	u32 dest_qp_num;
	u32 max_send_wr;
	u32 max_recv_wr;
	u32 mtu;
	u32 dst_ip_addr;
	u8 dst_mac_addr[ETH_ALEN];
	u8 wq_granularity;
};

/**
 * struct gid_entry - IB GID structure.
 * @gid: IB global identifier.
 * @gid_type: IB GID type.
 */
struct gid_entry {
	union ib_gid gid;
	enum ib_gid_type gid_type;
};

/**
 * struct hbl_ib_port_init_params - Habanalabs IB port input parameters.
 * @wq_arr_attr: Array of WQ-array attributes for each WQ-array type.
 * @qp_wq_bp_offs: Offsets in NIC memory to signal a back pressure.
 * @hbl_port_num: hbl port number that matches with the core code's port number.
 * @advanced: WQ should support advanced operations such as RDV, QMan, WTD, etc.
 * @adaptive_timeout_en: Enable adaptive_timeout feature on the port.
 */
struct hbl_ib_port_init_params {
	struct hbl_wq_array_attr wq_arr_attr[HBL_IB_WQ_ARRAY_TYPE_MAX];
	u32 qp_wq_bp_offs[HBL_IB_MAX_BP_OFFS];
	u32 hbl_port_num;
	u8 advanced;
	u8 adaptive_timeout_en;
};

/**
 * struct hbl_ib_port - Habanalabs IB port.
 * @hdev: Habanalabs IB device.
 * @hctx: hbl IB context.
 * @gids: Array of GIDs (group IDs).
 * @hbl_ibcq_tbl: CQ IDs table.
 * @eq_comp: Completion object for event queue.
 * @eq_thread: Event queue thread.
 * @eq_lock: Event queue handling synchronization object.
 * @port: Port ID.
 * @mtu: Port MTU.
 * @swqs_enabled: Array of send WQs from each type which indicate if WQ is enabled.
 * @rwqs_enabled: Array of receive WQs from each type which indicate if WQ is enabled.
 * @open: Port initialized.
 */
struct hbl_ib_port {
	struct hbl_ib_device *hdev;
	struct hbl_ib_ucontext *hctx;
	struct gid_entry gids[HBL_IB_MAX_PORT_GIDS];
	struct xarray hbl_ibcq_tbl;
	struct completion eq_comp;
	struct task_struct *eq_thread;
	atomic_t eq_lock;
	u32 port;
	u32 mtu;
	u8 swqs_enabled[HBL_IB_WQ_ARRAY_TYPE_MAX];
	u8 rwqs_enabled[HBL_IB_WQ_ARRAY_TYPE_MAX];
	u8 open;
};

/**
 * struct hbl_ib_device_stats - IB device counters structure.
 * @fatal_event: Fatal events counter.
 */
struct hbl_ib_device_stats {
	atomic_t fatal_event;
};

/**
 * struct hbl_ib_port_stats - IB port counters info.
 * @stat_desc: Core rdma stats structure of the counters.
 * @names: Names of the counters.
 * @num: Number of counters.
 */
struct hbl_ib_port_stats {
	struct rdma_stat_desc *stat_desc;
	u8 **names;
	u32 num;
};

/**
 * struct hbl_ib_device - habanalabs IB device structure.
 * @ibdev: IB device.
 * @dev_stats: Device counters.
 * @netdev_notifier: netdev events notifier.
 * @port_stats: Array of port counters.
 * @pdev: Pointer to PCI device.
 * @dev: Related kernel basic device structure.
 * @aux_dev: Pointer to auxiliary device.
 * @ib_port: IB port structure.
 * @hbl_to_ib_port_map: mapping array between hbl port to IB port.
 * @dev_lock: Device lock for configuration serialization.
 * @ctx_open: User context allocated.
 * @ports_mask: Mask of available ports.
 * @ext_ports_mask: Mask of external ports (subset of ports_mask).
 * @pending_reset_long_timeout: Long timeout for pending hard reset to finish in seconds.
 * @id: Core device ID.
 * @max_num_of_ports: Maximum number of ports supported by ASIC.
 * @mixed_qp_wq_types: Using mixed QP WQ types is supported.
 * @umr_support: device supports UMR.
 * @cc_support: device supports congestion control.
 */
struct hbl_ib_device {
	struct ib_device ibdev;
	struct hbl_ib_device_stats dev_stats;
	struct notifier_block netdev_notifier;
	struct hbl_ib_port_stats *port_stats;
	struct pci_dev *pdev;
	struct device *dev;
	struct hbl_aux_dev *aux_dev;
	struct hbl_ib_port *ib_port;
	u32 *hbl_to_ib_port_map;
	atomic_t ctx_open;
	u64 ports_mask;
	u64 ext_ports_mask;
	u32 pending_reset_long_timeout;
	u16 id;
	u8 max_num_of_ports;
	u8 mixed_qp_wq_types;
	u8 umr_support;
	u8 cc_support;
};

extern const struct ib_device_ops hbl_ib_dev_ops;
extern const struct uapi_definition hbl_usr_fifo_defs[];
extern const struct uapi_definition hbl_set_port_ex_defs[];
extern const struct uapi_definition hbl_query_port_defs[];
extern const struct uapi_definition hbl_encap_defs[];

static inline struct hbl_ib_device *to_hbl_ib_dev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct hbl_ib_device, ibdev);
}

static inline struct hbl_ib_ucontext *to_hbl_ib_ucontext(struct ib_ucontext *ibucontext)
{
	return container_of(ibucontext, struct hbl_ib_ucontext, ibucontext);
}

static inline u32 hbl_to_ib_port_num(struct hbl_ib_device *hdev, u32 hbl_port_num)
{
	return hdev->hbl_to_ib_port_map[hbl_port_num];
}

static inline int ib_to_hbl_port_num(struct hbl_ib_device *hdev, u32 ib_port_num, u32 *hbl_port_num)
{
	u32 hbl_port;

	if (!ib_port_num)
		return -EINVAL;

	for (hbl_port = 0; hbl_port < hdev->max_num_of_ports; hbl_port++)
		if (hbl_to_ib_port_num(hdev, hbl_port) == ib_port_num) {
			*hbl_port_num = hbl_port;
			return 0;
		}

	return -EINVAL;
}

static inline struct hbl_ib_user_mmap_entry *
to_hbl_ib_user_mmap_entry(struct rdma_user_mmap_entry *rdma_entry)
{
	return container_of(rdma_entry, struct hbl_ib_user_mmap_entry, rdma_entry);
}

struct rdma_user_mmap_entry *
hbl_ib_user_mmap_entry_insert(struct ib_ucontext *ucontext, u64 address, size_t length,
			      u64 *offset);

#define hbl_ibdev_emerg(ibdev, format, ...)	ibdev_emerg(ibdev, format, ##__VA_ARGS__)
#define hbl_ibdev_alert(ibdev, format, ...)	ibdev_alert(ibdev, format, ##__VA_ARGS__)
#define hbl_ibdev_crit(ibdev, format, ...)	ibdev_crit(ibdev, format, ##__VA_ARGS__)
#define hbl_ibdev_err(ibdev, format, ...)	ibdev_err(ibdev, format, ##__VA_ARGS__)
#define hbl_ibdev_warn(ibdev, format, ...)	ibdev_warn(ibdev, format, ##__VA_ARGS__)
#define hbl_ibdev_notice(ibdev, format, ...)	ibdev_notice(ibdev, format, ##__VA_ARGS__)
#define hbl_ibdev_info(ibdev, format, ...)	ibdev_info(ibdev, format, ##__VA_ARGS__)
#define hbl_ibdev_dbg(ibdev, format, ...)	ibdev_dbg(ibdev, format, ##__VA_ARGS__)

#define hbl_ibdev_emerg_ratelimited(ibdev, fmt, ...)		\
	ibdev_emerg_ratelimited(ibdev, fmt, ##__VA_ARGS__)
#define hbl_ibdev_alert_ratelimited(ibdev, fmt, ...)		\
	ibdev_alert_ratelimited(ibdev, fmt, ##__VA_ARGS__)
#define hbl_ibdev_crit_ratelimited(ibdev, fmt, ...)		\
	ibdev_crit_ratelimited(ibdev, fmt, ##__VA_ARGS__)
#define hbl_ibdev_err_ratelimited(ibdev, fmt, ...)		\
	ibdev_err_ratelimited(ibdev, fmt, ##__VA_ARGS__)
#define hbl_ibdev_warn_ratelimited(ibdev, fmt, ...)		\
	ibdev_warn_ratelimited(ibdev, fmt, ##__VA_ARGS__)
#define hbl_ibdev_notice_ratelimited(ibdev, fmt, ...)		\
	ibdev_notice_ratelimited(ibdev, fmt, ##__VA_ARGS__)
#define hbl_ibdev_info_ratelimited(ibdev, fmt, ...)		\
	ibdev_info_ratelimited(ibdev, fmt, ##__VA_ARGS__)
#define hbl_ibdev_dbg_ratelimited(ibdev, fmt, ...)		\
	ibdev_dbg_ratelimited(ibdev, fmt, ##__VA_ARGS__)

int hbl_ib_port_init(struct hbl_ib_ucontext *hctx, struct hbl_ib_port_init_params *init_params);
void hbl_ib_eqe_handler(struct hbl_ib_port *ib_port);
void hbl_ib_eqe_null_work(struct hbl_aux_dev *aux_dev, u32 port);
void hbl_ib_eqe_work_schd(struct hbl_aux_dev *aux_dev, u32 port);

#endif /* _HBL_H_ */
