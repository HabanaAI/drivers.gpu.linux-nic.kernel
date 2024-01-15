/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef HLIB_H_
#define HLIB_H_

#include <linux/net/intel/cn.h>

#include <uapi/rdma/hlib-abi.h>
#include <uapi/rdma/hlib_user_ioctl_cmds.h>
#include <uapi/rdma/hlib_user_ioctl_verbs.h>
#include <rdma/ib_verbs.h>
#include <linux/pci.h>
#include <rdma/uverbs_ioctl.h>
#include <linux/xarray.h>

#include "../../../net/ethernet/intel/hl_cn/common/habanalabs_cn_compat.h"

/*
 * For external ports, 2 GID entries, one for each type RoCEv1, RoCEv2 and for
 * each address type MAC, ipv4, ipv6. Allotting an extra GID slot for flexibility.
 * For internal ports, only one GID is required and that is based on the MAC address.
 */
#define HL_IB_MAX_PORT_GIDS 7
#define HL_IB_MAX_PORT_GIDS_INTERNAL 1

/* define maximum supported send and receive SGEs */
#define HL_IB_MAX_SEND_SGE 2
#define HL_IB_MAX_RECV_SGE 2

#define HL_IB_EQ_PORT_FIELD_MASK 0xFFFF
#define HL_IB_EQ_PORT_FIELD_SIZE 16

/**
 * struct hl_ib_pd - Habanalabs IB PD.
 * @ibpd: IB core PD.
 * @pdn: PD ID.
 */
struct hl_ib_pd {
	struct ib_pd ibpd;
	u32 pdn;
};

/**
 * struct hl_ib_ucontext - Habanalabs IB user context.
 * @ibucontext: IB core user context.
 * @qp_xarray: QP handle.
 * @cn_ctx: CN context private data.
 * @pd_allocated: is PD allocated.
 * @ports_mask: Mask of ports associated with this context.
 */
struct hl_ib_ucontext {
	struct ib_ucontext ibucontext;
	struct xarray qp_xarray;
	void *cn_ctx;
	atomic_t pd_allocated;
	u64 ports_mask;
};

/**
 * struct hl_ib_cq - Habanalabs IB CQ.
 * @ibcq: IB core CQ.
 * @cq_type: Type of CQ resource
 * @cq_num: CQ number that was allocated.
 * @hl_port_num: HL port number that matches with the core code's port number.
 */
struct hl_ib_cq {
	struct ib_cq ibcq;
	enum hlib_ibv_cq_type cq_type;
	u32 cq_num;
	u8 hl_port_num;
};

/**
 * struct hl_ib_qp - Habanalabs IB QP.
 * @ibqp: IB core QP.
 * @hctx: HL IB context.
 * @qp_state: Current QP state.
 * @wq_type: WQ type.
 * @qp_id: HL core QP ID.
 * @dest_qp_num: destination qp number.
 * @max_send_wr: maximum send work requests supported.
 * @max_recv_wr: maximum receive work requests supported.
 * @mtu: QP mtu.
 * @dst_ip_addr: destination IPv4 address.
 * @dst_mac_addr: destination MAC address.
 * @wq_granularity: send WQE granularity.
 */
struct hl_ib_qp {
	struct ib_qp ibqp;
	struct hl_ib_ucontext *hctx;
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
 * struct hl_ib_port_init_params - Habanalabs IB port input parameters.
 * @wq_arr_attr: Array of WQ-array attributes for each WQ-array type.
 * @qp_wq_bp_offs: Offsets in NIC memory to signal a back pressure.
 * @atomic_fna_fifo_offs: SRAM/DCCM addresses provided to the HW by the user when FnA completion is
 *		          configured in the SRAM/DDCM.
 * @hl_port_num: HL port number that matches with the core code's port number.
 * @atomic_fna_mask_size: Completion address value mask.
 * @advanced: WQ should support advanced operations such as RDV, QMan, WTD, etc.
 */
struct hl_ib_port_init_params {
	struct hlib_wq_array_attr wq_arr_attr[HL_IB_WQ_ARRAY_TYPE_MAX];
	u32 qp_wq_bp_offs[HL_IB_MAX_BP_OFFS];
	u32 atomic_fna_fifo_offs[HL_IB_FNA_CMPL_ADDR_NUM];
	u32 hl_port_num;
	u8 atomic_fna_mask_size;
	u8 advanced;
};

/**
 * struct hl_ib_port - Habanalabs IB port.
 * @hdev: Habanalabs IB device.
 * @hctx: HL IB context.
 * @init_params: Init parameters for this port.
 * @gids: Array of GIDs (group IDs).
 * @hl_ibcq_tbl: CQ IDs table.
 * @eq_comp: Completion object for event queue.
 * @eq_thread: Event queue thread.
 * @eq_lock: Event queue handling synchronization object.
 * @port: Port ID.
 * @mtu: Port MTU.
 * @swqs_enabled: Array of send WQs from each type which indicate if WQ is enabled.
 * @rwqs_enabled: Array of receive WQs from each type which indicate if WQ is enabled.
 * @open: Port initialized.
 */
struct hl_ib_port {
	struct hl_ib_device *hdev;
	struct hl_ib_ucontext *hctx;
	struct hl_ib_port_init_params init_params;
	struct gid_entry gids[HL_IB_MAX_PORT_GIDS];
	struct xarray hl_ibcq_tbl;
	struct completion eq_comp;
	struct task_struct *eq_thread;
	atomic_t eq_lock;
	u32 port;
	u32 mtu;
	u8 swqs_enabled[HL_IB_WQ_ARRAY_TYPE_MAX];
	u8 rwqs_enabled[HL_IB_WQ_ARRAY_TYPE_MAX];
	u8 open;
};

/**
 * struct hl_ib_device_stats - IB device counters structure.
 * @coll_qp: Collective QP counter.
 */
struct hl_ib_device_stats {
	atomic_t coll_qp;
};

#ifdef _HAS_STRUCT_RDMA_STAT_DESC
/**
 * struct hl_ib_port_stats - IB port counters info.
 * @stat_desc: Core rdma stats structure of the counters.
 * @names: Names of the counters.
 * @num: Number of counters.
 */
struct hl_ib_port_stats {
	struct rdma_stat_desc *stat_desc;
	u8 **names;
	u32 num;
};
#else
/**
 * struct hl_ib_port_stats - IB port counters info.
 * @names: Names of the counters.
 * @num: Number of counters.
 */
struct hl_ib_port_stats {
	u8 **names;
	u32 num;
};
#endif

/**
 * struct hl_ib_device - habanalabs IB device structure.
 * @ibdev: IB device.
 * @dev_stats: Device counters.
 * @netdev_notifier: netdev events notifier.
 * @port_stats: Array of port counters.
 * @pdev: Pointer to PCI device, can be NULL in case of simulator device.
 * @dev: Related kernel basic device structure.
 * @fw_ver: FW version.
 * @aux_dev: Pointer to auxiliary device.
 * @ib_port: IB port structure.
 * @hl_to_ib_port_map: mapping array between hl port to IB port.
 * @dev_lock: Device lock for configuration serialization.
 * @ctx_open: User context allocated.
 * @ports_mask: Mask of available ports.
 * @ext_ports_mask: Mask of external ports (subset of ports_mask).
 * @pending_reset_long_timeout: Long timeout for pending hard reset to finish in seconds.
 * @id: Core device ID.
 * @max_num_of_ports: Maximum number of ports supported by ASIC.
 * @mixed_qp_wq_types: Using mixed QP WQ types is supported.
 * @umr_support: device supports UMR.
 */
struct hl_ib_device {
	struct ib_device ibdev;
	struct hl_ib_device_stats dev_stats;
	struct notifier_block netdev_notifier;
	struct hl_ib_port_stats *port_stats;
	struct pci_dev *pdev;
	struct device *dev;
	char *fw_ver;
	struct hl_aux_dev *aux_dev;
	struct hl_ib_port *ib_port;
	u32 *hl_to_ib_port_map;
	atomic_t ctx_open;
	u64 ports_mask;
	u64 ext_ports_mask;
	u32 pending_reset_long_timeout;
	u16 id;
	u8 max_num_of_ports;
	u8 mixed_qp_wq_types;
	u8 umr_support;
};

extern const struct ib_device_ops hl_ib_dev_ops;
extern const struct uapi_definition hlib_usr_fifo_defs[];
extern const struct uapi_definition hlib_set_port_ex_defs[];
extern const struct uapi_definition hlib_query_port_defs[];
extern const struct uapi_definition hlib_collective_qp_defs[];
extern const struct uapi_definition hlib_encap_defs[];

static inline struct hl_ib_device *to_hl_ib_dev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct hl_ib_device, ibdev);
}

static inline struct hl_ib_ucontext *to_hl_ib_ucontext(struct ib_ucontext *ibucontext)
{
	return container_of(ibucontext, struct hl_ib_ucontext, ibucontext);
}

static inline int ib_to_hl_port_num(struct hl_ib_device *hdev, u32 ib_port_num, u32 *hl_port_num)
{
	u32 hl_port;

	if (!ib_port_num)
		return -EINVAL;

	for (hl_port = 0; hl_port < hdev->max_num_of_ports; hl_port++)
		if (hdev->hl_to_ib_port_map[hl_port] == ib_port_num) {
			*hl_port_num = hl_port;
			return 0;
		}

	return -EINVAL;
}

static inline u32 hl_to_ib_port_num(struct hl_ib_device *hdev, u32 hl_port_num)
{
	return hdev->hl_to_ib_port_map[hl_port_num];
}

#define hl_ibdev_emerg(ibdev, format, ...)	ibdev_emerg(ibdev, format, ##__VA_ARGS__)
#define hl_ibdev_alert(ibdev, format, ...)	ibdev_alert(ibdev, format, ##__VA_ARGS__)
#define hl_ibdev_crit(ibdev, format, ...)	ibdev_crit(ibdev, format, ##__VA_ARGS__)
#define hl_ibdev_err(ibdev, format, ...)	ibdev_err(ibdev, format, ##__VA_ARGS__)
#define hl_ibdev_warn(ibdev, format, ...)	ibdev_warn(ibdev, format, ##__VA_ARGS__)
#define hl_ibdev_notice(ibdev, format, ...)	ibdev_notice(ibdev, format, ##__VA_ARGS__)
#define hl_ibdev_info(ibdev, format, ...)	ibdev_info(ibdev, format, ##__VA_ARGS__)
#ifdef _HAS_IB_DEV_DBG
#define hl_ibdev_dbg(ibdev, format, ...) \
	dev_dbg((ibdev)->dev.parent, "%s: " format, dev_name(&(ibdev)->dev), ##__VA_ARGS__)
#else
#define hl_ibdev_dbg(ibdev, format, ...)	ibdev_dbg(ibdev, format, ##__VA_ARGS__)
#endif

#define hl_ibdev_emerg_ratelimited(ibdev, fmt, ...)		\
	ibdev_emerg_ratelimited(ibdev, fmt, ##__VA_ARGS__)
#define hl_ibdev_alert_ratelimited(ibdev, fmt, ...)		\
	ibdev_alert_ratelimited(ibdev, fmt, ##__VA_ARGS__)
#define hl_ibdev_crit_ratelimited(ibdev, fmt, ...)		\
	ibdev_crit_ratelimited(ibdev, fmt, ##__VA_ARGS__)
#define hl_ibdev_err_ratelimited(ibdev, fmt, ...)		\
	ibdev_err_ratelimited(ibdev, fmt, ##__VA_ARGS__)
#define hl_ibdev_warn_ratelimited(ibdev, fmt, ...)		\
	ibdev_warn_ratelimited(ibdev, fmt, ##__VA_ARGS__)
#define hl_ibdev_notice_ratelimited(ibdev, fmt, ...)		\
	ibdev_notice_ratelimited(ibdev, fmt, ##__VA_ARGS__)
#define hl_ibdev_info_ratelimited(ibdev, fmt, ...)		\
	ibdev_info_ratelimited(ibdev, fmt, ##__VA_ARGS__)
#ifdef _HAS_IB_DEV_DBG
#define hl_ibdev_dbg_ratelimited(ibdev, fmt, ...)		\
	dev_dbg_ratelimited((ibdev)->dev.parent, "%s: " fmt, dev_name(&(ibdev)->dev), ##__VA_ARGS__)
#else
#define hl_ibdev_dbg_ratelimited(ibdev, fmt, ...)		\
	ibdev_dbg_ratelimited(ibdev, fmt, ##__VA_ARGS__)
#endif

#ifndef _HAS_AUX_BUS_H
int hl_ib_probe(struct hl_aux_dev *aux_dev);
void hl_ib_remove(struct hl_aux_dev *aux_dev);
#endif

int hl_ib_port_init(struct hl_ib_ucontext *hctx, struct hl_ib_port_init_params *in);
void hl_ib_eqe_handler(struct hl_ib_port *ib_port);
void hl_ib_eqe_null_work(struct hl_aux_dev *aux_dev, u32 port);
void hl_ib_eqe_work_schd(struct hl_aux_dev *aux_dev, u32 port);

int hl_ib_sysfs_init(struct hl_ib_device *hdev);
void hl_ib_sysfs_fini(struct hl_ib_device *hdev);

#endif /* HLIB_H_ */
