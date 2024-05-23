/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#ifndef HBL_CN_H_
#define HBL_CN_H_

#include <linux/types.h>
#include <linux/sizes.h>
#include <linux/net/intel/cn_aux.h>

#define HBL_EN_PFC_PRIO_NUM	4
#define CQ_ARM_TIMEOUT_USEC	10

struct qpc_mask;

/**
 * enum hbl_cn_pflags - mutable capabilities of the port.
 * PFLAGS_PCS_LINK_CHECK: check for PCS link periodically.
 * PFLAGS_PHY_AUTO_NEG_LPBK: allow Autonegotiation in loopback.
 */
enum hbl_cn_pflags {
	PFLAGS_PCS_LINK_CHECK = BIT(0),
	PFLAGS_PHY_AUTO_NEG_LPBK = BIT(1),
};

enum hbl_ts_type {
	TS_RC = 0,
	TS_RAW = 1
};

enum hbl_trust_level {
	UNSECURED = 0,
	SECURED = 1,
	PRIVILEGE = 2
};

/**
 * enum qpc_req_wq_type - QP REQ WQ type.
 * @QPC_REQ_WQ_TYPE_WRITE: WRITE, "native" SEND, RECV-RDV or READ-RDV operations are allowed.
 * @QPC_REQ_WQ_TYPE_RDV_READ: No operation is allowed on this endpoint QP.
 * @QPC_REQ_WQ_TYPE_RDV_WRITE: SEND-RDV operation is allowed on this QP.
 */
enum qpc_req_wq_type {
	QPC_REQ_WQ_TYPE_WRITE = 1,
	QPC_REQ_WQ_TYPE_RDV_READ = 2,
	QPC_REQ_WQ_TYPE_RDV_WRITE = 3
};

/**
 * enum hbl_ib_mem_type - Memory allocation types.
 * @HBL_IB_MEM_INVALID: N/A option.
 * @HBL_IB_MEM_HOST_DMA_COHERENT: Host DMA coherent memory.
 * @HBL_IB_MEM_HOST_VIRTUAL: Host virtual memory.
 * @HBL_IB_MEM_DEVICE: Device HBM memory.
 * @HBL_IB_MEM_HOST_MAP_ONLY: Host mapping only.
 * @HBL_IB_MEM_HW_BLOCK: Hw registers.
 */
enum hbl_ib_mem_type {
	HBL_IB_MEM_INVALID,
	HBL_IB_MEM_HOST_DMA_COHERENT,
	HBL_IB_MEM_HOST_VIRTUAL,
	HBL_IB_MEM_DEVICE,
	HBL_IB_MEM_HOST_MAP_ONLY,
	HBL_IB_MEM_HW_BLOCK,
};

/**
 * struct hbl_cn_eqe - describes an event-queue entry
 * @data: the data each event-queue entry contains
 */
struct hbl_cn_eqe {
	u32 data[4];
};

/**
 * struct hbl_cn_mem_resources - memory resource used by a memory ring.
 * @addr: virtual address of the memory.
 * @dma_addr: physical address of the memory.
 * @size: memory size.
 */
struct hbl_cn_mem_resource {
	void *addr;
	dma_addr_t dma_addr;
	u32 size;
};

/**
 * struct hbl_cn_ring - represents a memory ring.
 * @buf: the ring buffer memory resource.
 * @pi: the memory-resident producer index of the ring, updated by HW
 * @pi_shadow: producer shadow index - used by SW
 * @ci_shadow: consumer shadow index - used by SW
 * @rep_idx: use to count until a threshold value, like HW update
 * @asid: the asid of the ring
 * @count: the number of elements the ring can hold
 * @elem_size: the rings's element size
 */
struct hbl_cn_ring {
	struct hbl_cn_mem_resource buf;
	struct hbl_cn_mem_resource pi;
	u32 pi_shadow;
	u32 ci_shadow;
	u32 rep_idx;
	u32 asid;
	u32 count;
	u32 elem_size;
};

/* ring support */
#define RING_BUF_DMA_ADDRESS(ring)	((ring)->buf.dma_addr)
#define RING_BUF_ADDRESS(ring)		((ring)->buf.addr)
#define RING_BUF_SIZE(ring)		((ring)->buf.size)
#define RING_PI_DMA_ADDRESS(ring)	((ring)->pi.dma_addr)
#define RING_PI_ADDRESS(ring)		((ring)->pi.addr)
#define RING_PI_SIZE(ring)		((ring)->pi.size)
#define RING_CI_ADDRESS(ring)		RING_BUF_ADDRESS(ring)

/* Ethernet */

/**
 * struct hbl_en_aux_data - habanalabs data for the Ethernet driver.
 * @pdev: pointer to PCI device.
 * @dev: related kernel basic device structure.
 * @asic_specific: ASIC specific data.
 * @fw_ver: FW version.
 * @qsfp_eeprom: QSFPD EEPROM info.
 * @mac_addr: array of all MAC addresses.
 * @asic_type: ASIC specific type.
 * @ports_mask: mask of available ports.
 * @auto_neg_mask: mask of port with Autonegotiation enabled.
 * @pending_reset_long_timeout: long timeout for pending hard reset to finish in seconds.
 * @max_frm_len: maximum allowed frame length.
 * @raw_elem_size: size of element in raw buffers.
 * @max_raw_mtu: maximum MTU size for raw packets.
 * @min_raw_mtu: minimum MTU size for raw packets.
 * @id: device ID.
 * @max_num_of_ports: max number of available ports.
 * @has_eq: true if event queue is supported.
 */
struct hbl_en_aux_data {
	struct pci_dev *pdev;
	struct device *dev;
	void *asic_specific;
	char *fw_ver;
	char *qsfp_eeprom;
	char **mac_addr;
	enum hbl_cn_asic_type asic_type;
	u64 ports_mask;
	u64 auto_neg_mask;
	u32 pending_reset_long_timeout;
	u32 max_frm_len;
	u32 raw_elem_size;
	u16 max_raw_mtu;
	u16 min_raw_mtu;
	u16 id;
	u8 max_num_of_ports;
	u8 has_eq;
};

/**
 * struct hbl_en_aux_ops - pointer functions for cn <-> en drivers communication.
 * @device_operational: is device operational.
 * @hw_access_lock: prevent HW access.
 * @hw_access_unlock: allow HW access.
 * @is_eth_lpbk: is Ethernet loopback enabled.
 * @port_hw_init: port HW init.
 * @port_hw_fini: port HW cleanup.
 * @phy_init: port PHY init.
 * @phy_fini: port PHY cleanup.
 * @set_pfc: enable/disable PFC.
 * @get_cnts_num: get the number of available counters.
 * @get_cnts_names: get the names of the available counters.
 * @get_cnts_values: get the values of the available counters.
 * @eq_dispatcher_register_qp: register QP to its event dispatch queue.
 * @eq_dispatcher_unregister_qp: un-register QP from its event dispatch queue.
 * @get_speed: get the port speed in Mb/s.
 * @track_ext_port_reset: track the reset of the given port according to the given syndrome.
 * @port_toggle_count: count port toggles upon actions that teardown or create a port.
 * @ports_reopen: reopen the ports after hard reset.
 * @ports_stop_prepare: prepare the ports for a stop.
 * @ports_stop: stop traffic.
 * @set_port_status: set the link port status.
 * @get_mac_lpbk: get MAC loopback status.
 * @set_mac_lpbk: set MAC loopback status.
 * @update_mtu: update all QPs to use the new MTU value.
 * @qpc_write: write a QP context to the HW.
 * @ctrl_lock: control mutex lock.
 * @ctrl_unlock: control mutex unlock.
 * @is_port_open: is port open;
 * @get_src_ip: get the source IP of the given port.
 * @reset_stats: reset port statistics (called from debugfs only).
 * @get_mtu: get the port MTU value.
 * @get_pflags: get the port private flags.
 * @set_dev_lpbk: set loopback status on the net-device.
 * @handle_eqe: handle event queue entry from H/W.
 * @asic_ops: pointer for ASIC specific ops struct.
 */
struct hbl_en_aux_ops {
	/* en2cn */
	bool (*device_operational)(struct hbl_aux_dev *aux_dev);
	void (*hw_access_lock)(struct hbl_aux_dev *aux_dev);
	void (*hw_access_unlock)(struct hbl_aux_dev *aux_dev);
	bool (*is_eth_lpbk)(struct hbl_aux_dev *aux_dev);
	int (*port_hw_init)(struct hbl_aux_dev *aux_dev, u32 port);
	void (*port_hw_fini)(struct hbl_aux_dev *aux_dev, u32 port);
	int (*phy_init)(struct hbl_aux_dev *aux_dev, u32 port);
	void (*phy_fini)(struct hbl_aux_dev *aux_dev, u32 port);
	int (*set_pfc)(struct hbl_aux_dev *aux_dev, u32 port, bool enable);
	int (*get_cnts_num)(struct hbl_aux_dev *aux_dev, u32 port);
	void (*get_cnts_names)(struct hbl_aux_dev *aux_dev, u32 port, u8 *data);
	void (*get_cnts_values)(struct hbl_aux_dev *aux_dev, u32 port, u64 *data);
	bool (*get_mac_lpbk)(struct hbl_aux_dev *aux_dev, u32 port);
	int (*set_mac_lpbk)(struct hbl_aux_dev *aux_dev, u32 port, bool enable);
	int (*update_mtu)(struct hbl_aux_dev *aux_dev, u32 port, u32 mtu);
	int (*qpc_write)(struct hbl_aux_dev *aux_dev, u32 port, void *qpc,
			 struct qpc_mask *qpc_mask, u32 qpn, bool is_req);
	void (*ctrl_lock)(struct hbl_aux_dev *aux_dev, u32 port);
	void (*ctrl_unlock)(struct hbl_aux_dev *aux_dev, u32 port);
	int (*eq_dispatcher_register_qp)(struct hbl_aux_dev *aux_dev, u32 port, u32 asid,
					 u32 qp_id);
	int (*eq_dispatcher_unregister_qp)(struct hbl_aux_dev *aux_dev, u32 port, u32 qp_id);
	u32 (*get_speed)(struct hbl_aux_dev *aux_dev, u32 port);
	void (*track_ext_port_reset)(struct hbl_aux_dev *aux_dev, u32 port, u32 syndrome);
	void (*port_toggle_count)(struct hbl_aux_dev *aux_dev, u32 port);

	/* cn2en */
	int (*ports_reopen)(struct hbl_aux_dev *aux_dev);
	void (*ports_stop_prepare)(struct hbl_aux_dev *aux_dev);
	void (*ports_stop)(struct hbl_aux_dev *aux_dev);
	void (*set_port_status)(struct hbl_aux_dev *aux_dev, u32 port_idx, bool up);
	bool (*is_port_open)(struct hbl_aux_dev *aux_dev, u32 port_idx);
	int (*get_src_ip)(struct hbl_aux_dev *aux_dev, u32 port_idx, u32 *src_ip);
	void (*reset_stats)(struct hbl_aux_dev *aux_dev, u32 port_idx);
	u32 (*get_mtu)(struct hbl_aux_dev *aux_dev, u32 port_idx);
	u32 (*get_pflags)(struct hbl_aux_dev *aux_dev, u32 port_idx);
	void (*set_dev_lpbk)(struct hbl_aux_dev *aux_dev, u32 port_idx, bool enable);
	void (*handle_eqe)(struct hbl_aux_dev *aux_dev, u32 port, struct hbl_cn_eqe *eqe);
	void *asic_ops;
};

/* InfiniBand */

#define HBL_IB_CNT_NAME_LEN	(ETH_GSTRING_LEN * 2)

/**
 * struct hbl_ib_device_attr - IB device attributes.
 * @fw_ver: firmware version.
 * @max_mr_size: max size of a memory region.
 * @page_size_cap: largest page size in MMU.
 * @vendor_id: device vendor ID.
 * @vendor_part_id: device vendor part ID.
 * @hw_ver: device chip version.
 * @cqe_size: Size of Completion Queue Entry.
 * @min_cq_entries: Minimum completion queue entries needed.
 * @max_qp: max QPs supported.
 * @max_qp_wr: max QPs per work-request supported.
 * @max_cqe: max completion-queue entries supported.
 */
struct hbl_ib_device_attr {
	u64 fw_ver;
	u64 max_mr_size;
	u64 page_size_cap;
	u32 vendor_id;
	u32 vendor_part_id;
	u32 hw_ver;
	u32 cqe_size;
	u32 min_cq_entries;
	s32 max_qp;
	s32 max_qp_wr;
	s32 max_cqe;
};

/**
 * struct hbl_ib_port_attr - IB port attributes.
 * @speed: speed in Mb/s.
 * @max_msg_sz: max message size
 * @max_mtu: max mtu size
 * @open: is open and fully initialized.
 * @link_up: has PCS link.
 * @num_lanes: number of lanes per port.
 */
struct hbl_ib_port_attr {
	u32 speed;
	u32 max_msg_sz;
	u32 max_mtu;
	u8 open;
	u8 link_up;
	u8 num_lanes;
};

/**
 * struct hbl_ib_port_cnts_data - IB port counters data.
 * @names: Names of the counters.
 * @num: Number of counters.
 */
struct hbl_ib_port_cnts_data {
	u8 *names;
	u32 num;
};

/**
 * struct hbl_ib_dump_qp_attr - IB QP dump attributes.
 * @port: Port ID the QP belongs to.
 * @qpn: QP number.
 * @req: Requester QP, otherwise responder.
 * @full: Include full QP information.
 * @force: Force reading a QP in invalid/error state.
 */
struct hbl_ib_dump_qp_attr {
	u32 port;
	u32 qpn;
	u8 req;
	u8 full;
	u8 force;
};

/**
 * struct hbl_ib_mem_info - Information for a memory region pertaining to a memory handle.
 * @cpu_addr: The kernel virtual address.
 * @bus_addr: The bus address.
 * @mtype: The memory type.
 * @mem_handle: The memory handle.
 * @size: The size of the memory region.
 * @vmalloc: The memory is virtually contiguous only.
 */
struct hbl_ib_mem_info {
	void *cpu_addr;
	dma_addr_t bus_addr;
	enum hbl_ib_mem_type mtype;
	u64 mem_handle;
	u64 size;
	u8 vmalloc;
};

/**
 * struct hbl_ib_aux_data - habanalabs data for the IB driver.
 * @pdev: pointer to PCI device.
 * @dev: related kernel basic device structure.
 * @cnts_data: Ports counters data.
 * @ports_mask: mask of available ports.
 * @ext_ports_mask: mask of external ports (subset of ports_mask).
 * @dram_size: available DRAM size.
 * @max_num_of_wqes: maximum number of WQ entries.
 * @pending_reset_long_timeout: long timeout for pending hard reset to finish in seconds.
 * @id: device ID.
 * @max_num_of_ports: maximum number of ports supported by ASIC.
 * @mixed_qp_wq_types: Using mixed QP WQ types is supported.
 * @umr_support: device supports UMR.
 * @cc_support: device supports congestion control.
 */
struct hbl_ib_aux_data {
	struct pci_dev *pdev;
	struct device *dev;
	struct hbl_ib_port_cnts_data *cnts_data;
	u64 ports_mask;
	u64 ext_ports_mask;
	u64 dram_size;
	u32 max_num_of_wqes;
	u32 pending_reset_long_timeout;
	u16 id;
	u8 max_num_of_ports;
	u8 mixed_qp_wq_types;
	u8 umr_support;
	u8 cc_support;
};

/**
 * struct hbl_ib_aux_ops - pointer functions for cn <-> ib drivers communication.
 * @device_operational: is device operational.
 * @hw_access_lock: prevent HW access.
 * @hw_access_unlock: allow HW access.
 * @alloc_ucontext: allocate user context.
 * @dealloc_ucontext: deallocate user context.
 * @query_port: get port attributes.
 * @cmd_ctrl: operate the device with proprietary opcodes.
 * @query_device: get device attributes.
 * @set_ip_addr_encap: setup IP address encapsulation.
 * @qp_syndrome_to_str: translates syndrome qp number to string.
 * @verify_qp_id: verify if the specified QP id is valid.
 * @get_cnts_values: get the values of the available counters.
 * @dump_qp: dump QP context to the given buffer.
 * @query_mem_handle: query information for a memory handle.
 * @eqe_work_schd: schedule a user eq poll work on hbl side.
 * @dispatch_fatal_event: raise a fatal event to user space.
 */
struct hbl_ib_aux_ops {
	/* ib2cn */
	bool (*device_operational)(struct hbl_aux_dev *aux_dev);
	void (*hw_access_lock)(struct hbl_aux_dev *aux_dev);
	void (*hw_access_unlock)(struct hbl_aux_dev *aux_dev);
	int (*alloc_ucontext)(struct hbl_aux_dev *aux_dev, int user_fd, void **cn_ib_ctx);
	void (*dealloc_ucontext)(struct hbl_aux_dev *aux_dev, void *cn_ib_ctx);
	void (*query_port)(struct hbl_aux_dev *aux_dev, u32 port,
			   struct hbl_ib_port_attr *port_attr);
	int (*cmd_ctrl)(struct hbl_aux_dev *aux_dev, void *cn_ib_ctx, u32 op, void *input,
			void *output);
	void (*query_device)(struct hbl_aux_dev *aux_dev, struct hbl_ib_device_attr *device_attr);
	void (*set_ip_addr_encap)(struct hbl_aux_dev *aux_dev, u32 ip_addr, u32 port);
	char *(*qp_syndrome_to_str)(struct hbl_aux_dev *aux_dev, u32 syndrome);
	int (*verify_qp_id)(struct hbl_aux_dev *aux_dev, u32 qp_id, u32 port);
	void (*get_cnts_values)(struct hbl_aux_dev *aux_dev, u32 port, u64 *data);
	int (*dump_qp)(struct hbl_aux_dev *aux_dev, struct hbl_ib_dump_qp_attr *attr, char *buf,
		       size_t size);
	int (*query_mem_handle)(struct hbl_aux_dev *aux_dev, u64 mem_handle,
				struct hbl_ib_mem_info *info);

	/* cn2ib */
	void (*eqe_work_schd)(struct hbl_aux_dev *aux_dev, u32 port);
	void (*dispatch_fatal_event)(struct hbl_aux_dev *aux_dev, u32 asid);
};

/* CN */

/* interrupt type */
enum hbl_cn_cpucp_interrupt_type {
	HBL_CN_CPUCP_INTR_NONE = 0,
	HBL_CN_CPUCP_INTR_TMR = 1,
	HBL_CN_CPUCP_INTR_RXB_CORE_SPI,
	HBL_CN_CPUCP_INTR_RXB_CORE_SEI,
	HBL_CN_CPUCP_INTR_QPC_RESP_ERR,
	HBL_CN_CPUCP_INTR_RXE_SPI,
	HBL_CN_CPUCP_INTR_RXE_SEI,
	HBL_CN_CPUCP_INTR_TXS,
	HBL_CN_CPUCP_INTR_TXE,
};

/*
 * struct hbl_cn_eq_port_intr_cause - port interrupt cause data.
 * @intr_cause_data: interrupt cause data.
 */
struct hbl_cn_eq_port_intr_cause {
	u64 intr_cause_data;
};

/*
 * struct hbl_cn_eq_intr_cause - interrupt cause data.
 * @intr_type: interrupt type.
 * @intr_cause: array of ports interrupt cause data.
 */
struct hbl_cn_eq_intr_cause {
	u32 intr_type; /* enum hbl_cn_cpucp_interrupt_type */
	u32 pad;
	struct hbl_cn_eq_port_intr_cause intr_cause[MAX_PORTS_PER_NIC];
};

/*
 * struct hbl_cn_cpucp_frac_val - fracture value represented by "integer.frac".
 * @integer: the integer part of the fracture value;
 * @frac: the fracture part of the fracture value.
 */
struct hbl_cn_cpucp_frac_val {
	union {
		struct {
			u16 integer;
			u16 frac;
		};
		u16 val;
	};
};

/*
 * struct hbl_cn_cpucp_ser_val - Symbol Error Rate value represented by "integer * 10 ^ -exp".
 * @integer: the integer part of the SER value.
 * @exp: the exponent part of the SER value.
 */
struct hbl_cn_cpucp_ser_val {
	u16 integer;
	u16 exp;
};

#endif /* HBL_CN_H_ */
