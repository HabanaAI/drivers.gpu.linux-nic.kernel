/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2023-2024, Intel Corporation.
 * Copyright 2021-2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef HL_CN_H_
#define HL_CN_H_

#include <linux/types.h>
#include <linux/sizes.h>
#include <linux/net/intel/cn_aux.h>

#define HL_EN_PFC_PRIO_NUM	4
#define CQ_ARM_TIMEOUT_USEC	10

struct qpc_mask;

/**
 * enum hl_cn_pflags - mutable capabilities of the port.
 * PFLAGS_PCS_LINK_CHECK: check for PCS link periodically.
 * PFLAGS_PHY_AUTO_NEG_LPBK: allow Autonegotiation in loopback.
 */
enum hl_cn_pflags {
	PFLAGS_PCS_LINK_CHECK = BIT(0),
	PFLAGS_PHY_AUTO_NEG_LPBK = BIT(1),
};

enum hl_ts_type {
	TS_RC = 0,
	TS_RAW = 1
};

enum hl_trust_level {
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
 * enum qp_wq_types - QP WQ type.
 * @QPC_WQ_TYPE_WRITE: WRITE or "native" SEND operations are allowed on this QP.
 *                   NOTE: the latter is currently unsupported.
 * @QPC_WQ_TYPE_RECV_RDV: RECEIVE-RDV or WRITE operations are allowed on this QP.
 *                      NOTE: posting all operations at the same time is unsupported.
 * @QPC_WQ_TYPE_READ_RDV: READ-RDV or WRITE operations are allowed on this QP.
 *                      NOTE: posting all operations at the same time is unsupported.
 * @QPC_WQ_TYPE_SEND_RDV: SEND-RDV operation is allowed on this QP.
 * @QPC_WQ_TYPE_READ_RDV_ENDP: No operation is allowed on this endpoint QP.
 */
enum qp_wq_types {
	QPC_WQ_TYPE_WRITE = 0x1,
	QPC_WQ_TYPE_RECV_RDV = 0x2,
	QPC_WQ_TYPE_READ_RDV = 0x4,
	QPC_WQ_TYPE_SEND_RDV = 0x8,
	QPC_WQ_TYPE_READ_RDV_ENDP = 0x10,
};

/**
 * struct hl_cn_eqe - describes an event-queue entry
 * @data: the data each event-queue entry contains
 */
struct hl_cn_eqe {
	u32 data[4];
};

/**
 * struct hl_cn_mem_resources - memory resource used by a memory ring.
 * @addr: virtual address of the memory.
 * @dma_addr: physical address of the memory.
 * @size: memory size.
 */
struct hl_cn_mem_resource {
	void *addr;
	dma_addr_t dma_addr;
	u32 size;
};

/**
 * struct hl_cn_ring - represents a memory ring.
 * @buf: the ring buffer memory resource.
 * @pi: the memory-resident producer index of the ring, updated by HW
 * @pi_shadow: producer shadow index - used by SW
 * @ci_shadow: consumer shadow index - used by SW
 * @rep_idx: use to count until a threshold value, like HW update
 * @asid: the asid of the ring
 * @count: the number of elements the ring can hold
 * @elem_size: the rings's element size
 */
struct hl_cn_ring {
	struct hl_cn_mem_resource buf;
	struct hl_cn_mem_resource pi;
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
 * struct hl_en_aux_data - habanalabs data for the Ethernet driver.
 * @pdev: pointer to PCI device, can be NULL in case of simulator device.
 * @dev: related kernel basic device structure.
 * @asic_specific: ASIC specific data.
 * @driver_ver: Kernel driver version.
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
 * @minor: minor id of the device.
 * @id: device ID.
 * @max_num_of_ports: max number of available ports.
 * @has_eq: true if event queue is supported.
 */
struct hl_en_aux_data {
	struct pci_dev *pdev;
	struct device *dev;
	void *asic_specific;
	char *driver_ver;
	char *fw_ver;
	char *qsfp_eeprom;
	char **mac_addr;
	enum hl_cn_asic_type asic_type;
	u64 ports_mask;
	u64 auto_neg_mask;
	u32 pending_reset_long_timeout;
	u32 max_frm_len;
	u32 raw_elem_size;
	u16 max_raw_mtu;
	u16 min_raw_mtu;
	u16 minor;
	u16 id;
	u8 max_num_of_ports;
	u8 has_eq;
};

/**
 * struct hl_en_aux_ops - pointer functions for cn <-> en drivers communication.
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
 * @track_ext_port_reset: track the reset of the given port according to the given syndrom.
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
 * @get_netdev: get the netdev structure for the port
 * @handle_eqe: handle event queue entry from H/W.
 * @asic_ops: pointer for ASIC specific ops struct.
 */
struct hl_en_aux_ops {
	/* en2cn */
	bool (*device_operational)(struct hl_aux_dev *aux_dev);
	void (*hw_access_lock)(struct hl_aux_dev *aux_dev);
	void (*hw_access_unlock)(struct hl_aux_dev *aux_dev);
	bool (*is_eth_lpbk)(struct hl_aux_dev *aux_dev);
	int (*port_hw_init)(struct hl_aux_dev *aux_dev, u32 port);
	void (*port_hw_fini)(struct hl_aux_dev *aux_dev, u32 port);
	int (*phy_init)(struct hl_aux_dev *aux_dev, u32 port);
	void (*phy_fini)(struct hl_aux_dev *aux_dev, u32 port);
	int (*set_pfc)(struct hl_aux_dev *aux_dev, u32 port, bool enable);
	int (*get_cnts_num)(struct hl_aux_dev *aux_dev, u32 port);
	void (*get_cnts_names)(struct hl_aux_dev *aux_dev, u32 port, u8 *data);
	void (*get_cnts_values)(struct hl_aux_dev *aux_dev, u32 port, u64 *data);
	bool (*get_mac_lpbk)(struct hl_aux_dev *aux_dev, u32 port);
	int (*set_mac_lpbk)(struct hl_aux_dev *aux_dev, u32 port, bool enable);
	int (*update_mtu)(struct hl_aux_dev *aux_dev, u32 port, u32 mtu);
	int (*qpc_write)(struct hl_aux_dev *aux_dev, u32 port, void *qpc,
			 struct qpc_mask *qpc_mask, u32 qpn, bool is_req);
	void (*ctrl_lock)(struct hl_aux_dev *aux_dev, u32 port);
	void (*ctrl_unlock)(struct hl_aux_dev *aux_dev, u32 port);
	int (*eq_dispatcher_register_qp)(struct hl_aux_dev *aux_dev, u32 port, u32 asid,
						u32 qp_id);
	int (*eq_dispatcher_unregister_qp)(struct hl_aux_dev *aux_dev, u32 port, u32 qp_id);
	u32 (*get_speed)(struct hl_aux_dev *aux_dev, u32 port);
	void (*track_ext_port_reset)(struct hl_aux_dev *aux_dev, u32 port, u32 syndrome);
	void (*port_toggle_count)(struct hl_aux_dev *aux_dev, u32 port);

	/* cn2en */
	int (*ports_reopen)(struct hl_aux_dev *aux_dev);
	void (*ports_stop_prepare)(struct hl_aux_dev *aux_dev);
	void (*ports_stop)(struct hl_aux_dev *aux_dev);
	void (*set_port_status)(struct hl_aux_dev *aux_dev, u32 port_idx, bool up);
	bool (*is_port_open)(struct hl_aux_dev *aux_dev, u32 port_idx);
	int (*get_src_ip)(struct hl_aux_dev *aux_dev, u32 port_idx, u32 *src_ip);
	void (*reset_stats)(struct hl_aux_dev *aux_dev, u32 port_idx);
	u32 (*get_mtu)(struct hl_aux_dev *aux_dev, u32 port_idx);
	u32 (*get_pflags)(struct hl_aux_dev *aux_dev, u32 port_idx);
	void (*set_dev_lpbk)(struct hl_aux_dev *aux_dev, u32 port_idx, bool enable);
	struct net_device *(*get_netdev)(struct hl_aux_dev *aux_dev, u32 port_idx);
	void (*handle_eqe)(struct hl_aux_dev *aux_dev, u32 port, struct hl_cn_eqe *eqe);
	void *asic_ops;
};

/* InfiniBand */

#define HL_IB_CNT_NAME_LEN	(ETH_GSTRING_LEN * 2)

/**
 * struct hl_ib_device_attr - IB device attributes.
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
struct hl_ib_device_attr {
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
 * struct hl_ib_port_attr - IB port attributes.
 * @speed: speed in Mb/s.
 * @max_msg_sz: max message size
 * @max_mtu: max mtu size
 * @swqe_size: send WQE size.
 * @rwqe_size: receive WQE size.
 * @open: is open and fully initialized.
 * @link_up: has PCS link.
 * @num_lanes: number of lanes per port.
 */
struct hl_ib_port_attr {
	u32 speed;
	u32 max_msg_sz;
	u32 max_mtu;
	u32 swqe_size;
	u32 rwqe_size;
	u8 open;
	u8 link_up;
	u8 num_lanes;
};

/**
 * struct hl_ib_port_cnts_data - IB port counters data.
 * @names: Names of the counters.
 * @num: Number of counters.
 */
struct hl_ib_port_cnts_data {
	u8 *names;
	u32 num;
};

/**
 * struct hl_ib_dump_qp_attr - IB QP dump attributes.
 * @port: Port ID the QP belongs to.
 * @qpn: QP number.
 * @req: Requester QP, otherwise responder.
 * @full: Include full QP information.
 * @force: Force reading a QP in invalid/error state.
 * @exts: Include QPC extensions like SAL or collective-descriptor.
 */
struct hl_ib_dump_qp_attr {
	u32 port;
	u32 qpn;
	u8 req;
	u8 full;
	u8 force;
	u8 exts;
};

/**
 * struct hl_ib_aux_data - habanalabs data for the IB driver.
 * @pdev: pointer to PCI device, can be NULL in case of simulator device.
 * @dev: related kernel basic device structure.
 * @cnts_data: Ports counters data.
 * @sim_mac_addr: array of all MAC addresses required by simulator.
 * @fw_ver: FW version.
 * @ports_mask: mask of available ports.
 * @ext_ports_mask: mask of external ports (subset of ports_mask).
 * @dram_size: available DRAM size.
 * @max_num_of_wqes: maximum number of WQ entries.
 * @pending_reset_long_timeout: long timeout for pending hard reset to finish in seconds.
 * @id: device ID.
 * @max_num_of_ports: maximum number of ports supported by ASIC.
 * @mixed_qp_wq_types: Using mixed QP WQ types is supported.
 * @umr_support: device supports UMR.
 */
struct hl_ib_aux_data {
	struct pci_dev *pdev;
	struct device *dev;
	struct hl_ib_port_cnts_data *cnts_data;
	u8 **sim_mac_addr;
	char *fw_ver;
	u64 ports_mask;
	u64 ext_ports_mask;
	u64 dram_size;
	u32 max_num_of_wqes;
	u32 pending_reset_long_timeout;
	u16 id;
	u8 max_num_of_ports;
	u8 mixed_qp_wq_types;
	u8 umr_support;
};

/**
 * struct hl_ib_aux_ops - pointer functions for cn <-> ib drivers communication.
 * @device_operational: is device operational.
 * @hw_access_lock: prevent HW access.
 * @hw_access_unlock: allow HW access.
 * @alloc_ucontext: allocate user context.
 * @dealloc_ucontext: deallocate user context.
 * @query_port: get port attributes.
 * @cmd_ctrl: operate the device with proprietary opcodes.
 * @query_device: get device attributes.
 * @mmap: cn mmap handler.
 * @set_ip_addr_encap: setup IP address encapsulation.
 * @qp_syndrome_to_str: translates syndrome qp number to string.
 * @verify_qp_id: verify if the specified QP id is valid.
 * @get_cnts_values: get the values of the available counters.
 * @dump_qp: dump QP context to the given buffer.
 * @eqe_work_schd: schedule a user eq poll work on hlib side.
 * @dispatch_fatal_event: raise a fatal event to user space.
 */
struct hl_ib_aux_ops {
	/* ib2cn */
	bool (*device_operational)(struct hl_aux_dev *aux_dev);
	void (*hw_access_lock)(struct hl_aux_dev *aux_dev);
	void (*hw_access_unlock)(struct hl_aux_dev *aux_dev);
	int (*alloc_ucontext)(struct hl_aux_dev *aux_dev, int user_fd, void **cn_ib_ctx);
	void (*dealloc_ucontext)(struct hl_aux_dev *aux_dev, void *cn_ib_ctx);
	void (*query_port)(struct hl_aux_dev *aux_dev, u32 port, struct hl_ib_port_attr *port_attr);
	int (*cmd_ctrl)(struct hl_aux_dev *aux_dev, void *cn_ib_ctx, u32 op, void *input,
			void *output);
	void (*query_device)(struct hl_aux_dev *aux_dev, struct hl_ib_device_attr *device_attr);
	int (*mmap)(struct hl_aux_dev *aux_dev, void *cn_ib_ctx, struct vm_area_struct *vma);
	void (*set_ip_addr_encap)(struct hl_aux_dev *aux_dev, u32 ip_addr, u32 port);
	char *(*qp_syndrome_to_str)(struct hl_aux_dev *aux_dev, u32 syndrome);
	int (*verify_qp_id)(struct hl_aux_dev *aux_dev, u32 qp_id, u32 port, u8 is_coll);
	void (*get_cnts_values)(struct hl_aux_dev *aux_dev, u32 port, u64 *data);
	int (*dump_qp)(struct hl_aux_dev *aux_dev, struct hl_ib_dump_qp_attr *attr, char *buf,
			size_t size);

	/* cn2ib */
	void (*eqe_work_schd)(struct hl_aux_dev *aux_dev, u32 port);
	void (*dispatch_fatal_event)(struct hl_aux_dev *aux_dev, u32 asid);
};

/* CN */

/* interrupt type */
enum hl_cn_cpucp_interrupt_type {
	HL_CN_CPUCP_INTR_NONE = 0,
	HL_CN_CPUCP_INTR_TMR = 1,
	HL_CN_CPUCP_INTR_RXB_CORE_SPI,
	HL_CN_CPUCP_INTR_RXB_CORE_SEI,
	HL_CN_CPUCP_INTR_QPC_RESP_ERR,
	HL_CN_CPUCP_INTR_RXE_SPI,
	HL_CN_CPUCP_INTR_RXE_SEI,
	HL_CN_CPUCP_INTR_TXS,
	HL_CN_CPUCP_INTR_TXE,
};

/*
 * struct hl_cn_eq_port_intr_cause - port interrupt cause data.
 * @intr_cause_data: interrupt cause data.
 */
struct hl_cn_eq_port_intr_cause {
	u64 intr_cause_data;
};

/*
 * struct hl_cn_eq_intr_cause - interrupt cause data.
 * @intr_type: interrupt type.
 * @intr_cause: array of ports interrupt cause data.
 */
struct hl_cn_eq_intr_cause {
	u32 intr_type; /* enum hl_cn_cpucp_interrupt_type */
	u32 pad;
	struct hl_cn_eq_port_intr_cause intr_cause[MAX_PORTS_PER_NIC];
};

/*
 * struct hl_cn_cpucp_frac_val - fracture value represented by "integer.frac".
 * @integer: the integer part of the fracture value;
 * @frac: the fracture part of the fracture value.
 */
struct hl_cn_cpucp_frac_val {
	union {
		struct {
			u16 integer;
			u16 frac;
		};
		u16 val;
	};
};

/*
 * struct hl_cn_cpucp_ser_val - Symbol Error Rate value represented by "integer * 10 ^ -exp".
 * @integer: the integer part of the SER value.
 * @exp: the exponent part of the SER value.
 */
struct hl_cn_cpucp_ser_val {
	u16 integer;
	u16 exp;
};

/*
 * struct hl_cn_cpucp_status - describes the status of a port.
 * @port: port index.
 * @bad_format_cnt: e.g. CRC.
 * @responder_out_of_sequence_psn_cnt: e.g NAK.
 * @high_ber_reinit_cnt: link reinit due to high BER.
 * @correctable_err_cnt: e.g. bit-flip.
 * @uncorrectable_err_cnt: e.g. MAC errors.
 * @retraining_cnt: re-training counter.
 * @up: is port up.
 * @pcs_link: has PCS link.
 * @phy_ready: is PHY ready.
 * @auto_neg: is Autoneg enabled.
 * @timeout_retransmission_cnt: timeout retransmission events.
 * @high_ber_cnt: high ber events.
 * @pre_fec_ser: pre FEC SER value.
 * @post_fec_ser: post FEC SER value.
 * @bandwidth: measured bandwidth.
 * @lat: measured latency.
 * @port_toggle_cnt: counts how many times the link toggled since last port PHY init.
 */
struct hl_cn_cpucp_status {
	u32 port;
	u32 bad_format_cnt;
	u32 responder_out_of_sequence_psn_cnt;
	u32 high_ber_reinit;
	u32 correctable_err_cnt;
	u32 uncorrectable_err_cnt;
	u32 retraining_cnt;
	u8 up;
	u8 pcs_link;
	u8 phy_ready;
	u8 auto_neg;
	u32 timeout_retransmission_cnt;
	u32 high_ber_cnt;
	struct hl_cn_cpucp_ser_val pre_fec_ser;
	struct hl_cn_cpucp_ser_val post_fec_ser;
	struct hl_cn_cpucp_frac_val bandwidth;
	struct hl_cn_cpucp_frac_val lat;
	u32 port_toggle_cnt;
	u8 reserved[4];
};

#endif /* HL_CN_H_ */
