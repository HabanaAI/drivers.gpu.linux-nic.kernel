/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#ifndef GAUDI2_CN_H_
#define GAUDI2_CN_H_

#include <linux/net/intel/gaudi2.h>

#include "../common/hbl_cn.h"
#include "asic_reg/gaudi2_regs.h"

#define NIC_NUMBER_OF_MACROS		12
#define NIC_NUMBER_OF_ENGINES		(NIC_NUMBER_OF_MACROS * 2)
#define NIC_MAX_NUMBER_OF_PORTS		(NIC_NUMBER_OF_ENGINES * 2)
#define NIC_MAX_FIFO_RINGS		32
#define NIC_MAC_NUM_OF_LANES		4
#define NIC_MAC_LANES_START		0
#define NIC_NUMBER_OF_EQS		1
#define DEVICE_CACHE_LINE_SIZE		128
#define NIC_SEND_WQE_SIZE		32
#define NIC_SEND_WQE_SIZE_MULTI_STRIDE	64
#define NIC_RECV_WQE_SIZE		16
#define DB_FIFO_ELEMENT_SIZE		8
/* 4 entries of 32 bit each i.e. 16 bytes */
#define NIC_RAW_EQE_SIZE		16
#define NIC_MAX_CCQS_NUM		1
#define NIC_HW_MAX_QP_NUM		BIT(24) /* 16M (per port) */

#define NIC_NUMBER_OF_PORTS		NIC_NUMBER_OF_ENGINES
#define NIC_MAX_NUM_OF_LANES		(NIC_NUMBER_OF_MACROS * NIC_MAC_LANES)
#define NIC_CQS_NUM			2 /* For Raw and RDMA */
#define NIC_EQ_ERR_SYNDROME		0
#define NIC_QP_ERR_RETRY_SYNDROME	0x40
#define NIC_MAX_QP_ERR_SYNDROMES	0x100
#define GAUDI2_NIC_MAX_CQS_NUM		16

/* make sure generic max CCQs number is always larger than h/w specific max CCQs number */
static_assert(NIC_MAX_CCQS_NUM <= NIC_DRV_MAX_CCQS_NUM);

#define GAUDI2_NIC_NUM_DB_FIFOS			32

/* writing to the device memory-mapped dram using the writel or writeb commands (for example) is
 * subject to the write-combined rules, meaning that writes temporarily stored in a buffer and are
 * released together later in burst mode towards the device.
 * Due to the high latencies in the PLDM such writes take a lot of time which may lead to system
 * hangs. The burst issue gets more severe if ports are opened in parallel as each port accesses
 * this memory, therefore we limit the amount of pending writes by inserting reads every several
 * writes which causes the pending writes to be flushed to the device.
 */
#define NIC_MAX_COMBINED_WRITES	0x2000

#define NIC_MAX_RC_MTU		SZ_8K

#define UDP_HDR_SIZE		8

/* This is the max frame length the H/W supports (Tx/Rx) */
#define NIC_MAX_RDMA_HDRS	128
#define NIC_MAX_TNL_HDR_SIZE	32 /* Bytes */
#define NIC_MAX_TNL_HDRS	(NIC_MAX_TNL_HDR_SIZE + UDP_HDR_SIZE)
#define NIC_MAX_FRM_LEN		(NIC_MAX_RC_MTU + NIC_MAX_RDMA_HDRS)
#define NIC_MAC_MAX_FRM_LEN	(NIC_MAX_FRM_LEN + HBL_EN_MAX_HEADERS_SZ + NIC_MAX_TNL_HDRS)
#define NIC_RAW_MIN_MTU		(SZ_1K - HBL_EN_MAX_HEADERS_SZ)
#define NIC_RAW_MAX_MTU		(NIC_MAX_RC_MTU - HBL_EN_MAX_HEADERS_SZ)

/* This is the size of an element size in the RAW buffer - note that it is different than
 * NIC_MAX_FRM_LEN, because it has to be power of 2.
 */
#define NIC_RAW_ELEM_SIZE	(2 * NIC_MAX_RC_MTU)

#define NIC_RX_RING_PKT_NUM	BIT(8)

#define NIC_MIN_CONN_ID		1
#define NIC_MAX_CONN_ID		(BIT(13) - 1) /* 8K QPs */

#define NIC_MAX_QP_NUM		(NIC_MAX_CONN_ID + 1)

/* Number of available QPs must not exceed NIC_HW_MAX_QP_NUM */
static_assert(NIC_MAX_QP_NUM <= NIC_HW_MAX_QP_NUM);

/* Allocate an extra QP to be used as dummy QP. */
#define REQ_QPC_TOTAL_PORT_SIZE		((NIC_MAX_QP_NUM + 1) * sizeof(struct gaudi2_qpc_requester))
#define RES_QPC_TOTAL_PORT_SIZE		ALIGN((NIC_MAX_QP_NUM + 1) * \
					      sizeof(struct gaudi2_qpc_responder),  \
					      DEVICE_CACHE_LINE_SIZE)

#define TMR_ENT_SIZE		4
#define TMR_GRANULARITY		256
#define TMR_FSM_SIZE		ALIGN(NIC_MAX_QP_NUM, DEVICE_CACHE_LINE_SIZE)
/* each timer serves two NICs, hence multiply by 2 */
#define TMR_FIFO_SIZE		ALIGN((NIC_MAX_QP_NUM * 2 * TMR_ENT_SIZE) + \
				      DEVICE_CACHE_LINE_SIZE * TMR_GRANULARITY, \
				      DEVICE_CACHE_LINE_SIZE)
#define TMR_FREE_NUM_ENTRIES	(TMR_FIFO_SIZE / DEVICE_CACHE_LINE_SIZE)
#define TMR_FREE_SIZE		ALIGN(TMR_FREE_NUM_ENTRIES * TMR_ENT_SIZE, \
				      DEVICE_CACHE_LINE_SIZE)
#define TMR_TOTAL_MACRO_SIZE	(TMR_FSM_SIZE * 2 + TMR_FREE_SIZE + TMR_FIFO_SIZE)

#define TMR_FSM0_OFFS		0
#define TMR_FREE_OFFS		(TMR_FSM0_OFFS + 2 * TMR_FSM_SIZE)
#define TMR_FIFO_OFFS		(TMR_FREE_OFFS + TMR_FREE_SIZE)

#define TXS_ENT_SIZE		4
#define TXS_GRANULARITY		256
#define TXS_FIFO_SIZE		ALIGN((NIC_MAX_QP_NUM * 2 * TXS_ENT_SIZE) + \
				      DEVICE_CACHE_LINE_SIZE * TXS_GRANULARITY, \
				      DEVICE_CACHE_LINE_SIZE)
#define TXS_FREE_NUM_ENTRIES	(TXS_FIFO_SIZE / DEVICE_CACHE_LINE_SIZE)
#define TXS_FREE_SIZE		ALIGN(TXS_FREE_NUM_ENTRIES * TXS_ENT_SIZE, \
				      DEVICE_CACHE_LINE_SIZE)
#define TXS_TOTAL_PORT_SIZE	(TXS_FREE_SIZE + TXS_FIFO_SIZE)

#define TXS_FREE_OFFS		0
#define TXS_FIFO_OFFS		(TXS_FREE_OFFS + TXS_FREE_SIZE)

#define TXS_NUM_PORTS		NIC_MAC_LANES
#define TXS_SCHEDQ		TXS_GRANULARITY
#define TXS_NUM_SCHEDQS		TXS_SCHEDQ

#define TXS_PORT_NUM_SCHEDQS		(TXS_NUM_SCHEDQS / TXS_NUM_PORTS)
#define TXS_PORT_NUM_SCHED_GRANS	(TXS_PORT_NUM_SCHEDQS / HBL_EN_PFC_PRIO_NUM)
#define TXS_PORT_RAW_SCHED_Q		(TXS_PORT_NUM_SCHED_GRANS - QPC_RAW_SCHED_Q)
#define TXS_PORT_RES_SCHED_Q		(TXS_PORT_NUM_SCHED_GRANS - QPC_RES_SCHED_Q)
#define TXS_PORT_REQ_SCHED_Q		(TXS_PORT_NUM_SCHED_GRANS - QPC_REQ_SCHED_Q)

#define RXB_NUM_BUFFS			2880
#define RXB_BUFF_SIZE			128 /* size in bytes */
#define RXB_NUM_MTU_BUFFS		((NIC_MAX_FRM_LEN / RXB_BUFF_SIZE) + 1)
#define RXB_DROP_SMALL_TH_DEPTH		3
#define RXB_DROP_TH_DEPTH		(1 * RXB_NUM_MTU_BUFFS)
#define RXB_XOFF_TH_DEPTH		(11 * RXB_NUM_MTU_BUFFS)
#define RXB_XON_TH_DEPTH		(1 * RXB_NUM_MTU_BUFFS)
#define RXB_NUM_STATIC_CREDITS		(RXB_NUM_BUFFS / 2)

#define SECTION_ALIGN_SIZE		0x100000ull
#define NIC_DRV_BASE_ADDR(nic_drv_addr)	ALIGN(nic_drv_addr, SECTION_ALIGN_SIZE)

#define NIC_DRV_END_ADDR(nic_drv_addr, nic_drv_size) \
					ALIGN(((nic_drv_addr) + (nic_drv_size)), \
					      SECTION_ALIGN_SIZE)

#define REQ_QPC_BASE_ADDR		NIC_DRV_BASE_ADDR

#define RES_QPC_BASE_ADDR(nic_drv_addr)	(REQ_QPC_BASE_ADDR(nic_drv_addr) + \
					 ALIGN(NIC_NUMBER_OF_ENGINES * REQ_QPC_TOTAL_PORT_SIZE, \
					       SECTION_ALIGN_SIZE))

#define TMR_BASE_ADDR(nic_drv_addr)	(RES_QPC_BASE_ADDR(nic_drv_addr) + \
					 ALIGN(NIC_NUMBER_OF_ENGINES * RES_QPC_TOTAL_PORT_SIZE, \
					       SECTION_ALIGN_SIZE))

#define TXS_BASE_ADDR(nic_drv_addr)	(TMR_BASE_ADDR(nic_drv_addr) + \
					 ALIGN(NIC_NUMBER_OF_MACROS * TMR_TOTAL_MACRO_SIZE, \
					       SECTION_ALIGN_SIZE))

#define WQ_BASE_ADDR(nic_drv_addr)	(TXS_BASE_ADDR(nic_drv_addr) + \
					 ALIGN(NIC_NUMBER_OF_ENGINES * TXS_TOTAL_PORT_SIZE, \
					       SECTION_ALIGN_SIZE))

/* Unlike the other port related sizes, this size is shared between all the engines */
#define WQ_BASE_SIZE(nic_drv_addr, nic_drv_size) \
	({ \
		u64 __nic_drv_addr = (nic_drv_addr); \
		NIC_DRV_END_ADDR(__nic_drv_addr, (nic_drv_size)) - WQ_BASE_ADDR(__nic_drv_addr); \
	})

#define WQ_BUFFER_LOG_SIZE		8
#define WQ_BUFFER_SIZE			(1 << (WQ_BUFFER_LOG_SIZE))
#define CQE_SIZE			sizeof(struct gaudi2_cqe)
#define NIC_CQ_RAW_IDX			0
#define NIC_CQ_RDMA_IDX			1
#define QP_WQE_NUM_REC			128
#define TX_WQE_NUM_IN_CLINE		(DEVICE_CACHE_LINE_SIZE / NIC_SEND_WQE_SIZE_MULTI_STRIDE)
#define RX_WQE_NUM_IN_CLINE		(DEVICE_CACHE_LINE_SIZE / NIC_RECV_WQE_SIZE)
#define RAW_QPN				0

#define NIC_FIFO_DB_SIZE		64
#define NIC_TX_BUF_SIZE			QP_WQE_NUM_REC
#define NIC_CQ_MAX_ENTRIES		BIT(13)
#define NIC_EQ_RING_NUM_REC		BIT(18)

/* if not equal, the size of the WQ must be considered when checking data bounds in en_tx_done */
static_assert(NIC_TX_BUF_SIZE == QP_WQE_NUM_REC);

#define NIC_TOTAL_CQ_MEM_SIZE		(NIC_CQ_MAX_ENTRIES * CQE_SIZE)

#define NIC_CQ_USER_MIN_ENTRIES		4
#define NIC_CQ_USER_MAX_ENTRIES		NIC_CQ_MAX_ENTRIES

#define NIC_MIN_CQ_ID			NIC_CQS_NUM
#define NIC_MAX_CQ_ID			(GAUDI2_NIC_MAX_CQS_NUM - 1)

static_assert(NIC_CQ_RDMA_IDX < GAUDI2_NIC_MAX_CQS_NUM);
static_assert(NIC_CQ_RAW_IDX < GAUDI2_NIC_MAX_CQS_NUM);

#define USER_WQES_MIN_NUM		16
#define USER_WQES_MAX_NUM		BIT(15) /* 32K */

#define NIC_RXE_AXUSER_AXUSER_CQ_OFFSET (NIC0_RXE0_AXUSER_AXUSER_CQ1_HB_ASID - \
					 NIC0_RXE0_AXUSER_AXUSER_CQ0_HB_ASID)

/* Unsecure userspace doorbell fifo IDs as reported to the user, HW IDs are 0-29 */
#define GAUDI2_MIN_DB_FIFO_ID	1
#define GAUDI2_MAX_DB_FIFO_ID	30

#define GAUDI2_DB_FIFO_SECURE_HW_ID	30
#define GAUDI2_DB_FIFO_PRIVILEGE_HW_ID	31

/* The size of the DB FIFO in bytes is constant */
#define DB_FIFO_ENTRY_SIZE	8
#define DB_FIFO_NUM_OF_ENTRIES	64
#define DB_FIFO_SIZE		(DB_FIFO_NUM_OF_ENTRIES * DB_FIFO_ENTRY_SIZE)

/* User encapsulation IDs. There are 8 encaps and 4 decap resources available per macro.
 * So for now let's allow the max of 2 encaps per port.
 */
#define GAUDI2_MIN_ENCAP_ID	0
#define GAUDI2_MAX_ENCAP_ID	1

#define QPC_GW_MASK_REG_NUM	(((NIC0_QPC0_GW_MASK_31 - NIC0_QPC0_GW_MASK_0) >> 2) + 1)

#define NIC_CFG_LO_SIZE		(NIC0_QPC1_REQ_STATIC_CONFIG - NIC0_QPC0_REQ_STATIC_CONFIG)

#define NIC_CFG_HI_SIZE		(NIC0_RXE1_CONTROL - NIC0_RXE0_CONTROL)

#define NIC_CFG_BASE(port, reg) \
	({ \
		u32 __port = (port); \
		u32 __reg = (reg); \
		(u64)(NIC_MACRO_CFG_BASE(__port) + ((__reg < NIC0_RXE0_CONTROL) ? \
		(NIC_CFG_LO_SIZE * (u64)(__port & 1)) : (NIC_CFG_HI_SIZE * (u64)(__port & 1)))); \
	})

#define NIC_RREG32(reg) \
	({ \
		u32 _reg = (reg); \
		RREG32(NIC_CFG_BASE(port, _reg) + _reg); \
	})

#define NIC_WREG32(reg, val) \
	({ \
		u32 _reg = (reg); \
		WREG32(NIC_CFG_BASE(port, _reg) + _reg, (val)); \
	})

#define NIC_RMWREG32(reg, val, mask) \
	({ \
		u32 _reg = (reg); \
		RMWREG32(NIC_CFG_BASE(port, _reg) + _reg, (val), (mask)); \
	})

#define NIC_RMWREG32_SHIFTED(reg, val, mask) \
	({ \
		u32 _reg = (reg); \
		RMWREG32_SHIFTED(NIC_CFG_BASE(port, _reg) + _reg, (val), (mask)); \
	})

#define MAC_CH_OFFSET(lane) ((NIC0_MAC_CH1_MAC_PCS_BASE - NIC0_MAC_CH0_MAC_PCS_BASE) * (lane))

#define WARN_ON_CACHE_UNALIGNED(addr) WARN_ON_ONCE(!IS_ALIGNED(addr, DEVICE_CACHE_LINE_SIZE))

enum gaudi2_cn_mac_fec_stats_type {
	FEC_CW_CORRECTED_ACCUM,
	FEC_CW_UNCORRECTED_ACCUM,
	FEC_CW_CORRECTED,
	FEC_CW_UNCORRECTED,
	FEC_SYMBOL_ERR_CORRECTED_LANE_0,
	FEC_SYMBOL_ERR_CORRECTED_LANE_1,
	FEC_SYMBOL_ERR_CORRECTED_LANE_2,
	FEC_SYMBOL_ERR_CORRECTED_LANE_3,
	FEC_PRE_FEC_SER_INT,
	FEC_PRE_FEC_SER_EXP,
	FEC_POST_FEC_SER_INT,
	FEC_POST_FEC_SER_EXP,
	FEC_STAT_LAST
};

enum gaudi2_cn_perf_stats_type {
	PERF_BANDWIDTH_INT,
	PERF_BANDWIDTH_FRAC,
	PERF_LATENCY_INT,
	PERF_LATENCY_FRAC,
	PERF_STAT_LAST
};

enum gaudi2_cn_pcs_link_state {
	PCS_LINK_STATE_SETTLING,
	PCS_LINK_STATE_STRESS,
	PCS_LINK_STATE_STEADY
};

struct gaudi2_cn_port;

/**
 * struct gaudi2_cn_port - manage specific port.
 * @hdev: habanalabs device structure.
 * @cn_port: pointer to a common device structure.
 * @fifo_ring: rings array for doorbell H/W interface.
 * @wq_ring: raw work queue ring.
 * @rx_ring: raw skb ring.
 * @cq_ring: ring array for the completion queue of raw/rdma packets.
 * @eq_ring: ring for the event queue.
 * @eq_work: EQ work for processing events (e.g Tx completion).
 * @qp_sanity_work: QPC sanity check worker.
 * @qp_sanity_wq: QPC sanity worker thread.
 * @cfg_lock: Serializes the port configuration.
 * @qp_destroy_lock: protects the MAC loopback switching for QP destroy flow.
 * @pcs_link_stady_state_ts: the timestamp to move to the pcs link steady state.
 * @pcs_link_state: the current pcs link state.
 * @qp_destroy_cnt: number of QPs currently under destruction.
 * @min_qp_size: the size of the smallest QP.
 * @db_fifo_pi: DB fifo ring producer index.
 * @qp_timeout_cnt: count of timeouts occurred on a port operating a QP.
 * @pcs_link_samples_per_sec: the number of times we check the pcs link in a second.
 * @advanced: true if advanced features are supported.
 * @adaptive_timeout_en: enable adaptive timeout feature.
 * @qp_destroy_mac_lpbk: port in is MAC loopback due to QP destroy flow.
 * @initial_tx_taps_cfg: first tx taps config since the last PHY power-up.
 * @tx_taps_cfg: current tx taps config.
 * @tx_taps_modified: flag to indicate if tx_taps were modified due to remote faults.
 */
struct gaudi2_cn_port {
	struct hbl_cn_device *hdev;
	struct hbl_cn_port *cn_port;
	struct hbl_cn_ring fifo_ring;
	struct hbl_cn_ring wq_ring;
	struct hbl_cn_ring rx_ring;
	struct hbl_cn_ring cq_rings[NIC_CQS_NUM];
	struct hbl_cn_ring eq_ring;
	struct delayed_work eq_work;
	struct delayed_work qp_sanity_work;
	struct workqueue_struct *qp_sanity_wq;
	/* Serializes the port configuration */
	struct mutex cfg_lock;
	/* protects the MAC loopback switching for QP destroy flow */
	struct mutex qp_destroy_lock;
	ktime_t pcs_link_stady_state_ts;
	enum gaudi2_cn_pcs_link_state pcs_link_state;
	u32 qp_destroy_cnt;
	u32 min_qp_size;
	u32 db_fifo_pi;
	u32 qp_timeout_cnt;
	u32 pcs_link_samples_per_sec;
	u8 advanced;
	u8 adaptive_timeout_en;
	u8 qp_destroy_mac_lpbk;
	u8 initial_tx_taps_cfg;
	u8 tx_taps_cfg;
	u8 tx_taps_modified;
};

/**
 * struct gaudi2_cn_device - ASIC specific manage structure.
 * @cn_ports: array that holds all ports manage structures.
 * @cn_macros: array that holds all macro manage structures.
 * @en_aux_data: data to be used by the Ethernet driver.
 * @en_aux_ops: functions for Ethernet <-> CN drivers communication.
 * @cn_aux_ops: functions for CN <-> compute drivers communication.
 * @setup_type: type of setup connectivity.
 * @cfg_base: configuration space base address.
 * @irq_num_port_base: base IRQ number for port EQ.
 * @sob_id_base: first reserved SOB ID.
 * @sob_inc_cfg_val: configuration value for incrementing SOB by one.
 * @fw_security_enabled: FW security enabled.
 * @msix_enabled: MSI-X enabled.
 * @temporal_polling: EQ polling activity is temporal and is used only in specific cases.
 * @flush_db_fifo: force flush DB FIFO after a write.
 * @in_compute_reset: device is under compute reset.
 * @mac_rs_fec_ctrl_support: Is MAC_RS_FEC_CONTROL block supported.
 */
struct gaudi2_cn_device {
	struct gaudi2_cn_port cn_ports[NIC_NUMBER_OF_PORTS];
	struct gaudi2_en_aux_data en_aux_data;
	struct gaudi2_en_aux_ops en_aux_ops;
	struct gaudi2_cn_aux_ops *cn_aux_ops;
	enum gaudi2_setup_type setup_type;
	u64 cfg_base;
	u32 irq_num_port_base;
	u32 sob_id_base;
	u32 sob_inc_cfg_val;
	u8 fw_security_enabled;
	u8 msix_enabled;
	u8 temporal_polling;
	u8 flush_db_fifo;
	u8 in_compute_reset;
	u8 mac_rs_fec_ctrl_support;
};

int gaudi2_cn_eq_init(struct hbl_cn_device *hdev);
void gaudi2_cn_eq_fini(struct hbl_cn_device *hdev);
int gaudi2_cn_debugfs_qp_read(struct hbl_cn_device *hdev, struct hbl_cn_qp_info *qp_info, char *buf,
			      size_t bsize);
int gaudi2_cn_debugfs_wqe_read(struct hbl_cn_device *hdev, char *buf, size_t bsize);
void gaudi2_cn_debugfs_collect_fec_stats(struct hbl_cn_port *cn_port, char *buf, size_t size);
int gaudi2_cn_eq_dispatcher_register_db(struct gaudi2_cn_port *gaudi2_cn, u32 asid, u32 dbn);
int gaudi2_cn_eq_request_irqs(struct hbl_cn_device *hdev);
void gaudi2_cn_eq_sync_irqs(struct hbl_cn_device *hdev);
void gaudi2_cn_eq_free_irqs(struct hbl_cn_device *hdev);
struct hbl_cn_ev_dq *gaudi2_cn_eq_dispatcher_select_dq(struct hbl_cn_port *cn_port,
						       const struct hbl_cn_eqe *eqe);
char *gaudi2_cn_qp_err_syndrome_to_str(u32 syndrome);
int gaudi2_cn_qpc_read(struct hbl_cn_port *cn_port, void *qpc, u32 qpn, bool is_req);
int gaudi2_cn_wqe_read(struct hbl_cn_port *cn_port, void *wqe, u32 qpn, u32 wqe_idx, bool is_tx);
void gaudi2_cn_hw_mac_loopback_cfg(struct gaudi2_cn_port *gaudi2_cn);
int gaudi2_cn_set_info(struct hbl_cn_device *hdev, bool get_from_fw);
int gaudi2_cn_phy_reset_macro(struct hbl_cn_macro *cn_macro);
int gaudi2_cn_phy_init(struct hbl_cn_device *hdev);
void gaudi2_cn_eq_enter_temporal_polling_mode(struct hbl_cn_device *hdev);
void gaudi2_cn_eq_exit_temporal_polling_mode(struct hbl_cn_device *hdev);
void gaudi2_cn_phy_flush_link_status_work(struct hbl_cn_device *hdev);
int gaudi2_cn_phy_port_init(struct hbl_cn_port *cn_port);
void gaudi2_cn_phy_port_start_stop(struct hbl_cn_port *cn_port, bool is_start);
const char *gaudi2_cn_phy_get_fw_name(void);
int gaudi2_cn_phy_fw_load_all(struct hbl_cn_device *hdev);
u16 gaudi2_cn_phy_get_crc(struct hbl_cn_device *hdev);
int gaudi2_cn_phy_port_power_up(struct hbl_cn_port *cn_port);
void gaudi2_cn_phy_port_reconfig(struct hbl_cn_port *cn_port);
void gaudi2_cn_phy_port_fini(struct hbl_cn_port *cn_port);
void gaudi2_cn_phy_link_status_work(struct work_struct *work);
void gaudi2_cn_phy_dump_serdes_params(struct hbl_cn_device *hdev, char *buf, size_t size);
void gaudi2_cn_get_mac_fec_stats(struct hbl_cn_port *cn_port, u64 *data);
bool gaudi2_cn_is_cq_in_overrun(struct hbl_cn_port *cn_port, u8 cq_id);
bool gaudi2_handle_qp_error_retry(struct hbl_cn_port *cn_port, u32 qpn);

#endif /* GAUDI2_CN_H_ */
