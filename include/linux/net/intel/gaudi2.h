/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#ifndef HBL_GAUDI2_H_
#define HBL_GAUDI2_H_

#include <linux/net/intel/cn.h>
#include <linux/net/intel/gaudi2_aux.h>

#define NIC_PSN_NBITS		24
#define NIC_PSN_MSB_MASK	(BIT(NIC_PSN_NBITS - 1))
#define NIC_PSN_LOWER_MASK	((NIC_PSN_MSB_MASK) - 1)

#define NIC_IS_PSN_CYCLIC_BIG(psn_a, psn_b) \
	({ \
		u32 _psn_a = (psn_a); \
		u32 _psn_b = (psn_b); \
		((_psn_a & NIC_PSN_MSB_MASK) == (_psn_b & NIC_PSN_MSB_MASK) ? \
		 (_psn_a & NIC_PSN_LOWER_MASK) > (_psn_b & NIC_PSN_LOWER_MASK) : \
		 (_psn_a & NIC_PSN_LOWER_MASK) < (_psn_b & NIC_PSN_LOWER_MASK)); \
	})

enum gaudi2_wqe_opcode {
	WQE_NOP = 0,
	WQE_SEND = 1,
	WQE_LINEAR = 2,
	WQE_STRIDE = 3,
	WQE_MULTI_STRIDE = 4,
	WQE_RENDEZVOUS_WR = 5,
	WQE_RENDEZVOUS_RD = 6,
	WQE_QOS_UPDATE = 7
};

#define NIC_SKB_PAD_SIZE       187

/**
 * enum gaudi2_eqe_type - Event queue element types for the NIC.
 * @EQE_COMP: Completion queue event. May occur upon Ethernet or RDMA Rx completion.
 * @EQE_COMP_ERR: Completion queue error event. May occur upon CQ overrun or other errors. Overrun
 *                may occur in case the S/W doesn't consume the CQ entries fast enough so there is
 *                no room for new H/W's entries.
 * @EQE_QP_ERR: QP moved to error state event. May occur by varies QP errors, e.g.: QP not valid,
 *              QP state invalid etc.
 * @EQE_LINK_STATUS: PCS link status changed event. May occur upon link up/down events.
 * @EQE_RAW_TX_COMP: Ethernet Tx completion event. May occur once H/W complete to send Ethernet
 *                   packet.
 * @EQE_DB_FIFO_OVERRUN: DB FIFO overrun event. May occur upon FIFO overrun in case S/W overwrite
 *                       un-consumed FIFO entry.
 * @EQE_CONG: Congestion control completion queue event. May occur upon any packet completion in
 *            case CC is enabled.
 * @EQE_CONG_ERR: Congestion control completion queue error event. May occur upon CCQ overrun or
 *                other errors. Overrun may occur in case the S/W doesn't consume the CCQ entries
 *                fast enough so there is no room for new H/W's entries.
 * @EQE_RESERVED: Reserved event value.
 *
 * ******************* SW events *******************
 * @EQE_QP_ALIGN_COUNTERS: QPC sanity failed and QPC counters were reset to last valid values.
 */
enum gaudi2_eqe_type {
	EQE_COMP = 0x0,
	EQE_COMP_ERR = 0x1,
	EQE_QP_ERR = 0x2,
	EQE_LINK_STATUS = 0x3,
	EQE_RAW_TX_COMP = 0x4,
	EQE_DB_FIFO_OVERRUN = 0x5,
	EQE_CONG = 0x6,
	EQE_CONG_ERR = 0x7,
	EQE_RESERVED = 0x8,

	/* events triggered by SW */
	EQE_QP_ALIGN_COUNTERS = 0xa,
};

/* BIT() macro is overflowing on full 64 bit mask, use the safer BITMLL() instead */
#define BITMLL(nr)	(U64_MAX >> (64 - (nr)))

/* Use multiple underscores to avoid hiding collisions. Using len and _len like in NIC_SET_BITS()
 * causes len to be 0 here in NIC_SET().
 */
#define NIC_SET(desc, idx, shift, val, __len) \
	({ \
		u64 *_data = &(desc).data[(idx)]; \
		u32 _shift = (shift); \
		u32 ___len = (__len); \
		*_data &= ~((u64)(BITMLL(___len)) << _shift); \
		*_data |= (u64)((val) & BITMLL(___len)) << _shift; \
	})

#define NIC_SET_BITS(desc, lsb, val, len) \
	do { \
		u32 _lsb = (lsb); \
		u32 _len = (len); \
		BUILD_BUG_ON((_lsb / 64) != ((_lsb + _len - 1) / 64)); \
		NIC_SET((desc), _lsb / 64, _lsb % 64, (val), _len); \
	} while (0)

#define NIC_GET(desc, idx, shift, len) \
		((((desc).data[idx]) >> (shift)) & BITMLL(len))

#define NIC_GET_BITS(desc, lsb, len) \
	({ \
		u32 _lsb = (lsb); \
		u32 _len = (len); \
		BUILD_BUG_ON((_lsb / 64) != ((_lsb + _len - 1) / 64)); \
		NIC_GET(desc, _lsb / 64, _lsb % 64, _len); \
	})

struct gaudi2_qpc_requester {
	u64 data[16];
};

struct qpc_mask {
	u64 data[sizeof(struct gaudi2_qpc_requester) >> 3];
};

#define REQ_QPC_SET_DST_QP(req, val)		NIC_SET_BITS(req, 0, val, 24)
#define REQ_QPC_SET_RKEY(req, val)		NIC_SET_BITS(req, 128, val, 32)
#define REQ_QPC_SET_DST_IP(req, val)		NIC_SET_BITS(req, 160, val, 32)
#define REQ_QPC_SET_DST_MAC_LSB(req, val)	NIC_SET_BITS(req, 192, val, 32)
#define REQ_QPC_SET_DST_MAC_MSB(req, val)	NIC_SET_BITS(req, 224, val, 16)
#define REQ_QPC_SET_TIMEOUT_RETRY_COUNT(req, val)	\
						NIC_SET_BITS(req, 248, val, 8)
#define REQ_QPC_SET_NTS_PSN(req, val)		NIC_SET_BITS(req, 256, val, 24)
#define REQ_QPC_SET_BCS_PSN(req, val)		NIC_SET_BITS(req, 288, val, 24)
#define REQ_QPC_SET_SCHD_Q_NUM(req, val)	NIC_SET_BITS(req, 312, val, 8)
#define REQ_QPC_SET_ONA_PSN(req, val)		NIC_SET_BITS(req, 320, val, 24)

#define REQ_QPC_SET_TM_GRANULARITY(req, val)	NIC_SET_BITS(req, 376, val, 7)
#define REQ_QPC_SET_WQ_BACK_PRESSURE(req, val)	NIC_SET_BITS(req, 383, val, 1)
#define REQ_QPC_SET_REMOTE_WQ_LOG_SZ(req, val)	NIC_SET_BITS(req, 408, val, 5)
#define REQ_QPC_SET_ENCAP_TYPE(req, val)	NIC_SET_BITS(req, 413, val, 3)
#define REQ_QPC_SET_CQ_NUM(req, val)		NIC_SET_BITS(req, 440, val, 5)
#define REQ_QPC_SET_RTT_STATE(req, val)		NIC_SET_BITS(req, 445, val, 2)
#define REQ_QPC_SET_ENCAP_ENABLE(req, val)	NIC_SET_BITS(req, 447, val, 1)
#define REQ_QPC_SET_CONGESTION_WIN(req, val)	NIC_SET_BITS(req, 448, val, 24)
#define REQ_QPC_SET_BURST_SIZE(req, val)	NIC_SET_BITS(req, 544, val, 22)
#define REQ_QPC_SET_ASID(req, val)		NIC_SET_BITS(req, 566, val, 8)

#define REQ_QPC_SET_LAST_IDX(req, val)		NIC_SET_BITS(req, 576, val, 22)
#define REQ_QPC_SET_EXECUTION_IDX(req, val)	NIC_SET_BITS(req, 608, val, 22)
#define REQ_QPC_SET_CONSUMER_IDX(req, val)	NIC_SET_BITS(req, 640, val, 22)
#define REQ_QPC_SET_LOCAL_PRODUCER_IDX(req, val)	NIC_SET_BITS(req, 672, val, 22)
#define REQ_QPC_SET_REMOTE_PRODUCER_IDX(req, val)	NIC_SET_BITS(req, 704, val, 22)
#define REQ_QPC_SET_REMOTE_CONSUMER_IDX(req, val)	NIC_SET_BITS(req, 736, val, 22)
#define REQ_QPC_SET_OLDEST_UNACKED_REMOTE_PRODUCER_IDX(req, val)	NIC_SET_BITS(req, 768, \
											val, 22)
#define REQ_QPC_SET_PSN_SINCE_ACKREQ(req, val)	NIC_SET_BITS(req, 800, val, 8)
#define REQ_QPC_SET_ACKREQ_FREQ(req, val)	NIC_SET_BITS(req, 808, val, 8)
#define REQ_QPC_SET_PACING_TIME(req, val)	NIC_SET_BITS(req, 832, val, 16)

#define REQ_QPC_SET_DATA_MMU_BYPASS(req, val)	NIC_SET_BITS(req, 1003, val, 1)
#define REQ_QPC_SET_MOD_GAUDI1(req, val)	NIC_SET_BITS(req, 1004, val, 1)
#define REQ_QPC_SET_PORT(req, val)		NIC_SET_BITS(req, 1005, val, 2)
#define REQ_QPC_SET_WQ_TYPE(req, val)		NIC_SET_BITS(req, 1007, val, 2)

#define REQ_QPC_SET_SWQ_GRANULARITY(req, val)	NIC_SET_BITS(req, 1009, val, 1)
#define REQ_QPC_SET_TRANSPORT_SERVICE(req, val)	NIC_SET_BITS(req, 1010, val, 1)
#define REQ_QPC_SET_PRIORITY(req, val)		NIC_SET_BITS(req, 1011, val, 2)
#define REQ_QPC_SET_CONGESTION_MODE(req, val)	NIC_SET_BITS(req, 1013, val, 2)
#define REQ_QPC_SET_MTU(req, val)		NIC_SET_BITS(req, 1015, val, 2)

#define REQ_QPC_SET_WQ_BASE_ADDR(req, val)	NIC_SET_BITS(req, 1017, val, 2)
#define REQ_QPC_SET_TRUST_LEVEL(req, val)	NIC_SET_BITS(req, 1019, val, 2)
#define REQ_QPC_SET_ERR(req, val)		NIC_SET_BITS(req, 1022, val, 1)
#define REQ_QPC_SET_VALID(req, val)		NIC_SET_BITS(req, 1023, val, 1)

/* REQ QPC Get */
#define REQ_QPC_GET_DST_QP(req)					NIC_GET_BITS(req, 0, 24)
#define REQ_QPC_GET_MULTI_STRIDE_STATE_LSB(req)			NIC_GET_BITS(req, 32, 32)
#define REQ_QPC_GET_MULTI_STRIDE_STATE_MSB(req)			NIC_GET_BITS(req, 64, 64)
#define REQ_QPC_GET_RKEY(req)					NIC_GET_BITS(req, 128, 32)
#define REQ_QPC_GET_DST_IP(req)					NIC_GET_BITS(req, 160, 32)
#define REQ_QPC_GET_DST_MAC_LSB(req)				NIC_GET_BITS(req, 192, 32)
#define REQ_QPC_GET_DST_MAC_MSB(req)				NIC_GET_BITS(req, 224, 16)
#define REQ_QPC_GET_SEQUENCE_ERROR_RETRY_COUNT(req)		NIC_GET_BITS(req, 240, 8)
#define REQ_QPC_GET_TIMEOUT_RETRY_COUNT(req)			NIC_GET_BITS(req, 248, 8)
#define REQ_QPC_GET_NTS_PSN(req)				NIC_GET_BITS(req, 256, 24)
#define REQ_QPC_GET_BCS_PSN(req)				NIC_GET_BITS(req, 288, 24)
#define REQ_QPC_GET_SCHD_Q_NUM(req)				NIC_GET_BITS(req, 312, 8)
#define REQ_QPC_GET_ONA_PSN(req)				NIC_GET_BITS(req, 320, 24)
#define REQ_QPC_GET_BCC_PSN(req)				NIC_GET_BITS(req, 352, 24)
#define REQ_QPC_GET_TM_GRANULARITY(req)				NIC_GET_BITS(req, 376, 7)
#define REQ_QPC_GET_WQ_BACK_PRESSURE(req)			NIC_GET_BITS(req, 383, 1)
#define REQ_QPC_GET_CONGESTION_MARKED_ACK(req)			NIC_GET_BITS(req, 384, 24)
#define REQ_QPC_GET_REMOTE_WQ_LOG_SZ(req)			NIC_GET_BITS(req, 408, 5)
#define REQ_QPC_GET_ENCAP_TYPE(req)				NIC_GET_BITS(req, 413, 3)
#define REQ_QPC_GET_CONGESTION_NON_MARKED_ACK(req)		NIC_GET_BITS(req, 416, 24)
#define REQ_QPC_GET_CQ_NUM(req)					NIC_GET_BITS(req, 440, 5)
#define REQ_QPC_GET_RTT_STATE(req)				NIC_GET_BITS(req, 445, 2)
#define REQ_QPC_GET_ENCAP_ENABLE(req)				NIC_GET_BITS(req, 447, 1)
#define REQ_QPC_GET_CONGESTION_WIN(req)				NIC_GET_BITS(req, 448, 24)
#define REQ_QPC_GET_RTT_TIMESTAMP(req)				NIC_GET_BITS(req, 480, 25)
#define REQ_QPC_GET_RTT_MARKED_PSN(req)				NIC_GET_BITS(req, 512, 24)
#define REQ_QPC_GET_BURST_SIZE(req)				NIC_GET_BITS(req, 544, 22)
#define REQ_QPC_GET_ASID(req)					NIC_GET_BITS(req, 566, 10)
#define REQ_QPC_GET_LAST_IDX(req)				NIC_GET_BITS(req, 576, 22)
#define REQ_QPC_GET_EXECUTION_IDX(req)				NIC_GET_BITS(req, 608, 22)
#define REQ_QPC_GET_CONSUMER_IDX(req)				NIC_GET_BITS(req, 640, 22)
#define REQ_QPC_GET_LOCAL_PRODUCER_IDX(req)			NIC_GET_BITS(req, 672, 22)
#define REQ_QPC_GET_REMOTE_PRODUCER_IDX(req)			NIC_GET_BITS(req, 704, 22)
#define REQ_QPC_GET_REMOTE_CONSUMER_IDX(req)			NIC_GET_BITS(req, 736, 22)
#define REQ_QPC_GET_OLDEST_UNACKED_REMOTE_PRODUCER_IDX(req)	NIC_GET_BITS(req, 768, 22)
#define REQ_QPC_GET_PSN_SINCE_ACKREQ(req)			NIC_GET_BITS(req, 800, 8)
#define REQ_QPC_GET_ACKREQ_FREQ(req)				NIC_GET_BITS(req, 808, 8)
#define REQ_QPC_GET_PACING_TIME(req)				NIC_GET_BITS(req, 832, 16)
#define REQ_QPC_GET_PSN_DELIVERED(req)				NIC_GET_BITS(req, 864, 24)
#define REQ_QPC_GET_DATA_MMU_BYPASS(req)			NIC_GET_BITS(req, 1003, 1)
#define REQ_QPC_GET_MOD_GAUDI1(req)				NIC_GET_BITS(req, 1004, 1)
#define REQ_QPC_GET_PORT(req)					NIC_GET_BITS(req, 1005, 2)
#define REQ_QPC_GET_WQ_TYPE(req)				NIC_GET_BITS(req, 1007, 2)
#define REQ_QPC_GET_SWQ_GRANULARITY(req)			NIC_GET_BITS(req, 1009, 1)
#define REQ_QPC_GET_TRANSPORT_SERVICE(req)			NIC_GET_BITS(req, 1010, 1)
#define REQ_QPC_GET_PRIORITY(req)				NIC_GET_BITS(req, 1011, 2)
#define REQ_QPC_GET_CONGESTION_MODE(req)			NIC_GET_BITS(req, 1013, 2)
#define REQ_QPC_GET_MTU(req)					NIC_GET_BITS(req, 1015, 2)
#define REQ_QPC_GET_WQ_BASE_ADDR(req)				NIC_GET_BITS(req, 1017, 2)
#define REQ_QPC_GET_TRUST_LEVEL(req)				NIC_GET_BITS(req, 1019, 2)
#define REQ_QPC_GET_IN_WORK(req)				NIC_GET_BITS(req, 1021, 1)
#define REQ_QPC_GET_ERROR(req)					NIC_GET_BITS(req, 1022, 1)
#define REQ_QPC_GET_VALID(req)					NIC_GET_BITS(req, 1023, 1)

/* Resp QPC */
struct gaudi2_qpc_responder {
	u64 data[4];
};

#define RES_QPC_SET_DST_QP(res, val)		NIC_SET_BITS(res, 0, val, 24)
#define RES_QPC_SET_PORT(res, val)		NIC_SET_BITS(res, 24, val, 2)
#define RES_QPC_SET_PRIORITY(res, val)		NIC_SET_BITS(res, 26, val, 2)
#define RES_QPC_SET_LKEY(res, val)		NIC_SET_BITS(res, 32, val, 32)

#define RES_QPC_SET_DST_IP(res, val)		NIC_SET_BITS(res, 64, val, 32)
#define RES_QPC_SET_DST_MAC_LSB(res, val)	NIC_SET_BITS(res, 96, val, 32)
#define RES_QPC_SET_DST_MAC_MSB(res, val)	NIC_SET_BITS(res, 128, val, 16)
#define RES_QPC_SET_TRANSPORT_SERVICE(res, val)	NIC_SET_BITS(res, 149, val, 1)

#define RES_QPC_SET_ASID(res, val)		NIC_SET_BITS(res, 150, val, 10)
#define RES_QPC_SET_PEER_QP(res, val)		NIC_SET_BITS(res, 160, val, 24)
#define RES_QPC_SET_SCHD_Q_NUM(res, val)	NIC_SET_BITS(res, 184, val, 8)

#define RES_QPC_SET_TRUST_LEVEL(res, val)	NIC_SET_BITS(res, 216, val, 2)
#define RES_QPC_SET_MOD_GAUDI1(res, val)	NIC_SET_BITS(res, 218, val, 1)
#define RES_QPC_SET_DATA_MMU_BYPASS(res, val)	NIC_SET_BITS(res, 219, val, 1)
#define RES_QPC_SET_ENCAP_TYPE(res, val)	NIC_SET_BITS(res, 220, val, 3)
#define RES_QPC_SET_ENCAP_ENABLE(res, val)	NIC_SET_BITS(res, 223, val, 1)
#define RES_QPC_SET_CQ_NUM(res, val)		NIC_SET_BITS(res, 248, val, 5)

#define RES_QPC_SET_PEER_WQ_GRAN(res, val)	NIC_SET_BITS(res, 253, val, 1)
#define RES_QPC_SET_VALID(res, val)		NIC_SET_BITS(res, 255, val, 1)

/* Resp QPC Get */
#define RES_QPC_GET_DESTINATION_QP(res)		NIC_GET_BITS(res, 0, 24)
#define RES_QPC_GET_PORT(res)			NIC_GET_BITS(res, 24, 2)
#define RES_QPC_GET_PRIORITY(res)		NIC_GET_BITS(res, 26, 2)
#define RES_QPC_GET_CONN_STATE(res)		NIC_GET_BITS(res, 28, 2)
#define RES_QPC_GET_NACK_SYNDROME(res)		NIC_GET_BITS(res, 30, 2)
#define RES_QPC_GET_LKEY(res)			NIC_GET_BITS(res, 32, 32)
#define RES_QPC_GET_DST_IP(res)			NIC_GET_BITS(res, 64, 32)
#define RES_QPC_GET_DST_MAC_LSB(res)		NIC_GET_BITS(res, 96, 32)
#define RES_QPC_GET_DST_MAC_MSB(res)		NIC_GET_BITS(res, 128, 16)
#define RES_QPC_GET_ECN_COUNT(res)		NIC_GET_BITS(res, 144, 5)
#define RES_QPC_GET_TRANSPORT_SERVICE(res)	NIC_GET_BITS(res, 149, 1)
#define RES_QPC_GET_ASID(res)			NIC_GET_BITS(res, 150, 10)
#define RES_QPC_GET_PEER_QP(res)		NIC_GET_BITS(res, 160, 24)
#define RES_QPC_GET_SCHD_Q_NUM(res)		NIC_GET_BITS(res, 184, 8)
#define RES_QPC_GET_EXPECTED_PSN(res)		NIC_GET_BITS(res, 192, 24)
#define RES_QPC_GET_TRUST_LEVEL(res)		NIC_GET_BITS(res, 216, 2)
#define RES_QPC_GET_MOD_GAUDI1(res)		NIC_GET_BITS(res, 218, 1)
#define RES_QPC_GET_DATA_MMU_BYPASS(res)	NIC_GET_BITS(res, 219, 1)
#define RES_QPC_GET_ENCAP_TYPE(res)		NIC_GET_BITS(res, 220, 3)
#define RES_QPC_GET_ENCAP_ENABLE(res)		NIC_GET_BITS(res, 223, 1)
#define RES_QPC_GET_CYCLIC_IDX(res)		NIC_GET_BITS(res, 224, 24)
#define RES_QPC_GET_CQ_NUM(res)			NIC_GET_BITS(res, 248, 5)
#define RES_QPC_GET_PEER_WQ_GRAN(res)		NIC_GET_BITS(res, 253, 1)
#define RES_QPC_GET_IN_WORK(res)		NIC_GET_BITS(res, 254, 1)
#define RES_QPC_GET_VALID(res)			NIC_GET_BITS(res, 255, 1)

struct gaudi2_sq_wqe {
	u64 data[4];
};

/* TX WQE Get */
#define TX_WQE_GET_OPCODE(wqe)			NIC_GET_BITS(wqe, 0, 5)
#define TX_WQE_GET_TRACE_EVENT_DATA(wqe)	NIC_GET_BITS(wqe, 5, 1)
#define TX_WQE_GET_TRACE_EVENT(wqe)		NIC_GET_BITS(wqe, 6, 1)
#define TX_WQE_GET_WQE_INDEX(wqe)		NIC_GET_BITS(wqe, 8, 8)
#define TX_WQE_GET_REDUCTION_OPCODE(wqe)	NIC_GET_BITS(wqe, 16, 13)
#define TX_WQE_GET_SE(wqe)			NIC_GET_BITS(wqe, 29, 1)
#define TX_WQE_GET_INLINE(wqe)			NIC_GET_BITS(wqe, 30, 1)
#define TX_WQE_GET_ACKREQ(wqe)			NIC_GET_BITS(wqe, 31, 1)
#define TX_WQE_GET_SIZE(wqe)			NIC_GET_BITS(wqe, 32, 32)
#define TX_WQE_GET_LOCAL_ADDR_LSB(wqe)		NIC_GET_BITS(wqe, 64, 32)
#define TX_WQE_GET_LOCAL_ADDR_MSB(wqe)		NIC_GET_BITS(wqe, 96, 32)
#define TX_WQE_GET_REMOTE_ADDR_LSB(wqe)		NIC_GET_BITS(wqe, 128, 32)
#define TX_WQE_GET_REMOTE_ADDR_MSB(wqe)		NIC_GET_BITS(wqe, 160, 32)
#define TX_WQE_GET_TAG(wqe)			NIC_GET_BITS(wqe, 192, 32)
#define TX_WQE_GET_REMOTE_SOB(wqe)		NIC_GET_BITS(wqe, 224, 27)
#define TX_WQE_GET_REMOTE_SOB_DATA(wqe)		NIC_GET_BITS(wqe, 251, 2)
#define TX_WQE_GET_SOB_CMD(wqe)			NIC_GET_BITS(wqe, 253, 1)
#define TX_WQE_GET_COMPLETION_TYPE(wqe)		NIC_GET_BITS(wqe, 254, 2)

/* TX WQE Set */
#define CFG_SQ_WQE_RESET(swq) memset((swq)->data, 0, sizeof(u64) * 4)

#define CFG_SQ_WQE_OPCODE(swq, val) \
						((swq)->data[0] |= (val))
#define CFG_SQ_WQE_INDEX(swq, val) \
						((swq)->data[0] |= (val) << 8)
#define CFG_SQ_WQE_SOL_EVENT(swq, val) \
						((swq)->data[0] |= (val) << 29)
#define CFG_SQ_WQE_INLINE(swq, val) \
						((swq)->data[0] |= (val) << 30)
#define CFG_SQ_WQE_SIZE(swq, val) \
						((swq)->data[0] |= (val) << 32)
#define CFG_SQ_WQE_LOCAL_ADDRESS(swq, val) \
						((swq)->data[1] = (val))
struct gaudi2_rq_wqe {
	u64 data[2];
};

/* RX WQE Get */
#define RX_WQE_GET_OPCODE(wqe)			NIC_GET_BITS(wqe, 0, 5)
#define RX_WQE_GET_WQE_INDEX(wqe)		NIC_GET_BITS(wqe, 8, 8)
#define RX_WQE_GET_SOB_CMD(wqe)			NIC_GET_BITS(wqe, 31, 1)
#define RX_WQE_GET_LOCAL_SOB(wqe)		NIC_GET_BITS(wqe, 32, 27)
#define RX_WQE_GET_LOCAL_SOB_DATA(wqe)		NIC_GET_BITS(wqe, 59, 3)
#define RX_WQE_GET_COMPLETION_TYPE(wqe)		NIC_GET_BITS(wqe, 62, 2)
#define RX_WQE_GET_SIZE(wqe)			NIC_GET_BITS(wqe, 64, 32)
#define RX_WQE_GET_TAG(wqe)			NIC_GET_BITS(wqe, 96, 32)

struct gaudi2_cqe {
	u32 data[4];
};

#define CQE_IS_VALID(cqe)		(((cqe)->data[0] >> 31) & 1)
#define CQE_IS_REQ(cqe)			(((cqe)->data[0] >> 24) & 1)
#define CQE_QPN(cqe)			((cqe)->data[0] & 0xFFFFFF)
#define CQE_SET_INVALID(cqe)		((cqe)->data[0] &= ~(1ull << 31))
#define CQE_WQE_IDX(cqe)		((cqe)->data[1])
#define CQE_TAG(cqe)			((cqe)->data[2])
#define CQE_RAW_PKT_SIZE(cqe)		((cqe)->data[3])

#define EQE_HEADER(valid, type)		((!!(valid) << 31) | (type))
#define EQE_TYPE(eqe)			((eqe)->data[0] & 0xf)
#define EQE_IS_VALID(eqe)		(((eqe)->data[0] >> 31) & 0x1)
#define EQE_SET_INVALID(eqe)		((eqe)->data[0] &= ~(1ull << 31))
#define EQE_CQ_EVENT_CQ_NUM(eqe)	((eqe)->data[1] & 0xffff)
#define EQE_CQ_EVENT_PI(eqe)		((eqe)->data[2])
#define EQE_CQ_EVENT_CCQ_NUM(eqe)	((eqe)->data[1] & 0xffff)

#define EQE_QP_EVENT_QPN(eqe)		((eqe)->data[1] & 0xffffff)
#define EQE_QP_EVENT_RESET(eqe)		(((eqe)->data[1] >> 31) & 0x1)
#define EQE_QP_EVENT_ERR_SYND(eqe)	((eqe)->data[2])

#define EQE_RAW_TX_EVENT_QPN(eqe)	((eqe)->data[1] & 0xffffff)
#define EQE_RAW_TX_EVENT_IDX(eqe)	((eqe)->data[2] & 0xffffffff)

#define EQE_LINK_STATUS_TIME_STAMP(eqe)	((eqe)->data[1])
#define EQE_LINK_STATUS(eqe)		((eqe)->data[2] & 0xf)

#define EQE_DB_EVENT_DB_NUM(eqe)	((eqe)->data[1] & 0xffff)

#define EQE_SW_EVENT_QPN(eqe)		((eqe)->data[1] & 0xffffff)

#define EQ_IDX_MASK			GENMASK(23, 0)

/**
 * struct gaudi2_en_tx_buf - indicates a tx buffer
 * @skb: the transmitted skb
 * @dma_addr: the skb's mapped dma address
 * @len: buffer size
 */
struct gaudi2_en_tx_buf {
	struct sk_buff *skb;
	dma_addr_t dma_addr;
	int len;
};

/**
 * struct gaudi2_en_aux_data - Gaudi2 Ethernet driver data.
 * @rx_rings: array of the Rx rings of all ports.
 * @cq_rings: array of the CQ rings of all ports.
 * @wq_rings: array of the WQ rings of all ports.
 * @kernel_asid: kernel ASID.
 * @raw_qpn: raw data (Ethernet) QP number.
 * @tx_ring_len: number of elements in the Tx ring.
 * @schedq_num: sched-Q number used for the Eth driver of the port.
 * @pad_size: the pad size in bytes for the skb to transmit.
 */
struct gaudi2_en_aux_data {
	struct hbl_cn_ring **rx_rings;
	struct hbl_cn_ring **cq_rings;
	struct hbl_cn_ring **wq_rings;
	u32 kernel_asid;
	u32 raw_qpn;
	u32 tx_ring_len;
	u32 schedq_num;
	u16 pad_size;
};

/**
 * struct gaudi2_en_aux_ops - ASIC specific functions for cn <-> en drivers communication.
 * @configure_cq: configure a CQ.
 * @arm_cq: arm a CQ to issue an interrupt after reaching certain index or timeout.
 * @write_rx_ci: write the Rx CI to the HW.
 * @get_pfc_cnts: retrieve PFC counters.
 * @ring_tx_doorbell: ring the Tx door bell so the HW will send it.
 * @qp_err_syndrome_to_str: Convert error syndrome id to string.
 * @db_fifo_reset: Reset Ethernet doorbell fifo.
 * @port_reset_locked: reset the port assuming we are under lock.
 * @get_overrun_cnt: get db fifo overrun counter.
 */
struct gaudi2_en_aux_ops {
	/* en2cn */
	void (*configure_cq)(struct hbl_aux_dev *aux_dev, u32 port, u16 coalesce_usec, bool enable);
	void (*arm_cq)(struct hbl_aux_dev *aux_dev, u32 port, u32 index);
	void (*write_rx_ci)(struct hbl_aux_dev *aux_dev, u32 port, u32 ci);
	void (*get_pfc_cnts)(struct hbl_aux_dev *aux_dev, u32 port, int pfc_prio,
			     u64 *indications, u64 *requests);
	int (*ring_tx_doorbell)(struct hbl_aux_dev *aux_dev, u32 port, u32 pi, bool *full_after_tx);
	char* (*qp_err_syndrome_to_str)(u32 syndrome);
	void (*db_fifo_reset)(struct hbl_aux_dev *aux_dev, u32 port);

	/* cn2en */
	int (*port_reset_locked)(struct hbl_aux_dev *aux_dev, u32 port);
	u32 (*get_overrun_cnt)(struct hbl_aux_dev *aux_dev, u32 port_idx);
};

#endif /* HBL_GAUDI2_H_ */
