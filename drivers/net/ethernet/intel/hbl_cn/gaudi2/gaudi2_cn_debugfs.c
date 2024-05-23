// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#include "gaudi2_cn.h"

#define _fsnprintf(buf, size, fmt, ...)							\
		do {									\
			if (full_print)							\
				__snprintf(buf, size, fmt, ##__VA_ARGS__);		\
											\
		} while (0)

static int gaudi2_cn_debugfs_qpc_req_parse(struct hbl_cn_device *hdev,
					   struct hbl_cn_qp_info *qp_info,
					   struct gaudi2_qpc_requester *req, char *buf,
					   size_t bsize)
{
	bool full_print, force_read;

	force_read = qp_info->force_read;
	full_print = qp_info->full_print;

	__snprintf(buf, bsize, "Valid: %lld\n", REQ_QPC_GET_VALID(*req));
	if (strlen(buf) >= bsize)
		return -EFBIG;

	if (!force_read && !REQ_QPC_GET_VALID(*req))
		return 0;

	__snprintf(buf, bsize, "Error: %lld\n", REQ_QPC_GET_ERROR(*req));
	if (strlen(buf) >= bsize)
		return -EFBIG;

	if (!force_read && REQ_QPC_GET_ERROR(*req))
		return 0;

	_fsnprintf(buf, bsize, "in_work: 0x%llx\n", REQ_QPC_GET_IN_WORK(*req));
	_fsnprintf(buf, bsize, "trusted: 0x%llx\n", REQ_QPC_GET_TRUST_LEVEL(*req));
	_fsnprintf(buf, bsize, "WQ addr: 0x%llx\n", REQ_QPC_GET_WQ_BASE_ADDR(*req));
	_fsnprintf(buf, bsize, "MTU: 0x%llx\n", REQ_QPC_GET_MTU(*req));
	_fsnprintf(buf, bsize, "cong mode: 0x%llx\n", REQ_QPC_GET_CONGESTION_MODE(*req));
	_fsnprintf(buf, bsize, "priority: 0x%llx\n", REQ_QPC_GET_PRIORITY(*req));
	_fsnprintf(buf, bsize, "transport service: 0x%llx\n", REQ_QPC_GET_TRANSPORT_SERVICE(*req));
	_fsnprintf(buf, bsize, "SWQ gran: 0x%llx\n", REQ_QPC_GET_SWQ_GRANULARITY(*req));
	__snprintf(buf, bsize, "WQ type: 0x%llx\n", REQ_QPC_GET_WQ_TYPE(*req));
	_fsnprintf(buf, bsize, "port/lane: 0x%llx\n", REQ_QPC_GET_PORT(*req));
	_fsnprintf(buf, bsize, "Gaudi1 mode: 0x%llx\n", REQ_QPC_GET_MOD_GAUDI1(*req));
	__snprintf(buf, bsize, "data MMU BP: 0x%llx\n", REQ_QPC_GET_DATA_MMU_BYPASS(*req));
	_fsnprintf(buf, bsize, "PSN delivered: 0x%llx\n", REQ_QPC_GET_PSN_DELIVERED(*req));
	_fsnprintf(buf, bsize, "pacing time: 0x%llx\n", REQ_QPC_GET_PACING_TIME(*req));
	_fsnprintf(buf, bsize, "Ackreq freq: 0x%llx\n", REQ_QPC_GET_ACKREQ_FREQ(*req));
	_fsnprintf(buf, bsize, "PSN since ackreq: 0x%llx\n", REQ_QPC_GET_PSN_SINCE_ACKREQ(*req));
	__snprintf(buf, bsize, "oldest unacked remote PI: 0x%llx\n",
		   REQ_QPC_GET_OLDEST_UNACKED_REMOTE_PRODUCER_IDX(*req));
	__snprintf(buf, bsize, "remote CI: 0x%llx\n", REQ_QPC_GET_REMOTE_CONSUMER_IDX(*req));
	__snprintf(buf, bsize, "remote PI: 0x%llx\n", REQ_QPC_GET_REMOTE_PRODUCER_IDX(*req));
	__snprintf(buf, bsize, "local PI: 0x%llx\n", REQ_QPC_GET_LOCAL_PRODUCER_IDX(*req));
	__snprintf(buf, bsize, "local CI: 0x%llx\n", REQ_QPC_GET_CONSUMER_IDX(*req));
	__snprintf(buf, bsize, "local EI: 0x%llx\n", REQ_QPC_GET_EXECUTION_IDX(*req));
	__snprintf(buf, bsize, "last index: 0x%llx\n", REQ_QPC_GET_LAST_IDX(*req));
	__snprintf(buf, bsize, "ASID: 0x%llx\n", REQ_QPC_GET_ASID(*req));
	_fsnprintf(buf, bsize, "burst size: 0x%llx\n", REQ_QPC_GET_BURST_SIZE(*req));
	_fsnprintf(buf, bsize, "CC RTT PSN: 0x%llx\n", REQ_QPC_GET_RTT_MARKED_PSN(*req));
	_fsnprintf(buf, bsize, "CC RTT timestamp: 0x%llx\n", REQ_QPC_GET_RTT_TIMESTAMP(*req));
	_fsnprintf(buf, bsize, "congestion window: 0x%llx\n", REQ_QPC_GET_CONGESTION_WIN(*req));
	_fsnprintf(buf, bsize, "encap en: 0x%llx\n", REQ_QPC_GET_ENCAP_ENABLE(*req));
	_fsnprintf(buf, bsize, "RTT state: 0x%llx\n", REQ_QPC_GET_RTT_STATE(*req));
	_fsnprintf(buf, bsize, "CQ num: 0x%llx\n", REQ_QPC_GET_CQ_NUM(*req));
	_fsnprintf(buf, bsize, "congestion window NMA: 0x%llx\n",
		   REQ_QPC_GET_CONGESTION_NON_MARKED_ACK(*req));
	_fsnprintf(buf, bsize, "encap type: 0x%llx\n", REQ_QPC_GET_ENCAP_TYPE(*req));
	__snprintf(buf, bsize, "remote WQ log bsize: 0x%llx\n", REQ_QPC_GET_REMOTE_WQ_LOG_SZ(*req));
	_fsnprintf(buf, bsize, "congestion window MA: 0x%llx\n",
		   REQ_QPC_GET_CONGESTION_MARKED_ACK(*req));
	_fsnprintf(buf, bsize, "WQ back-press: 0x%llx\n", REQ_QPC_GET_WQ_BACK_PRESSURE(*req));
	_fsnprintf(buf, bsize, "timeout gran: 0x%llx\n", REQ_QPC_GET_TM_GRANULARITY(*req));
	__snprintf(buf, bsize, "BCC PSN: 0x%llx\n", REQ_QPC_GET_BCC_PSN(*req));
	__snprintf(buf, bsize, "ONA PSN: 0x%llx\n", REQ_QPC_GET_ONA_PSN(*req));
	_fsnprintf(buf, bsize, "sched Q: 0x%llx\n", REQ_QPC_GET_SCHD_Q_NUM(*req));
	__snprintf(buf, bsize, "BCS PSN: 0x%llx\n", REQ_QPC_GET_BCS_PSN(*req));
	__snprintf(buf, bsize, "NTS PSN: 0x%llx\n", REQ_QPC_GET_NTS_PSN(*req));
	_fsnprintf(buf, bsize, "timeout retry cnt: 0x%llx\n",
		   REQ_QPC_GET_TIMEOUT_RETRY_COUNT(*req));
	_fsnprintf(buf, bsize, "seq ERR retry cnt: 0x%llx\n",
		   REQ_QPC_GET_SEQUENCE_ERROR_RETRY_COUNT(*req));
	__snprintf(buf, bsize, "dst MAC: %04llx%08llx\n", REQ_QPC_GET_DST_MAC_MSB(*req),
		   REQ_QPC_GET_DST_MAC_LSB(*req));
	_fsnprintf(buf, bsize, "dst ipv4: 0x%llx\n", REQ_QPC_GET_DST_IP(*req));
	_fsnprintf(buf, bsize, "remote key: 0x%llx\n", REQ_QPC_GET_RKEY(*req));
	_fsnprintf(buf, bsize, "multi-stride state: 0x%016llx%08llx\n",
		   REQ_QPC_GET_MULTI_STRIDE_STATE_MSB(*req),
		   REQ_QPC_GET_MULTI_STRIDE_STATE_LSB(*req));
	_fsnprintf(buf, bsize, "dest QP: 0x%llx\n", REQ_QPC_GET_DST_QP(*req));

	/* make sure the caller is aware that the buffer it is using is not long enough */
	if (strlen(buf) >= bsize)
		return -EFBIG;

	return 0;
}

static int gaudi2_cn_debugfs_qpc_res_parse(struct hbl_cn_device *hdev,
					   struct hbl_cn_qp_info *qp_info,
					   struct gaudi2_qpc_responder *res, char *buf,
					   size_t bsize)
{
	bool full_print, force_read;

	force_read = qp_info->force_read;
	full_print = qp_info->full_print;

	__snprintf(buf, bsize, "Valid: %lld\n", RES_QPC_GET_VALID(*res));
	if (strlen(buf) >= bsize)
		return -EFBIG;

	if (!force_read && !RES_QPC_GET_VALID(*res))
		return 0;

	_fsnprintf(buf, bsize, "in work: 0x%llx\n", RES_QPC_GET_IN_WORK(*res));
	_fsnprintf(buf, bsize, "peer WQ gran: 0x%llx\n", RES_QPC_GET_PEER_WQ_GRAN(*res));
	_fsnprintf(buf, bsize, "CQ num: 0x%llx\n", RES_QPC_GET_CQ_NUM(*res));
	__snprintf(buf, bsize, "cyc_idx: 0x%llx\n", RES_QPC_GET_CYCLIC_IDX(*res));
	_fsnprintf(buf, bsize, "encap EN: 0x%llx\n", RES_QPC_GET_ENCAP_ENABLE(*res));
	_fsnprintf(buf, bsize, "encap type: 0x%llx\n", RES_QPC_GET_ENCAP_TYPE(*res));
	__snprintf(buf, bsize, "data MMU BP: 0x%llx\n", RES_QPC_GET_DATA_MMU_BYPASS(*res));
	_fsnprintf(buf, bsize, "Gaudi1 mode: 0x%llx\n", RES_QPC_GET_MOD_GAUDI1(*res));
	_fsnprintf(buf, bsize, "trust level: 0x%llx\n", RES_QPC_GET_TRUST_LEVEL(*res));
	__snprintf(buf, bsize, "expected PSN: 0x%llx\n", RES_QPC_GET_EXPECTED_PSN(*res));
	_fsnprintf(buf, bsize, "sched Q: 0x%llx\n", RES_QPC_GET_SCHD_Q_NUM(*res));
	_fsnprintf(buf, bsize, "peer QP: 0x%llx\n", RES_QPC_GET_PEER_QP(*res));
	__snprintf(buf, bsize, "ASID: 0x%llx\n", RES_QPC_GET_ASID(*res));
	_fsnprintf(buf, bsize, "transport service: 0x%llx\n", RES_QPC_GET_TRANSPORT_SERVICE(*res));
	_fsnprintf(buf, bsize, "ECN count: 0x%llx\n", RES_QPC_GET_ECN_COUNT(*res));
	__snprintf(buf, bsize, "dst MAC: %04llx%08llx\n", RES_QPC_GET_DST_MAC_MSB(*res),
		   RES_QPC_GET_DST_MAC_LSB(*res));
	__snprintf(buf, bsize, "dst ipv4: 0x%llx\n", RES_QPC_GET_DST_IP(*res));
	_fsnprintf(buf, bsize, "local key: 0x%llx\n", RES_QPC_GET_LKEY(*res));
	_fsnprintf(buf, bsize, "NACK syndrome: 0x%llx\n", RES_QPC_GET_NACK_SYNDROME(*res));
	__snprintf(buf, bsize, "conn state: 0x%llx\n", RES_QPC_GET_CONN_STATE(*res));
	_fsnprintf(buf, bsize, "priority: 0x%llx\n", RES_QPC_GET_PRIORITY(*res));
	_fsnprintf(buf, bsize, "port/lane: 0x%llx\n", RES_QPC_GET_PORT(*res));
	_fsnprintf(buf, bsize, "dest QP: 0x%llx\n", RES_QPC_GET_DESTINATION_QP(*res));

	/* make sure the caller is aware that the buffer it is using is not long enough */
	if (strlen(buf) >= bsize)
		return -EFBIG;

	return 0;
}

int gaudi2_cn_debugfs_qp_read(struct hbl_cn_device *hdev, struct hbl_cn_qp_info *qp_info, char *buf,
			      size_t bsize)
{
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct gaudi2_qpc_requester qpc_req = {};
	struct gaudi2_qpc_responder qpc_res = {};
	struct hbl_cn_port *cn_port;
	u32 port, qpn;
	void *qpc;
	bool req;
	int rc;

	req = qp_info->req;
	port = qp_info->port;
	qpn = qp_info->qpn;

	port_funcs = hdev->asic_funcs->port_funcs;
	cn_port = &hdev->cn_ports[port];
	qpc = req ? (void *)&qpc_req : (void *)&qpc_res;

	if (!hbl_cn_is_port_open(cn_port)) {
		dev_err(hdev->dev,
			"Cannot read port %d QP %d, port is not initialized\n", port, qpn);
		return -EPERM;
	}

	port_funcs->cfg_lock(cn_port);
	rc = gaudi2_cn_qpc_read(cn_port, qpc, qpn, req);
	port_funcs->cfg_unlock(cn_port);
	if (rc)
		return rc;

	__snprintf(buf, bsize, "port %d, qpn %d, req %d:\n", port, qpn, req);
	if (strlen(buf) >= bsize)
		return -EFBIG;

	if (req)
		rc = gaudi2_cn_debugfs_qpc_req_parse(hdev, qp_info, &qpc_req, buf, bsize);
	else
		rc = gaudi2_cn_debugfs_qpc_res_parse(hdev, qp_info, &qpc_res, buf, bsize);

	return rc;
}

static int gaudi2_cn_debugfs_wqe_parse(struct hbl_cn_device *hdev, struct hbl_cn_wqe_info *wqe_info,
				       void *wqe, char *buf, size_t bsize)
{
	struct gaudi2_sq_wqe *sq_wqe;
	struct gaudi2_rq_wqe *rq_wqe;
	u8 i;

	if (wqe_info->tx) {
		i = wqe_info->wqe_idx % TX_WQE_NUM_IN_CLINE;
		sq_wqe = &(((struct gaudi2_sq_wqe *)wqe)[i]);
		__snprintf(buf, bsize, "opcode: 0x%llx\n", TX_WQE_GET_OPCODE(*sq_wqe));
		__snprintf(buf, bsize, "trace event data: 0x%llx\n",
			   TX_WQE_GET_TRACE_EVENT_DATA(*sq_wqe));
		__snprintf(buf, bsize, "trace event: 0x%llx\n", TX_WQE_GET_TRACE_EVENT(*sq_wqe));
		__snprintf(buf, bsize, "WQE index: 0x%llx\n", TX_WQE_GET_WQE_INDEX(*sq_wqe));
		__snprintf(buf, bsize, "reduction opcode: 0x%llx\n",
			   TX_WQE_GET_REDUCTION_OPCODE(*sq_wqe));
		__snprintf(buf, bsize, "SE: 0x%llx\n", TX_WQE_GET_SE(*sq_wqe));
		__snprintf(buf, bsize, "inline: 0x%llx\n", TX_WQE_GET_INLINE(*sq_wqe));
		__snprintf(buf, bsize, "ackreq: 0x%llx\n", TX_WQE_GET_ACKREQ(*sq_wqe));
		__snprintf(buf, bsize, "size: 0x%llx\n", TX_WQE_GET_SIZE(*sq_wqe));
		__snprintf(buf, bsize, "local address LSB: 0x%llx\n",
			   TX_WQE_GET_LOCAL_ADDR_LSB(*sq_wqe));
		__snprintf(buf, bsize, "local address MSB: 0x%llx\n",
			   TX_WQE_GET_LOCAL_ADDR_MSB(*sq_wqe));
		__snprintf(buf, bsize, "remote address LSB: 0x%llx\n",
			   TX_WQE_GET_REMOTE_ADDR_LSB(*sq_wqe));
		__snprintf(buf, bsize, "remote address MSB: 0x%llx\n",
			   TX_WQE_GET_REMOTE_ADDR_MSB(*sq_wqe));
		__snprintf(buf, bsize, "tag: 0x%llx\n", TX_WQE_GET_TAG(*sq_wqe));
		__snprintf(buf, bsize, "remote SOB: 0x%llx\n", TX_WQE_GET_REMOTE_SOB(*sq_wqe));
		__snprintf(buf, bsize, "remote SOB data: 0x%llx\n",
			   TX_WQE_GET_REMOTE_SOB_DATA(*sq_wqe));
		__snprintf(buf, bsize, "SOB command: 0x%llx\n", TX_WQE_GET_SOB_CMD(*sq_wqe));
		__snprintf(buf, bsize, "completion type: 0x%llx\n",
			   TX_WQE_GET_COMPLETION_TYPE(*sq_wqe));
	} else {
		i = wqe_info->wqe_idx % RX_WQE_NUM_IN_CLINE;
		rq_wqe = &(((struct gaudi2_rq_wqe *)wqe)[i]);
		__snprintf(buf, bsize, "opcode: 0x%llx\n", RX_WQE_GET_OPCODE(*rq_wqe));
		__snprintf(buf, bsize, "WQE index: 0x%llx\n", RX_WQE_GET_WQE_INDEX(*rq_wqe));
		__snprintf(buf, bsize, "SOB command: 0x%llx\n", RX_WQE_GET_SOB_CMD(*rq_wqe));
		__snprintf(buf, bsize, "local SOB: 0x%llx\n", RX_WQE_GET_LOCAL_SOB(*rq_wqe));
		__snprintf(buf, bsize, "local SOB data: 0x%llx\n",
			   RX_WQE_GET_LOCAL_SOB_DATA(*rq_wqe));
		__snprintf(buf, bsize, "completion type: 0x%llx\n",
			   RX_WQE_GET_COMPLETION_TYPE(*rq_wqe));
		__snprintf(buf, bsize, "size: 0x%llx\n", RX_WQE_GET_SIZE(*rq_wqe));
		__snprintf(buf, bsize, "tag: 0x%llx\n", RX_WQE_GET_TAG(*rq_wqe));
	}

	/* Make sure the caller is aware that the buffer used isn't big enough */
	if (strlen(buf) >= bsize)
		return -EFBIG;

	return 0;
}

int gaudi2_cn_debugfs_wqe_read(struct hbl_cn_device *hdev, char *buf, size_t bsize)
{
	struct gaudi2_sq_wqe sq_wqe[TX_WQE_NUM_IN_CLINE] = {};
	struct gaudi2_rq_wqe rq_wqe[RX_WQE_NUM_IN_CLINE] = {};
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_wqe_info *wqe_info;
	struct hbl_cn_port *cn_port;
	u32 port, qpn, wqe_idx;
	void *wqe;
	bool tx;
	int rc;

	port_funcs = hdev->asic_funcs->port_funcs;

	/* Get the details of the WQE to read as written by the user via debugfs */
	wqe_info = &hdev->wqe_info;
	tx = wqe_info->tx;
	port = wqe_info->port;
	qpn = wqe_info->qpn;
	wqe_idx = wqe_info->wqe_idx;

	cn_port = &hdev->cn_ports[port];
	wqe = tx ? (void *)&sq_wqe : (void *)&rq_wqe;

	if (!hbl_cn_is_port_open(cn_port)) {
		dev_err(hdev->dev,
			"Cannot read port %d QP %d, port is not initialized\n", port, qpn);
		return -EPERM;
	}

	port_funcs->cfg_lock(cn_port);
	rc = gaudi2_cn_wqe_read(cn_port, wqe, qpn, wqe_idx, tx);
	port_funcs->cfg_unlock(cn_port);
	if (rc)
		goto exit;

	__snprintf(buf, bsize, "port %d, qpn %d, wqe_idx %d, tx %d:\n", port, qpn, wqe_idx, tx);

	rc = gaudi2_cn_debugfs_wqe_parse(hdev, wqe_info, wqe, buf, bsize);

exit:
	return rc;
}

void gaudi2_cn_debugfs_collect_fec_stats(struct hbl_cn_port *cn_port, char *buf, size_t size)
{
	u32 port = cn_port->port;
	u64 data[FEC_STAT_LAST];
	ssize_t len;

	gaudi2_cn_get_mac_fec_stats(cn_port, data);

	len = strlen(buf);
	if ((size - len) <= 1)
		return;

	if (cn_port->pcs_link)
		snprintf(buf + len, size - len,
			 "Port %u: pre_fec_SER: %llue-%llu post_fec_SER: %llue-%llu\n", port,
			 data[FEC_PRE_FEC_SER_INT], data[FEC_PRE_FEC_SER_EXP],
			 data[FEC_POST_FEC_SER_INT], data[FEC_POST_FEC_SER_EXP]);
	else
		snprintf(buf + len, size - len, "Port %u: Link is down\n", port);
}
