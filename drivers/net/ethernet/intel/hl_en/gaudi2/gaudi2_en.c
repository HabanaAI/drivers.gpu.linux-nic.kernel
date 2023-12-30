// SPDX-License-Identifier: GPL-2.0

/* Copyright 2021-2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "gaudi2_en.h"

#include <linux/circ_buf.h>

#define RING_SIZE_MASK(ring)		((ring)->count - 1)

static void req_qpc_init(struct gaudi2_qpc_requester *req_qpc, unsigned int mtu, int last_idx,
			 u32 schedq_num, bool enable)
{
	REQ_QPC_SET_TRANSPORT_SERVICE(*req_qpc, TS_RAW);
	REQ_QPC_SET_LAST_IDX(*req_qpc, last_idx);
	REQ_QPC_SET_WQ_TYPE(*req_qpc, 1);
	REQ_QPC_SET_WQ_BASE_ADDR(*req_qpc, 0);
	REQ_QPC_SET_MTU(*req_qpc, mtu);
	REQ_QPC_SET_REMOTE_WQ_LOG_SZ(*req_qpc, 1);
	REQ_QPC_SET_VALID(*req_qpc, (u64)enable);
	REQ_QPC_SET_TRUST_LEVEL(*req_qpc, SECURED);
	REQ_QPC_SET_PORT(*req_qpc, 0);
	REQ_QPC_SET_DATA_MMU_BYPASS(*req_qpc, 1);
	REQ_QPC_SET_BURST_SIZE(*req_qpc, 1);
	REQ_QPC_SET_SCHD_Q_NUM(*req_qpc, schedq_num);
	/* Due to a HW bug, backpressure is indicated on the ETH QP after some time. In order to
	 * avoid the BP message being sent, set the QP as backpressured to begin with. This will
	 * have no further impact, as the BP mechanism is assoicated with RDMA only.
	 */
	REQ_QPC_SET_WQ_BACK_PRESSURE(*req_qpc, 1);
}

static void res_qpc_init(struct gaudi2_qpc_responder *res_qpc, u32 raw_qpn, u32 schedq_num,
			 bool enable)
{
	RES_QPC_SET_TRANSPORT_SERVICE(*res_qpc, TS_RAW);
	RES_QPC_SET_VALID(*res_qpc, (u64)enable);
	RES_QPC_SET_TRUST_LEVEL(*res_qpc, SECURED);
	RES_QPC_SET_PORT(*res_qpc, 0);
	RES_QPC_SET_CQ_NUM(*res_qpc, raw_qpn);
	RES_QPC_SET_DATA_MMU_BYPASS(*res_qpc, 1);
	RES_QPC_SET_SCHD_Q_NUM(*res_qpc, schedq_num);
}

static int gaudi2_en_read_pkt_from_hw(struct hl_en_port *port, void **pkt_addr, u32 *pkt_size)
{
	struct gaudi2_en_port *gaudi2_port = port->asic_specific;
	struct hl_en_device *hdev = port->hdev;
	struct hl_cn_ring *rx_ring, *cq_ring;
	enum hl_en_eth_pkt_status pkt_status;
	struct gaudi2_en_aux_ops *aux_ops;
	struct gaudi2_en_device *gaudi2;
	struct hl_aux_dev *aux_dev;
	u32 port_idx = port->idx;
	struct gaudi2_cqe *cqe_p;
	u32 pi, size, wqe_idx;

	gaudi2 = hdev->asic_specific;
	aux_ops = gaudi2->aux_ops;
	aux_dev = hdev->aux_dev;

	rx_ring = gaudi2_port->rx_ring;
	cq_ring = gaudi2_port->cq_ring;

	/* check if packet is available by reading the PI */
	if (cq_ring->ci_shadow == cq_ring->pi_shadow) {
		pi = *((u32 *)RING_PI_ADDRESS(cq_ring));
		if (pi == cq_ring->pi_shadow)
			return ETH_PKT_NONE;

		cq_ring->pi_shadow = pi;
	}

	cqe_p = (struct gaudi2_cqe *)RING_BUF_ADDRESS(cq_ring) +
		(cq_ring->ci_shadow & RING_SIZE_MASK(cq_ring));

	if (!CQE_IS_VALID(cqe_p)) {
		dev_warn_ratelimited(hdev->dev, "Port-%d got invalid CQE on CQ\n", port_idx);
		return ETH_PKT_DROP;
	}

	pkt_status = ETH_PKT_OK;

	/* wqe index will point to the buffer consumed by HW */
	wqe_idx = CQE_WQE_IDX(cqe_p) & RING_SIZE_MASK(rx_ring);
	size = CQE_RAW_PKT_SIZE(cqe_p);

	/* Since CQE is valid, SW must consume it, even if packet would eventually be dropped. */
	if (size > hdev->max_frm_len || size == 0) {
		dev_warn_ratelimited(hdev->dev, "Port-%d got invalid packet size %u\n",
				     port_idx, size);
		pkt_status = ETH_PKT_DROP;
	}

	*pkt_addr = RING_BUF_ADDRESS(rx_ring) + wqe_idx * hdev->raw_elem_size;
	*pkt_size = size;

	cq_ring->ci_shadow++;

	/* Mark the CQ-entry is not valid */
	CQE_SET_INVALID(cqe_p);

	/* inform the HW with our current CI */
	aux_ops->write_rx_ci(aux_dev, port_idx, cq_ring->ci_shadow);

	return pkt_status;
}

static int gaudi2_en_get_rx_ring_size(struct hl_en_port *port)
{
	struct gaudi2_en_port *gaudi2_port = port->asic_specific;
	struct hl_cn_ring *rx_ring;

	rx_ring = gaudi2_port->rx_ring;

	return RING_SIZE_MASK(rx_ring);
}

static void gaudi2_en_configure_cq(struct hl_en_port *port, bool enable)
{
	struct hl_en_device *hdev = port->hdev;
	struct gaudi2_en_aux_ops *aux_ops;
	struct gaudi2_en_device *gaudi2;
	struct hl_aux_dev *aux_dev;
	u32 port_idx = port->idx;

	gaudi2 = hdev->asic_specific;
	aux_ops = gaudi2->aux_ops;
	aux_dev = hdev->aux_dev;

	/* if rx_coalesce_usecs is 0 then timer should be disabled */
	aux_ops->configure_cq(aux_dev, port_idx, port->rx_coalesce_usecs,
			      port->rx_coalesce_usecs ? enable : false);
}

static void gaudi2_en_arm_cq(struct hl_en_port *port)
{
	struct gaudi2_en_port *gaudi2_port = port->asic_specific;
	struct hl_en_device *hdev = port->hdev;
	struct gaudi2_en_aux_ops *aux_ops;
	struct gaudi2_en_device *gaudi2;
	struct hl_aux_dev *aux_dev;
	u32 port_idx = port->idx;

	gaudi2 = hdev->asic_specific;
	aux_ops = gaudi2->aux_ops;
	aux_dev = hdev->aux_dev;

	/* The trigger happens only when PI > IDX, therefore subtract 1 from arming index */
	aux_ops->arm_cq(aux_dev, port_idx,
			gaudi2_port->cq_ring->ci_shadow + port->rx_max_coalesced_frames - 1);
}

static int gaudi2_en_set_coalesce(struct hl_en_port *port)
{
	struct hl_en_device *hdev = port->hdev;
	struct hl_en_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;
	u32 port_idx = port->idx;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	if (!aux_ops->is_port_open(aux_dev, port_idx))
		return 0;

	gaudi2_en_configure_cq(port, port->is_initialized);
	gaudi2_en_arm_cq(port);

	return 0;
}

static int gaudi2_en_config_qp(struct hl_en_port *port, bool enable)
{
	struct gaudi2_en_port *gaudi2_port = port->asic_specific;
	struct hl_en_device *hdev = gaudi2_port->hdev;
	struct gaudi2_qpc_requester req_qpc = {};
	struct gaudi2_qpc_responder res_qpc = {};
	struct gaudi2_en_aux_data *aux_data;
	u32 port_idx, raw_qpn, schedq_num;
	struct gaudi2_en_device *gaudi2;
	struct hl_en_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;
	struct qpc_mask mask = {};
	int last_idx, rc;
	unsigned int mtu;

	gaudi2 = hdev->asic_specific;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	aux_data = gaudi2->aux_data;
	port_idx = gaudi2_port->idx;
	raw_qpn = aux_data->raw_qpn;
	schedq_num = aux_data->schedq_num;
	mtu = port->ndev->mtu + HL_EN_MAX_HEADERS_SZ;

	/* Need to configure the log of the MTU value minus 1KB as this is the minimum valid MTU.
	 * If the MTU value is not a power of 2, use the next possible value.
	 */
	mtu = __fls(mtu) - 10 + !is_power_of_2(mtu);

	last_idx = gaudi2_port->wq_ring->count - 1;

	if (!enable) {
		rc = aux_ops->eq_dispatcher_unregister_qp(aux_dev, port_idx, raw_qpn);
		if (rc) {
			netdev_err(port->ndev, "Failed to unregister QP, %d\n", rc);
			return rc;
		}

		REQ_QPC_SET_VALID(mask, 1);
		rc = aux_ops->qpc_write(aux_dev, port_idx, &req_qpc, &mask, raw_qpn, true);
		if (rc) {
			netdev_err(port->ndev, "Failed to configure requester QP, %d\n", rc);
			return rc;
		}

		memset(&mask, 0, sizeof(mask));
		RES_QPC_SET_VALID(mask, 1);
		rc = aux_ops->qpc_write(aux_dev, port_idx, &res_qpc, &mask, raw_qpn, false);
		if (rc)
			netdev_err(port->ndev, "Failed to configure responder QP, %d\n", rc);

		return rc;
	}

	memset(&res_qpc, 0, sizeof(res_qpc));
	res_qpc_init(&res_qpc, raw_qpn, schedq_num, enable);
	rc = aux_ops->qpc_write(aux_dev, port_idx, &res_qpc, NULL, raw_qpn, false);
	if (rc) {
		netdev_err(port->ndev, "Failed to configure responder QP, %d\n", rc);
		goto qp_register_fail;
	}

	memset(&req_qpc, 0, sizeof(req_qpc));
	req_qpc_init(&req_qpc, mtu, last_idx, schedq_num, enable);
	rc = aux_ops->qpc_write(aux_dev, port_idx, &req_qpc, NULL, raw_qpn, true);
	if (rc) {
		netdev_err(port->ndev, "Failed to configure requester QP, %d\n", rc);
		goto qp_register_fail;
	}

	rc = aux_ops->eq_dispatcher_register_qp(aux_dev, port_idx, aux_data->kernel_asid, raw_qpn);
	if (rc) {
		netdev_err(port->ndev, "Failed to register QP, %d\n", rc);
		goto qp_register_fail;
	}

	return 0;

qp_register_fail:
	memset(&res_qpc, 0, sizeof(res_qpc));
	RES_QPC_SET_VALID(res_qpc, 0);
	aux_ops->qpc_write(aux_dev, port_idx, &res_qpc, NULL, raw_qpn, false);
	memset(&req_qpc, 0, sizeof(req_qpc));
	REQ_QPC_SET_VALID(req_qpc, 0);
	aux_ops->qpc_write(aux_dev, port_idx, &req_qpc, NULL, raw_qpn, true);

	return rc;
}

static void gaudi2_en_tx_done(struct gaudi2_en_port *gaudi2_port, struct hl_cn_eqe *eqe_p)
{
	u32 port_idx, raw_qpn, handled_ci, pi, previous_pi;
	struct hl_en_device *hdev = gaudi2_port->hdev;
	struct gaudi2_en_aux_data *asic_aux_data;
	struct hl_en_aux_data *aux_data;
	struct gaudi2_en_tx_buf *tx_buf;
	struct hl_aux_dev *aux_dev;
	struct net_device *ndev;

	port_idx = gaudi2_port->idx;
	ndev = hdev->ports[port_idx].ndev;
	aux_dev = hdev->aux_dev;
	aux_data = aux_dev->aux_data;
	asic_aux_data = aux_data->asic_specific;
	raw_qpn = asic_aux_data->raw_qpn;

	if (EQE_RAW_TX_EVENT_QPN(eqe_p) != raw_qpn) {
		netdev_warn(ndev, "tx-done: port %d got wrong QP (%d vs %d); ignoring",
			    gaudi2_port->idx, EQE_RAW_TX_EVENT_QPN(eqe_p), raw_qpn);
		return;
	}

	if (EQE_RAW_TX_EVENT_IDX(eqe_p) >= asic_aux_data->tx_ring_len) {
		netdev_err(ndev, "tx-done: port %d got invalid WQE index (%d max %d); ignoring",
			   gaudi2_port->idx, EQE_RAW_TX_EVENT_IDX(eqe_p),
			   asic_aux_data->tx_ring_len - 1);
		return;
	}

	/* Check if the index we got is in the current data bounds (indicated by the CI and PI).
	 * The out of bounds region is [PI,CI-1] circulary
	 */
	pi = gaudi2_port->tx_buf_info_pi;
	previous_pi = CIRC_CNT(pi, 1, asic_aux_data->tx_ring_len);

	if (CIRC_CNT(previous_pi, EQE_RAW_TX_EVENT_IDX(eqe_p), asic_aux_data->tx_ring_len) >=
	    CIRC_CNT(pi, gaudi2_port->tx_buf_info_ci, asic_aux_data->tx_ring_len)) {
		dev_warn_ratelimited(hdev->dev,
				     "tx-done: port %d got stale WQE index (expecting values between 0x%x to 0x%x, got 0x%x); ignoring",
				     gaudi2_port->idx, gaudi2_port->tx_buf_info_ci,
				     pi, EQE_RAW_TX_EVENT_IDX(eqe_p));
		return;
	}

	/* Handle all entries up to the entry reported in the event */
	do {
		tx_buf = gaudi2_port->tx_buf_info + gaudi2_port->tx_buf_info_ci;
		if (!tx_buf->skb) {
			dev_warn_ratelimited(hdev->dev,
					     "Port-%d attempted to free a NULL element in TX ring (ci 0x%x, pi 0x%x, idx 0x%x)\n",
					     gaudi2_port->idx, gaudi2_port->tx_buf_info_ci, pi,
					     EQE_RAW_TX_EVENT_IDX(eqe_p));
			return;
		}
		hl_en_dma_unmap(hdev, tx_buf->dma_addr, tx_buf->len);
		dev_consume_skb_any(tx_buf->skb);

		tx_buf->skb = NULL;
		handled_ci = gaudi2_port->tx_buf_info_ci;
		gaudi2_port->tx_buf_info_ci =
			(gaudi2_port->tx_buf_info_ci + 1) & (asic_aux_data->tx_ring_len - 1);
	} while (EQE_RAW_TX_EVENT_IDX(eqe_p) != handled_ci);

	/* No need to check for fifo space because if queue was stopped then fifo has room by now
	 * as it cleaned within a device cycle.
	 */
	if (netif_queue_stopped(ndev))
		netif_wake_queue(ndev);
}

static u32 gaudi2_en_get_overrun_cnt(struct hl_aux_dev *aux_dev, u32 port_idx)
{
	struct hl_en_port *port = HL_EN_PORT(aux_dev, port_idx);
	struct gaudi2_en_port *gaudi2_port;

	gaudi2_port = port->asic_specific;

	return gaudi2_port->fifo_overrun_err_cnt;
}

static void gaudi2_en_handle_eqe(struct hl_aux_dev *aux_dev, u32 port_idx, struct hl_cn_eqe *eqe)
{
	struct hl_en_port *port = HL_EN_PORT(aux_dev, port_idx);
	u32 event_type = EQE_TYPE(eqe), qp, synd;
	struct hl_en_device *hdev = port->hdev;
	struct gaudi2_en_aux_ops *asic_aux_ops;
	struct gaudi2_en_port *gaudi2_port;
	struct hl_en_aux_ops *aux_ops;

	gaudi2_port = port->asic_specific;
	aux_ops = hdev->aux_dev->aux_ops;
	asic_aux_ops = aux_ops->asic_ops;

	if (!EQE_IS_VALID(eqe)) {
		dev_warn_ratelimited(hdev->dev, "Port-%d got invalid EQE on EQ!\n", port_idx);
		return;
	}

	switch (event_type) {
	case EQE_COMP_ERR:
		dev_warn_ratelimited(hdev->dev, "Port-%d cq-err event CQ:%d PI:0x%x\n",
				     port_idx, EQE_CQ_EVENT_CQ_NUM(eqe), EQE_CQ_EVENT_PI(eqe));

		atomic64_inc(&port->net_stats.rx_dropped);
		/* CQ is configured to generate BP on such cases hence we just need to handle
		 * the packets in the Rx buffer
		 */
		fallthrough;
	case EQE_COMP:
		if (!hdev->poll_enable) {
			/* napi_schedule() eventually calls __raise_softirq_irqoff() which sets the
			 * net Rx softirq to run. Since we are in thread context here, the pending
			 * softirq flag won't be checked and the Rx softirq won't be invoked. Hence
			 * we need to use the bh_disable/enable pair to invoke it.
			 */
			local_bh_disable();
			napi_schedule(&port->napi);
			local_bh_enable();
		} else {
			hl_en_rx_poll_start(port);
		}
		break;
	case EQE_RAW_TX_COMP:
		gaudi2_en_tx_done(gaudi2_port, eqe);
		break;
	case EQE_QP_ERR:
		synd = EQE_QP_EVENT_ERR_SYND(eqe);
		qp = EQE_QP_EVENT_QPN(eqe);
		dev_err_ratelimited(hdev->dev, "Port-%d qp-err event QP:%d err:%d %s\n", port_idx,
				    qp, synd, asic_aux_ops->qp_err_syndrome_to_str(synd));

		/* In case of QP error we need to reset the port. We are calling the "locked"
		 * version of that function since the port->control_lock has been already
		 * taken at the beginning of the EQ handler.
		 */
		dev_err_ratelimited(hdev->dev, "Going to reset port %d\n", port_idx);
		aux_ops->track_ext_port_reset(aux_dev, port_idx, synd);
		hl_en_port_reset_locked(aux_dev, port_idx);
		break;
	case EQE_DB_FIFO_OVERRUN:
		dev_warn_ratelimited(hdev->dev, "Port-%d db-fifo overrun event\n", port_idx);
		gaudi2_port->fifo_overrun_err_cnt++;
		atomic64_inc(&port->net_stats.tx_dropped);
		break;
	default:
		dev_warn_ratelimited(hdev->dev, "Port-%d unsupported event type: %d", port_idx,
				     event_type);
		break;
	}
}

static void gaudi2_en_check_wake_queue(struct gaudi2_en_port *gaudi2_port, struct net_device *ndev,
				       u32 tx_ring_len)
{
	u32 space_left_in_qp;

	/* Wake queue to avoid queue deadlock in case of the following race condition:
	 * 1. space_left_in_qp or space_left_in_db_fifo equal to zero.
	 * 2. tx_done thread (on a different CPU) consume all skbs, i.e.:
	 *    space_left_in_qp == (tx_ring_len - 1).
	 * 3. netif_stop_queue is called due to 1., and no pending tx_done events due to 2. so
	 *    netif_wake_queue will never be called again.
	 */
	space_left_in_qp = CIRC_SPACE(gaudi2_port->tx_buf_info_pi, gaudi2_port->tx_buf_info_ci,
				      tx_ring_len);
	if (space_left_in_qp == (tx_ring_len - 1))
		netif_wake_queue(ndev);
}

static netdev_tx_t gaudi2_en_write_pkt_to_hw(struct hl_en_port *port, struct sk_buff *skb)
{
	u32 port_idx, tx_buf_info_pi, pi, space_left_in_qp, wq_ring_pi;
	struct gaudi2_en_port *gaudi2_port = port->asic_specific;
	struct hl_en_device *hdev = gaudi2_port->hdev;
	struct gaudi2_en_aux_data *asic_aux_data;
	struct gaudi2_en_aux_ops *aux_ops;
	struct hl_en_aux_data *aux_data;
	struct gaudi2_en_device *gaudi2;
	struct gaudi2_sq_wqe *wqe_p;
	struct hl_cn_ring *wq_ring;
	bool db_fifo_full_after_tx;
	struct hl_aux_dev *aux_dev;
	dma_addr_t dma_addr;
	int rc;

	/* write_pkt_to_hw() can't fail due to overflow of tx queue, since the number of free
	 * descriptors in the queue is checked after sending the previous packet. In case there
	 * isn't enough space in the queue for the next packet, it is stopped until there is again
	 * enough available space in the queue.
	 *
	 * In case of threaded_tx we might reach here on a pending work queue thread while
	 * previous thread called netif_stop_queue so no need to stop queue again.
	 */
	if (hdev->is_threaded_tx && netif_queue_stopped(skb->dev))
		goto threaded_tx_err_exit;

	tx_buf_info_pi = gaudi2_port->tx_buf_info_pi;
	port_idx = port->idx;
	gaudi2 = hdev->asic_specific;
	aux_ops = gaudi2->aux_ops;
	aux_dev = hdev->aux_dev;
	aux_data = aux_dev->aux_data;
	asic_aux_data = aux_data->asic_specific;
	wq_ring = gaudi2_port->wq_ring;

	dma_addr = hl_en_dma_map(hdev, skb->data, skb->len);
	if (unlikely(dma_mapping_error(hdev->dev, dma_addr))) {
		dev_err_ratelimited(hdev->dev, "port %d failed to map DMA address\n", port_idx);
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	gaudi2_port->tx_buf_info[tx_buf_info_pi].dma_addr = dma_addr;
	gaudi2_port->tx_buf_info[tx_buf_info_pi].skb = skb;
	gaudi2_port->tx_buf_info[tx_buf_info_pi].len = skb->len;
	gaudi2_port->tx_buf_info_pi = (tx_buf_info_pi + 1) & (asic_aux_data->tx_ring_len - 1);

	/* point on the next WQE */
	pi = wq_ring->pi_shadow;
	wq_ring_pi = (wq_ring->pi_shadow + 1) & (wq_ring->count - 1);

	wqe_p = (struct gaudi2_sq_wqe *)RING_BUF_ADDRESS(wq_ring) + pi;
	memset(wqe_p, 0, sizeof(*wqe_p));

	/* for ethernet only, turn on the solicite event bit */
	CFG_SQ_WQE_RESET(wqe_p);
	CFG_SQ_WQE_OPCODE(wqe_p, WQE_LINEAR);
	CFG_SQ_WQE_INDEX(wqe_p, pi & 0xff);
	CFG_SQ_WQE_INLINE(wqe_p, 0);
	CFG_SQ_WQE_LOCAL_ADDRESS(wqe_p, dma_addr);
	CFG_SQ_WQE_SIZE(wqe_p, (u64)skb->len);
	CFG_SQ_WQE_SOL_EVENT(wqe_p, (pi % port->tx_max_coalesced_frames) ? 0 : 1);

	/* make sure data is filled before ringing the db */
	mb();

	/* Ring doorbell */
	rc = aux_ops->ring_tx_doorbell(aux_dev, port_idx, wq_ring_pi, &db_fifo_full_after_tx);
	if (rc) {
		/* Fifo is full, revert indices, unmap the skb, stop queue and return the error. */
		gaudi2_port->tx_buf_info_pi = tx_buf_info_pi;
		hl_en_dma_unmap(hdev, dma_addr, skb->len);
		gaudi2_port->tx_buf_info[tx_buf_info_pi].skb = NULL;

		netdev_dbg(port->ndev, "port: %d stop queue due to full fifo - packet not sent\n",
			   port_idx);
		netif_stop_queue(skb->dev);

		gaudi2_en_check_wake_queue(gaudi2_port, skb->dev, asic_aux_data->tx_ring_len);

		if (hdev->is_threaded_tx)
			goto threaded_tx_err_exit;

		return NETDEV_TX_BUSY;
	}

	wq_ring->pi_shadow = wq_ring_pi;

	/* Check if we have enough space on the QP-WQ for the next xmit. */
	space_left_in_qp = CIRC_SPACE(gaudi2_port->tx_buf_info_pi, gaudi2_port->tx_buf_info_ci,
				      asic_aux_data->tx_ring_len);
	if (!space_left_in_qp || db_fifo_full_after_tx) {
		netdev_dbg(port->ndev, "port: %d stop queue due to full %s\n", port_idx,
			   db_fifo_full_after_tx ? "fifo" : "WQ");
		netif_stop_queue(skb->dev);

		gaudi2_en_check_wake_queue(gaudi2_port, skb->dev, asic_aux_data->tx_ring_len);
	}

	return NETDEV_TX_OK;

threaded_tx_err_exit:
	/* in threaded TX we (eventually) return success which will cause the SKB not to be
	 * freed so we need to free it here.
	 */
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static int gaudi2_en_port_open(struct hl_en_port *port)
{
	struct gaudi2_en_port *gaudi2_port = port->asic_specific;
	struct hl_cn_ring *wq_ring, *cq_ring;
	int rc;

	/* Reset Tx ring shadow PI/CI */
	wq_ring = gaudi2_port->wq_ring;
	wq_ring->pi_shadow = 0;
	wq_ring->ci_shadow = 0; /* Unused */

	/* Reset SW Tx buffer PI/CI */
	gaudi2_port->tx_buf_info_pi = 0;
	gaudi2_port->tx_buf_info_ci = 0;

	/* Reset FIFO overrun error counter */
	gaudi2_port->fifo_overrun_err_cnt = 0;

	/* Reset CQ ring HW PI and shadow PI/CI */
	cq_ring = gaudi2_port->cq_ring;
	*((u32 *)RING_PI_ADDRESS(cq_ring)) = 0;
	cq_ring->pi_shadow = 0;
	cq_ring->ci_shadow = 0;

	rc = gaudi2_en_config_qp(port, true);
	if (rc) {
		netdev_warn(port->ndev, "Failed to configure QPs, %d\n", rc);
		return rc;
	}

	/* We would need the CQ-ARM for both polling and NAPI flows. This is because, even in
	 * polling mode, we would start the Rx Poll only upon the CQ-ARM event triggering the EQ
	 * for Rx completion.
	 */
	gaudi2_en_configure_cq(port, true);
	gaudi2_en_arm_cq(port);

	return 0;
}

static void gaudi2_en_db_fifo_reset(struct gaudi2_en_port *gaudi2_port)
{
	struct hl_en_device *hdev = gaudi2_port->hdev;
	struct gaudi2_en_aux_ops *asic_aux_ops;
	struct hl_en_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	asic_aux_ops = aux_ops->asic_ops;

	asic_aux_ops->db_fifo_reset(aux_dev, gaudi2_port->idx);
}

static void gaudi2_en_flush_tx_buffer(struct gaudi2_en_port *gaudi2_port)
{
	struct hl_en_device *hdev = gaudi2_port->hdev;
	struct gaudi2_en_aux_data *asic_aux_data;
	struct hl_en_aux_data *aux_data;
	struct gaudi2_en_tx_buf *tx_buf;
	struct hl_aux_dev *aux_dev;
	u32 ci, pi;

	aux_dev = hdev->aux_dev;
	aux_data = aux_dev->aux_data;
	asic_aux_data = aux_data->asic_specific;
	ci = gaudi2_port->tx_buf_info_ci;
	pi = gaudi2_port->tx_buf_info_pi;

	while (ci != pi) {
		tx_buf = &gaudi2_port->tx_buf_info[ci];
		hl_en_dma_unmap(hdev, tx_buf->dma_addr, tx_buf->len);
		dev_kfree_skb_any(tx_buf->skb);

		ci = (ci + 1) & (asic_aux_data->tx_ring_len - 1);
	}

	gaudi2_port->tx_buf_info_ci = ci;
}

static void gaudi2_en_port_close(struct hl_en_port *port)
{
	struct gaudi2_en_port *gaudi2_port = port->asic_specific;
	int rc;

	gaudi2_en_configure_cq(port, false);

	/* disable ETH Rx/Tx in H/W */
	rc = gaudi2_en_config_qp(port, false);
	if (rc)
		netdev_warn(port->ndev, "Failed to destroy QPs, %d\n", rc);

	gaudi2_en_db_fifo_reset(gaudi2_port);

	/* Discard skbs safely from tx_buf as we won't get the tx_done call from the EQ now that the
	 * port is closed.
	 */
	gaudi2_en_flush_tx_buffer(gaudi2_port);
}

static int gaudi2_en_dev_init(struct hl_en_device *hdev)
{
	struct hl_aux_dev *aux_dev = hdev->aux_dev;
	struct gaudi2_en_port *gaudi2_port, *ports;
	struct gaudi2_en_aux_data *asic_aux_data;
	struct gaudi2_en_aux_ops *asic_aux_ops;
	struct hl_en_aux_data *aux_data;
	struct gaudi2_en_device *gaudi2;
	struct hl_en_aux_ops *aux_ops;
	int i, rc = 0, ports_cnt = 0;
	struct hl_en_port *port;
	u32 tx_ring_size;

	aux_data = aux_dev->aux_data;
	asic_aux_data = aux_data->asic_specific;
	aux_ops = aux_dev->aux_ops;
	asic_aux_ops = aux_ops->asic_ops;

	gaudi2 = kzalloc(sizeof(*gaudi2), GFP_KERNEL);
	if (!gaudi2)
		return -ENOMEM;

	ports = kcalloc(hdev->max_num_of_ports, sizeof(*ports), GFP_KERNEL);
	if (!ports) {
		rc = -ENOMEM;
		goto ports_alloc_fail;
	}

	tx_ring_size = asic_aux_data->tx_ring_len * sizeof(struct gaudi2_en_tx_buf);

	for (i = 0; i < hdev->max_num_of_ports; i++, ports_cnt++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		gaudi2_port = &ports[i];
		gaudi2_port->tx_buf_info = kzalloc(tx_ring_size, GFP_KERNEL);
		if (!gaudi2_port->tx_buf_info) {
			rc = -ENOMEM;
			goto ports_init_fail;
		}

		gaudi2_port->idx = i;
		gaudi2_port->hdev = hdev;
		gaudi2_port->rx_ring = asic_aux_data->rx_rings[i];
		gaudi2_port->cq_ring = asic_aux_data->cq_rings[i];
		gaudi2_port->wq_ring = asic_aux_data->wq_rings[i];
		port = &hdev->ports[i];
		port->asic_specific = gaudi2_port;
	}

	asic_aux_ops->port_reset_locked = hl_en_port_reset_locked;
	asic_aux_ops->get_overrun_cnt = gaudi2_en_get_overrun_cnt;

	gaudi2->ports = ports;
	gaudi2->aux_data = asic_aux_data;
	gaudi2->aux_ops = asic_aux_ops;

	hdev->asic_specific = gaudi2;

	/* Due to a H/W bug that even ports' link-up event arrives to the odd ports' EQ, we can't
	 * avoid obsolete events to arrive once the port is up again by flushing the H/W EQ.
	 * Instead we sleep to allows the obsolete events to be dropped while the port is closed.
	 * In hard reset flow we flush the EQ so the below doesn't needed.
	 */
	hdev->sleep_after_port_close = true;

	hdev->pad_size = gaudi2->aux_data->pad_size;

	return 0;

ports_init_fail:
	for (i = 0; i < ports_cnt; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		gaudi2_port = &ports[i];
		kfree(gaudi2_port->tx_buf_info);
	}

	kfree(ports);
ports_alloc_fail:
	kfree(gaudi2);

	return rc;
}

static void gaudi2_en_dev_fini(struct hl_en_device *hdev)
{
	struct gaudi2_en_device *gaudi2 = hdev->asic_specific;
	struct gaudi2_en_port *gaudi2_port;
	int i;

	if (!gaudi2)
		return;

	for (i = 0; i < hdev->max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		gaudi2_port = &gaudi2->ports[i];
		kfree(gaudi2_port->tx_buf_info);
	}

	kfree(gaudi2->ports);
	kfree(gaudi2);
}

void gaudi2_en_set_asic_funcs(struct hl_en_device *hdev)
{
	struct hl_en_asic_funcs *asic_funcs = &hdev->asic_funcs;

	asic_funcs->dev_init = gaudi2_en_dev_init;
	asic_funcs->dev_fini = gaudi2_en_dev_fini;
	asic_funcs->eth_port_open = gaudi2_en_port_open;
	asic_funcs->eth_port_close = gaudi2_en_port_close;
	asic_funcs->reenable_rx_irq = gaudi2_en_arm_cq;
	asic_funcs->write_pkt_to_hw = gaudi2_en_write_pkt_to_hw;
	asic_funcs->read_pkt_from_hw = gaudi2_en_read_pkt_from_hw;
	asic_funcs->get_pfc_cnts = gaudi2_en_dcbnl_get_pfc_cnts;
	asic_funcs->set_coalesce = gaudi2_en_set_coalesce;
	asic_funcs->get_rx_ring_size = gaudi2_en_get_rx_ring_size;
	asic_funcs->handle_eqe = gaudi2_en_handle_eqe;
}
