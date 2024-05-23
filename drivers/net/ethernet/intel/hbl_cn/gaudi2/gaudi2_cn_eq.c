// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#include <linux/pci.h>

#include "gaudi2_cn.h"

#define GAUDI2_NIC_MAX_STRING_LEN	64

static const char
gaudi2_cn_eq_irq_name[NIC_NUMBER_OF_ENGINES][GAUDI2_NIC_MAX_STRING_LEN] = {
	"gaudi2 cn0 qpc0 EQ",
	"gaudi2 cn0 qpc1 EQ",
	"gaudi2 cn1 qpc0 EQ",
	"gaudi2 cn1 qpc1 EQ",
	"gaudi2 cn2 qpc0 EQ",
	"gaudi2 cn2 qpc1 EQ",
	"gaudi2 cn3 qpc0 EQ",
	"gaudi2 cn3 qpc1 EQ",
	"gaudi2 cn4 qpc0 EQ",
	"gaudi2 cn4 qpc1 EQ",
	"gaudi2 cn5 qpc0 EQ",
	"gaudi2 cn5 qpc1 EQ",
	"gaudi2 cn6 qpc0 EQ",
	"gaudi2 cn6 qpc1 EQ",
	"gaudi2 cn7 qpc0 EQ",
	"gaudi2 cn7 qpc1 EQ",
	"gaudi2 cn8 qpc0 EQ",
	"gaudi2 cn8 qpc1 EQ",
	"gaudi2 cn9 qpc0 EQ",
	"gaudi2 cn9 qpc1 EQ",
	"gaudi2 cn10 qpc0 EQ",
	"gaudi2 cn10 qpc1 EQ",
	"gaudi2 cn11 qpc0 EQ",
	"gaudi2 cn11 qpc1 EQ",
};

/* Event queues for all the ports are initialized ahead of port-specific initialization regardless
 * of being enabled or not. We do the same for their IRQs.
 */
static irqreturn_t gaudi2_cn_eq_threaded_isr(int irq, void *arg);

int gaudi2_cn_eq_request_irqs(struct hbl_cn_device *hdev)
{
	struct gaudi2_cn_device *gaudi2 = hdev->asic_specific;
	struct gaudi2_cn_port *gaudi2_port;
	int i, rc, irq;

	if (!gaudi2->msix_enabled)
		return 0;

	/* IRQs should be allocated if polling activity is only temporal */
	if (hdev->poll_enable && !gaudi2->temporal_polling)
		return 0;

	for (i = 0; i < NIC_NUMBER_OF_PORTS; i++) {
		gaudi2_port = &gaudi2->cn_ports[i];
		irq = pci_irq_vector(hdev->pdev, gaudi2->irq_num_port_base + i);
		rc = request_threaded_irq(irq, NULL, gaudi2_cn_eq_threaded_isr, IRQF_ONESHOT,
					  gaudi2_cn_eq_irq_name[i], gaudi2_port);
		if (rc) {
			dev_err(hdev->dev, "Failed to request IRQ %d for port %d\n", irq, i);
			goto irq_fail;
		}
	}

	return 0;

irq_fail:
	for (i--; i >= 0; i--) {
		gaudi2_port = &gaudi2->cn_ports[i];
		irq = pci_irq_vector(hdev->pdev, gaudi2->irq_num_port_base + i);
		free_irq(irq, gaudi2_port);
	}
	return rc;
}

void gaudi2_cn_eq_sync_irqs(struct hbl_cn_device *hdev)
{
	struct gaudi2_cn_device *gaudi2 = hdev->asic_specific;
	int i, irq;

	if (!gaudi2->msix_enabled)
		return;

	/* IRQs are allocated if polling is temporal so return only if polling mode is constant */
	if (hdev->poll_enable && !gaudi2->temporal_polling)
		return;

	for (i = 0; i < NIC_NUMBER_OF_PORTS; i++) {
		irq = pci_irq_vector(hdev->pdev, gaudi2->irq_num_port_base + i);
		synchronize_irq(irq);
	}
}

void gaudi2_cn_eq_free_irqs(struct hbl_cn_device *hdev)
{
	struct gaudi2_cn_device *gaudi2 = hdev->asic_specific;
	struct gaudi2_cn_port *gaudi2_port;
	int i, irq;

	if (!gaudi2->msix_enabled)
		return;

	/* IRQs are allocated if polling is temporal so return only if polling mode is constant */
	if (hdev->poll_enable && !gaudi2->temporal_polling)
		return;

	for (i = 0; i < NIC_NUMBER_OF_PORTS; i++) {
		gaudi2_port = &gaudi2->cn_ports[i];
		irq = pci_irq_vector(hdev->pdev, gaudi2->irq_num_port_base + i);
		free_irq(irq, gaudi2_port);
	}
}

/* HW per port link/lane status mask */
static u32 gaudi2_cn_get_link_status_mask(struct gaudi2_cn_port *gaudi2_port)
{
	switch (gaudi2_port->cn_port->speed) {
	case SPEED_50000:
		/* In 50GbE mode, HW supports up to 2 SERDES
		 * links per port.
		 * Note: SW uses fixed link 0 per port for
		 * transmission. Link 1 is unused.
		 */
		return 0x3;
	case SPEED_25000:
		fallthrough;
	case SPEED_100000:
		/* In 100GbE mode, HW supports only one
		 * SERDES link per port.
		 */
		return 0x1;
	default:
		dev_err(gaudi2_port->hdev->dev, "Unsupported speed %d\n",
			gaudi2_port->cn_port->speed);
	}

	return 0;
}

static void gaudi2_cn_link_event_handler(struct gaudi2_cn_port *gaudi2_port)
{
	u32 curr_link_sts, link_sts_change, link_status_mask, port;
	struct hbl_cn_device *hdev = gaudi2_port->hdev;
	struct gaudi2_cn_port *gaudi2_port_curr;
	u8 l, cn_m, port_offset, port_shift;
	struct hbl_cn_port *cn_port_curr;
	struct gaudi2_cn_device *gaudi2;
	struct hbl_cn_macro *cn_macro;
	bool link_up, prev_link_up;

	gaudi2 = hdev->asic_specific;
	port = gaudi2_port->cn_port->port;
	cn_macro = gaudi2_port->cn_port->cn_macro;

	curr_link_sts = (NIC_MACRO_RREG32(PRT0_MAC_CORE_MAC_REC_STS0) &
			 PRT0_MAC_CORE_MAC_REC_STS0_REC_LINK_STS_MASK) >>
			PRT0_MAC_CORE_MAC_REC_STS0_REC_LINK_STS_SHIFT;

	/* get the change on the serdes by XOR with previous val */
	link_sts_change = curr_link_sts ^ cn_macro->rec_link_sts;

	/* store current value as previous (for next round) */
	cn_macro->rec_link_sts = curr_link_sts;

	/* calc the MACRO its link-change we need to handle */
	cn_m = port >> 1;

	/* Iterate all SERDES links and check which one was changed */
	for (l = 0; l < NIC_MAC_LANES; l++) {
		if (!(link_sts_change & BIT(l)))
			continue;

		/* calc port offset from current link
		 * (2 ports per macro and 2 links per port)
		 */
		port_offset = l >> 1;
		port_shift = port_offset ? 2 : 0;

		/* get the port struct to handle its link according to the
		 * current SERDES link index
		 */
		gaudi2_port_curr = &gaudi2->cn_ports[cn_m * 2 + port_offset];
		cn_port_curr = gaudi2_port_curr->cn_port;

		mutex_lock(&cn_port_curr->control_lock);

		/* Skip in case the port is closed because the port_close method took care of
		 * disabling the carrier and stopping the queue.
		 */
		if (!hbl_cn_is_port_open(cn_port_curr)) {
			mutex_unlock(&cn_port_curr->control_lock);
			continue;
		}

		link_status_mask = gaudi2_cn_get_link_status_mask(gaudi2_port_curr);
		link_up = (curr_link_sts >> port_shift) & link_status_mask;
		prev_link_up = cn_port_curr->pcs_link;

		if (prev_link_up != link_up && !link_up) {
			mutex_lock(&gaudi2_port_curr->qp_destroy_lock);

			if (gaudi2_port_curr->qp_destroy_cnt && !cn_port_curr->mac_loopback) {
				cn_port_curr->mac_loopback = true;
				gaudi2_cn_hw_mac_loopback_cfg(gaudi2_port_curr);
				gaudi2_port_curr->qp_destroy_mac_lpbk = true;
			}

			mutex_unlock(&gaudi2_port_curr->qp_destroy_lock);
		}

		/* Record the current link status that we got.
		 * In case it is UP, and PHY is not ready, we don't want to actually set it and
		 * reflect it to the user - this will be done later once the PHY will be ready.
		 */
		cn_port_curr->eq_pcs_link = link_up;

		/* In case of link DOWN, set the actual link and reflect it to the user */
		if (!link_up)
			cn_port_curr->pcs_link = false;

		/* Set the actual link status that is reflected to the user and print it in case
		 * either we don't have PHY or we have PHY and it's ready.
		 */
		if (!hdev->phy_config_fw || cn_port_curr->phy_fw_tuned) {
			cn_port_curr->pcs_link = link_up;
			hbl_cn_phy_set_port_status(cn_port_curr, link_up);
		}

		mutex_unlock(&cn_port_curr->control_lock);
	}
}

static void gaudi2_cn_eq_dispatcher_default_handler(struct gaudi2_cn_port *gaudi2_port)
{
	struct hbl_cn_port *cn_port = gaudi2_port->cn_port;
	struct hbl_cn_device *hdev = gaudi2_port->hdev;
	u32 event_type, port, synd;
	struct hbl_cn_eqe eqe;

	port = cn_port->port;

	mutex_lock(&cn_port->control_lock);

	while (!hbl_cn_eq_dispatcher_dequeue(cn_port, hdev->kernel_asid, &eqe, true)) {
		if (!EQE_IS_VALID(&eqe)) {
			dev_warn_ratelimited(hdev->dev,
					     "Port-%d got invalid EQE on default queue!\n", port);
			continue;
		}

		event_type = EQE_TYPE(&eqe);

		switch (event_type) {
		case EQE_COMP:
			dev_warn_ratelimited(hdev->dev, "Port-%d comp event for invalid CQ:%d\n",
					     port, EQE_CQ_EVENT_CQ_NUM(&eqe));
			break;
		case EQE_RAW_TX_COMP:
			dev_warn_ratelimited(hdev->dev,
					     "Port-%d raw-tx-comp event for invalid QP:%d\n",
					     port, EQE_RAW_TX_EVENT_QPN(&eqe));
			break;
		case EQE_QP_ERR:
			synd = EQE_QP_EVENT_ERR_SYND(&eqe);
			dev_warn_ratelimited(hdev->dev,
					     "Port-%d qp-err event: %d ,%s, for invalid QP:%d\n",
					     port, synd, gaudi2_cn_qp_err_syndrome_to_str(synd),
					     EQE_QP_EVENT_QPN(&eqe));
			break;
		case EQE_COMP_ERR:
			dev_warn_ratelimited(hdev->dev, "Port-%d cq-err event for invalid CQ:%d\n",
					     port, EQE_CQ_EVENT_CQ_NUM(&eqe));
			break;
		case EQE_DB_FIFO_OVERRUN:
			dev_warn_ratelimited(hdev->dev,
					     "Port-%d db-fifo overrun event for invalid DB:%d\n",
					     port, EQE_DB_EVENT_DB_NUM(&eqe));
			break;
		case EQE_CONG:
			dev_warn_ratelimited(hdev->dev,
					     "Port-%d congestion event for invalid CCQ:%d\n",
					     port, EQE_CQ_EVENT_CCQ_NUM(&eqe));
			break;
		case EQE_CONG_ERR:
			/* congestion error due to cc cq hw bug is known */
			cn_port->cong_q_err_cnt++;
			dev_dbg_ratelimited(hdev->dev, "Port-%d congestion error event\n", port);
			break;
		case EQE_QP_ALIGN_COUNTERS:
			dev_warn_ratelimited(hdev->dev,
					     "Port-%d QP align counters event, for invalid QP:%d\n",
					     port, EQE_SW_EVENT_QPN(&eqe));
			break;
		default:
			dev_warn_ratelimited(hdev->dev, "Port-%d unsupported event type: %d",
					     port, event_type);
		}
	}

	mutex_unlock(&cn_port->control_lock);
}

static void cn_eq_handler(struct gaudi2_cn_port *gaudi2_port)
{
	struct hbl_cn_port *cn_port = gaudi2_port->cn_port;
	struct hbl_cn_device *hdev = gaudi2_port->hdev;
	u32 event_type, port, synd, qpn;
	bool qp_retry_handled = false;
	struct hbl_cn_ring *eq_ring;
	struct hbl_cn_eqe *eqe_p;
	int rc;

	eq_ring = &gaudi2_port->eq_ring;
	port = cn_port->port;

	/* read the producer index from HW once. New event, received
	 * after the "read once", will be handled in the next callback.
	 */
	eq_ring->pi_shadow = *((u32 *)RING_PI_ADDRESS(eq_ring));

	while (eq_ring->ci_shadow != eq_ring->pi_shadow) {
		eqe_p = (struct hbl_cn_eqe *)RING_BUF_ADDRESS(eq_ring) +
			(eq_ring->ci_shadow & (eq_ring->count - 1));
		if (!EQE_IS_VALID(eqe_p)) {
			dev_warn_ratelimited(hdev->dev,
					     "Port-%d got invalid EQE on EQ (eq.data[0] 0x%x, ci 0x%x, pi 0x%x)\n",
					     port, eqe_p->data[0], eq_ring->ci_shadow,
					     eq_ring->pi_shadow);
		} else {
			event_type = EQE_TYPE(eqe_p);

			if (event_type == EQE_QP_ERR) {
				synd = EQE_QP_EVENT_ERR_SYND(eqe_p);
				if (gaudi2_port->adaptive_timeout_en && synd ==
				    NIC_QP_ERR_RETRY_SYNDROME) {
					qpn = EQE_RAW_TX_EVENT_QPN(eqe_p);
					if (qpn != RAW_QPN)
						qp_retry_handled =
							gaudi2_handle_qp_error_retry(cn_port, qpn);
				}
			}

			/* In case this is link event, we handle it now and the dispatcher won't be
			 * involved.
			 */
			if (event_type == EQE_LINK_STATUS) {
				gaudi2_cn_link_event_handler(gaudi2_port);
			/* ignore CQ errors when CQ is in overrun, as CQ overflow errors are
			 * expected.
			 */
			} else if (!qp_retry_handled && ((event_type != EQE_COMP_ERR) ||
				!gaudi2_cn_is_cq_in_overrun(cn_port, EQE_CQ_EVENT_CQ_NUM(eqe_p)))) {
				rc = hbl_cn_eq_dispatcher_enqueue(cn_port, eqe_p);
				if (rc)
					dev_warn_ratelimited(hdev->dev,
							     "failed to dispatch event %d, err %d\n",
							     event_type, rc);
			}

			/* Mark the EQ-entry is not valid */
			EQE_SET_INVALID(eqe_p);
		}

		eq_ring->rep_idx++;
		eq_ring->ci_shadow = (eq_ring->ci_shadow + 1) & EQ_IDX_MASK;

		/* Update the HW consumer index, every quarter ring, with an
		 * absolute value (ci_shadow is a wrap-around value).
		 * Use the read producer index value for that.
		 */
		if (eq_ring->rep_idx > (eq_ring->count / 4) - 1) {
			eq_ring->rep_idx = 0;
			NIC_WREG32(NIC0_QPC0_EVENT_QUE_CONSUMER_INDEX, eq_ring->ci_shadow);
		}
	}

	if (!qp_retry_handled) {
		hbl_cn_eq_handler(cn_port);

		/* Handle unknown resources and events */
		gaudi2_cn_eq_dispatcher_default_handler(gaudi2_port);
	}
}

static inline void gaudi2_cn_eq_clr_interrupts(struct gaudi2_cn_port *gaudi2_port)
{
	struct hbl_cn_device *hdev = gaudi2_port->hdev;
	u32 port = gaudi2_port->cn_port->port;

	/* Release the HW to allow more EQ interrupts.
	 * No need for interrupt masking. As long as the SW hasn't set the clear reg,
	 * new interrupts won't be raised
	 */
	NIC_WREG32(NIC0_QPC0_INTERRUPT_CLR, 0x200);

	/* flush write so the interrupt will be cleared as soon as possible */
	NIC_RREG32(NIC0_QPC0_INTERRUPT_CLR);
}

static void gaudi2_cn_eq_work(struct work_struct *work)
{
	struct gaudi2_cn_port *gaudi2_port = container_of(work, struct gaudi2_cn_port,
							  eq_work.work);
	struct hbl_cn_device *hdev = gaudi2_port->hdev;

	cn_eq_handler(gaudi2_port);

	if (hdev->poll_enable)
		schedule_delayed_work(&gaudi2_port->eq_work, msecs_to_jiffies(1));
	else
		gaudi2_cn_eq_clr_interrupts(gaudi2_port);
}

/* Use this routine when working with real HW */
static irqreturn_t gaudi2_cn_eq_threaded_isr(int irq, void *arg)
{
	struct gaudi2_cn_port *gaudi2_port = arg;

	gaudi2_cn_eq_clr_interrupts(gaudi2_port);
	cn_eq_handler(gaudi2_port);

	return IRQ_HANDLED;
}

static void gaudi2_cn_eq_hw_config(struct gaudi2_cn_port *gaudi2_port)
{
	struct hbl_cn_ring *ring = &gaudi2_port->eq_ring;
	struct hbl_cn_device *hdev = gaudi2_port->hdev;
	u32 port = gaudi2_port->cn_port->port;

	WARN_ON_CACHE_UNALIGNED(RING_PI_DMA_ADDRESS(ring));
	WARN_ON_CACHE_UNALIGNED(RING_BUF_DMA_ADDRESS(ring));

	/* set base address for event queue */
	NIC_WREG32(NIC0_QPC0_EVENT_QUE_PI_ADDR_63_32, upper_32_bits(RING_PI_DMA_ADDRESS(ring)));

	NIC_WREG32(NIC0_QPC0_EVENT_QUE_PI_ADDR_31_7,
		   lower_32_bits(RING_PI_DMA_ADDRESS(ring)) >> 7);

	NIC_WREG32(NIC0_QPC0_EVENT_QUE_BASE_ADDR_63_32,
		   upper_32_bits(RING_BUF_DMA_ADDRESS(ring)));

	NIC_WREG32(NIC0_QPC0_EVENT_QUE_BASE_ADDR_31_7,
		   lower_32_bits(RING_BUF_DMA_ADDRESS(ring)) >> 7);

	NIC_WREG32(NIC0_QPC0_EVENT_QUE_LOG_SIZE, ilog2(ring->count));

	NIC_WREG32(NIC0_QPC0_EVENT_QUE_WRITE_INDEX, 0);
	NIC_WREG32(NIC0_QPC0_EVENT_QUE_PRODUCER_INDEX, 0);
	NIC_WREG32(NIC0_QPC0_EVENT_QUE_CONSUMER_INDEX, 0);
	NIC_WREG32(NIC0_QPC0_EVENT_QUE_CONSUMER_INDEX_CB, 0);

	NIC_WREG32(NIC0_QPC0_EVENT_QUE_CFG, NIC0_QPC0_EVENT_QUE_CFG_INTERRUPT_PER_EQE_MASK |
		   NIC0_QPC0_EVENT_QUE_CFG_WRITE_PI_EN_MASK | NIC0_QPC0_EVENT_QUE_CFG_ENABLE_MASK);

	NIC_WREG32(NIC0_QPC0_AXUSER_EV_QUE_LBW_INTR_HB_WR_OVRD_LO, 0xFFFFFBFF);
	NIC_WREG32(NIC0_QPC0_AXUSER_EV_QUE_LBW_INTR_HB_RD_OVRD_LO, 0xFFFFFBFF);

	/* reset SW indices */
	*((u32 *)RING_PI_ADDRESS(ring)) = 0;
	ring->pi_shadow = 0;
	ring->ci_shadow = 0;
	ring->rep_idx = 0;
}

static void gaudi2_cn_eq_interrupts_enable_conditionally(struct gaudi2_cn_port *gaudi2_port,
							 bool poll_enable)
{
	struct hbl_cn_port *cn_port = gaudi2_port->cn_port;
	struct hbl_cn_device *hdev = gaudi2_port->hdev;
	u32 port = cn_port->port, sob_id;
	struct gaudi2_cn_device *gaudi2;

	gaudi2 = hdev->asic_specific;

	if (poll_enable) {
		/* Masking all QPC Interrupts except EQ wire int */
		NIC_WREG32(NIC0_QPC0_INTERRUPT_MASK, 0x3FF);
		NIC_WREG32(NIC0_QPC0_INTERRUPT_EN,
			   NIC0_QPC0_INTERRUPT_EN_INTERRUPT10_WIRE_EN_MASK);
	} else {
		sob_id = gaudi2->sob_id_base + port;
		NIC_WREG32(NIC0_QPC0_INTERRUPT_BASE_9,
			   DCORE0_SYNC_MNGR_OBJS_SOB_OBJ_0 + sob_id * sizeof(u32));
		NIC_WREG32(NIC0_QPC0_INTERRUPT_DATA_9, gaudi2->sob_inc_cfg_val);

		/* Masking all QPC Interrupts except EQ int and error event queue int */
		NIC_WREG32(NIC0_QPC0_INTERRUPT_MASK, 0x1FF);

		NIC_WREG32(NIC0_QPC0_INTERRUPT_EN,
			   NIC0_QPC0_INTERRUPT_EN_INTERRUPT9_MSI_EN_MASK |
			   NIC0_QPC0_INTERRUPT_EN_INTERRUPT10_WIRE_EN_MASK);
	}

	/* flush */
	NIC_RREG32(NIC0_QPC0_INTERRUPT_EN);
}

static void gaudi2_cn_eq_interrupts_disable(struct gaudi2_cn_port *gaudi2_port)
{
	struct hbl_cn_port *cn_port = gaudi2_port->cn_port;
	struct hbl_cn_device *hdev = gaudi2_port->hdev;
	u32 port = cn_port->port;

	/* disabling and masking all QPC Interrupts */
	NIC_WREG32(NIC0_QPC0_INTERRUPT_EN, 0);
	NIC_WREG32(NIC0_QPC0_INTERRUPT_MASK, 0x7FF);

	/* flush */
	NIC_RREG32(NIC0_QPC0_INTERRUPT_EN);
}

void gaudi2_cn_eq_enter_temporal_polling_mode(struct hbl_cn_device *hdev)
{
	struct gaudi2_cn_device *gaudi2 = hdev->asic_specific;
	struct gaudi2_cn_port *gaudi2_port;
	int i;

	if (hdev->poll_enable)
		return;

	for (i = 0; i < NIC_NUMBER_OF_PORTS; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		gaudi2_port = &gaudi2->cn_ports[i];
		gaudi2_cn_eq_interrupts_enable_conditionally(gaudi2_port, true);
	}

	hdev->poll_enable = true;

	/* wait for ISRs to complete before scheduling the polling work */
	gaudi2_cn_eq_sync_irqs(hdev);

	for (i = 0; i < NIC_NUMBER_OF_PORTS; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		gaudi2_port = &gaudi2->cn_ports[i];
		schedule_delayed_work(&gaudi2_port->eq_work, msecs_to_jiffies(1));
	}
}

void gaudi2_cn_eq_exit_temporal_polling_mode(struct hbl_cn_device *hdev)
{
	struct gaudi2_cn_device *gaudi2 = hdev->asic_specific;
	struct gaudi2_cn_port *gaudi2_port;
	int i;

	if (!hdev->poll_enable)
		return;

	if (!gaudi2->temporal_polling)
		return;

	for (i = 0; i < NIC_NUMBER_OF_PORTS; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		gaudi2_port = &gaudi2->cn_ports[i];
		cancel_delayed_work_sync(&gaudi2_port->eq_work);
	}

	hdev->poll_enable = false;

	for (i = 0; i < NIC_NUMBER_OF_PORTS; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		gaudi2_port = &gaudi2->cn_ports[i];
		gaudi2_cn_eq_interrupts_enable_conditionally(gaudi2_port, false);
		/* Schedule the work as interrupts may be pending but not acked thus preventing
		 * interrupts from triggering.
		 * Double scheduling avoidance of the work (from the ISR and from here)
		 * is done by the WQ scheduler itself.
		 */
		schedule_delayed_work(&gaudi2_port->eq_work, 0);
	}
}

static int gaudi2_cn_eq_port_init(struct gaudi2_cn_port *gaudi2_port)
{
	struct hbl_cn_device *hdev = gaudi2_port->hdev;

	gaudi2_cn_eq_hw_config(gaudi2_port);

	/* we disable eq handler here in order to prevent a crash if a race occurs
	 * between the work-queue calling the handler routine and the eth driver
	 * unregistering it.
	 */
	gaudi2_port->cn_port->eq_handler_enable = false;

	INIT_DELAYED_WORK(&gaudi2_port->eq_work, gaudi2_cn_eq_work);

	gaudi2_cn_eq_interrupts_enable_conditionally(gaudi2_port, hdev->poll_enable);

	if (hdev->poll_enable)
		schedule_delayed_work(&gaudi2_port->eq_work, msecs_to_jiffies(1));

	return 0;
}

static void gaudi2_cn_eq_port_fini(struct gaudi2_cn_port *gaudi2_port)
{
	gaudi2_cn_eq_interrupts_disable(gaudi2_port);
	cancel_delayed_work_sync(&gaudi2_port->eq_work);
	gaudi2_port->cn_port->eq_handler_enable = false;
}

int gaudi2_cn_eq_init(struct hbl_cn_device *hdev)
{
	struct gaudi2_cn_device *gaudi2 = hdev->asic_specific;
	struct gaudi2_cn_port *gaudi2_port;
	int rc, i, port_cnt = 0;
	u32 port;

	/* Need to reset the value of 'poll_enable' for a case that we entered temporal polling mode
	 * but didn't exit it (e.g. during a failing soft-reset).
	 * The original value is actually the inverse of 'temporal_polling' which is set once in
	 * sw_init and is constant.
	 */
	hdev->poll_enable = !gaudi2->temporal_polling;

	/* Due to H/W bug on gaudi2, link events for both even and odd ports arrive only on the odd
	 * port in the macro. Therefore, need to initialize all EQs of all ports regardless of their
	 * enablement.
	 */
	for (i = 0; i < NIC_NUMBER_OF_PORTS; i++, port_cnt++) {
		gaudi2_port = &gaudi2->cn_ports[i];
		port = gaudi2_port->cn_port->port;

		rc = gaudi2_cn_eq_port_init(gaudi2_port);
		if (rc) {
			dev_err(hdev->dev, "Failed to init the hardware EQ, port: %d, %d\n", port,
				rc);
			goto err;
		}
	}

	return 0;

err:
	for (i = 0; i < port_cnt; i++)
		gaudi2_cn_eq_port_fini(&gaudi2->cn_ports[i]);

	return rc;
}

void gaudi2_cn_eq_fini(struct hbl_cn_device *hdev)
{
	struct gaudi2_cn_device *gaudi2 = hdev->asic_specific;
	int i;

	for (i = 0; i < NIC_NUMBER_OF_PORTS; i++)
		gaudi2_cn_eq_port_fini(&gaudi2->cn_ports[i]);
}

/* event dispatcher
 *
 * In gaudi2 each port has a single EQ. The HW writes all the related events
 * to this EQ. Since multiple applications can use the port at the same time we
 * need to have a way to dispatch the app-related events to the correct
 * application, these events will be read later on by the IB API.
 */

struct hbl_cn_ev_dq *gaudi2_cn_eq_dispatcher_select_dq(struct hbl_cn_port *cn_port,
						       const struct hbl_cn_eqe *eqe)
{
	struct gaudi2_cn_port *gaudi2_port = (struct gaudi2_cn_port *)cn_port->cn_specific;
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hbl_cn_ev_dq *dq = NULL;
	u32 event_type = EQE_TYPE(eqe);
	u32 cqn, qpn, dbn, ccqn;

	switch (event_type) {
	case EQE_COMP:
		fallthrough;
	case EQE_COMP_ERR:
		cqn = EQE_CQ_EVENT_CQ_NUM(eqe);
		dq = hbl_cn_cqn_to_dq(ev_dqs, cqn, gaudi2_port->hdev);
		break;
	case EQE_QP_ERR:
		qpn = EQE_QP_EVENT_QPN(eqe);
		dq = hbl_cn_qpn_to_dq(ev_dqs, qpn);
		break;
	case EQE_RAW_TX_COMP:
		qpn = EQE_RAW_TX_EVENT_QPN(eqe);
		dq = hbl_cn_qpn_to_dq(ev_dqs, qpn);
		break;
	case EQE_DB_FIFO_OVERRUN:
		dbn = EQE_DB_EVENT_DB_NUM(eqe);
		dq = hbl_cn_dbn_to_dq(ev_dqs, dbn, gaudi2_port->hdev);
		break;
	case EQE_CONG:
		ccqn = EQE_CQ_EVENT_CCQ_NUM(eqe);
		dq = hbl_cn_ccqn_to_dq(ev_dqs, ccqn, gaudi2_port->hdev);
		break;
	case EQE_QP_ALIGN_COUNTERS:
		qpn = EQE_SW_EVENT_QPN(eqe);
		dq = hbl_cn_qpn_to_dq(ev_dqs, qpn);
		break;
	case EQE_CONG_ERR:
		fallthrough;
	case EQE_RESERVED:
		fallthrough;
	default:
		dq = &ev_dqs->default_edq;
	}

	/* Unknown resources and events should be handled by default events
	 * dispatch queue.
	 */
	return IS_ERR_OR_NULL(dq) ? &ev_dqs->default_edq : dq;
}

int gaudi2_cn_eq_dispatcher_register_db(struct gaudi2_cn_port *gaudi2_port, u32 asid, u32 dbn)
{
	struct hbl_cn_device *hdev = gaudi2_port->hdev;

	if (dbn == GAUDI2_DB_FIFO_PRIVILEGE_HW_ID)
		return -EINVAL;

	if (asid != hdev->kernel_asid && dbn == GAUDI2_DB_FIFO_SECURE_HW_ID)
		return -EINVAL;

	return hbl_cn_eq_dispatcher_register_db(gaudi2_port->cn_port, asid, dbn);
}
