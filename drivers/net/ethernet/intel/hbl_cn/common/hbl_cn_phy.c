// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#include <linux/firmware.h>
#include "hbl_cn.h"

static void port_reset_state(struct hbl_cn_port *cn_port)
{
	cn_port->pcs_link = false;
	cn_port->eq_pcs_link = false;
	cn_port->auto_neg_resolved = false;
	cn_port->auto_neg_skipped = false;
	cn_port->phy_fw_tuned = false;
	cn_port->retry_cnt = 0;
	cn_port->pcs_remote_fault_seq_cnt = 0;
	cn_port->pcs_link_restore_cnt = 0;
	cn_port->correctable_errors_cnt = 0;
	cn_port->uncorrectable_errors_cnt = 0;
}

static u32 get_data_rate(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	u32 port, speed, data_rate;

	port = cn_port->port;
	speed = cn_port->speed;

	switch (speed) {
	case SPEED_10000:
		data_rate = NIC_DR_10;
		break;
	case SPEED_25000:
		data_rate = NIC_DR_25;
		break;
	case SPEED_50000:
		data_rate = NIC_DR_50;
		break;
	case SPEED_100000:
		data_rate = NIC_DR_50;
		break;
	case SPEED_200000:
		data_rate = NIC_DR_100;
		break;
	case SPEED_400000:
		data_rate = NIC_DR_100;
		break;
	default:
		data_rate = NIC_DR_50;
		dev_err(hdev->dev, "unknown port %d speed, continue with 50 GHz\n", port);
		break;
	}

	dev_dbg(hdev->dev, "port %d, speed %d data rate %d\n", port, speed, data_rate);

	return data_rate;
}

void hbl_cn_phy_set_port_status(struct hbl_cn_port *cn_port, bool up)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	u32 port = cn_port->port;
	bool is_ibdev;
	int rc;

	aux_dev = &hdev->en_aux_dev;
	aux_ops = aux_dev->aux_ops;
	port_funcs = hdev->asic_funcs->port_funcs;
	is_ibdev = hbl_cn_is_ibdev(hdev);

	port_funcs->set_port_status(cn_port, up);

	if (cn_port->eth_enable) {
		if (aux_ops->set_port_status)
			aux_ops->set_port_status(aux_dev, port, up);
	} else {
		if (hdev->ctx)
			dev_info(hdev->dev, "Card %u Port %u: link %s\n",
				 hdev->card_location, port, up ? "up" : "down");
		else
			dev_dbg(hdev->dev, "Card %u Port %u: link %s\n",
				hdev->card_location, port, up ? "up" : "down");
	}

	/* IB flow. User polls for IB events.
	 *  - internal ports: Enqueue link event in EQ dispatcher. IB event would be dispatched in
	 *                    response.
	 *  - external ports: Do not enqueue. hbl IB driver dispatches IB events from netdev
	 *                    notifier chain handler.
	 * non-IB flow. User polls for EQ events.
	 *  - internal ports: Enqueue link event in EQ dispatcher.
	 *  - external ports: Enqueue link event in EQ dispatcher.
	 */
	if (!is_ibdev || !cn_port->eth_enable) {
		if (hdev->has_eq) {
			rc = hbl_cn_eq_dispatcher_enqueue_bcast(cn_port, &cn_port->link_eqe);
			if (rc)
				dev_dbg_ratelimited(hdev->dev,
						    "Port %d, failed to dispatch link event %s, %d\n",
						    port, up ? "up" : "down", rc);
		}
	}

	cn_port->port_toggle_cnt++;

	/* The FEC counters are relevant during the time that link is UP, hence reset them here */
	if (up) {
		cn_port->correctable_errors_cnt = 0;
		cn_port->uncorrectable_errors_cnt = 0;
	}

	if (hdev->pldm) {
		dev_dbg(hdev->dev, "%s: port %u\n", __func__, port);
		msleep(1000);
	}
}

int hbl_cn_phy_init(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_asic_port_funcs *port_funcs;
	int rc;

	port_funcs = hdev->asic_funcs->port_funcs;

	/* If mac_loopback is enabled on this port, move the port status to UP state */
	if (cn_port->mac_loopback) {
		cn_port->pcs_link = true;
		hbl_cn_phy_set_port_status(cn_port, true);
		return 0;
	}

	if (!hdev->phy_config_fw) {
		/* If EQ is supported, it will take care of setting the port status */
		if (!hdev->has_eq) {
			cn_port->pcs_link = true;
			hbl_cn_phy_set_port_status(cn_port, true);
		}

		return 0;
	}

	cn_port->data_rate = get_data_rate(cn_port);

	rc = port_funcs->phy_port_power_up(cn_port);
	if (rc) {
		dev_err(hdev->dev, "ASIC specific phy port power-up failed, %d\n", rc);
		return rc;
	}

	port_funcs->phy_port_start_stop(cn_port, true);

	queue_delayed_work(cn_port->wq, &cn_port->link_status_work, msecs_to_jiffies(1));

	return 0;
}

/* This function does not change the port link status in order to avoid unnecessary netdev actions
 * and prints. Hence it should be done from outside.
 */
void hbl_cn_phy_fini(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_asic_port_funcs *port_funcs;

	/* This is done before the check because we support setting mac loopback for a specific port
	 * and this function might be called when cn_port->mac_loopback is true (during the port
	 * reset after setting mac loopback), but the link status work was scheduled before (when
	 * the port was opened w/o mac loopback).
	 */
	cancel_delayed_work_sync(&cn_port->link_status_work);

	port_funcs = hdev->asic_funcs->port_funcs;

	if (!hdev->phy_config_fw || cn_port->mac_loopback) {
		cn_port->pcs_link = false;
		cn_port->eq_pcs_link = false;
		return;
	}

	port_reset_state(cn_port);
	port_funcs->phy_port_start_stop(cn_port, false);
}

void hbl_cn_phy_port_reconfig(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_asic_port_funcs *port_funcs;

	port_funcs = hdev->asic_funcs->port_funcs;

	port_funcs->phy_port_reconfig(cn_port);

	port_reset_state(cn_port);
}

int hbl_cn_phy_has_binary_fw(struct hbl_cn_device *hdev)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	const struct firmware *fw;
	const char *fw_name;
	int rc;

	fw_name = asic_funcs->get_phy_fw_name();

	rc = request_firmware(&fw, fw_name, hdev->dev);
	if (rc) {
		dev_err(hdev->dev, "Firmware file %s is not found!\n", fw_name);
		return rc;
	}

	release_firmware(fw);

	return 0;
}

void hbl_cn_phy_set_fw_polarity(struct hbl_cn_device *hdev)
{
	struct hbl_cn_cpucp_info *cpucp_info;

	if (hdev->skip_phy_pol_cfg)
		return;

	cpucp_info = hdev->cpucp_info;

	hdev->pol_tx_mask = cpucp_info->pol_tx_mask[0];
	hdev->pol_rx_mask = cpucp_info->pol_rx_mask[0];
}
