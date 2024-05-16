// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#include "hbl_en.h"
#include <linux/ethtool.h>

#define RX_COALESCED_FRAMES_MIN		1
#define TX_COALESCED_FRAMES_MIN		1
#define TX_COALESCED_FRAMES_MAX		10

static const char pflags_str[][ETH_GSTRING_LEN] = {
	"pcs-link-check",
	"phy-auto-neg-lpbk",
};

#define NIC_STAT(m) {#m, offsetof(struct hbl_en_port, net_stats.m)}

static struct hbl_cn_stat netdev_eth_stats[] = {
	NIC_STAT(rx_packets),
	NIC_STAT(tx_packets),
	NIC_STAT(rx_bytes),
	NIC_STAT(tx_bytes),
	NIC_STAT(tx_errors),
	NIC_STAT(rx_dropped),
	NIC_STAT(tx_dropped)
};

static size_t pflags_str_len = ARRAY_SIZE(pflags_str);
static size_t netdev_eth_stats_len = ARRAY_SIZE(netdev_eth_stats);

static void hbl_en_ethtool_get_drvinfo(struct net_device *ndev, struct ethtool_drvinfo *drvinfo)
{
	struct hbl_en_device *hdev;
	struct hbl_en_port *port;

	port = hbl_netdev_priv(ndev);
	hdev = port->hdev;

	strscpy(drvinfo->driver, HBL_EN_NAME, sizeof(drvinfo->driver));
	strscpy(drvinfo->fw_version, hdev->fw_ver, sizeof(drvinfo->fw_version));
	strscpy(drvinfo->bus_info, pci_name(hdev->pdev), sizeof(drvinfo->bus_info));
}

static int hbl_en_ethtool_get_module_info(struct net_device *ndev, struct ethtool_modinfo *modinfo)
{
	modinfo->eeprom_len = ETH_MODULE_SFF_8636_LEN;
	modinfo->type = ETH_MODULE_SFF_8636;

	return 0;
}

static int hbl_en_ethtool_get_module_eeprom(struct net_device *ndev, struct ethtool_eeprom *ee,
					    u8 *data)
{
	struct hbl_en_device *hdev;
	struct hbl_en_port *port;
	u32 first, last, len;
	u8 *qsfp_eeprom;

	port = hbl_netdev_priv(ndev);
	hdev = port->hdev;
	qsfp_eeprom = hdev->qsfp_eeprom;

	if (ee->len == 0)
		return -EINVAL;

	first = ee->offset;
	last = ee->offset + ee->len;

	if (first < ETH_MODULE_SFF_8636_LEN) {
		len = min_t(unsigned int, last, ETH_MODULE_SFF_8079_LEN);
		len -= first;

		memcpy(data, qsfp_eeprom + first, len);
	}

	return 0;
}

static u32 hbl_en_ethtool_get_priv_flags(struct net_device *ndev)
{
	struct hbl_en_port *port = hbl_netdev_priv(ndev);

	return port->pflags;
}

static int hbl_en_ethtool_set_priv_flags(struct net_device *ndev, u32 priv_flags)
{
	struct hbl_en_port *port = hbl_netdev_priv(ndev);

	port->pflags = priv_flags;

	return 0;
}

static int hbl_en_ethtool_get_link_ksettings(struct net_device *ndev,
					     struct ethtool_link_ksettings *cmd)
{
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	struct hbl_en_device *hdev;
	struct hbl_en_port *port;
	u32 port_idx, speed;

	port = hbl_netdev_priv(ndev);
	hdev = port->hdev;
	port_idx = port->idx;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	speed = aux_ops->get_speed(aux_dev, port_idx);

	cmd->base.speed = speed;
	cmd->base.duplex = DUPLEX_FULL;

	ethtool_link_ksettings_zero_link_mode(cmd, supported);
	ethtool_link_ksettings_zero_link_mode(cmd, advertising);

	switch (speed) {
	case SPEED_100000:
		ethtool_link_ksettings_add_link_mode(cmd, supported, 100000baseCR4_Full);
		ethtool_link_ksettings_add_link_mode(cmd, supported, 100000baseSR4_Full);
		ethtool_link_ksettings_add_link_mode(cmd, supported, 100000baseKR4_Full);
		ethtool_link_ksettings_add_link_mode(cmd, supported, 100000baseLR4_ER4_Full);

		ethtool_link_ksettings_add_link_mode(cmd, advertising, 100000baseCR4_Full);
		ethtool_link_ksettings_add_link_mode(cmd, advertising, 100000baseSR4_Full);
		ethtool_link_ksettings_add_link_mode(cmd, advertising, 100000baseKR4_Full);
		ethtool_link_ksettings_add_link_mode(cmd, advertising, 100000baseLR4_ER4_Full);

		cmd->base.port = PORT_FIBRE;

		ethtool_link_ksettings_add_link_mode(cmd, supported, FIBRE);
		ethtool_link_ksettings_add_link_mode(cmd, advertising, FIBRE);

		ethtool_link_ksettings_add_link_mode(cmd, supported, Backplane);
		ethtool_link_ksettings_add_link_mode(cmd, advertising, Backplane);
		break;
	case SPEED_50000:
		ethtool_link_ksettings_add_link_mode(cmd, supported, 50000baseSR2_Full);
		ethtool_link_ksettings_add_link_mode(cmd, supported, 50000baseCR2_Full);
		ethtool_link_ksettings_add_link_mode(cmd, supported, 50000baseKR2_Full);

		ethtool_link_ksettings_add_link_mode(cmd, advertising, 50000baseSR2_Full);
		ethtool_link_ksettings_add_link_mode(cmd, advertising, 50000baseCR2_Full);
		ethtool_link_ksettings_add_link_mode(cmd, advertising, 50000baseKR2_Full);
		break;
	case SPEED_25000:
		ethtool_link_ksettings_add_link_mode(cmd, supported, 25000baseCR_Full);

		ethtool_link_ksettings_add_link_mode(cmd, advertising, 25000baseCR_Full);
		break;
	case SPEED_200000:
		ethtool_link_ksettings_add_link_mode(cmd, supported, 200000baseCR4_Full);
		ethtool_link_ksettings_add_link_mode(cmd, supported, 200000baseKR4_Full);

		ethtool_link_ksettings_add_link_mode(cmd, advertising, 200000baseCR4_Full);
		ethtool_link_ksettings_add_link_mode(cmd, advertising, 200000baseKR4_Full);
		break;
	case SPEED_400000:
		ethtool_link_ksettings_add_link_mode(cmd, supported, 400000baseCR4_Full);
		ethtool_link_ksettings_add_link_mode(cmd, supported, 400000baseKR4_Full);

		ethtool_link_ksettings_add_link_mode(cmd, advertising, 400000baseCR4_Full);
		ethtool_link_ksettings_add_link_mode(cmd, advertising, 400000baseKR4_Full);
		break;
	default:
		netdev_err(port->ndev, "unknown speed %d\n", speed);
		return -EFAULT;
	}

	ethtool_link_ksettings_add_link_mode(cmd, supported, Autoneg);

	if (port->auto_neg_enable) {
		ethtool_link_ksettings_add_link_mode(cmd, advertising, Autoneg);
		cmd->base.autoneg = AUTONEG_ENABLE;
		if (port->auto_neg_resolved)
			ethtool_link_ksettings_add_link_mode(cmd, lp_advertising, Autoneg);
	} else {
		cmd->base.autoneg = AUTONEG_DISABLE;
	}

	ethtool_link_ksettings_add_link_mode(cmd, supported, Pause);

	if (port->pfc_enable)
		ethtool_link_ksettings_add_link_mode(cmd, advertising, Pause);

	return 0;
}

/* only autoneg is mutable */
static bool check_immutable_ksettings(const struct ethtool_link_ksettings *old_cmd,
				      const struct ethtool_link_ksettings *new_cmd)
{
	return (old_cmd->base.speed == new_cmd->base.speed) &&
	       (old_cmd->base.duplex == new_cmd->base.duplex) &&
	       (old_cmd->base.port == new_cmd->base.port) &&
	       (old_cmd->base.phy_address == new_cmd->base.phy_address) &&
	       (old_cmd->base.eth_tp_mdix_ctrl == new_cmd->base.eth_tp_mdix_ctrl) &&
	       bitmap_equal(old_cmd->link_modes.advertising, new_cmd->link_modes.advertising,
			    __ETHTOOL_LINK_MODE_MASK_NBITS);
}

static int
hbl_en_ethtool_set_link_ksettings(struct net_device *ndev, const struct ethtool_link_ksettings *cmd)
{
	struct ethtool_link_ksettings curr_cmd;
	struct hbl_en_device *hdev;
	struct hbl_en_port *port;
	bool auto_neg;
	u32 port_idx;
	int rc;

	port = hbl_netdev_priv(ndev);
	hdev = port->hdev;
	port_idx = port->idx;

	memset(&curr_cmd, 0, sizeof(struct ethtool_link_ksettings));

	rc = hbl_en_ethtool_get_link_ksettings(ndev, &curr_cmd);
	if (rc)
		return rc;

	if (!check_immutable_ksettings(&curr_cmd, cmd))
		return -EOPNOTSUPP;

	auto_neg = cmd->base.autoneg == AUTONEG_ENABLE;

	if (port->auto_neg_enable == auto_neg)
		return 0;

	if (atomic_cmpxchg(&port->in_reset, 0, 1)) {
		netdev_err(port->ndev, "port is in reset, can't update settings\n");
		return -EBUSY;
	}

	if (auto_neg && !(hdev->auto_neg_mask & BIT(port_idx))) {
		netdev_err(port->ndev, "port autoneg is disabled by BMC\n");
		rc = -EFAULT;
		goto out;
	}

	port->auto_neg_enable = auto_neg;

	if (netif_running(port->ndev)) {
		rc = hbl_en_port_reset(port);
		if (rc)
			netdev_err(port->ndev, "Failed to reset port for settings update, rc %d\n",
				   rc);
	}

out:
	atomic_set(&port->in_reset, 0);

	return rc;
}

static int hbl_en_ethtool_get_sset_count(struct net_device *ndev, int sset)
{
	struct hbl_en_port *port = hbl_netdev_priv(ndev);
	struct hbl_en_device *hdev = port->hdev;
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	u32 port_idx = port->idx;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	switch (sset) {
	case ETH_SS_STATS:
		return netdev_eth_stats_len + aux_ops->get_cnts_num(aux_dev, port_idx);
	case ETH_SS_PRIV_FLAGS:
		return pflags_str_len;
	default:
		return -EOPNOTSUPP;
	}
}

static void hbl_en_ethtool_get_strings(struct net_device *ndev, u32 stringset, u8 *data)
{
	struct hbl_en_port *port = hbl_netdev_priv(ndev);
	struct hbl_en_device *hdev = port->hdev;
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	u32 port_idx = port->idx;
	int i;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < netdev_eth_stats_len; i++)
			ethtool_puts(&data, netdev_eth_stats[i].str);

		aux_ops->get_cnts_names(aux_dev, port_idx, data);
		break;
	case ETH_SS_PRIV_FLAGS:
		for (i = 0; i < pflags_str_len; i++)
			ethtool_puts(&data, pflags_str[i]);
		break;
	}
}

static void hbl_en_ethtool_get_ethtool_stats(struct net_device *ndev,
					     __always_unused struct ethtool_stats *stats, u64 *data)
{
	struct hbl_en_port *port = hbl_netdev_priv(ndev);
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	struct hbl_en_device *hdev;
	u32 port_idx;
	char *p;
	int i;

	hdev = port->hdev;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	port_idx = port->idx;

	if (atomic_cmpxchg(&port->in_reset, 0, 1)) {
		dev_info_ratelimited(hdev->dev, "port %d is in reset, can't get ethtool stats",
				     port_idx);
		return;
	}

	/* Even though the Ethernet Rx/Tx flow might update the stats in parallel, there is not an
	 * absolute need for synchronisation. This is because, missing few counts of these stats is
	 * much better than adding a lock to synchronize and increase the overhead of the Rx/Tx
	 * flows. In worst case scenario, reader will get stale stats. He will receive updated
	 * stats in next read.
	 */
	for (i = 0; i < netdev_eth_stats_len; i++) {
		p = (char *)port + netdev_eth_stats[i].lo_offset;
		data[i] = *(u32 *)p;
	}

	data += i;

	aux_ops->get_cnts_values(aux_dev, port_idx, data);

	atomic_set(&port->in_reset, 0);
}

static int hbl_en_ethtool_get_coalesce(struct net_device *ndev,
				       struct ethtool_coalesce *coal,
				       struct kernel_ethtool_coalesce *kernel_coal,
				       struct netlink_ext_ack *extack)
{
	struct hbl_en_port *port = hbl_netdev_priv(ndev);
	struct hbl_en_device *hdev = port->hdev;
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	u32 port_idx = port->idx;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	aux_ops->ctrl_lock(aux_dev, port_idx);

	coal->tx_max_coalesced_frames = port->tx_max_coalesced_frames;
	coal->rx_coalesce_usecs = port->rx_coalesce_usecs;
	coal->rx_max_coalesced_frames = port->rx_max_coalesced_frames;

	aux_ops->ctrl_unlock(aux_dev, port_idx);

	return 0;
}

static int hbl_en_ethtool_set_coalesce(struct net_device *ndev,
				       struct ethtool_coalesce *coal,
				       struct kernel_ethtool_coalesce *kernel_coal,
				       struct netlink_ext_ack *extack)
{
	struct hbl_en_port *port = hbl_netdev_priv(ndev);
	struct hbl_en_device *hdev = port->hdev;
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	u32 port_idx = port->idx;
	int rc, rx_ring_size;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	if (atomic_cmpxchg(&port->in_reset, 0, 1)) {
		netdev_err(port->ndev, "port is in reset, can't update settings\n");
		return -EBUSY;
	}

	if (coal->tx_max_coalesced_frames < TX_COALESCED_FRAMES_MIN ||
	    coal->tx_max_coalesced_frames > TX_COALESCED_FRAMES_MAX) {
		netdev_err(ndev, "tx max_coalesced_frames should be between %d and %d\n",
			   TX_COALESCED_FRAMES_MIN, TX_COALESCED_FRAMES_MAX);
		rc = -EINVAL;
		goto atomic_out;
	}

	rx_ring_size = hdev->asic_funcs.get_rx_ring_size(port);
	if (coal->rx_max_coalesced_frames < RX_COALESCED_FRAMES_MIN ||
	    coal->rx_max_coalesced_frames >= rx_ring_size) {
		netdev_err(ndev, "rx max_coalesced_frames should be between %d and %d\n",
			   RX_COALESCED_FRAMES_MIN, rx_ring_size);
		rc = -EINVAL;
		goto atomic_out;
	}

	aux_ops->ctrl_lock(aux_dev, port_idx);

	port->tx_max_coalesced_frames = coal->tx_max_coalesced_frames;
	port->rx_coalesce_usecs = coal->rx_coalesce_usecs;
	port->rx_max_coalesced_frames = coal->rx_max_coalesced_frames;

	rc = hdev->asic_funcs.set_coalesce(port);

	aux_ops->ctrl_unlock(aux_dev, port_idx);

atomic_out:
	atomic_set(&port->in_reset, 0);
	return rc;
}

void hbl_en_ethtool_init_coalesce(struct hbl_en_port *port)
{
	port->rx_coalesce_usecs = CQ_ARM_TIMEOUT_USEC;
	port->rx_max_coalesced_frames = 1;
	port->tx_max_coalesced_frames = 1;
}

static const struct ethtool_ops hbl_en_ethtool_ops_coalesce = {
	.supported_coalesce_params = ETHTOOL_COALESCE_RX_USECS | ETHTOOL_COALESCE_RX_MAX_FRAMES |
				     ETHTOOL_COALESCE_TX_MAX_FRAMES,
	.get_drvinfo = hbl_en_ethtool_get_drvinfo,
	.get_link = ethtool_op_get_link,
	.get_module_info = hbl_en_ethtool_get_module_info,
	.get_module_eeprom = hbl_en_ethtool_get_module_eeprom,
	.get_priv_flags = hbl_en_ethtool_get_priv_flags,
	.set_priv_flags = hbl_en_ethtool_set_priv_flags,
	.get_link_ksettings = hbl_en_ethtool_get_link_ksettings,
	.set_link_ksettings = hbl_en_ethtool_set_link_ksettings,
	.get_sset_count = hbl_en_ethtool_get_sset_count,
	.get_strings = hbl_en_ethtool_get_strings,
	.get_ethtool_stats = hbl_en_ethtool_get_ethtool_stats,
	.get_coalesce = hbl_en_ethtool_get_coalesce,
	.set_coalesce = hbl_en_ethtool_set_coalesce,
};

const struct ethtool_ops *hbl_en_ethtool_get_ops(struct net_device *ndev)
{
	return &hbl_en_ethtool_ops_coalesce;
}
