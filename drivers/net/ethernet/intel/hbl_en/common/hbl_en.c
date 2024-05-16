// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#include "hbl_en.h"
#include <linux/inetdevice.h>

#define TX_TIMEOUT			(5 * HZ)
#define PORT_RESET_TIMEOUT_MSEC		(60 * 1000ull) /* 60s */

/**
 * struct hbl_en_tx_pkt_work - used to schedule a work of a Tx packet.
 * @tx_work: workqueue object to run when packet needs to be sent.
 * @port: pointer to current port structure.
 * @skb: copy of the packet to send.
 */
struct hbl_en_tx_pkt_work {
	struct work_struct tx_work;
	struct hbl_en_port *port;
	struct sk_buff *skb;
};

static int hbl_en_napi_poll(struct napi_struct *napi, int budget);
static int hbl_en_port_open(struct hbl_en_port *port);

static int hbl_en_ports_reopen(struct hbl_aux_dev *aux_dev)
{
	struct hbl_en_device *hdev = aux_dev->priv;
	struct hbl_en_port *port;
	int rc = 0, i;

	for (i = 0; i < hdev->max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		port = &hdev->ports[i];

		/* It could be that the port was shutdown by 'ip link set down' and there is no need
		 * in reopening it.
		 * Since we mark the ports as in reset even if they are disabled, we clear the flag
		 * here anyway.
		 * See hbl_en_ports_stop_prepare() for more info.
		 */
		if (!netif_running(port->ndev)) {
			atomic_set(&port->in_reset, 0);
			continue;
		}

		rc = hbl_en_port_open(port);

		atomic_set(&port->in_reset, 0);

		if (rc)
			break;
	}

	hdev->in_reset = false;

	return rc;
}

static void hbl_en_port_fini(struct hbl_en_port *port)
{
	if (port->rx_wq)
		destroy_workqueue(port->rx_wq);
}

static int hbl_en_port_init(struct hbl_en_port *port)
{
	struct hbl_en_device *hdev = port->hdev;
	u32 port_idx = port->idx;
	char wq_name[32];
	int rc;

	if (hdev->poll_enable) {
		memset(wq_name, 0, sizeof(wq_name));
		snprintf(wq_name, sizeof(wq_name) - 1, "hbl%u-port%d-rx-wq", hdev->core_dev_id,
			 port_idx);
		port->rx_wq = alloc_ordered_workqueue(wq_name, 0);
		if (!port->rx_wq) {
			dev_err(hdev->dev, "Failed to allocate Rx WQ\n");
			rc = -ENOMEM;
			goto fail;
		}
	}

	hbl_en_ethtool_init_coalesce(port);

	return 0;

fail:
	hbl_en_port_fini(port);

	return rc;
}

static void _hbl_en_set_port_status(struct hbl_en_port *port, bool up)
{
	struct net_device *ndev = port->ndev;
	u32 port_idx = port->idx;

	if (up) {
		netif_carrier_on(ndev);
		netif_wake_queue(ndev);
	} else {
		netif_carrier_off(ndev);
		netif_stop_queue(ndev);
	}

	/* Unless link events are getting through the EQ, no need to print about link down events
	 * during port reset
	 */
	if (port->hdev->has_eq || up || !atomic_read(&port->in_reset))
		netdev_info(port->ndev, "link %s, port %d\n", up ? "up" : "down", port_idx);
}

static void hbl_en_set_port_status(struct hbl_aux_dev *aux_dev, u32 port_idx, bool up)
{
	struct hbl_en_port *port = HBL_EN_PORT(aux_dev, port_idx);

	_hbl_en_set_port_status(port, up);
}

static bool hbl_en_is_port_open(struct hbl_aux_dev *aux_dev, u32 port_idx)
{
	struct hbl_en_port *port = HBL_EN_PORT(aux_dev, port_idx);

	return port->is_initialized;
}

/* get the src IP as it is done in devinet_ioctl() */
static int hbl_en_get_src_ip(struct hbl_aux_dev *aux_dev, u32 port_idx, u32 *src_ip)
{
	struct hbl_en_port *port = HBL_EN_PORT(aux_dev, port_idx);
	struct net_device *ndev = port->ndev;
	struct in_device *in_dev;
	struct in_ifaddr *ifa;
	int rc = 0;

	/* for the case where no src IP is configured */
	*src_ip = 0;

	/* rtnl lock should be acquired in relevant flows before taking configuration lock */
	if (!rtnl_is_locked()) {
		netdev_err(port->ndev, "Rtnl lock is not acquired, can't proceed\n");
		rc = -EFAULT;
		goto out;
	}

	in_dev = __in_dev_get_rtnl(ndev);
	if (!in_dev) {
		netdev_err(port->ndev, "Failed to get IPv4 struct\n");
		rc = -EFAULT;
		goto out;
	}

	ifa = rtnl_dereference(in_dev->ifa_list);

	while (ifa) {
		if (!strcmp(ndev->name, ifa->ifa_label)) {
			/* convert the BE to native and later on it will be
			 * written to the HW as LE in QPC_SET
			 */
			*src_ip = be32_to_cpu(ifa->ifa_local);
			break;
		}
		ifa = rtnl_dereference(ifa->ifa_next);
	}
out:
	return rc;
}

static void hbl_en_reset_stats(struct hbl_aux_dev *aux_dev, u32 port_idx)
{
	struct hbl_en_port *port = HBL_EN_PORT(aux_dev, port_idx);

	port->net_stats.rx_packets = 0;
	port->net_stats.tx_packets = 0;
	port->net_stats.rx_bytes = 0;
	port->net_stats.tx_bytes = 0;
	port->net_stats.tx_errors = 0;
	atomic64_set(&port->net_stats.rx_dropped, 0);
	atomic64_set(&port->net_stats.tx_dropped, 0);
}

static u32 hbl_en_get_mtu(struct hbl_aux_dev *aux_dev, u32 port_idx)
{
	struct hbl_en_port *port = HBL_EN_PORT(aux_dev, port_idx);
	struct net_device *ndev = port->ndev;
	u32 mtu;

	if (atomic_cmpxchg(&port->in_reset, 0, 1)) {
		netdev_err(ndev, "port is in reset, can't get MTU\n");
		return 0;
	}

	mtu = ndev->mtu;

	atomic_set(&port->in_reset, 0);

	return mtu;
}

static u32 hbl_en_get_pflags(struct hbl_aux_dev *aux_dev, u32 port_idx)
{
	struct hbl_en_port *port = HBL_EN_PORT(aux_dev, port_idx);

	return port->pflags;
}

static void hbl_en_set_dev_lpbk(struct hbl_aux_dev *aux_dev, u32 port_idx, bool enable)
{
	struct hbl_en_port *port = HBL_EN_PORT(aux_dev, port_idx);
	struct net_device *ndev = port->ndev;

	if (enable)
		ndev->features |= NETIF_F_LOOPBACK;
	else
		ndev->features &= ~NETIF_F_LOOPBACK;
}

/* This function should be called after ctrl_lock was taken */
static int hbl_en_port_open_locked(struct hbl_en_port *port)
{
	struct hbl_en_device *hdev = port->hdev;
	struct net_device *ndev = port->ndev;
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	u32 port_idx = port->idx;
	int rc;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	if (port->is_initialized)
		return 0;

	if (!hdev->poll_enable)
		netif_napi_add(ndev, &port->napi, hbl_en_napi_poll);

	rc = aux_ops->port_hw_init(aux_dev, port_idx);
	if (rc) {
		netdev_err(ndev, "Failed to configure the HW, rc %d\n", rc);
		goto hw_init_fail;
	}

	if (!hdev->poll_enable)
		napi_enable(&port->napi);

	rc = hdev->asic_funcs.eth_port_open(port);
	if (rc) {
		netdev_err(ndev, "Failed to init H/W, rc %d\n", rc);
		goto port_open_fail;
	}

	rc = aux_ops->update_mtu(aux_dev, port_idx, ndev->mtu);
	if (rc) {
		netdev_err(ndev, "MTU update failed, rc %d\n", rc);
		goto update_mtu_fail;
	}

	rc = aux_ops->phy_init(aux_dev, port_idx);
	if (rc) {
		netdev_err(ndev, "PHY init failed, rc %d\n", rc);
		goto phy_init_fail;
	}

	netif_start_queue(ndev);

	port->is_initialized = true;

	return 0;

phy_init_fail:
	/* no need to revert the MTU change, it will be updated on next port open */
update_mtu_fail:
	hdev->asic_funcs.eth_port_close(port);
port_open_fail:
	if (!hdev->poll_enable)
		napi_disable(&port->napi);

	aux_ops->port_hw_fini(aux_dev, port_idx);
hw_init_fail:
	if (!hdev->poll_enable)
		netif_napi_del(&port->napi);

	return rc;
}

static int hbl_en_port_open(struct hbl_en_port *port)
{
	struct hbl_en_device *hdev = port->hdev;
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	u32 port_idx = port->idx;
	int rc;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	aux_ops->ctrl_lock(aux_dev, port_idx);
	rc = hbl_en_port_open_locked(port);
	aux_ops->ctrl_unlock(aux_dev, port_idx);

	return rc;
}

static int hbl_en_open(struct net_device *netdev)
{
	struct hbl_en_port *port = hbl_netdev_priv(netdev);
	int rc;

	if (atomic_cmpxchg(&port->in_reset, 0, 1)) {
		netdev_err(netdev, "port is in reset, can't open it\n");
		return -EBUSY;
	}

	rc = hbl_en_port_open(port);

	atomic_set(&port->in_reset, 0);

	return rc;
}

/* This function should be called after ctrl_lock was taken */
static void hbl_en_port_close_locked(struct hbl_en_port *port)
{
	struct hbl_en_device *hdev = port->hdev;
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	u32 port_idx = port->idx;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	if (!port->is_initialized)
		return;

	port->is_initialized = false;

	/* verify that the port is marked as closed before continuing */
	mb();

	/* Print if not in hard reset flow e.g. from ip cmd */
	if (!hdev->in_reset && netif_carrier_ok(port->ndev))
		netdev_info(port->ndev, "port was closed\n");

	/* disable the PHY here so no link changes will occur from this point forward */
	aux_ops->phy_fini(aux_dev, port_idx);

	/* disable Tx SW flow */
	netif_carrier_off(port->ndev);
	netif_tx_disable(port->ndev);

	/* stop Tx/Rx HW */
	aux_ops->port_hw_fini(aux_dev, port_idx);

	/* disable Tx/Rx QPs */
	hdev->asic_funcs.eth_port_close(port);

	/* stop Rx SW flow */
	if (hdev->poll_enable) {
		hbl_en_rx_poll_stop(port);
	} else {
		napi_disable(&port->napi);
		netif_napi_del(&port->napi);
	}

	/* Explicitly count the port close operations as we don't get a link event for this.
	 * Upon port open we receive a link event, hence no additional action required.
	 */
	aux_ops->port_toggle_count(aux_dev, port_idx);
}

static void hbl_en_port_close(struct hbl_en_port *port)
{
	struct hbl_en_device *hdev = port->hdev;
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	u32 port_idx = port->idx;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	aux_ops->ctrl_lock(aux_dev, port_idx);
	hbl_en_port_close_locked(port);
	aux_ops->ctrl_unlock(aux_dev, port_idx);
}

/* This function should be called after ctrl_lock was taken */
static int __hbl_en_port_reset_locked(struct hbl_en_port *port)
{
	hbl_en_port_close_locked(port);

	return hbl_en_port_open_locked(port);
}

/* This function should be called after ctrl_lock was taken */
int hbl_en_port_reset_locked(struct hbl_aux_dev *aux_dev, u32 port_idx)
{
	struct hbl_en_port *port = HBL_EN_PORT(aux_dev, port_idx);

	return __hbl_en_port_reset_locked(port);
}

int hbl_en_port_reset(struct hbl_en_port *port)
{
	hbl_en_port_close(port);

	/* Sleep in order to let obsolete events to be dropped before re-opening the port */
	msleep(20);

	return hbl_en_port_open(port);
}

static int hbl_en_close(struct net_device *netdev)
{
	struct hbl_en_port *port = hbl_netdev_priv(netdev);
	struct hbl_en_device *hdev = port->hdev;
	ktime_t timeout;

	/* Looks like the return value of this function is not checked, so we can't just return
	 * EBUSY if the port is under reset. We need to wait until the reset is finished and then
	 * close the port. Otherwise the netdev will set the port as closed although port_close()
	 * wasn't called. Only if we waited long enough and the reset hasn't finished, we can return
	 * an error without actually closing the port as it is a fatal flow anyway.
	 */
	timeout = ktime_add_ms(ktime_get(), PORT_RESET_TIMEOUT_MSEC);
	while (atomic_cmpxchg(&port->in_reset, 0, 1)) {
		/* If this is called from unregister_netdev() then the port was already closed and
		 * hence we can safely return.
		 * We could have just check the port_open boolean, but that might hide some future
		 * bugs. Hence it is better to use a dedicated flag for that.
		 */
		if (READ_ONCE(hdev->in_teardown))
			return 0;

		usleep_range(50, 200);
		if (ktime_compare(ktime_get(), timeout) > 0) {
			netdev_crit(netdev,
				    "Timeout while waiting for port to finish reset, can't close it\n"
				    );
			return -EBUSY;
		}
	}

	hbl_en_port_close(port);

	atomic_set(&port->in_reset, 0);

	return 0;
}

/**
 * hbl_en_ports_stop_prepare() - stop the Rx and Tx and synchronize with other reset flows.
 * @aux_dev: habanalabs auxiliary device structure.
 *
 * This function makes sure that during the reset no packets will be processed and that
 * ndo_open/ndo_close do not open/close the ports.
 * A hard reset might occur right after the driver was loaded, which means before the ports
 * initialization was finished. Therefore, even if the ports are not yet open, we mark it as in
 * reset in order to avoid races. We clear the in reset flag later on when reopening the ports.
 */
static void hbl_en_ports_stop_prepare(struct hbl_aux_dev *aux_dev)
{
	struct hbl_en_device *hdev = aux_dev->priv;
	struct hbl_en_port *port;
	ktime_t timeout;
	int i;

	/* Check if the ports where initialized. If not, we shouldn't mark them as in reset because
	 * they will fail to get opened.
	 */
	if (!hdev->is_initialized || hdev->in_reset)
		return;

	for (i = 0; i < hdev->max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		port = &hdev->ports[i];

		/* This function is competing with reset from ethtool/ip, so try to take the
		 * in_reset atomic and if we are already in a middle of reset, wait until reset
		 * function is finished.
		 * Reset function is designed to always finish (could take up to a few seconds in
		 * worst case).
		 * We mark also closed ports as in reset so they won't be able to get opened while
		 * the device in under reset.
		 */

		timeout = ktime_add_ms(ktime_get(), PORT_RESET_TIMEOUT_MSEC);
		while (atomic_cmpxchg(&port->in_reset, 0, 1)) {
			usleep_range(50, 200);
			if (ktime_compare(ktime_get(), timeout) > 0) {
				netdev_crit(port->ndev,
					    "Timeout while waiting for port %d to finish reset\n",
					    port->idx);
				break;
			}
		}
	}

	hdev->in_reset = true;
}

static void hbl_en_ports_stop(struct hbl_aux_dev *aux_dev)
{
	struct hbl_en_device *hdev = aux_dev->priv;
	struct hbl_en_port *port;
	int i;

	for (i = 0; i < hdev->max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		port = &hdev->ports[i];

		if (netif_running(port->ndev))
			hbl_en_port_close(port);
	}
}

static int hbl_en_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct hbl_en_port *port = hbl_netdev_priv(netdev);
	int rc = 0;

	if (atomic_cmpxchg(&port->in_reset, 0, 1)) {
		netdev_err(netdev, "port is in reset, can't change MTU\n");
		return -EBUSY;
	}

	if (netif_running(port->ndev)) {
		hbl_en_port_close(port);

		/* Sleep in order to let obsolete events to be dropped before re-opening the port */
		msleep(20);

		netdev->mtu = new_mtu;

		rc = hbl_en_port_open(port);
		if (rc)
			netdev_err(netdev, "Failed to reinit port for MTU change, rc %d\n", rc);
	} else {
		netdev->mtu = new_mtu;
	}

	atomic_set(&port->in_reset, 0);

	return rc;
}

/* Swap source and destination MAC addresses */
static inline void swap_l2(char *buf)
{
	u16 *eth_hdr, tmp;

	eth_hdr = (u16 *)buf;
	tmp = eth_hdr[0];
	eth_hdr[0] = eth_hdr[3];
	eth_hdr[3] = tmp;
	tmp = eth_hdr[1];
	eth_hdr[1] = eth_hdr[4];
	eth_hdr[4] = tmp;
	tmp = eth_hdr[2];
	eth_hdr[2] = eth_hdr[5];
	eth_hdr[5] = tmp;
}

/* Swap source and destination IP addresses
 */
static inline void swap_l3(char *buf)
{
	u32 tmp;

	/* skip the Ethernet header and the IP header till source IP address */
	buf += ETH_HLEN + 12;
	tmp = ((u32 *)buf)[0];
	((u32 *)buf)[0] = ((u32 *)buf)[1];
	((u32 *)buf)[1] = tmp;
}

static void do_tx_swap(struct hbl_en_port *port, struct sk_buff *skb)
{
	struct hbl_en_device *hdev = port->hdev;
	u16 *tmp_buff = (u16 *)skb->data;
	u32 port_idx = port->idx;

	/* First, let's print the SKB we got */
	dev_dbg_ratelimited(hdev->dev,
			    "Send [P%d]: dst-mac:%04x%04x%04x, src-mac:%04x%04x%04x, eth-type:%04x, len:%u\n",
			    port_idx, swab16(tmp_buff[0]), swab16(tmp_buff[1]), swab16(tmp_buff[2]),
			    swab16(tmp_buff[3]), swab16(tmp_buff[4]), swab16(tmp_buff[5]),
			    swab16(tmp_buff[6]), skb->len);

	/* Before submit it to HW, in case this is ipv4 pkt, swap eth/ip addresses.
	 * that way, we may send ECMP (ping) to ourselves in LB cases.
	 */
	swap_l2(skb->data);
	if (swab16(tmp_buff[6]) == ETH_P_IP)
		swap_l3(skb->data);
}

static bool is_pkt_swap_enabled(struct hbl_en_device *hdev)
{
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	return aux_ops->is_eth_lpbk(aux_dev);
}

static bool is_tx_disabled(struct hbl_en_port *port)
{
	struct hbl_en_device *hdev = port->hdev;
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	u32 port_idx = port->idx;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	return aux_ops->get_mac_lpbk(aux_dev, port_idx) && !is_pkt_swap_enabled(hdev);
}

static netdev_tx_t hbl_en_handle_tx(struct hbl_en_port *port, struct sk_buff *skb)
{
	struct hbl_en_device *hdev = port->hdev;
	netdev_tx_t ret;

	if (skb->len <= 0 || is_tx_disabled(port))
		goto free_skb;

	if (skb->len > hdev->max_frm_len) {
		netdev_err(port->ndev, "Tx pkt size %uB exceeds maximum of %uB\n", skb->len,
			   hdev->max_frm_len);
		goto free_skb;
	}

	if (is_pkt_swap_enabled(hdev))
		do_tx_swap(port, skb);

	/* Pad the ethernet packets to the minimum frame size as the NIC hw doesn't do it.
	 * eth_skb_pad() frees the packet on failure, so just increment the dropped counter and
	 * return as success to avoid a retry.
	 */
	if (skb_put_padto(skb, hdev->pad_size)) {
		dev_err_ratelimited(hdev->dev, "Padding failed, the skb is dropped\n");
		atomic64_inc(&port->net_stats.tx_dropped);
		return NETDEV_TX_OK;
	}

	ret = hdev->asic_funcs.write_pkt_to_hw(port, skb);
	if (ret == NETDEV_TX_OK) {
		port->net_stats.tx_packets++;
		port->net_stats.tx_bytes += skb->len;
	}

	return ret;

free_skb:
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static netdev_tx_t hbl_en_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct hbl_en_port *port = hbl_netdev_priv(netdev);
	struct hbl_en_device *hdev;

	hdev = port->hdev;

	return hbl_en_handle_tx(port, skb);
}

static int hbl_en_set_port_mac_loopback(struct hbl_en_port *port, bool enable)
{
	struct hbl_en_device *hdev = port->hdev;
	struct net_device *ndev = port->ndev;
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	u32 port_idx = port->idx;
	int rc;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	rc = aux_ops->set_mac_lpbk(aux_dev, port_idx, enable);
	if (rc)
		return rc;

	netdev_info(ndev, "port %u: mac loopback is %s\n", port_idx,
		    enable ? "enabled" : "disabled");

	if (netif_running(ndev)) {
		rc = hbl_en_port_reset(port);
		if (rc) {
			netdev_err(ndev, "Failed to reset port %u, rc %d\n", port_idx, rc);
			return rc;
		}
	}

	return 0;
}

static int hbl_en_set_features(struct net_device *netdev, netdev_features_t features)
{
	struct hbl_en_port *port = hbl_netdev_priv(netdev);
	netdev_features_t changed;
	int rc = 0;

	if (atomic_cmpxchg(&port->in_reset, 0, 1)) {
		netdev_err(netdev, "port %d is in reset, can't update settings", port->idx);
		return -EBUSY;
	}

	changed = netdev->features ^ features;

	if (changed & NETIF_F_LOOPBACK)
		rc = hbl_en_set_port_mac_loopback(port, !!(features & NETIF_F_LOOPBACK));

	atomic_set(&port->in_reset, 0);

	return rc;
}

static void hbl_en_handle_tx_timeout(struct net_device *netdev, unsigned int txqueue)
{
	struct hbl_en_port *port = hbl_netdev_priv(netdev);

	port->net_stats.tx_errors++;
	atomic64_inc(&port->net_stats.tx_dropped);
}

static void hbl_en_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	struct hbl_en_port *port = hbl_netdev_priv(dev);

	stats->rx_bytes = port->net_stats.rx_bytes;
	stats->tx_bytes = port->net_stats.tx_bytes;
	stats->rx_packets = port->net_stats.rx_packets;
	stats->tx_packets = port->net_stats.tx_packets;
	stats->tx_errors = port->net_stats.tx_errors;
	stats->tx_dropped = (u64)atomic64_read(&port->net_stats.tx_dropped);
	stats->rx_dropped = (u64)atomic64_read(&port->net_stats.rx_dropped);
}

static const struct net_device_ops hbl_en_netdev_ops = {
	.ndo_open = hbl_en_open,
	.ndo_stop = hbl_en_close,
	.ndo_start_xmit = hbl_en_start_xmit,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_change_mtu = hbl_en_change_mtu,
	.ndo_set_features = hbl_en_set_features,
	.ndo_get_stats64 = hbl_en_get_stats64,
	.ndo_tx_timeout = hbl_en_handle_tx_timeout,
};

static void hbl_en_set_ops(struct net_device *ndev)
{
	ndev->netdev_ops = &hbl_en_netdev_ops;
	ndev->ethtool_ops = hbl_en_ethtool_get_ops(ndev);
#ifdef CONFIG_DCB
	ndev->dcbnl_ops = &hbl_en_dcbnl_ops;
#endif
}

static int hbl_en_port_register(struct hbl_en_port *port)
{
	struct hbl_en_device *hdev = port->hdev;
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	u32 port_idx = port->idx;
	struct hbl_en_port **ptr;
	struct net_device *ndev;
	int rc;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	ndev = alloc_etherdev(sizeof(struct hbl_en_port *));
	if (!ndev) {
		dev_err(hdev->dev, "netdevice %d alloc failed\n", port_idx);
		return -ENOMEM;
	}

	port->ndev = ndev;
	SET_NETDEV_DEV(ndev, &hdev->pdev->dev);
	ptr = netdev_priv(ndev);
	*ptr = port;

	/* necessary for creating multiple interfaces */
	ndev->dev_port = port_idx;

	hbl_en_set_ops(ndev);

	ndev->watchdog_timeo = TX_TIMEOUT;
	ndev->min_mtu = hdev->min_raw_mtu;
	ndev->max_mtu = hdev->max_raw_mtu;

	/* Add loopback capability to the device. */
	ndev->hw_features |= NETIF_F_LOOPBACK;

	/* If this port was set to loopback, set it also to the ndev features */
	if (aux_ops->get_mac_lpbk(aux_dev, port_idx))
		ndev->features |= NETIF_F_LOOPBACK;

	eth_hw_addr_set(ndev, port->mac_addr);

	/* It's more an intelligent poll wherein, we enable the Rx completion EQE event and then
	 * start the poll from there.
	 * Inside the polling thread, we read packets from hardware and then reschedule the poll
	 * only if there are more packets to be processed. Else we re-enable the CQ Arm interrupt
	 * and exit the poll.
	 */
	if (hdev->poll_enable)
		hbl_en_rx_poll_trigger_init(port);

	netif_carrier_off(ndev);

	rc = register_netdev(ndev);
	if (rc) {
		dev_err(hdev->dev, "Could not register netdevice %d\n", port_idx);
		goto err;
	}

	return 0;

err:
	if (ndev) {
		free_netdev(ndev);
		port->ndev = NULL;
	}

	return rc;
}

static void dump_swap_pkt(struct hbl_en_port *port, struct sk_buff *skb)
{
	struct hbl_en_device *hdev = port->hdev;
	u16 *tmp_buff = (u16 *)skb->data;
	u32 port_idx = port->idx;

	/* The SKB is ready now (before stripping-out the L2), print its content */
	dev_dbg_ratelimited(hdev->dev,
			    "Recv [P%d]: dst-mac:%04x%04x%04x, src-mac:%04x%04x%04x, eth-type:%04x, len:%u\n",
			    port_idx, swab16(tmp_buff[0]), swab16(tmp_buff[1]), swab16(tmp_buff[2]),
			    swab16(tmp_buff[3]), swab16(tmp_buff[4]), swab16(tmp_buff[5]),
			    swab16(tmp_buff[6]), skb->len);
}

int hbl_en_handle_rx(struct hbl_en_port *port, int budget)
{
	struct hbl_en_device *hdev = port->hdev;
	enum hbl_en_eth_pkt_status pkt_status;
	struct net_device *ndev = port->ndev;
	int rc, pkt_count = 0;
	struct sk_buff *skb;
	void *pkt_addr;
	u32 pkt_size;

	if (!netif_carrier_ok(ndev))
		return 0;

	while (pkt_count < budget) {
		pkt_status = hdev->asic_funcs.read_pkt_from_hw(port, &pkt_addr, &pkt_size);

		if (pkt_status == ETH_PKT_NONE)
			break;

		pkt_count++;

		if (pkt_status == ETH_PKT_DROP) {
			atomic64_inc(&port->net_stats.rx_dropped);
			continue;
		}

		if (hdev->poll_enable)
			skb = __netdev_alloc_skb_ip_align(ndev, pkt_size, GFP_KERNEL);
		else
			skb = napi_alloc_skb(&port->napi, pkt_size);

		if (!skb) {
			atomic64_inc(&port->net_stats.rx_dropped);
			break;
		}

		skb_copy_to_linear_data(skb, pkt_addr, pkt_size);
		skb_put(skb, pkt_size);

		if (is_pkt_swap_enabled(hdev))
			dump_swap_pkt(port, skb);

		skb->protocol = eth_type_trans(skb, ndev);

		/* Zero the packet buffer memory to avoid leak in case of wrong
		 * size is used when next packet populates the same memory
		 */
		memset(pkt_addr, 0, pkt_size);

		/* polling is done in thread context and hence BH should be disabled */
		if (hdev->poll_enable)
			local_bh_disable();

		rc = netif_receive_skb(skb);

		if (hdev->poll_enable)
			local_bh_enable();

		if (rc == NET_RX_SUCCESS) {
			port->net_stats.rx_packets++;
			port->net_stats.rx_bytes += pkt_size;
		} else {
			atomic64_inc(&port->net_stats.rx_dropped);
		}
	}

	return pkt_count;
}

static bool __hbl_en_rx_poll_schedule(struct hbl_en_port *port, unsigned long delay)
{
	return queue_delayed_work(port->rx_wq, &port->rx_poll_work, delay);
}

static void hbl_en_rx_poll_work(struct work_struct *work)
{
	struct hbl_en_port *port = container_of(work, struct hbl_en_port, rx_poll_work.work);
	struct hbl_en_device *hdev = port->hdev;
	int pkt_count;

	pkt_count = hbl_en_handle_rx(port, NAPI_POLL_WEIGHT);

	/* Reschedule the poll if we have consumed budget which means we still have packets to
	 * process. Else re-enable the Rx IRQs and exit the work.
	 */
	if (pkt_count < NAPI_POLL_WEIGHT)
		hdev->asic_funcs.reenable_rx_irq(port);
	else
		__hbl_en_rx_poll_schedule(port, 0);
}

/* Rx poll init and trigger routines are used in event-driven setups where
 * Rx polling is initialized once during init or open and started/triggered by the event handler.
 */
void hbl_en_rx_poll_trigger_init(struct hbl_en_port *port)
{
	INIT_DELAYED_WORK(&port->rx_poll_work, hbl_en_rx_poll_work);
}

bool hbl_en_rx_poll_start(struct hbl_en_port *port)
{
	return __hbl_en_rx_poll_schedule(port, msecs_to_jiffies(1));
}

void hbl_en_rx_poll_stop(struct hbl_en_port *port)
{
	cancel_delayed_work_sync(&port->rx_poll_work);
}

static int hbl_en_napi_poll(struct napi_struct *napi, int budget)
{
	struct hbl_en_port *port = container_of(napi, struct hbl_en_port, napi);
	struct hbl_en_device *hdev = port->hdev;
	int pkt_count;

	/* exit if we are called by netpoll as we free the Tx ring via EQ (if enabled) */
	if (!budget)
		return 0;

	pkt_count = hbl_en_handle_rx(port, budget);

	/* If budget not fully consumed, exit the polling mode */
	if (pkt_count < budget) {
		napi_complete_done(napi, pkt_count);
		hdev->asic_funcs.reenable_rx_irq(port);
	}

	return pkt_count;
}

static void hbl_en_port_unregister(struct hbl_en_port *port)
{
	struct net_device *ndev = port->ndev;

	unregister_netdev(ndev);
	free_netdev(ndev);
	port->ndev = NULL;
}

static int hbl_en_set_asic_funcs(struct hbl_en_device *hdev)
{
	switch (hdev->asic_type) {
	case HBL_ASIC_GAUDI2:
		gaudi2_en_set_asic_funcs(hdev);
		break;
	default:
		dev_err(hdev->dev, "Unrecognized ASIC type %d\n", hdev->asic_type);
		return -EINVAL;
	}

	return 0;
}

static void hbl_en_handle_eqe(struct hbl_aux_dev *aux_dev, u32 port, struct hbl_cn_eqe *eqe)
{
	struct hbl_en_device *hdev = aux_dev->priv;

	hdev->asic_funcs.handle_eqe(aux_dev, port, eqe);
}

static void hbl_en_set_aux_ops(struct hbl_en_device *hdev, bool enable)
{
	struct hbl_en_aux_ops *aux_ops = hdev->aux_dev->aux_ops;

	if (enable) {
		aux_ops->ports_reopen = hbl_en_ports_reopen;
		aux_ops->ports_stop_prepare = hbl_en_ports_stop_prepare;
		aux_ops->ports_stop = hbl_en_ports_stop;
		aux_ops->set_port_status = hbl_en_set_port_status;
		aux_ops->is_port_open = hbl_en_is_port_open;
		aux_ops->get_src_ip = hbl_en_get_src_ip;
		aux_ops->reset_stats = hbl_en_reset_stats;
		aux_ops->get_mtu = hbl_en_get_mtu;
		aux_ops->get_pflags = hbl_en_get_pflags;
		aux_ops->set_dev_lpbk = hbl_en_set_dev_lpbk;
		aux_ops->handle_eqe = hbl_en_handle_eqe;
	} else {
		aux_ops->ports_reopen = NULL;
		aux_ops->ports_stop_prepare = NULL;
		aux_ops->ports_stop = NULL;
		aux_ops->set_port_status = NULL;
		aux_ops->is_port_open = NULL;
		aux_ops->get_src_ip = NULL;
		aux_ops->reset_stats = NULL;
		aux_ops->get_mtu = NULL;
		aux_ops->get_pflags = NULL;
		aux_ops->set_dev_lpbk = NULL;
		aux_ops->handle_eqe = NULL;
	}
}

int hbl_en_dev_init(struct hbl_en_device *hdev)
{
	struct hbl_en_asic_funcs *asic_funcs = &hdev->asic_funcs;
	struct hbl_en_port *port;
	int rc, i, port_cnt = 0;

	/* must be called before the call to dev_init() */
	rc = hbl_en_set_asic_funcs(hdev);
	if (rc) {
		dev_err(hdev->dev, "failed to set aux ops\n");
		return rc;
	}

	rc = asic_funcs->dev_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "device init failed\n");
		return rc;
	}

	/* init the function pointers here before calling hbl_en_port_register which sets up
	 * net_device_ops, and its ops might start getting called.
	 * If any failure is encountered, these will be made NULL and the core driver won't call
	 * them.
	 */
	hbl_en_set_aux_ops(hdev, true);

	/* Port register depends on the above initialization so it must be called here and not
	 * before that.
	 */
	for (i = 0; i < hdev->max_num_of_ports; i++, port_cnt++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		port = &hdev->ports[i];

		rc = hbl_en_port_init(port);
		if (rc) {
			dev_err(hdev->dev, "port init failed\n");
			goto unregister_ports;
		}

		rc = hbl_en_port_register(port);
		if (rc) {
			dev_err(hdev->dev, "port register failed\n");

			hbl_en_port_fini(port);
			goto unregister_ports;
		}
	}

	hdev->is_initialized = true;

	return 0;

unregister_ports:
	for (i = 0; i < port_cnt; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		port = &hdev->ports[i];

		hbl_en_port_unregister(port);
		hbl_en_port_fini(port);
	}

	hbl_en_set_aux_ops(hdev, false);

	asic_funcs->dev_fini(hdev);

	return rc;
}

void hbl_en_dev_fini(struct hbl_en_device *hdev)
{
	struct hbl_en_asic_funcs *asic_funcs = &hdev->asic_funcs;
	struct hbl_en_port *port;
	int i;

	hdev->in_teardown = true;

	if (!hdev->is_initialized)
		return;

	hdev->is_initialized = false;

	for (i = 0; i < hdev->max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		port = &hdev->ports[i];

		/* It could be this cleanup flow is called after a failed init flow.
		 * Hence we need to check that we indeed have a netdev to unregister.
		 */
		if (!port->ndev)
			continue;

		hbl_en_port_unregister(port);
		hbl_en_port_fini(port);
	}

	hbl_en_set_aux_ops(hdev, false);

	asic_funcs->dev_fini(hdev);
}

dma_addr_t hbl_en_dma_map(struct hbl_en_device *hdev, void *addr, int len)
{
	dma_addr_t dma_addr;

	if (hdev->dma_map_support)
		dma_addr = dma_map_single(&hdev->pdev->dev, addr, len, DMA_TO_DEVICE);
	else
		dma_addr = virt_to_phys(addr);

	return dma_addr;
}

void hbl_en_dma_unmap(struct hbl_en_device *hdev, dma_addr_t dma_addr, int len)
{
	if (hdev->dma_map_support)
		dma_unmap_single(&hdev->pdev->dev, dma_addr, len, DMA_TO_DEVICE);
}
