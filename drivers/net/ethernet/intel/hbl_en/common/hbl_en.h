/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#ifndef HABANALABS_EN_H_
#define HABANALABS_EN_H_

#include <linux/net/intel/cn.h>

#include <linux/netdevice.h>
#include <linux/pci.h>

#define HBL_EN_NAME			"habanalabs_en"

#define HBL_EN_PORT(aux_dev, idx)	(&(((struct hbl_en_device *)(aux_dev)->priv)->ports[(idx)]))

#define hbl_netdev_priv(ndev) \
({ \
	typecheck(struct net_device *, ndev); \
	*(struct hbl_en_port **)netdev_priv(ndev); \
})

/**
 * enum hbl_en_eth_pkt_status - status of Rx Ethernet packet.
 * ETH_PKT_OK: packet was received successfully.
 * ETH_PKT_DROP: packet should be dropped.
 * ETH_PKT_NONE: no available packet.
 */
enum hbl_en_eth_pkt_status {
	ETH_PKT_OK,
	ETH_PKT_DROP,
	ETH_PKT_NONE
};

/**
 * struct hbl_en_net_stats - stats of Ethernet interface.
 * rx_packets: number of packets received.
 * tx_packets: number of packets sent.
 * rx_bytes: total bytes of data received.
 * tx_bytes: total bytes of data sent.
 * tx_errors: number of errors in the TX.
 * rx_dropped: number of packets dropped by the RX.
 * tx_dropped: number of packets dropped by the TX.
 */
struct hbl_en_net_stats {
	u64 rx_packets;
	u64 tx_packets;
	u64 rx_bytes;
	u64 tx_bytes;
	u64 tx_errors;
	atomic64_t rx_dropped;
	atomic64_t tx_dropped;
};

/**
 * struct hbl_en_port - manage port common structure.
 * @hdev: habanalabs Ethernet device structure.
 * @ndev: network device.
 * @rx_wq: WQ for Rx poll when we cannot schedule NAPI poll.
 * @mac_addr: HW MAC addresses.
 * @asic_specific: ASIC specific port structure.
 * @napi: New API structure.
 * @rx_poll_work: Rx work for polling mode.
 * @net_stats: statistics of the ethernet interface.
 * @in_reset: true if the NIC was marked as in reset, false otherwise. Used to avoid an additional
 *            stopping of the NIC if a hard reset was re-initiated.
 * @pflags: ethtool private flags bit mask.
 * @idx: index of this specific port.
 * @rx_max_coalesced_frames: Maximum number of packets to receive before an RX interrupt.
 * @tx_max_coalesced_frames: Maximum number of packets to be sent before a TX interrupt.
 * @rx_coalesce_usecs: How many usecs to delay an RX interrupt after a packet arrives.
 * @is_initialized: true if the port H/W is initialized, false otherwise.
 * @pfc_enable: true if this port supports Priority Flow Control, false otherwise.
 * @auto_neg_enable: is autoneg enabled.
 * @auto_neg_resolved: was autoneg phase finished successfully.
 */
struct hbl_en_port {
	struct hbl_en_device *hdev;
	struct net_device *ndev;
	struct workqueue_struct *rx_wq;
	char *mac_addr;
	void *asic_specific;
	struct napi_struct napi;
	struct delayed_work rx_poll_work;
	struct hbl_en_net_stats net_stats;
	atomic_t in_reset;
	u32 pflags;
	u32 idx;
	u32 rx_max_coalesced_frames;
	u32 tx_max_coalesced_frames;
	u16 rx_coalesce_usecs;
	u8 is_initialized;
	u8 pfc_enable;
	u8 auto_neg_enable;
	u8 auto_neg_resolved;
};

/**
 * struct hbl_en_asic_funcs - ASIC specific Ethernet functions.
 * @dev_init: device init.
 * @dev_fini: device cleanup.
 * @reenable_rx_irq: re-enable Rx interrupts.
 * @eth_port_open: initialize and open the Ethernet port.
 * @eth_port_close: close the Ethernet port.
 * @write_pkt_to_hw: write skb to HW.
 * @read_pkt_from_hw: read pkt from HW.
 * @get_pfc_cnts: get PFC counters.
 * @set_coalesce: set Tx/Rx coalesce config in HW.
 * @get_rx_ring size: get max number of elements the Rx ring can contain.
 * @handle_eqe: Handle a received event.
 */
struct hbl_en_asic_funcs {
	int (*dev_init)(struct hbl_en_device *hdev);
	void (*dev_fini)(struct hbl_en_device *hdev);
	void (*reenable_rx_irq)(struct hbl_en_port *port);
	int (*eth_port_open)(struct hbl_en_port *port);
	void (*eth_port_close)(struct hbl_en_port *port);
	netdev_tx_t (*write_pkt_to_hw)(struct hbl_en_port *port, struct sk_buff *skb);
	int (*read_pkt_from_hw)(struct hbl_en_port *port, void **pkt_addr, u32 *pkt_size);
	void (*get_pfc_cnts)(struct hbl_en_port *port, void *ptr);
	int (*set_coalesce)(struct hbl_en_port *port);
	int (*get_rx_ring_size)(struct hbl_en_port *port);
	void (*handle_eqe)(struct hbl_aux_dev *aux_dev, u32 port_idx, struct hbl_cn_eqe *eqe);
};

/**
 * struct hbl_en_device - habanalabs Ethernet device structure.
 * @pdev: pointer to PCI device.
 * @dev: related kernel basic device structure.
 * @ports: array of all ports manage common structures.
 * @aux_dev: pointer to auxiliary device.
 * @asic_specific: ASIC specific device structure.
 * @fw_ver: FW version.
 * @qsfp_eeprom: QSFPD EEPROM info.
 * @mac_addr: array of all MAC addresses.
 * @asic_funcs: ASIC specific Ethernet functions.
 * @asic_type: ASIC specific type.
 * @ports_mask: mask of available ports.
 * @auto_neg_mask: mask of port with Autonegotiation enabled.
 * @port_reset_timeout: max time in seconds for a port reset flow to finish.
 * @pending_reset_long_timeout: long timeout for pending hard reset to finish in seconds.
 * @max_frm_len: maximum allowed frame length.
 * @raw_elem_size: size of element in raw buffers.
 * @max_raw_mtu: maximum MTU size for raw packets.
 * @min_raw_mtu: minimum MTU size for raw packets.
 * @pad_size: the pad size in bytes for the skb to transmit.
 * @core_dev_id: core device ID.
 * @max_num_of_ports: max number of available ports;
 * @in_reset: is the entire NIC currently under reset.
 * @poll_enable: Enable Rx polling rather than IRQ + NAPI.
 * @in_teardown: true if the NIC is in teardown (during device remove).
 * @is_initialized: was the device initialized successfully.
 * @has_eq: true if event queue is supported.
 * @dma_map_support: HW supports DMA mapping.
 */
struct hbl_en_device {
	struct pci_dev *pdev;
	struct device *dev;
	struct hbl_en_port *ports;
	struct hbl_aux_dev *aux_dev;
	void *asic_specific;
	char *fw_ver;
	char *qsfp_eeprom;
	char *mac_addr;
	struct hbl_en_asic_funcs asic_funcs;
	enum hbl_cn_asic_type asic_type;
	u64 ports_mask;
	u64 auto_neg_mask;
	u32 port_reset_timeout;
	u32 pending_reset_long_timeout;
	u32 max_frm_len;
	u32 raw_elem_size;
	u16 max_raw_mtu;
	u16 min_raw_mtu;
	u16 pad_size;
	u16 core_dev_id;
	u8 max_num_of_ports;
	u8 in_reset;
	u8 poll_enable;
	u8 in_teardown;
	u8 is_initialized;
	u8 has_eq;
	u8 dma_map_support;
};

int hbl_en_dev_init(struct hbl_en_device *hdev);
void hbl_en_dev_fini(struct hbl_en_device *hdev);

const struct ethtool_ops *hbl_en_ethtool_get_ops(struct net_device *ndev);
void hbl_en_ethtool_init_coalesce(struct hbl_en_port *port);

extern const struct dcbnl_rtnl_ops hbl_en_dcbnl_ops;

bool hbl_en_rx_poll_start(struct hbl_en_port *port);
void hbl_en_rx_poll_stop(struct hbl_en_port *port);
void hbl_en_rx_poll_trigger_init(struct hbl_en_port *port);
int hbl_en_port_reset(struct hbl_en_port *port);
int hbl_en_port_reset_locked(struct hbl_aux_dev *aux_dev, u32 port_idx);
int hbl_en_handle_rx(struct hbl_en_port *port, int budget);
dma_addr_t hbl_en_dma_map(struct hbl_en_device *hdev, void *addr, int len);
void hbl_en_dma_unmap(struct hbl_en_device *hdev, dma_addr_t dma_addr, int len);

#endif /* HABANALABS_EN_H_ */
