// SPDX-License-Identifier: GPL-2.0

/* Copyright (C) 2023-2024, Intel Corporation.
 * Copyright 2021-2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "habanalabs_cn.h"

#include <linux/overflow.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/pci.h>

#define NIC_SEQ_RESETS_TIMEOUT_MS	15000 /* 15 seconds */
#define NIC_MAX_SEQ_RESETS		3

/* Use upper bits of mmap offset to store habana CN driver specific information.
 * bits[63:60] - Encode mmap type
 * bits[45:0]  - mmap offset value
 *
 * NOTE: struct vm_area_struct.vm_pgoff uses offset in pages. Hence, these
 *  defines are w.r.t to PAGE_SIZE
 */
#define HL_CN_MMAP_TYPE_SHIFT			(60 - PAGE_SHIFT)
#define HL_CN_MMAP_TYPE_MASK			(0xfull << HL_CN_MMAP_TYPE_SHIFT)
#define HL_CN_MMAP_TYPE_CN_MEM			(0x2ull << HL_CN_MMAP_TYPE_SHIFT)
#define HL_CN_MMAP_TYPE_BLOCK			(0x1ull << HL_CN_MMAP_TYPE_SHIFT)

#define HL_CN_MMAP_OFFSET_VALUE_MASK		(0x0FFFFFFFFFFFull >> PAGE_SHIFT)
#define HL_CN_MMAP_OFFSET_VALUE_GET(off)	((off) & HL_CN_MMAP_OFFSET_VALUE_MASK)

/* SOB mask is not expected to change across ASIC. Hence common defines. */
#define NIC_SOB_INC_MASK		0x80000000
#define NIC_SOB_VAL_MASK		0x7fff

#define NIC_DUMP_QP_SZ			SZ_4K

#define HL_AUX2NIC(aux_dev)	container_of(aux_dev, struct hl_cn_device, en_aux_dev)

#define RAND_STAT_CNT(cnt) \
	do { \
		u32 __cnt = get_random_u32(); \
		(cnt) = __cnt; \
		dev_info(hdev->dev, "port %d, %s: %u\n", port, #cnt, __cnt); \
	} while (0)

struct hl_cn_stat hl_cn_mac_fec_stats[] = {
	{"correctable_errors", 0x2, 0x3},
	{"uncorrectable_errors", 0x4, 0x5}
};

struct hl_cn_stat hl_cn_mac_stats_rx[] = {
	{"etherStatsOctets", 0x0},
	{"OctetsReceivedOK", 0x4},
	{"aAlignmentErrors", 0x8},
	{"aPAUSEMACCtrlFramesReceived", 0xC},
	{"aFrameTooLongErrors", 0x10},
	{"aInRangeLengthErrors", 0x14},
	{"aFramesReceivedOK", 0x18},
	{"aFrameCheckSequenceErrors", 0x1C},
	{"VLANReceivedOK", 0x20},
	{"ifInErrors", 0x24},
	{"ifInUcastPkts", 0x28},
	{"ifInMulticastPkts", 0x2C},
	{"ifInBroadcastPkts", 0x30},
	{"etherStatsDropEvents", 0x34},
	{"etherStatsPkts", 0x38},
	{"etherStatsUndersizePkts", 0x3C},
	{"etherStatsPkts64Octets", 0x40},
	{"etherStatsPkts65to127Octets", 0x44},
	{"etherStatsPkts128to255Octets", 0x48},
	{"etherStatsPkts256to511Octets", 0x4C},
	{"etherStatsPkts512to1023Octets", 0x50},
	{"etherStatsPkts1024to1518Octets", 0x54},
	{"etherStatsPkts1519toMaxOctets", 0x58},
	{"etherStatsOversizePkts", 0x5C},
	{"etherStatsJabbers", 0x60},
	{"etherStatsFragments", 0x64},
	{"aCBFCPAUSEFramesReceived_0", 0x68},
	{"aCBFCPAUSEFramesReceived_1", 0x6C},
	{"aCBFCPAUSEFramesReceived_2", 0x70},
	{"aCBFCPAUSEFramesReceived_3", 0x74},
	{"aCBFCPAUSEFramesReceived_4", 0x78},
	{"aCBFCPAUSEFramesReceived_5", 0x7C},
	{"aCBFCPAUSEFramesReceived_6", 0x80},
	{"aCBFCPAUSEFramesReceived_7", 0x84},
	{"aMACControlFramesReceived", 0x88}
};

struct hl_cn_stat hl_cn_mac_stats_tx[] = {
	{"etherStatsOctets", 0x0},
	{"OctetsTransmittedOK", 0x4},
	{"aPAUSEMACCtrlFramesTransmitted", 0x8},
	{"aFramesTransmittedOK", 0xC},
	{"VLANTransmittedOK", 0x10},
	{"ifOutErrors", 0x14},
	{"ifOutUcastPkts", 0x18},
	{"ifOutMulticastPkts", 0x1C},
	{"ifOutBroadcastPkts", 0x20},
	{"etherStatsPkts64Octets", 0x24},
	{"etherStatsPkts65to127Octets", 0x28},
	{"etherStatsPkts128to255Octets", 0x2C},
	{"etherStatsPkts256to511Octets", 0x30},
	{"etherStatsPkts512to1023Octets", 0x34},
	{"etherStatsPkts1024to1518Octets", 0x38},
	{"etherStatsPkts1519toMaxOctets", 0x3C},
	{"aCBFCPAUSEFramesTransmitted_0", 0x40},
	{"aCBFCPAUSEFramesTransmitted_1", 0x44},
	{"aCBFCPAUSEFramesTransmitted_2", 0x48},
	{"aCBFCPAUSEFramesTransmitted_3", 0x4C},
	{"aCBFCPAUSEFramesTransmitted_4", 0x50},
	{"aCBFCPAUSEFramesTransmitted_5", 0x54},
	{"aCBFCPAUSEFramesTransmitted_6", 0x58},
	{"aCBFCPAUSEFramesTransmitted_7", 0x5C},
	{"aMACControlFramesTransmitted", 0x60},
	{"etherStatsPkts", 0x64}
};

static const char pcs_counters_str[][ETH_GSTRING_LEN] = {
	{"pcs_local_faults"},
	{"pcs_remote_faults"},
	{"pcs_remote_fault_reconfig"},
	{"pcs_link_restores"},
};

static size_t pcs_counters_str_len = ARRAY_SIZE(pcs_counters_str);
size_t hl_cn_mac_fec_stats_len = ARRAY_SIZE(hl_cn_mac_fec_stats);
size_t hl_cn_mac_stats_rx_len = ARRAY_SIZE(hl_cn_mac_stats_rx);
size_t hl_cn_mac_stats_tx_len = ARRAY_SIZE(hl_cn_mac_stats_tx);

static void qps_stop(struct hl_cn_device *hdev);
static void user_cq_destroy(struct kref *kref);
static void hl_cn_reset_stats_counters_port(struct hl_cn_device *hdev, u32 port);
static void hl_cn_late_init(struct hl_cn_device *hdev);
static void hl_cn_late_fini(struct hl_cn_device *hdev);
static int hl_cn_sw_init(struct hl_cn_device *hdev);
static void hl_cn_sw_fini(struct hl_cn_device *hdev);
static void hl_cn_spmu_init(struct hl_cn_port *cn_port, bool full);
static void hl_cn_qps_stop(struct hl_cn_port *cn_port);

static int hl_cn_request_irqs(struct hl_cn_device *hdev)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	return asic_funcs->request_irqs(hdev);
}

static void hl_cn_free_irqs(struct hl_cn_device *hdev)
{
	struct hl_cn_asic_funcs *asic_funcs =  hdev->asic_funcs;

	asic_funcs->free_irqs(hdev);
}

static void hl_cn_synchronize_irqs(struct hl_aux_dev *cn_aux_dev)
{
	struct hl_cn_device *hdev = cn_aux_dev->priv;
	struct hl_cn_asic_funcs *asic_funcs;

	asic_funcs = hdev->asic_funcs;

	asic_funcs->synchronize_irqs(hdev);
}

void hl_cn_get_frac_info(u64 numerator, u64 denominator, u64 *integer, u64 *exp)
{
	u64 high_digit_n, high_digit_d, integer_tmp, exp_tmp;
	u8 num_digits_n, num_digits_d;
	int i;

	num_digits_d = hl_cn_get_num_of_digits(denominator);
	high_digit_d = denominator;
	for (i = 0; i < num_digits_d - 1; i++)
		high_digit_d /= 10;

	integer_tmp = 0;
	exp_tmp = 0;

	if (numerator) {
		num_digits_n = hl_cn_get_num_of_digits(numerator);
		high_digit_n = numerator;
		for (i = 0; i < num_digits_n - 1; i++)
			high_digit_n /= 10;

		exp_tmp = num_digits_d - num_digits_n;

		if (high_digit_n < high_digit_d) {
			high_digit_n *= 10;
			exp_tmp++;
		}

		integer_tmp = div_u64(high_digit_n, high_digit_d);
	}

	*integer = integer_tmp;
	*exp = exp_tmp;
}

int hl_cn_read_spmu_counters(struct hl_cn_port *cn_port, u64 out_data[], u32 *num_out_data)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;
	struct hl_cn_stat *ignore;
	u32 port = cn_port->port;
	int rc;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	aux_ops->spmu_get_stats_info(aux_dev, port, &ignore, num_out_data);

	/* this function can be called from ethtool, get_statistics ioctl and FW status thread */
	mutex_lock(&cn_port->cnt_lock);
	rc = aux_ops->spmu_sample(aux_dev, port, *num_out_data, out_data);
	mutex_unlock(&cn_port->cnt_lock);

	return rc;
}

static int __hl_cn_get_cnts_num(struct hl_cn_port *cn_port)
{
	struct hl_cn_device *hdev = cn_port->hdev;

	return pcs_counters_str_len +
		hdev->asic_funcs->port_funcs->get_cnts_num(cn_port);
}

static void __hl_cn_get_cnts_names(struct hl_cn_port *cn_port, u8 *data)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	int i, len;

	len = ETH_GSTRING_LEN;

	for (i = 0; i < pcs_counters_str_len; i++)
		memcpy(data + i * len, pcs_counters_str[i], ETH_GSTRING_LEN);
	data += i * len;

	hdev->asic_funcs->port_funcs->get_cnts_names(cn_port, data);
}

static void __hl_cn_get_cnts_values(struct hl_cn_port *cn_port, u64 *data)
{
	struct hl_cn_device *hdev = cn_port->hdev;

	data[0] = cn_port->pcs_local_fault_cnt;
	data[1] = cn_port->pcs_remote_fault_cnt;
	data[2] = cn_port->pcs_remote_fault_reconfig_cnt;
	data[3] = cn_port->pcs_link_restore_cnt;
	data += pcs_counters_str_len;

	hdev->asic_funcs->port_funcs->get_cnts_values(cn_port, data);
}

static int __hl_cn_port_hw_init(struct hl_cn_port *cn_port)
{
	struct hl_cn_device *hdev = cn_port->hdev;

	if (cn_port->disabled) {
		dev_err(hdev->dev, "Port %u is disabled\n", cn_port->port);
		return -EPERM;
	}

	hl_cn_reset_stats_counters_port(hdev, cn_port->port);

	return hdev->asic_funcs->port_funcs->port_hw_init(cn_port);
}

static void __hl_cn_port_hw_fini(struct hl_cn_port *cn_port)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_asic_funcs *asic_funcs;

	asic_funcs = hdev->asic_funcs;

	/* in hard reset the QPs were stopped by hl_cn_stop called from halt engines */
	if (hdev->operational)
		hl_cn_qps_stop(cn_port);

	asic_funcs->port_funcs->port_hw_fini(cn_port);
}

bool hl_cn_comp_device_operational(struct hl_cn_device *hdev)
{
	struct hl_aux_dev *aux_dev = hdev->cn_aux_dev;
	struct hl_cn_aux_ops *aux_ops;

	aux_ops = aux_dev->aux_ops;

	return aux_ops->device_operational(aux_dev);
}

void hl_cn_spmu_get_stats_info(struct hl_cn_port *cn_port, struct hl_cn_stat **stats, u32 *n_stats)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;
	u32 port = cn_port->port;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	aux_ops->spmu_get_stats_info(aux_dev, port, stats, n_stats);
}

void *hl_cn_dma_pool_zalloc(struct hl_cn_device *hdev, size_t size, gfp_t mem_flags,
			    dma_addr_t *dma_handle)
{
	struct hl_aux_dev *aux_dev = hdev->cn_aux_dev;
	struct hl_cn_aux_ops *aux_ops;

	aux_ops = aux_dev->aux_ops;

	return aux_ops->dma_pool_zalloc(aux_dev, size, mem_flags, dma_handle);
}

void hl_cn_dma_pool_free(struct hl_cn_device *hdev, void *vaddr, dma_addr_t dma_addr)
{
	struct hl_aux_dev *aux_dev = hdev->cn_aux_dev;
	struct hl_cn_aux_ops *aux_ops;

	aux_ops = aux_dev->aux_ops;

	aux_ops->dma_pool_free(aux_dev, vaddr, dma_addr);
}

static int hl_cn_reserve_dva_block(struct hl_cn_ctx *ctx, u64 size, u64 *dva)
{
	struct hl_cn_device *hdev = ctx->hdev;
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	return aux_ops->vm_reserve_dva_block(aux_dev, ctx->driver_vm_info.vm_handle, size, dva);
}

void hl_cn_unreserve_dva_block(struct hl_cn_ctx *ctx, u64 dva, u64 size)
{
	struct hl_cn_device *hdev = ctx->hdev;
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	aux_ops->vm_unreserve_dva_block(aux_dev, ctx->driver_vm_info.vm_handle, dva, size);
}

int hl_cn_get_hw_block_handle(struct hl_cn_device *hdev, u64 address, u64 *handle)
{
	return hdev->asic_funcs->get_hw_block_handle(hdev, address, handle);
}

int hl_cn_send_cpucp_packet(struct hl_cn_device *hdev, u32 port, enum cpucp_packet_id pkt_id,
			    int val)
{
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return hdev->asic_funcs->port_funcs->send_cpucp_packet(cn_port, pkt_id, val);
}

static bool hl_cn_device_operational(struct hl_aux_dev *aux_dev)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);

	return hdev->operational;
}

static void hl_cn_hw_access_lock(struct hl_aux_dev *aux_dev)
	__acquires(&hdev->hw_access_lock)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);

	mutex_lock(&hdev->hw_access_lock);
}

static void hl_cn_hw_access_unlock(struct hl_aux_dev *aux_dev)
	__releases(&hdev->hw_access_lock)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);

	mutex_unlock(&hdev->hw_access_lock);
}

static bool hl_cn_is_eth_lpbk(struct hl_aux_dev *aux_dev)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);

	return hdev->eth_loopback;
}

static int hl_cn_port_hw_init(struct hl_aux_dev *aux_dev, u32 port)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return __hl_cn_port_hw_init(cn_port);
}

static void hl_cn_port_hw_fini(struct hl_aux_dev *aux_dev, u32 port)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	__hl_cn_port_hw_fini(cn_port);
}

static int hl_cn_phy_port_init(struct hl_aux_dev *aux_dev, u32 port)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return hdev->asic_funcs->port_funcs->phy_port_init(cn_port);
}

static void hl_cn_phy_port_fini(struct hl_aux_dev *aux_dev, u32 port)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	hdev->asic_funcs->port_funcs->phy_port_fini(cn_port);
}

static int hl_cn_set_pfc(struct hl_aux_dev *aux_dev, u32 port, bool enable)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	cn_port->pfc_enable = enable;

	return hdev->asic_funcs->port_funcs->set_pfc(cn_port);
}

static int hl_cn_get_cnts_num(struct hl_aux_dev *aux_dev, u32 port)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return __hl_cn_get_cnts_num(cn_port);
}

static void hl_cn_get_cnts_names(struct hl_aux_dev *aux_dev, u32 port, u8 *data)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	__hl_cn_get_cnts_names(cn_port, data);
}

static void hl_cn_get_cnts_values(struct hl_aux_dev *aux_dev, u32 port, u64 *data)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	__hl_cn_get_cnts_values(cn_port, data);
}

static bool hl_cn_get_mac_lpbk(struct hl_aux_dev *aux_dev, u32 port)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return cn_port->mac_loopback;
}

static int hl_cn_set_mac_lpbk(struct hl_aux_dev *aux_dev, u32 port, bool enable)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	if (atomic_read(&cn_port->num_of_allocated_qps)) {
		dev_dbg(hdev->dev,
			"There are active QPs under this port - Can't %s mac loopback\n",
			enable ? "enable" : "disable");
		return -EBUSY;
	}

	cn_port->mac_loopback = enable;

	if (enable)
		hdev->mac_loopback |= BIT(port);
	else
		hdev->mac_loopback &= ~BIT(port);

	return 0;
}

static int hl_cn_update_mtu(struct hl_aux_dev *aux_dev, u32 port, u32 mtu)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_port *cn_port;
	unsigned long qp_id = 0;
	struct hl_cn_qp *qp;
	int rc = 0;

	cn_port = &hdev->cn_ports[port];
	port_funcs = hdev->asic_funcs->port_funcs;
	mtu += HL_EN_MAX_HEADERS_SZ;

	port_funcs->cfg_lock(cn_port);
	xa_for_each(&cn_port->qp_ids, qp_id, qp) {
		if (qp->mtu_type == MTU_FROM_NETDEV && qp->mtu != mtu) {
			rc = port_funcs->update_qp_mtu(cn_port, qp, mtu);
			if (rc) {
				dev_err(hdev->dev, "Failed to update MTU, port: %d, qpn: %ld, %d\n",
					port, qp_id, rc);
				break;
			}
		}
	}
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int hl_cn_qpc_write(struct hl_aux_dev *aux_dev, u32 port, void *qpc,
			   struct qpc_mask *qpc_mask, u32 qpn, bool is_req)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_port *cn_port;
	int rc;

	cn_port = &hdev->cn_ports[port];
	port_funcs = hdev->asic_funcs->port_funcs;

	port_funcs->cfg_lock(cn_port);
	rc = port_funcs->qpc_write(cn_port, qpc, qpc_mask, qpn, is_req);
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static void hl_cn_ctrl_lock(struct hl_aux_dev *aux_dev, u32 port)
	__acquires(&cn_port->control_lock)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	mutex_lock(&cn_port->control_lock);
}

static void hl_cn_ctrl_unlock(struct hl_aux_dev *aux_dev, u32 port)
	__releases(&cn_port->control_lock)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	mutex_unlock(&cn_port->control_lock);
}

static int hl_cn_dispatcher_register_qp(struct hl_aux_dev *aux_dev, u32 port, u32 asid, u32 qp_id)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return hl_cn_eq_dispatcher_register_qp(cn_port, asid, qp_id);
}

static int hl_cn_dispatcher_unregister_qp(struct hl_aux_dev *aux_dev, u32 port, u32 qp_id)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return hl_cn_eq_dispatcher_unregister_qp(cn_port, qp_id);
}

static u32 hl_cn_get_speed(struct hl_aux_dev *aux_dev, u32 port)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return cn_port->speed;
}

static void hl_cn_track_ext_port_reset(struct hl_aux_dev *aux_dev, u32 port, u32 syndrome)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	hl_cn_track_port_reset(cn_port, syndrome);
}

static void hl_cn_port_toggle_count(struct hl_aux_dev *aux_dev, u32 port)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	cn_port->port_toggle_cnt++;
}

static int hl_cn_en_aux_data_init(struct hl_cn_device *hdev)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	struct hl_en_aux_data *en_aux_data;
	struct hl_cn_properties *cn_props;
	struct hl_en_aux_ops *en_aux_ops;
	struct hl_aux_dev *en_aux_dev;
	char **mac_addr;
	int i;

	en_aux_dev = &hdev->en_aux_dev;
	en_aux_dev->type = HL_AUX_DEV_ETH;
	en_aux_data = en_aux_dev->aux_data;
	en_aux_ops = en_aux_dev->aux_ops;
	cn_props = &hdev->cn_props;

	en_aux_data->pdev = hdev->pdev;
	en_aux_data->dev = hdev->dev;
	en_aux_data->ports_mask = hdev->ext_ports_mask;
	en_aux_data->auto_neg_mask = hdev->auto_neg_mask;
	en_aux_data->minor = hdev->minor;
	en_aux_data->id = hdev->id;
	en_aux_data->fw_ver = hdev->fw_ver;
	en_aux_data->qsfp_eeprom = hdev->cpucp_info->qsfp_eeprom;
	en_aux_data->pending_reset_long_timeout = hdev->pending_reset_long_timeout;
	en_aux_data->max_frm_len = cn_props->max_frm_len;
	en_aux_data->raw_elem_size = cn_props->raw_elem_size;
	en_aux_data->max_raw_mtu = cn_props->max_raw_mtu;
	en_aux_data->min_raw_mtu = cn_props->min_raw_mtu;
	en_aux_data->max_num_of_ports = hdev->cn_props.max_num_of_ports;
	en_aux_data->has_eq = hdev->has_eq;
	en_aux_data->asic_type = hdev->asic_type;

	mac_addr = kcalloc(hdev->cn_props.max_num_of_ports, sizeof(*mac_addr), GFP_KERNEL);
	if (!mac_addr)
		return -ENOMEM;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(en_aux_data->ports_mask & BIT(i)))
			continue;

		mac_addr[i] = hdev->cpucp_info->mac_addrs[i].mac_addr;
	}

	en_aux_data->mac_addr = mac_addr;

	/* set en -> cn ops */
	/* device functions */
	en_aux_ops->device_operational = hl_cn_device_operational;
	en_aux_ops->hw_access_lock = hl_cn_hw_access_lock;
	en_aux_ops->hw_access_unlock = hl_cn_hw_access_unlock;
	en_aux_ops->is_eth_lpbk = hl_cn_is_eth_lpbk;
	/* port functions */
	en_aux_ops->port_hw_init = hl_cn_port_hw_init;
	en_aux_ops->port_hw_fini = hl_cn_port_hw_fini;
	en_aux_ops->phy_init = hl_cn_phy_port_init;
	en_aux_ops->phy_fini = hl_cn_phy_port_fini;
	en_aux_ops->set_pfc = hl_cn_set_pfc;
	en_aux_ops->get_cnts_num = hl_cn_get_cnts_num;
	en_aux_ops->get_cnts_names = hl_cn_get_cnts_names;
	en_aux_ops->get_cnts_values = hl_cn_get_cnts_values;
	en_aux_ops->get_mac_lpbk = hl_cn_get_mac_lpbk;
	en_aux_ops->set_mac_lpbk = hl_cn_set_mac_lpbk;
	en_aux_ops->update_mtu = hl_cn_update_mtu;
	en_aux_ops->qpc_write = hl_cn_qpc_write;
	en_aux_ops->ctrl_lock = hl_cn_ctrl_lock;
	en_aux_ops->ctrl_unlock = hl_cn_ctrl_unlock;
	en_aux_ops->eq_dispatcher_register_qp = hl_cn_dispatcher_register_qp;
	en_aux_ops->eq_dispatcher_unregister_qp = hl_cn_dispatcher_unregister_qp;
	en_aux_ops->get_speed = hl_cn_get_speed;
	en_aux_ops->track_ext_port_reset = hl_cn_track_ext_port_reset;
	en_aux_ops->port_toggle_count = hl_cn_port_toggle_count;

	asic_funcs->set_en_data(hdev);

	return 0;
}

static void hl_cn_en_aux_data_fini(struct hl_cn_device *hdev)
{
	struct hl_aux_dev *aux_dev = &hdev->en_aux_dev;
	struct hl_en_aux_data *aux_data;

	aux_data = aux_dev->aux_data;

	kfree(aux_data->mac_addr);
	aux_data->mac_addr = NULL;
}

static void eth_adev_release(struct device *dev)
{
	struct hl_aux_dev *aux_dev = container_of(dev, struct hl_aux_dev, adev.dev);
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);

	hdev->is_eth_aux_dev_initialized = false;
}

static int hl_cn_en_aux_drv_init(struct hl_cn_device *hdev)
{
	struct hl_aux_dev *aux_dev = &hdev->en_aux_dev;
	struct auxiliary_device *adev;
	int rc;

	rc = hl_cn_en_aux_data_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "eth aux data init failed\n");
		return rc;
	}

	adev = &aux_dev->adev;
	adev->id = hdev->id;
	adev->name = "en";
	adev->dev.parent = hdev->dev;
	adev->dev.release = eth_adev_release;

	rc = auxiliary_device_init(adev);
	if (rc) {
		dev_err(hdev->dev, "eth auxiliary_device_init failed\n");
		goto aux_data_free;
	}

	rc = auxiliary_device_add(adev);
	if (rc) {
		dev_err(hdev->dev, "eth auxiliary_device_add failed\n");
		goto uninit_adev;
	}

	hdev->is_eth_aux_dev_initialized = true;

	return 0;

uninit_adev:
	auxiliary_device_uninit(adev);
aux_data_free:
	hl_cn_en_aux_data_fini(hdev);

	return rc;
}

static void hl_cn_en_aux_drv_fini(struct hl_cn_device *hdev)
{
	struct auxiliary_device *adev;

	if (!hdev->is_eth_aux_dev_initialized)
		return;

	adev = &hdev->en_aux_dev.adev;

	auxiliary_device_delete(adev);
	auxiliary_device_uninit(adev);

	hl_cn_en_aux_data_fini(hdev);
}

void hl_cn_internal_port_fini_locked(struct hl_cn_port *cn_port)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_asic_funcs *asic_funcs;

	asic_funcs = hdev->asic_funcs;

	if (!cn_port->port_open)
		return;

	cn_port->port_open = false;

	/* verify that the port is marked as closed before continuing */
	mb();

	asic_funcs->port_funcs->phy_port_fini(cn_port);

	__hl_cn_port_hw_fini(cn_port);
}

static void hl_cn_internal_ports_fini(struct hl_cn_device *hdev)
{
	struct hl_cn_port *cn_port;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)) || (hdev->ext_ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		mutex_lock(&cn_port->control_lock);

		hl_cn_internal_port_fini_locked(cn_port);

		mutex_unlock(&cn_port->control_lock);
	}
}

static void hl_cn_ports_cancel_status_work(struct hl_cn_device *hdev)
{
	struct hl_cn_port *cn_port;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		cancel_delayed_work_sync(&cn_port->fw_status_work);
	}
}

int hl_cn_internal_port_init_locked(struct hl_cn_port *cn_port)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_asic_funcs *asic_funcs;
	u32 port = cn_port->port;
	int rc;

	asic_funcs = hdev->asic_funcs;

	rc = __hl_cn_port_hw_init(cn_port);
	if (rc) {
		dev_err(hdev->dev, "Failed to configure the HW, port: %d, %d", port, rc);
		return rc;
	}

	rc = asic_funcs->port_funcs->phy_port_init(cn_port);
	if (rc) {
		dev_err(hdev->dev, "Failed to configure the HW, port: %d, %d", port, rc);
		goto phy_fail;
	}

	cn_port->port_open = true;

	return 0;

phy_fail:
	__hl_cn_port_hw_fini(cn_port);

	return rc;
}

static int hl_cn_internal_ports_init(struct hl_cn_device *hdev)
{
	struct hl_cn_port *cn_port;
	u32 port;
	int rc, i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)) || (hdev->ext_ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];
		port = cn_port->port;

		mutex_lock(&cn_port->control_lock);

		rc = hl_cn_internal_port_init_locked(cn_port);
		if (rc) {
			dev_err(hdev->dev, "Failed to configure the HW, port: %d, %d", port, rc);
			mutex_unlock(&cn_port->control_lock);
			goto port_init_fail;
		}

		mutex_unlock(&cn_port->control_lock);
	}

	return 0;

port_init_fail:
	hl_cn_internal_ports_fini(hdev);

	return rc;
}

static int hl_cn_kernel_ctx_init(struct hl_cn_device *hdev)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	return asic_funcs->kernel_ctx_init(hdev, hdev->kernel_asid);
}

static void hl_cn_kernel_ctx_fini(struct hl_cn_device *hdev)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	asic_funcs->kernel_ctx_fini(hdev, hdev->kernel_asid);
}

static void hl_cn_mac_loopback_init(struct hl_cn_port *cn_port)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_en_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;
	u32 port = cn_port->port;
	bool enable;

	aux_dev = &hdev->en_aux_dev;
	aux_ops = aux_dev->aux_ops;

	enable = !!(hdev->mac_loopback & BIT(port));
	cn_port->mac_loopback = enable;

	if (cn_port->eth_enable && aux_ops->set_dev_lpbk)
		aux_ops->set_dev_lpbk(aux_dev, port, enable);
}

static int hl_cn_core_init(struct hl_cn_device *hdev)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	struct hl_cn_macro *cn_macro;
	struct hl_cn_port *cn_port;
	int rc, i, port_cnt = 0;
	u32 port;

	/* RX packet drop config is not preserved across hard reset. */
	hdev->rx_drop_percent = 0;

	if (hdev->phy_load_fw) {
		if (hdev->cn_props.is_phy_fw_binary) {
			rc = hl_cn_phy_has_binary_fw(hdev);
			if (rc) {
				dev_err(hdev->dev, "F/W file was not found\n");
				return rc;
			}
		}

		rc = asic_funcs->phy_fw_load_all(hdev);
		if (rc) {
			dev_err(hdev->dev, "F/W load for all failed\n");
			return rc;
		}
	}

	if (hdev->phy_config_fw)
		dev_dbg(hdev->dev, "F/W CRC: 0x%x\n", asic_funcs->phy_get_crc(hdev));

	for (i = 0; i < hdev->cn_props.num_of_macros; i++) {
		hdev->cn_macros[i].phy_macro_needs_reset = true;
		hdev->cn_macros[i].rec_link_sts = 0;
	}

	memset(hdev->phy_ber_info, 0,
	       hdev->cn_props.max_num_of_lanes * sizeof(struct hl_cn_ber_info));

	rc = asic_funcs->core_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "core init failed\n");
		return rc;
	}

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++, port_cnt++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];
		cn_macro = cn_port->cn_macro;
		port = cn_port->port;

		/* In case this port got disabled, enable it back here */
		cn_port->disabled = false;
		/* Port toggle count should be reinitialized for each port upond hard reset only */
		cn_port->port_toggle_cnt = 0;

		/* Reset the macro PHY once on boot.
		 * This function resets all the 4 lanes in the PHY macro, therefore only one of the
		 * two ports of the macro should call it.
		 */
		if (hdev->phy_config_fw && cn_macro->phy_macro_needs_reset) {
			rc = asic_funcs->phy_reset_macro(cn_macro);
			if (rc) {
				dev_err(hdev->dev, "PHY reset macro failed for port %d\n", port);
				goto err;
			}

			cn_macro->phy_macro_needs_reset = false;
		}

		hl_cn_spmu_init(cn_port, false);

		cn_port->auto_neg_enable = !!(hdev->auto_neg_mask & BIT(port));

		if (!hdev->in_reset)
			cn_port->eth_enable = !!(BIT(port) & hdev->ext_ports_mask);

		/* This function must be called after setting cn_port->eth_enable */
		hl_cn_mac_loopback_init(cn_port);
	}

	return 0;

err:
	asic_funcs->core_fini(hdev);

	return rc;
}

static void hl_cn_core_fini(struct hl_cn_device *hdev)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	asic_funcs->core_fini(hdev);
}

static void wq_arrays_pool_destroy(struct hl_cn_device *hdev)
{
	if (!hdev->wq_arrays_pool_enable)
		return;

	gen_pool_destroy(hdev->wq_arrays_pool);
}

static int wq_arrays_pool_alloc(struct hl_cn_device *hdev)
{
	struct hl_cn_properties *cn_props;
	int rc;

	if (!hdev->wq_arrays_pool_enable)
		return 0;

	cn_props = &hdev->cn_props;

	hdev->wq_arrays_pool = gen_pool_create(ilog2(hdev->cache_line_size), -1);
	if (!hdev->wq_arrays_pool) {
		dev_err(hdev->dev, "Failed to create a pool to manage WQ arrays on HBM\n");
		rc = -ENOMEM;
		goto gen_pool_create_fail;
	}

	gen_pool_set_algo(hdev->wq_arrays_pool, gen_pool_best_fit, NULL);

	rc = gen_pool_add(hdev->wq_arrays_pool, cn_props->wq_base_addr, cn_props->wq_base_size,
			  -1);
	if (rc) {
		dev_err(hdev->dev, "Failed to add memory to the WQ arrays pool\n");
		goto gen_pool_add_fail;
	}

	return 0;

gen_pool_add_fail:
	gen_pool_destroy(hdev->wq_arrays_pool);
gen_pool_create_fail:
	return rc;
}

int __hl_cn_ports_reopen(struct hl_cn_device *hdev)
{
	struct hl_en_aux_ops *aux_ops;
	struct hl_aux_dev *en_aux_dev;
	int rc;

	en_aux_dev = &hdev->en_aux_dev;
	aux_ops = en_aux_dev->aux_ops;

	rc = hl_cn_kernel_ctx_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init kernel context\n");
		return rc;
	}

	rc = hl_cn_core_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init core\n");
		goto core_init_fail;
	}

	rc = hl_cn_internal_ports_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init internal ports\n");
		goto internal_ports_fail;
	}

	hdev->in_reset = false;
	hdev->fw_reset = false;
	hdev->operational = true;

	if (aux_ops->ports_reopen) {
		rc = aux_ops->ports_reopen(en_aux_dev);
		if (rc) {
			dev_err(hdev->dev, "Failed to reopen en ports\n");
			goto en_ports_reopen_fail;
		}
	}

	return 0;

en_ports_reopen_fail:
	hdev->operational = false;
	hl_cn_internal_ports_fini(hdev);
internal_ports_fail:
	hl_cn_core_fini(hdev);
core_init_fail:
	hl_cn_kernel_ctx_fini(hdev);

	return rc;
}

void __hl_cn_stop(struct hl_cn_device *hdev)
{
	struct hl_en_aux_ops *aux_ops;
	struct hl_aux_dev *en_aux_dev;

	en_aux_dev = &hdev->en_aux_dev;
	aux_ops = en_aux_dev->aux_ops;

	/* Cancelling all outstanding works for all ports should be done first when stopping */
	hl_cn_ports_cancel_status_work(hdev);

	qps_stop(hdev);

	if (aux_ops->ports_stop)
		aux_ops->ports_stop(en_aux_dev);

	hl_cn_internal_ports_fini(hdev);
	hl_cn_core_fini(hdev);
	hl_cn_kernel_ctx_fini(hdev);
}

void __hl_cn_hard_reset_prepare(struct hl_cn_device *hdev, bool fw_reset, bool in_teardown)
{
	struct hl_en_aux_ops *aux_ops;
	struct hl_aux_dev *en_aux_dev;

	en_aux_dev = &hdev->en_aux_dev;
	aux_ops = en_aux_dev->aux_ops;

	hdev->in_reset = true;
	hdev->fw_reset = fw_reset;
	hdev->in_teardown = in_teardown;
	hdev->operational = false;

	mutex_lock(&hdev->hw_access_lock);
	mutex_unlock(&hdev->hw_access_lock);

	if (aux_ops->ports_stop_prepare)
		aux_ops->ports_stop_prepare(en_aux_dev);
}

static void hl_cn_get_cpucp_info(struct hl_cn_device *hdev)
{
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	aux_ops->get_cpucp_info(aux_dev, hdev->cpucp_info);
}

static int hl_cn_ports_reopen(struct hl_aux_dev *aux_dev)
{
	struct hl_cn_device *hdev = aux_dev->priv;
	int rc;

	/* update CPUCP info after device reset */
	hl_cn_get_cpucp_info(hdev);

	rc = hl_cn_request_irqs(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to request IRQs\n");
		return rc;
	}

	rc = __hl_cn_ports_reopen(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to reopen ports\n");
		goto free_irqs;
	}

	return 0;

free_irqs:
	hl_cn_free_irqs(hdev);

	return rc;
}

static void hl_cn_stop(struct hl_aux_dev *aux_dev)
{
	struct hl_cn_device *hdev = aux_dev->priv;

	__hl_cn_stop(hdev);

	hl_cn_synchronize_irqs(aux_dev);
	hl_cn_free_irqs(hdev);
}

static void hl_cn_hard_reset_prepare(struct hl_aux_dev *cn_aux_dev, bool fw_reset, bool in_teardown)
{
	struct hl_cn_device *hdev = cn_aux_dev->priv;

	__hl_cn_hard_reset_prepare(hdev, fw_reset, in_teardown);
}

static int hl_cn_set_static_properties(struct hl_cn_device *hdev)
{
	return hdev->asic_funcs->set_static_properties(hdev);
}

static int hl_cn_set_dram_properties(struct hl_cn_device *hdev)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	return asic_funcs->set_dram_properties(hdev);
}

static int hl_cn_set_asic_funcs(struct hl_cn_device *hdev)
{
	switch (hdev->asic_type) {
	case HL_ASIC_GAUDI2:
		gaudi2_cn_set_asic_funcs(hdev);
		break;
	default:
		dev_err(hdev->dev, "Unrecognized ASIC type %d\n", hdev->asic_type);
		return -EINVAL;
	}

	return 0;
}

int hl_cn_dev_init(struct hl_cn_device *hdev)
{
	int rc;

	if (!hdev->ports_mask) {
		dev_err(hdev->dev, "All ports are disabled\n");
		return -EINVAL;
	}

	/* must be called first to init the ASIC funcs */
	rc = hl_cn_set_asic_funcs(hdev);
	if (rc) {
		dev_err(hdev->dev, "failed to set ASIC aux ops\n");
		return rc;
	}

	/* get CPUCP info before initializing the device */
	hl_cn_get_cpucp_info(hdev);

	/* init static cn properties */
	rc = hl_cn_set_static_properties(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to set static properties\n");
		return rc;
	}

	/* init DRAM cn properties */
	rc = hl_cn_set_dram_properties(hdev);
	if (rc) {
		dev_err(hdev->dev, "failed to set DRAM properties\n");
		return rc;
	}

	rc = hl_cn_sw_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "SW init failed\n");
		return rc;
	}

	rc = hl_cn_request_irqs(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to request IRQs\n");
		goto request_irqs_fail;
	}

	rc = hl_cn_kernel_ctx_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init kernel context\n");
		goto kernel_ctx_init_fail;
	}

	rc = hl_cn_core_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init core\n");
		goto core_init_fail;
	}

	rc = hl_cn_internal_ports_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init internal ports\n");
		goto internal_ports_init_fail;
	}

	rc = wq_arrays_pool_alloc(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init WQ arrays pool\n");
		goto wq_arrays_pool_alloc_fail;
	}

	hl_cn_mem_init(hdev);

	hdev->operational = true;

	rc = hl_cn_en_aux_drv_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init Ethernet driver\n");
		goto en_aux_drv_fail;
	}

	hl_cn_late_init(hdev);

	hl_cn_debugfs_dev_init(hdev);

	hdev->is_initialized = true;

	return 0;

en_aux_drv_fail:
	hdev->operational = false;
	hl_cn_mem_fini(hdev);
	wq_arrays_pool_destroy(hdev);
wq_arrays_pool_alloc_fail:
	hl_cn_internal_ports_fini(hdev);
internal_ports_init_fail:
	hl_cn_core_fini(hdev);
core_init_fail:
	hl_cn_kernel_ctx_fini(hdev);
kernel_ctx_init_fail:
	hl_cn_free_irqs(hdev);
request_irqs_fail:
	hl_cn_sw_fini(hdev);

	return rc;
}

void hl_cn_dev_fini(struct hl_cn_device *hdev)
{
	if (!hdev->is_initialized)
		return;

	hdev->is_initialized = false;

	if (hdev->hw_stop_during_teardown) {
		hl_cn_hard_reset_prepare(hdev->cn_aux_dev, false, true);
		hl_cn_stop(hdev->cn_aux_dev);
	}

	hl_cn_debugfs_dev_fini(hdev);

	hl_cn_late_fini(hdev);

	/* must be called after MSI was disabled */
	hl_cn_en_aux_drv_fini(hdev);
	hl_cn_mem_fini(hdev);
	wq_arrays_pool_destroy(hdev);
	hl_cn_sw_fini(hdev);
}

static void cfg_lock_unlock_all(struct hl_cn_device *hdev, bool lock)
{
	struct hl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	struct hl_cn_port *cn_port;
	int i;

	/* no need to check which ports are enabled, all of them have an initialized lock */
	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (hdev->skip_odd_ports_cfg_lock && (i & 1))
			continue;

		cn_port = &hdev->cn_ports[i];

		if (lock)
			port_funcs->cfg_lock(cn_port);
		else
			port_funcs->cfg_unlock(cn_port);
	}
}

void hl_cn_cfg_lock_all(struct hl_cn_device *hdev)
{
	return cfg_lock_unlock_all(hdev, true);
}

void hl_cn_cfg_unlock_all(struct hl_cn_device *hdev)
{
	return cfg_lock_unlock_all(hdev, false);
}

/* must be called under the port cfg lock */
u32 hl_cn_get_max_qp_id(struct hl_cn_port *cn_port)
{
	int max_qp_id = cn_port->qp_idx_offset;
	unsigned long qp_id = 0;
	struct hl_cn_qp *qp;

	xa_for_each(&cn_port->qp_ids, qp_id, qp)
		if (qp->qp_id > max_qp_id)
			max_qp_id = qp->qp_id;

	return max_qp_id;
}

static void hl_cn_qps_stop(struct hl_cn_port *cn_port)
{
	struct hl_cn_asic_port_funcs *port_funcs = cn_port->hdev->asic_funcs->port_funcs;
	struct hl_cn_qpc_drain_attr drain = { .wait_for_idle = false, };
	unsigned long qp_id = 0;
	struct hl_cn_qp *qp;

	port_funcs->cfg_lock(cn_port);

	xa_for_each(&cn_port->qp_ids, qp_id, qp) {
		if (IS_ERR_OR_NULL(qp))
			continue;

		hl_cn_qp_modify(cn_port, qp, CN_QP_STATE_QPD, (void *)&drain);
	}

	port_funcs->cfg_unlock(cn_port);
}

static void qps_stop(struct hl_cn_device *hdev)
{
	struct hl_cn_port *cn_port;
	int i;

	/* stop the QPs */
	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		hl_cn_qps_stop(cn_port);
	}
}

static void user_cq_destroy(struct kref *kref)
{
	struct hl_cn_user_cq *user_cq = container_of(kref, struct hl_cn_user_cq, refcount);
	struct hl_cn_port *cn_port = user_cq->cn_port;
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_asic_port_funcs *port_funcs;

	port_funcs = hdev->asic_funcs->port_funcs;

	/* Destroy the remaining resources allocated during SET state. The below callback needs to
	 * be called only if the CQ moved to unset from set state. This is because, this resource
	 * was created only during set state. If the CQ moved directly to unset from alloc then we
	 * shouldn't be trying to clear the resource.
	 */
	if (user_cq->state == USER_CQ_STATE_SET_TO_UNSET)
		port_funcs->user_cq_destroy(user_cq);

	mutex_destroy(&user_cq->overrun_lock);
	xa_erase(&cn_port->cq_ids, user_cq->id);
	kfree(user_cq);
}

struct hl_cn_user_cq *hl_cn_user_cq_get(struct hl_cn_port *cn_port, u8 cq_id)
{
	struct hl_cn_user_cq *user_cq;

	user_cq = xa_load(&cn_port->cq_ids, cq_id);
	if (!user_cq || user_cq->state != USER_CQ_STATE_SET)
		return NULL;

	kref_get(&user_cq->refcount);

	return user_cq;
}

int hl_cn_user_cq_put(struct hl_cn_user_cq *user_cq)
{
	return kref_put(&user_cq->refcount, user_cq_destroy);
}

static int user_db_fifo_unset_and_free(struct hl_cn_port *cn_port, u32 id,
				       struct hl_cn_db_fifo_xarray_pdata *xa_pdata)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_asic_funcs *asic_funcs;
	int rc = 0;

	asic_funcs = hdev->asic_funcs;

	asic_funcs->port_funcs->db_fifo_unset(cn_port, id, xa_pdata);

	/* Destroy CI buffer if we allocated one.
	 * Note: Not all DB fifo modes need CI memory buffer.
	 * Track CI via sync objects.
	 * If there is an issue in destroying the CI memory, then we might exit this function
	 * without freeing the db_fifo_pool. This would cause a kernel assertion when we try to do
	 * rmmod as the gen_alloc_destroy for db_fifo_pool would fail as there are allocations
	 * still left in the pool. So, the db_fifo_pool needs to be freed irrespective of the ci
	 * memory being destroyed or not.
	 */
	if (xa_pdata->ci_mmap_handle)
		rc = hl_cn_mem_destroy(hdev, xa_pdata->ci_mmap_handle);

	asic_funcs->port_funcs->db_fifo_free(cn_port, xa_pdata->db_pool_addr, xa_pdata->fifo_size);

	return rc;
}

static int __user_db_fifo_unset(struct hl_cn_port *cn_port, u32 id,
				struct hl_cn_db_fifo_xarray_pdata *xa_pdata)
{
	int rc = 0;

	/* User may call unset or the context may be destroyed while a db fifo is still in
	 * allocated state. When we call alloc_user_db_fifo next time, we would skip that
	 * particular id. This way, the id is blocked indefinitely until a full reset is done.
	 * So to fix this issue, we maintain the state of the idr. Perform unset only if set had
	 * been previously done for the idr.
	 */
	if (xa_pdata->state == DB_FIFO_STATE_SET)
		rc = user_db_fifo_unset_and_free(cn_port, id, xa_pdata);

	kfree(xa_pdata);
	xa_erase(&cn_port->db_fifo_ids, id);

	return rc;
}

static void __user_db_fifo_ctx_destroy(struct hl_cn_port *cn_port, struct hl_cn_ctx *ctx)
{
	struct hl_cn_asic_port_funcs *port_funcs = cn_port->hdev->asic_funcs->port_funcs;
	struct hl_cn_db_fifo_xarray_pdata *xa_pdata;
	unsigned long id;

	port_funcs->cfg_lock(cn_port);

	xa_for_each(&cn_port->db_fifo_ids, id, xa_pdata) {
		if (xa_pdata->asid == ctx->asid)
			__user_db_fifo_unset(cn_port, id, xa_pdata);
	}

	port_funcs->cfg_unlock(cn_port);
}

void hl_cn_user_db_fifo_ctx_destroy(struct hl_cn_ctx *ctx)
{
	struct hl_cn_device *hdev = ctx->hdev;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++)
		if (hdev->ports_mask & BIT(i))
			__user_db_fifo_ctx_destroy(&hdev->cn_ports[i], ctx);
}

int hl_cn_alloc_ring(struct hl_cn_device *hdev, struct hl_cn_ring *ring, int elem_size, int count)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	int rc;

	ring->count = count;
	ring->elem_size = elem_size;
	ring->asid = hdev->kernel_asid;

	RING_BUF_SIZE(ring) = elem_size * count;
	RING_BUF_ADDRESS(ring) = asic_funcs->dma_alloc_coherent(hdev, RING_BUF_SIZE(ring),
								&RING_BUF_DMA_ADDRESS(ring),
								GFP_KERNEL);
	if (!RING_BUF_ADDRESS(ring))
		return -ENOMEM;

	/* ring's idx_ptr shall point on pi/ci address */
	RING_PI_SIZE(ring) = sizeof(u64);
	RING_PI_ADDRESS(ring) = hl_cn_dma_pool_zalloc(hdev, RING_PI_SIZE(ring),
						      GFP_KERNEL | __GFP_ZERO,
						      &RING_PI_DMA_ADDRESS(ring));
	if (!RING_PI_ADDRESS(ring)) {
		rc = -ENOMEM;
		goto pi_alloc_fail;
	}

	return 0;

pi_alloc_fail:
	asic_funcs->dma_free_coherent(hdev, RING_BUF_SIZE(ring), RING_BUF_ADDRESS(ring),
				      RING_BUF_DMA_ADDRESS(ring));

	return rc;
}

void hl_cn_free_ring(struct hl_cn_device *hdev, struct hl_cn_ring *ring)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	hl_cn_dma_pool_free(hdev, RING_PI_ADDRESS(ring), RING_PI_DMA_ADDRESS(ring));

	asic_funcs->dma_free_coherent(hdev, RING_BUF_SIZE(ring), RING_BUF_ADDRESS(ring),
				      RING_BUF_DMA_ADDRESS(ring));
}

static int hl_cn_send_port_cpucp_status(struct hl_aux_dev *aux_dev, u32 port, u8 cmd, u8 period)
{
	struct hl_cn_device *hdev = aux_dev->priv;
	struct hl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	if (cmd > HL_CN_STATUS_PERIODIC_STOP) {
		dev_err(hdev->dev, "Received invalid CN status cmd (%d) from F/W, port %d", cmd,
			port);
		return -EINVAL;
	}

	hdev->status_cmd = cmd;
	hdev->status_period = (cmd == HL_CN_STATUS_PERIODIC_START) ? period : 0;

	if (cmd == HL_CN_STATUS_PERIODIC_STOP)
		cancel_delayed_work_sync(&cn_port->fw_status_work);
	else
		queue_delayed_work(cn_port->wq, &cn_port->fw_status_work, 0);

	return 0;
}

static int hl_cn_mmap(struct hl_aux_dev *aux_dev, u32 asid, struct vm_area_struct *vma)
{
	struct hl_cn_device *hdev = aux_dev->priv;

	return hl_cn_mem_mmap(hdev, vma);
}

static void hl_cn_randomize_status_cnts(struct hl_cn_port *cn_port,
					struct hl_cn_cpucp_status *status)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	u32 port = cn_port->port;

	RAND_STAT_CNT(status->high_ber_reinit);
	RAND_STAT_CNT(status->correctable_err_cnt);
	RAND_STAT_CNT(status->uncorrectable_err_cnt);
	RAND_STAT_CNT(status->bad_format_cnt);
	RAND_STAT_CNT(status->responder_out_of_sequence_psn_cnt);
}

static void hl_cn_get_status(struct hl_cn_port *cn_port, struct hl_cn_cpucp_status *status)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	u32 port = cn_port->port;

	/* Port toggle counter should always be filled regardless of the logical state of the port.
	 * We should not count the first toggle, as it marks that port was brought up for
	 * the first time. In case port connection wasn't established, the counter should be 0.
	 */
	status->port_toggle_cnt = cn_port->port_toggle_cnt ? cn_port->port_toggle_cnt - 1 : 0;

	status->port = port;
	status->up = hl_cn_is_port_open(cn_port);

	if (!status->up)
		return;

	status->pcs_link = cn_port->pcs_link;
	status->phy_ready = cn_port->phy_fw_tuned;
	status->auto_neg = cn_port->auto_neg_enable;

	if (hdev->rand_status) {
		hl_cn_randomize_status_cnts(cn_port, status);
		return;
	}

	status->high_ber_reinit = cn_port->pcs_remote_fault_reconfig_cnt;

	/* Each ASIC will fill the rest of the statistics */
	hdev->asic_funcs->port_funcs->get_status(cn_port, status);
}

static void hl_cn_convert_cpucp_status(struct cpucp_nic_status *to,
				       struct hl_cn_cpucp_status *from)
{
	to->port = cpu_to_le32(from->port);
	to->bad_format_cnt = cpu_to_le32(from->bad_format_cnt);
	to->responder_out_of_sequence_psn_cnt =
					cpu_to_le32(from->responder_out_of_sequence_psn_cnt);
	to->high_ber_reinit = cpu_to_le32(from->high_ber_reinit);
	to->correctable_err_cnt = cpu_to_le32(from->correctable_err_cnt);
	to->uncorrectable_err_cnt = cpu_to_le32(from->uncorrectable_err_cnt);
	to->retraining_cnt = cpu_to_le32(from->retraining_cnt);
	to->up = from->up;
	to->pcs_link = from->pcs_link;
	to->phy_ready = from->phy_ready;
	to->auto_neg = from->auto_neg;
	to->timeout_retransmission_cnt = cpu_to_le32(from->timeout_retransmission_cnt);
	to->high_ber_cnt = cpu_to_le32(from->high_ber_cnt);
	to->pre_fec_ser.integer = cpu_to_le16(from->pre_fec_ser.integer);
	to->pre_fec_ser.exp = cpu_to_le16(from->pre_fec_ser.exp);
	to->post_fec_ser.integer = cpu_to_le16(from->post_fec_ser.integer);
	to->post_fec_ser.exp = cpu_to_le16(from->post_fec_ser.exp);
	to->bandwidth.integer = cpu_to_le16(from->bandwidth.integer);
	to->bandwidth.frac = cpu_to_le16(from->bandwidth.frac);
	to->lat.integer = cpu_to_le16(from->lat.integer);
	to->lat.frac = cpu_to_le16(from->lat.frac);
	to->port_toggle_cnt = cpu_to_le32(from->port_toggle_cnt);
}

static int hl_cn_send_cpucp_status(struct hl_cn_device *hdev, u32 port,
				   struct hl_cn_cpucp_status *cn_status)
{
	struct hl_cn_properties *cn_props;
	struct cpucp_nic_status_packet *pkt;
	struct cpucp_nic_status status = {};
	size_t total_pkt_size, data_size;
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;
	u64 result;
	int rc;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;
	cn_props = &hdev->cn_props;
	data_size = cn_props->status_packet_size;

	total_pkt_size = sizeof(struct cpucp_nic_status_packet) + data_size;

	/* data should be aligned to 8 bytes in order to CPU-CP to copy it */
	total_pkt_size = (total_pkt_size + 0x7) & ~0x7;

	/* total_pkt_size is casted to u16 later on */
	if (total_pkt_size > USHRT_MAX) {
		dev_err(hdev->dev, "NIC status data is too big\n");
		rc = -EINVAL;
		goto out;
	}

	pkt = kzalloc(total_pkt_size, GFP_KERNEL);
	if (!pkt) {
		rc = -ENOMEM;
		goto out;
	}

	hl_cn_convert_cpucp_status(&status, cn_status);

	pkt->length = cpu_to_le32(data_size / sizeof(u32));
	memcpy(&pkt->data, &status, data_size);

	pkt->cpucp_pkt.ctl = cpu_to_le32(CPUCP_PACKET_NIC_STATUS << CPUCP_PKT_CTL_OPCODE_SHIFT);

	rc = aux_ops->send_cpu_message(aux_dev, (u32 *)pkt, total_pkt_size, 0, &result);

	if (rc)
		dev_err(hdev->dev, "failed to send NIC status, port %d\n", port);

	kfree(pkt);
out:
	aux_ops->post_send_status(aux_dev, port);

	return rc;
}

static void fw_status_work(struct work_struct *work)
{
	struct hl_cn_port *cn_port = container_of(work, struct hl_cn_port, fw_status_work.work);
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_cpucp_status status = {0};
	u32 port = cn_port->port;
	int rc;

	hl_cn_get_status(cn_port, &status);

	rc = hl_cn_send_cpucp_status(hdev, port, &status);
	if (rc)
		return;

	if (hdev->status_cmd == HL_CN_STATUS_PERIODIC_START)
		queue_delayed_work(cn_port->wq, &cn_port->fw_status_work,
				   msecs_to_jiffies(hdev->status_period * 1000));
}

static void cn_port_sw_fini(struct hl_cn_port *cn_port)
{
	struct hl_cn_asic_funcs *asic_funcs = cn_port->hdev->asic_funcs;

	if (!cn_port->sw_initialized)
		return;

	cn_port->sw_initialized = false;

	asic_funcs->port_funcs->port_sw_fini(cn_port);

	xa_destroy(&cn_port->cq_ids);
	xa_destroy(&cn_port->encap_ids);
	xa_destroy(&cn_port->db_fifo_ids);
	xa_destroy(&cn_port->qp_ids);

	mutex_destroy(&cn_port->cnt_lock);
	mutex_destroy(&cn_port->control_lock);

	kfree(cn_port->reset_tracker);

	destroy_workqueue(cn_port->qp_wq);
	destroy_workqueue(cn_port->wq);
}

static void cn_wq_arr_props_init(struct hl_cn_wq_array_properties *wq_arr_props)
{
	wq_arr_props[HL_CNI_USER_WQ_SEND].type_str = "send";
	wq_arr_props[HL_CNI_USER_WQ_SEND].is_send = true;

	wq_arr_props[HL_CNI_USER_WQ_RECV].type_str = "recv";
	wq_arr_props[HL_CNI_USER_WQ_RECV].is_send = false;
}

static int cn_port_sw_init(struct hl_cn_port *cn_port)
{
	struct hl_cn_wq_array_properties *wq_arr_props;
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_reset_tracker *reset_tracker;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_asic_funcs *asic_funcs;
	u32 port, max_qp_error_syndromes;
	char wq_name[32] = {0};
	int rc;

	port = cn_port->port;
	asic_funcs = hdev->asic_funcs;
	port_funcs = asic_funcs->port_funcs;
	wq_arr_props = cn_port->wq_arr_props;
	reset_tracker = NULL;

	snprintf(wq_name, sizeof(wq_name) - 1, "hl%u-cn%d-wq", hdev->id, port);
	cn_port->wq = alloc_workqueue(wq_name, 0, 0);
	if (!cn_port->wq) {
		dev_err(hdev->dev, "Failed to create WQ, port: %d\n", port);
		return -ENOMEM;
	}

	snprintf(wq_name, sizeof(wq_name) - 1, "hl%u-cn%d-qp-wq", hdev->id, port);
	cn_port->qp_wq = alloc_workqueue(wq_name, WQ_UNBOUND, 0);
	if (!cn_port->qp_wq) {
		dev_err(hdev->dev, "Failed to create QP WQ, port: %d\n", port);
		rc = -ENOMEM;
		goto qp_wq_err;
	}

	max_qp_error_syndromes = hdev->cn_props.max_qp_error_syndroms;
	if (max_qp_error_syndromes) {
		reset_tracker = kcalloc(max_qp_error_syndromes, sizeof(*reset_tracker), GFP_KERNEL);
		if (!reset_tracker) {
			rc = -ENOMEM;
			goto reset_tracker_err;
		}

		cn_port->reset_tracker = reset_tracker;
	}

	mutex_init(&cn_port->control_lock);
	mutex_init(&cn_port->cnt_lock);

	xa_init_flags(&cn_port->qp_ids, XA_FLAGS_ALLOC);
	xa_init_flags(&cn_port->db_fifo_ids, XA_FLAGS_ALLOC);
	xa_init_flags(&cn_port->encap_ids, XA_FLAGS_ALLOC);
	xa_init_flags(&cn_port->cq_ids, XA_FLAGS_ALLOC);

	INIT_DELAYED_WORK(&cn_port->fw_status_work, fw_status_work);
	INIT_DELAYED_WORK(&cn_port->link_status_work, port_funcs->phy_link_status_work);

	cn_port->speed = asic_funcs->get_default_port_speed(hdev);
	cn_port->pfc_enable = true;
	cn_port->pflags = PFLAGS_PCS_LINK_CHECK | PFLAGS_PHY_AUTO_NEG_LPBK;

	cn_wq_arr_props_init(wq_arr_props);

	rc = port_funcs->port_sw_init(cn_port);
	if (rc)
		goto sw_init_err;

	cn_port->sw_initialized = true;

	return 0;

sw_init_err:
	xa_destroy(&cn_port->cq_ids);
	xa_destroy(&cn_port->encap_ids);
	xa_destroy(&cn_port->db_fifo_ids);
	xa_destroy(&cn_port->qp_ids);

	mutex_destroy(&cn_port->cnt_lock);
	mutex_destroy(&cn_port->control_lock);

	if (max_qp_error_syndromes)
		kfree(reset_tracker);
reset_tracker_err:
	destroy_workqueue(cn_port->qp_wq);
qp_wq_err:
	destroy_workqueue(cn_port->wq);

	return rc;
}

static int cn_macro_sw_init(struct hl_cn_macro *cn_macro)
{
	struct hl_cn_asic_funcs *asic_funcs;

	asic_funcs = cn_macro->hdev->asic_funcs;

	return asic_funcs->macro_sw_init(cn_macro);
}

static void cn_macro_sw_fini(struct hl_cn_macro *cn_macro)
{
	struct hl_cn_asic_funcs *asic_funcs;

	asic_funcs = cn_macro->hdev->asic_funcs;

	asic_funcs->macro_sw_fini(cn_macro);
}

static void hl_cn_sw_fini(struct hl_cn_device *hdev)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++)
		cn_port_sw_fini(&hdev->cn_ports[i]);

	for (i = 0; i < hdev->cn_props.num_of_macros; i++)
		cn_macro_sw_fini(&hdev->cn_macros[i]);

	asic_funcs->sw_fini(hdev);

	kfree(hdev->en_aux_dev.aux_data);
	kfree(hdev->en_aux_dev.aux_ops);
	kfree(hdev->mac_lane_remap);
	kfree(hdev->phy_ber_info);
	kfree(hdev->phy_tx_taps);
	kfree(hdev->cn_macros);
	kfree(hdev->cn_ports);
}

static int hl_cn_sw_init(struct hl_cn_device *hdev)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	struct hl_cn_macro *cn_macro, *cn_macros;
	int rc, i, macro_cnt = 0, port_cnt = 0;
	struct hl_cn_port *cn_port, *cn_ports;
	struct hl_en_aux_data *en_aux_data;
	struct hl_en_aux_ops *en_aux_ops;
	struct hl_cn_ber_info *ber_info;
	struct hl_cn_tx_taps *tx_taps;
	u32 *mac_lane_remap;

	asic_funcs->pre_sw_init(hdev);

	/* Allocate per port common structure array */
	cn_ports = kcalloc(hdev->cn_props.max_num_of_ports, sizeof(*cn_ports), GFP_KERNEL);
	if (!cn_ports)
		return -ENOMEM;

	/* Allocate per macro common structure array */
	cn_macros = kcalloc(hdev->cn_props.num_of_macros, sizeof(*cn_macros), GFP_KERNEL);
	if (!cn_macros) {
		rc = -ENOMEM;
		goto macro_alloc_fail;
	}

	tx_taps = kcalloc(hdev->cn_props.max_num_of_lanes, sizeof(*tx_taps), GFP_KERNEL);
	if (!tx_taps) {
		rc = -ENOMEM;
		goto taps_alloc_fail;
	}

	ber_info = kcalloc(hdev->cn_props.max_num_of_lanes, sizeof(*ber_info), GFP_KERNEL);
	if (!ber_info) {
		rc = -ENOMEM;
		goto ber_info_alloc_fail;
	}

	mac_lane_remap = kcalloc(hdev->cn_props.num_of_macros, sizeof(*mac_lane_remap),
				 GFP_KERNEL);
	if (!mac_lane_remap) {
		rc = -ENOMEM;
		goto mac_remap_alloc_fail;
	}

	en_aux_data = kzalloc(sizeof(*en_aux_data), GFP_KERNEL);
	if (!en_aux_data) {
		rc = -ENOMEM;
		goto en_aux_data_alloc_fail;
	}

	en_aux_ops = kzalloc(sizeof(*en_aux_ops), GFP_KERNEL);
	if (!en_aux_ops) {
		rc = -ENOMEM;
		goto en_aux_ops_alloc_fail;
	}

	hdev->en_aux_dev.aux_data = en_aux_data;
	hdev->en_aux_dev.aux_ops = en_aux_ops;

	hdev->phy_tx_taps = tx_taps;
	hdev->phy_ber_info = ber_info;
	hdev->mac_lane_remap = mac_lane_remap;
	hdev->phy_config_fw = !hdev->pldm && !hdev->skip_phy_init;
	hdev->mmu_bypass = 1;
	hdev->phy_calc_ber_wait_sec = 30;
	/* Boot CPU loads the PHY F/W at boot */
	hdev->phy_load_fw = (!hdev->cpucp_fw && !hdev->pldm) || hdev->load_phy_fw;
	hdev->debugfs_reset = true;

	rc = asic_funcs->sw_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "ASIC SW init failed\n");
		goto sw_init_fail;
	}

	hdev->cn_ports = cn_ports;
	hdev->cn_macros = cn_macros;
	for (i = 0; i < hdev->cn_props.num_of_macros; i++, macro_cnt++) {
		cn_macro = &hdev->cn_macros[i];

		cn_macro->hdev = hdev;
		cn_macro->idx = i;

		rc = cn_macro_sw_init(cn_macro);
		if (rc) {
			dev_err(hdev->dev, "Macro %d SW init failed\n", i);
			goto macro_init_fail;
		}
	}

	/* At this stage, we don't know how many ports we have, so we must
	 * allocate for the maximum number of ports (and also free all of them
	 * in sw_fini)
	 */
	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++, port_cnt++) {
		cn_port = &hdev->cn_ports[i];
		cn_port->hdev = hdev;
		cn_port->port = i;
		atomic_set(&cn_port->num_of_allocated_qps, 0);
		rc = cn_port_sw_init(cn_port);
		if (rc) {
			dev_err(hdev->dev, "S/W init failed, port %d\n", i);
			goto port_init_fail;
		}
	}

	return 0;

port_init_fail:
	for (i = 0; i < port_cnt; i++)
		cn_port_sw_fini(&hdev->cn_ports[i]);
macro_init_fail:
	for (i = 0; i < macro_cnt; i++)
		cn_macro_sw_fini(&hdev->cn_macros[i]);

	asic_funcs->sw_fini(hdev);
sw_init_fail:
	kfree(en_aux_ops);
en_aux_ops_alloc_fail:
	kfree(en_aux_data);
en_aux_data_alloc_fail:
	kfree(mac_lane_remap);
mac_remap_alloc_fail:
	kfree(ber_info);
ber_info_alloc_fail:
	kfree(tx_taps);
taps_alloc_fail:
	kfree(cn_macros);
macro_alloc_fail:
	kfree(cn_ports);

	return rc;
}

static void hl_cn_late_init(struct hl_cn_device *hdev)
{
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	/* compute2cn */
	aux_ops->ports_reopen = hl_cn_ports_reopen;
	aux_ops->ports_stop_prepare = hl_cn_hard_reset_prepare;
	aux_ops->ports_stop = hl_cn_stop;
	aux_ops->synchronize_irqs = hl_cn_synchronize_irqs;
	aux_ops->send_port_cpucp_status = hl_cn_send_port_cpucp_status;
	aux_ops->mmap = hl_cn_mmap;

	hdev->asic_funcs->late_init(hdev);
}

static void hl_cn_late_fini(struct hl_cn_device *hdev)
{
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	/* compute2cn */
	aux_ops->ports_reopen = NULL;
	aux_ops->ports_stop_prepare = NULL;
	aux_ops->ports_stop = NULL;
	aux_ops->synchronize_irqs = NULL;
	aux_ops->send_port_cpucp_status = NULL;
	aux_ops->mmap = NULL;

	hdev->asic_funcs->late_fini(hdev);
}

bool hl_cn_is_port_open(struct hl_cn_port *cn_port)
{
	struct hl_aux_dev *aux_dev = &cn_port->hdev->en_aux_dev;
	struct hl_en_aux_ops *aux_ops = aux_dev->aux_ops;
	u32 port = cn_port->port;

	if (aux_ops->is_port_open && cn_port->eth_enable)
		return aux_ops->is_port_open(aux_dev, port);

	return cn_port->port_open;
}

u32 hl_cn_get_pflags(struct hl_cn_port *cn_port)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_en_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;
	u32 port = cn_port->port;

	aux_dev = &hdev->en_aux_dev;
	aux_ops = aux_dev->aux_ops;

	if (cn_port->eth_enable)
		return aux_ops->get_pflags(aux_dev, port);

	return cn_port->pflags;
}

u8 hl_cn_get_num_of_digits(u64 num)
{
	u8 n_digits = 0;

	while (num) {
		n_digits++;
		num /= 10;
	}

	return n_digits;
}

static void hl_cn_spmu_init(struct hl_cn_port *cn_port, bool full)
{
	u32 spmu_events[NIC_SPMU_STATS_LEN_MAX], num_event_types, port = cn_port->port;
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_stat *event_types;
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;
	int rc, i;

	if (!hdev->supports_coresight)
		return;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	aux_ops->spmu_get_stats_info(aux_dev, port, &event_types, &num_event_types);
	num_event_types = min_t(u32, num_event_types, NIC_SPMU_STATS_LEN_MAX);

	for (i = 0; i < num_event_types; i++)
		spmu_events[i] = event_types[i].lo_offset;

	if (full) {
		rc = aux_ops->spmu_config(aux_dev, port, num_event_types, spmu_events, false);
		if (rc)
			dev_err(hdev->dev, "Failed to disable spmu for port %d\n", port);
	}

	rc = aux_ops->spmu_config(aux_dev, port, num_event_types, spmu_events, true);
	if (rc)
		dev_err(hdev->dev, "Failed to enable spmu for port %d\n", port);
}

static void hl_cn_reset_stats_counters_port(struct hl_cn_device *hdev, u32 port)
{
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_en_aux_ops *aux_ops;
	struct hl_cn_port *cn_port;
	struct hl_aux_dev *aux_dev;

	cn_port = &hdev->cn_ports[port];
	aux_dev = &hdev->en_aux_dev;
	aux_ops = aux_dev->aux_ops;
	port_funcs = hdev->asic_funcs->port_funcs;

	/* Ethernet */
	if (cn_port->eth_enable)
		aux_ops->reset_stats(aux_dev, port);

	/* MAC */
	port_funcs->reset_mac_stats(cn_port);

	/* SPMU */
	hl_cn_spmu_init(cn_port, true);

	/* XPCS91 */
	cn_port->correctable_errors_cnt = 0;
	cn_port->uncorrectable_errors_cnt = 0;

	/* PCS */
	cn_port->pcs_local_fault_cnt = 0;
	cn_port->pcs_remote_fault_cnt = 0;
	cn_port->pcs_remote_fault_reconfig_cnt = 0;
	cn_port->pcs_link_restore_cnt = 0;

	/* Congestion Queue */
	cn_port->cong_q_err_cnt = 0;
}

void hl_cn_reset_stats_counters(struct hl_cn_device *hdev)
{
	struct hl_cn_port *cn_port;
	u32 port;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		if (!hl_cn_is_port_open(cn_port))
			continue;

		port = cn_port->port;

		hl_cn_reset_stats_counters_port(hdev, port);
	}
}

void hl_cn_reset_ports_toggle_counters(struct hl_cn_device *hdev)
{
	struct hl_cn_port *cn_port;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];
		cn_port->port_toggle_cnt = 0;
	}
}

/* The following implements the events dispatcher
 * Each application registering with the device is assigned a unique ASID
 * by the driver, it is also being associated with a SW-EQ by the dispatcher
 * (The Eth driver is handled by the kernel associated with ASID 0).
 * during the lifetime of the app/ASID, each resource allocated to it
 * that can generate events (such as QP and CQ) is being associated by the
 * dispatcher the appropriate ASID.
 * During the course of work of the NIC, the HW EQ is accessed
 * (by poling or interrupt), and for each event found in it
 * - The resource ID which generated the event is retrieved from it (CQ# or QP#)
 * - The ASID it retrieved from the ASID-resource association lists,
 * - The event is inserted to the ASID-specific SW-EQ to be retrieved later on
 *   by the app. An exception is the Eth driver which as for today is tightly
 *   coupled with the EQ so the dispatcher calls the Eth event handling routine
 *   (if registered) immediately after dispatching the events to the SW-EQs.
 * Note: The Link events which are always handled by the Eth driver (ASID 0).
 */

struct hl_cn_ev_dq *hl_cn_cqn_to_dq(struct hl_cn_ev_dqs *ev_dqs, u32 cqn, struct hl_cn_device *hdev)
{
	struct hl_cn_properties *cn_prop = &hdev->cn_props;
	struct hl_cn_ev_dq *dq;

	if (cqn >= cn_prop->max_cqs)
		return NULL;

	dq = ev_dqs->cq_dq[cqn];
	if (!dq || !dq->associated)
		return NULL;

	return dq;
}

struct hl_cn_ev_dq *hl_cn_ccqn_to_dq(struct hl_cn_ev_dqs *ev_dqs, u32 ccqn,
				     struct hl_cn_device *hdev)
{
	struct hl_cn_properties *cn_prop = &hdev->cn_props;
	struct hl_cn_ev_dq *dq;

	if (ccqn >= cn_prop->max_ccqs)
		return NULL;

	dq = ev_dqs->ccq_dq[ccqn];
	if (!dq || !dq->associated)
		return NULL;

	return dq;
}

struct hl_cn_dq_qp_info *hl_cn_get_qp_info(struct hl_cn_ev_dqs *ev_dqs, u32 qpn)
{
	struct hl_cn_dq_qp_info *qp_info = NULL;

	hash_for_each_possible(ev_dqs->qps, qp_info, node, qpn)
		if (qpn == qp_info->qpn)
			return qp_info;

	return NULL;
}

struct hl_cn_ev_dq *hl_cn_qpn_to_dq(struct hl_cn_ev_dqs *ev_dqs, u32 qpn)
{
	struct hl_cn_dq_qp_info *qp_info = hl_cn_get_qp_info(ev_dqs, qpn);

	if (qp_info)
		return qp_info->dq;

	return NULL;
}

struct hl_cn_ev_dq *hl_cn_dbn_to_dq(struct hl_cn_ev_dqs *ev_dqs, u32 dbn, struct hl_cn_device *hdev)
{
	struct hl_cn_properties *cn_prop = &hdev->cn_props;
	struct hl_cn_ev_dq *dq;

	if (dbn >= cn_prop->max_db_fifos)
		return NULL;

	dq = ev_dqs->db_dq[dbn];
	if (!dq || !dq->associated)
		return NULL;

	return dq;
}

struct hl_cn_ev_dq *hl_cn_asid_to_dq(struct hl_cn_ev_dqs *ev_dqs, u32 asid)
{
	struct hl_cn_ev_dq *dq;
	int i;

	for (i = 0; i < NIC_NUM_CONCUR_ASIDS; i++) {
		dq = &ev_dqs->edq[i];
		if (dq->associated && dq->asid == asid)
			return dq;
	}

	return NULL;
}

static void hl_cn_dq_reset(struct hl_cn_ev_dq *dq)
{
	struct hl_cn_eq_raw_buf *buf = &dq->buf;

	dq->overflow = 0;
	buf->tail = 0;
	buf->head = buf->tail;
	buf->events_count = 0;
	memset(buf->events, 0, sizeof(buf->events));
}

bool hl_cn_eq_dispatcher_is_empty(struct hl_cn_ev_dq *dq)
{
	return (dq->buf.events_count == 0);
}

bool hl_cn_eq_dispatcher_is_full(struct hl_cn_ev_dq *dq)
{
	return (dq->buf.events_count == (NIC_EQ_INFO_BUF_SIZE - 1));
}

void hl_cn_eq_dispatcher_init(struct hl_cn_port *cn_port)
{
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	int i;

	hash_init(ev_dqs->qps);
	mutex_init(&ev_dqs->lock);

	hl_cn_dq_reset(&ev_dqs->default_edq);

	for (i = 0; i < NIC_NUM_CONCUR_ASIDS; i++)
		hl_cn_dq_reset(&ev_dqs->edq[i]);

	for (i = 0; i < NIC_DRV_MAX_CQS_NUM; i++)
		ev_dqs->cq_dq[i] = NULL;

	for (i = 0; i < NIC_DRV_NUM_DB_FIFOS; i++)
		ev_dqs->db_dq[i] = NULL;
}

void hl_cn_eq_dispatcher_fini(struct hl_cn_port *cn_port)
{
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_ev_dqs *edqs = ev_dqs;
	struct hl_cn_dq_qp_info *qp_info;
	u32 port = cn_port->port;
	struct hlist_node *tmp;
	int i;

	if (!hash_empty(edqs->qps))
		dev_err(hdev->dev, "port %d dispatcher is closed while there are QPs in use\n",
			port);

	hash_for_each_safe(edqs->qps, i, tmp, qp_info, node) {
		dev_err_ratelimited(hdev->dev, "port %d QP %d was not destroyed\n", port,
				    qp_info->qpn);
		hash_del(&qp_info->node);
		kfree(qp_info);
	}

	mutex_destroy(&ev_dqs->lock);
}

void hl_cn_eq_dispatcher_reset(struct hl_cn_port *cn_port)
{
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hl_cn_ev_dqs *edqs = ev_dqs;
	int i;

	mutex_lock(&edqs->lock);

	hl_cn_dq_reset(&edqs->default_edq);

	for (i = 0; i < NIC_NUM_CONCUR_ASIDS; i++)
		hl_cn_dq_reset(&edqs->edq[i]);

	mutex_unlock(&edqs->lock);
}

int hl_cn_eq_dispatcher_associate_dq(struct hl_cn_port *cn_port, u32 asid)
{
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hl_cn_ev_dq *dq;
	int i, rc = -ENOSPC;

	mutex_lock(&ev_dqs->lock);

	dq = hl_cn_asid_to_dq(ev_dqs, asid);
	if (dq) {
		rc = 0;
		goto exit;
	}

	for (i = 0; i < NIC_NUM_CONCUR_ASIDS; i++) {
		dq = &ev_dqs->edq[i];
		if (!dq->associated) {
			dq->associated = true;
			dq->asid = asid;
			rc = 0;
			break;
		}
	}

exit:
	mutex_unlock(&ev_dqs->lock);

	return rc;
}

int hl_cn_eq_dispatcher_dissociate_dq(struct hl_cn_port *cn_port, u32 asid)
{
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hl_cn_ev_dq *dq;

	mutex_lock(&ev_dqs->lock);

	dq = hl_cn_asid_to_dq(ev_dqs, asid);
	if (!dq)
		goto exit;

	hl_cn_dq_reset(dq);
	dq->associated = false;
	dq->asid = U32_MAX;

exit:
	mutex_unlock(&ev_dqs->lock);

	return 0;
}

int hl_cn_eq_dispatcher_register_qp(struct hl_cn_port *cn_port, u32 asid, u32 qp_id)
{
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hl_cn_dq_qp_info *qp_info;
	struct hl_cn_ev_dq *dq;
	int rc = 0;

	mutex_lock(&ev_dqs->lock);

	/* check if such qp is already registered and if with the same asid */
	dq = hl_cn_qpn_to_dq(ev_dqs, qp_id);
	if (dq) {
		if (dq->asid != asid)
			rc = -EINVAL;

		goto exit;
	}

	/* find the dq associated with the given asid */
	dq = hl_cn_asid_to_dq(ev_dqs, asid);
	if (!dq) {
		rc = -ENODATA;
		goto exit;
	}

	/* register the QP */
	qp_info = kmalloc(sizeof(*qp_info), GFP_KERNEL);
	if (!qp_info) {
		rc = -ENOMEM;
		goto exit;
	}

	qp_info->dq = dq;
	qp_info->qpn = qp_id;
	hash_add(ev_dqs->qps, &qp_info->node, qp_id);

exit:
	mutex_unlock(&ev_dqs->lock);

	return rc;
}

int hl_cn_eq_dispatcher_unregister_qp(struct hl_cn_port *cn_port, u32 qp_id)
{
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hl_cn_dq_qp_info *qp_info;

	mutex_lock(&ev_dqs->lock);

	qp_info = hl_cn_get_qp_info(ev_dqs, qp_id);
	if (qp_info) {
		hash_del(&qp_info->node);
		kfree(qp_info);
	}

	mutex_unlock(&ev_dqs->lock);

	return 0;
}

int hl_cn_eq_dispatcher_register_cq(struct hl_cn_port *cn_port, u32 asid, u32 cqn)
{
	struct hl_cn_properties *cn_prop = &cn_port->hdev->cn_props;
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hl_cn_ev_dq *dq;
	int rc = 0;

	if (cqn >= cn_prop->max_cqs)
		return -EINVAL;

	mutex_lock(&ev_dqs->lock);

	/* check if such qp is already registered and if with the same
	 * asid
	 */
	dq = ev_dqs->cq_dq[cqn];
	if (dq) {
		if (dq->asid != asid)
			rc = -EINVAL;

		goto exit;
	}

	/* find the dq associated with the given asid */
	dq = hl_cn_asid_to_dq(ev_dqs, asid);
	if (!dq) {
		rc = -ENODATA;
		goto exit;
	}

	ev_dqs->cq_dq[cqn] = dq;

exit:
	mutex_unlock(&ev_dqs->lock);

	return rc;
}

int hl_cn_eq_dispatcher_unregister_cq(struct hl_cn_port *cn_port, u32 cqn)
{
	struct hl_cn_properties *cn_prop = &cn_port->hdev->cn_props;
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;

	if (cqn >= cn_prop->max_cqs)
		return -EINVAL;

	mutex_lock(&ev_dqs->lock);

	ev_dqs->cq_dq[cqn] = NULL;

	mutex_unlock(&ev_dqs->lock);

	return 0;
}

int hl_cn_eq_dispatcher_register_ccq(struct hl_cn_port *cn_port, u32 asid, u32 ccqn)
{
	struct hl_cn_properties *cn_prop = &cn_port->hdev->cn_props;
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hl_cn_ev_dq *dq;
	int rc = 0;

	if (ccqn >= cn_prop->max_ccqs)
		return -EINVAL;

	mutex_lock(&ev_dqs->lock);

	/* check if such qp is already registered and if with the same asid */
	dq = ev_dqs->ccq_dq[ccqn];
	if (dq) {
		rc = -EINVAL;
		goto exit;
	}

	/* find the dq associated with the given asid */
	dq = hl_cn_asid_to_dq(ev_dqs, asid);
	if (!dq) {
		rc = -ENODATA;
		goto exit;
	}

	ev_dqs->ccq_dq[ccqn] = dq;

exit:
	mutex_unlock(&ev_dqs->lock);
	return rc;
}

int hl_cn_eq_dispatcher_unregister_ccq(struct hl_cn_port *cn_port, u32 asid, u32 ccqn)
{
	struct hl_cn_properties *cn_prop = &cn_port->hdev->cn_props;
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;

	if (ccqn >= cn_prop->max_ccqs)
		return -EINVAL;

	if (!hl_cn_asid_to_dq(ev_dqs, asid))
		return -ENODATA;

	mutex_lock(&ev_dqs->lock);

	ev_dqs->ccq_dq[ccqn] = NULL;

	mutex_unlock(&ev_dqs->lock);

	return 0;
}

int hl_cn_eq_dispatcher_register_db(struct hl_cn_port *cn_port, u32 asid, u32 dbn)
{
	struct hl_cn_properties *cn_prop = &cn_port->hdev->cn_props;
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hl_cn_ev_dq *dq;
	int rc = 0;

	if (dbn >= cn_prop->max_db_fifos)
		return -EINVAL;

	mutex_lock(&ev_dqs->lock);

	/* check if doorbell is already registered and if so is it with the same
	 * asid
	 */
	dq = ev_dqs->db_dq[dbn];
	if (dq) {
		if (dq->asid != asid)
			rc = -EINVAL;

		goto exit;
	}

	/* find the dq associated with the given asid and transport */
	dq = hl_cn_asid_to_dq(ev_dqs, asid);
	if (!dq) {
		rc = -ENODATA;
		goto exit;
	}

	ev_dqs->db_dq[dbn] = dq;

exit:
	mutex_unlock(&ev_dqs->lock);

	return rc;
}

int hl_cn_eq_dispatcher_unregister_db(struct hl_cn_port *cn_port, u32 dbn)
{
	struct hl_cn_properties *cn_prop = &cn_port->hdev->cn_props;
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;

	if (dbn >= cn_prop->max_db_fifos)
		return -EINVAL;

	mutex_lock(&ev_dqs->lock);

	ev_dqs->db_dq[dbn] = NULL;

	mutex_unlock(&ev_dqs->lock);

	return 0;
}

static int __hl_cn_eq_dispatcher_enqueue(struct hl_cn_port *cn_port, struct hl_cn_ev_dq *dq,
					 const struct hl_cn_eqe *eqe)
{
	if (hl_cn_eq_dispatcher_is_full(dq)) {
		dq->overflow++;
		return -ENOSPC;
	}

	memcpy(&dq->buf.events[dq->buf.head], eqe, min(sizeof(*eqe), sizeof(dq->buf.events[0])));
	dq->buf.head = (dq->buf.head + 1) & (NIC_EQ_INFO_BUF_SIZE - 1);
	dq->buf.events_count++;

	return 0;
}

/* Broadcast event to all user ASIDs */
int hl_cn_eq_dispatcher_enqueue_bcast(struct hl_cn_port *cn_port, const struct hl_cn_eqe *eqe)
{
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_ev_dq *dq;
	int i, rc = 0;

	if (!hl_cn_is_port_open(cn_port))
		return 0;

	mutex_lock(&ev_dqs->lock);

	for (i = 0; i < NIC_NUM_CONCUR_ASIDS; i++) {
		if (i == hdev->kernel_asid)
			continue;

		dq = hl_cn_asid_to_dq(ev_dqs, i);
		if (!dq)
			continue;

		rc = __hl_cn_eq_dispatcher_enqueue(cn_port, dq, eqe);
		if (rc) {
			dev_dbg_ratelimited(cn_port->hdev->dev,
					    "Port %d, failed to enqueue dispatcher for ASID %d. %d\n",
					    cn_port->port, i, rc);
			break;
		}
	}

	mutex_unlock(&ev_dqs->lock);

	return rc;
}

int hl_cn_eq_dispatcher_enqueue(struct hl_cn_port *cn_port, const struct hl_cn_eqe *eqe)
{
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_ev_dq *dq;
	int rc;

	if (!hl_cn_is_port_open(cn_port))
		return 0;

	port_funcs = cn_port->hdev->asic_funcs->port_funcs;

	mutex_lock(&ev_dqs->lock);

	dq = port_funcs->eq_dispatcher_select_dq(cn_port, eqe);
	if (!dq) {
		rc = -ENODATA;
		goto exit;
	}

	rc = __hl_cn_eq_dispatcher_enqueue(cn_port, dq, eqe);
	if (rc)
		dev_dbg_ratelimited(cn_port->hdev->dev,
				    "Port %d, failed to enqueue dispatcher. %d\n", cn_port->port,
				    rc);

exit:
	mutex_unlock(&ev_dqs->lock);
	return rc;
}

int hl_cn_eq_dispatcher_dequeue(struct hl_cn_port *cn_port, u32 asid,
				struct hl_cn_eqe *eqe, bool is_default)
{
	struct hl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hl_cn_ev_dq *dq;
	int rc;

	mutex_lock(&ev_dqs->lock);

	if (is_default)
		dq = &ev_dqs->default_edq;
	else
		dq = hl_cn_asid_to_dq(ev_dqs, asid);

	if (!dq) {
		rc = -ESRCH;
		goto exit;
	}

	if (hl_cn_eq_dispatcher_is_empty(dq)) {
		rc = -ENODATA;
		goto exit;
	}

	/* We do a copy here instead of returning a pointer since a reset or
	 * destroy operation may occur after we return from the routine
	 */
	memcpy(eqe, &dq->buf.events[dq->buf.tail], min(sizeof(*eqe), sizeof(dq->buf.events[0])));

	dq->buf.tail = (dq->buf.tail + 1) & (NIC_EQ_INFO_BUF_SIZE - 1);
	dq->buf.events_count--;
	rc = 0;

exit:
	mutex_unlock(&ev_dqs->lock);
	return rc;
}

u32 hl_cn_dram_readl(struct hl_cn_device *hdev, u64 addr)
{
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	return aux_ops->dram_readl(aux_dev, addr);
}

void hl_cn_dram_writel(struct hl_cn_device *hdev, u32 val, u64 addr)
{
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	aux_ops->dram_writel(aux_dev, val, addr);
}

u32 hl_cn_rreg(struct hl_cn_device *hdev, u32 reg)
{
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	return aux_ops->rreg(aux_dev, reg);
}

void hl_cn_wreg(struct hl_cn_device *hdev, u32 reg, u32 val)
{
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	return aux_ops->wreg(aux_dev, reg, val);
}

int hl_cn_reserve_wq_dva(struct hl_cn_ctx *ctx, struct hl_cn_port *cn_port, u64 wq_arr_size,
			 u32 type, u64 *dva)
{
	struct hl_cn_wq_array_properties *wq_arr_props;
	int rc;

	/* The Device VA block for WQ array is just reserved here. It will be backed by host
	 * physical pages once the MMU mapping is done via hl_map_vmalloc_range inside the
	 * alloc_and_map_wq. Using host page alignment ensures we start with offset 0, both
	 * on host and device side.
	 */
	rc = hl_cn_reserve_dva_block(ctx, wq_arr_size, dva);
	if (rc)
		return rc;

	wq_arr_props = &cn_port->wq_arr_props[type];

	wq_arr_props->dva_base = *dva;
	wq_arr_props->dva_size = wq_arr_size;

	return 0;
}

void hl_cn_unreserve_wq_dva(struct hl_cn_ctx *ctx, struct hl_cn_port *cn_port, u32 type)
{
	struct hl_cn_wq_array_properties *wq_arr_props = &cn_port->wq_arr_props[type];

	hl_cn_unreserve_dva_block(ctx, wq_arr_props->dva_base, wq_arr_props->dva_size);
	wq_arr_props->dva_base = 0;
}

void hl_cn_track_port_reset(struct hl_cn_port *cn_port, u32 syndrome)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_reset_tracker *reset_tracker;
	unsigned long timestamp_jiffies = jiffies;
	u32 max_qp_error_syndromes;

	max_qp_error_syndromes = hdev->cn_props.max_qp_error_syndroms;
	if (syndrome >= max_qp_error_syndromes) {
		dev_dbg(hdev->dev, "Invalid syndrom %u\n", syndrome);
		return;
	}

	reset_tracker = &cn_port->reset_tracker[syndrome];

	/* In case the timeout passed, reset the tracker parameters and return */
	if (time_after_eq(timestamp_jiffies, reset_tracker->timeout_jiffies)) {
		reset_tracker->num_seq_resets = 1;
		reset_tracker->timeout_jiffies = timestamp_jiffies +
						 msecs_to_jiffies(NIC_SEQ_RESETS_TIMEOUT_MS);
		return;
	}

	reset_tracker->num_seq_resets++;

	/* In case the max sequential resets was reached before we passed the timeout,
	 * disable that port.
	 */
	if (reset_tracker->num_seq_resets == NIC_MAX_SEQ_RESETS) {
		dev_err(hdev->dev,
			"Disabling port %u due to %d sequential resets, syndrome %u\n",
			cn_port->port, NIC_MAX_SEQ_RESETS, syndrome);
		cn_port->disabled = true;
	}
}

void hl_cn_eq_handler(struct hl_cn_port *cn_port)
{
	struct hl_en_aux_ops *en_aux_ops;
	struct hl_aux_dev *aux_dev;
	struct hl_cn_device *hdev;
	struct hl_cn_eqe eqe;
	u32 port;

	if (!cn_port->eq_handler_enable)
		return;

	hdev = cn_port->hdev;
	aux_dev = &hdev->en_aux_dev;
	en_aux_ops = aux_dev->aux_ops;
	port = cn_port->port;

	mutex_lock(&cn_port->control_lock);

	if (!hl_cn_is_port_open(cn_port)) {
		dev_dbg(hdev->dev, "ignoring events while port %d closed", port);
		goto out;
	}

	while (!hl_cn_eq_dispatcher_dequeue(cn_port, hdev->kernel_asid, &eqe, false))
		en_aux_ops->handle_eqe(aux_dev, port, &eqe);

out:
	mutex_unlock(&cn_port->control_lock);
}
