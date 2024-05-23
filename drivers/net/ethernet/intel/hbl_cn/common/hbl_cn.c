// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#include "hbl_cn.h"

#include <linux/file.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/pci.h>
#include <linux/slab.h>

#define NIC_MIN_WQS_PER_PORT		2

#define NIC_SEQ_RESETS_TIMEOUT_MS	15000 /* 15 seconds */
#define NIC_MAX_SEQ_RESETS		3

#define HBL_CN_IPV4_PROTOCOL_UDP	17

/* SOB mask is not expected to change across ASIC. Hence common defines. */
#define NIC_SOB_INC_MASK		0x80000000
#define NIC_SOB_VAL_MASK		0x7fff

#define NIC_DUMP_QP_SZ			SZ_4K

#define HBL_AUX2NIC(aux_dev)	\
	({ \
		struct hbl_aux_dev *__aux_dev = (aux_dev); \
		((__aux_dev)->type == HBL_AUX_DEV_ETH) ? \
		container_of(__aux_dev, struct hbl_cn_device, en_aux_dev) : \
		container_of(__aux_dev, struct hbl_cn_device, ib_aux_dev); \
	})

#define RAND_STAT_CNT(cnt) \
	do { \
		u32 __cnt = get_random_u32(); \
		(cnt) = __cnt; \
		dev_info(hdev->dev, "port %d, %s: %u\n", port, #cnt, __cnt); \
	} while (0)

struct hbl_cn_stat hbl_cn_mac_fec_stats[] = {
	{"correctable_errors", 0x2, 0x3},
	{"uncorrectable_errors", 0x4, 0x5}
};

struct hbl_cn_stat hbl_cn_mac_stats_rx[] = {
	{"Octets", 0x0},
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
	{"DropEvents", 0x34},
	{"Pkts", 0x38},
	{"UndersizePkts", 0x3C},
	{"Pkts64Octets", 0x40},
	{"Pkts65to127Octets", 0x44},
	{"Pkts128to255Octets", 0x48},
	{"Pkts256to511Octets", 0x4C},
	{"Pkts512to1023Octets", 0x50},
	{"Pkts1024to1518Octets", 0x54},
	{"Pkts1519toMaxOctets", 0x58},
	{"OversizePkts", 0x5C},
	{"Jabbers", 0x60},
	{"Fragments", 0x64},
	{"aCBFCPAUSERx0", 0x68},
	{"aCBFCPAUSERx1", 0x6C},
	{"aCBFCPAUSERx2", 0x70},
	{"aCBFCPAUSERx3", 0x74},
	{"aCBFCPAUSERx4", 0x78},
	{"aCBFCPAUSERx5", 0x7C},
	{"aCBFCPAUSERx6", 0x80},
	{"aCBFCPAUSERx7", 0x84},
	{"aMACControlFramesReceived", 0x88}
};

struct hbl_cn_stat hbl_cn_mac_stats_tx[] = {
	{"Octets", 0x0},
	{"OctetsTransmittedOK", 0x4},
	{"aPAUSEMACCtrlFramesTransmitted", 0x8},
	{"aFramesTransmittedOK", 0xC},
	{"VLANTransmittedOK", 0x10},
	{"ifOutErrors", 0x14},
	{"ifOutUcastPkts", 0x18},
	{"ifOutMulticastPkts", 0x1C},
	{"ifOutBroadcastPkts", 0x20},
	{"Pkts64Octets", 0x24},
	{"Pkts65to127Octets", 0x28},
	{"Pkts128to255Octets", 0x2C},
	{"Pkts256to511Octets", 0x30},
	{"Pkts512to1023Octets", 0x34},
	{"Pkts1024to1518Octets", 0x38},
	{"Pkts1519toMaxOctets", 0x3C},
	{"aCBFCPAUSETx0", 0x40},
	{"aCBFCPAUSETx1", 0x44},
	{"aCBFCPAUSETx2", 0x48},
	{"aCBFCPAUSETx3", 0x4C},
	{"aCBFCPAUSETx4", 0x50},
	{"aCBFCPAUSETx5", 0x54},
	{"aCBFCPAUSETx6", 0x58},
	{"aCBFCPAUSETx7", 0x5C},
	{"aMACControlFramesTx", 0x60},
	{"Pkts", 0x64}
};

static const char pcs_counters_str[][ETH_GSTRING_LEN] = {
	{"pcs_local_faults"},
	{"pcs_remote_faults"},
	{"pcs_remote_fault_reconfig"},
	{"pcs_link_restores"},
	{"pcs_link_toggles"},
};

static size_t pcs_counters_str_len = ARRAY_SIZE(pcs_counters_str);
size_t hbl_cn_mac_fec_stats_len = ARRAY_SIZE(hbl_cn_mac_fec_stats);
size_t hbl_cn_mac_stats_rx_len = ARRAY_SIZE(hbl_cn_mac_stats_rx);
size_t hbl_cn_mac_stats_tx_len = ARRAY_SIZE(hbl_cn_mac_stats_tx);

static void qps_stop(struct hbl_cn_device *hdev);
static void qp_destroy_work(struct work_struct *work);
static int __user_wq_arr_unset(struct hbl_cn_ctx *ctx, struct hbl_cn_port *cn_port, u32 type);
static void user_cq_destroy(struct kref *kref);
static void set_app_params_clear(struct hbl_cn_device *hdev);
static int hbl_cn_ib_cmd_ctrl(struct hbl_aux_dev *aux_dev, void *cn_ib_ctx, u32 op, void *input,
			      void *output);
static int hbl_cn_ib_query_mem_handle(struct hbl_aux_dev *ib_aux_dev, u64 mem_handle,
				      struct hbl_ib_mem_info *info);

static void hbl_cn_reset_stats_counters_port(struct hbl_cn_device *hdev, u32 port);
static void hbl_cn_late_init(struct hbl_cn_device *hdev);
static void hbl_cn_late_fini(struct hbl_cn_device *hdev);
static int hbl_cn_sw_init(struct hbl_cn_device *hdev);
static void hbl_cn_sw_fini(struct hbl_cn_device *hdev);
static void hbl_cn_spmu_init(struct hbl_cn_port *cn_port, bool full);
static int hbl_cn_cmd_port_check(struct hbl_cn_device *hdev, u32 port, u32 flags);
static void hbl_cn_qps_stop(struct hbl_cn_port *cn_port);

static int hbl_cn_request_irqs(struct hbl_cn_device *hdev)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	return asic_funcs->request_irqs(hdev);
}

static void hbl_cn_free_irqs(struct hbl_cn_device *hdev)
{
	struct hbl_cn_asic_funcs *asic_funcs =  hdev->asic_funcs;

	asic_funcs->free_irqs(hdev);
}

static void hbl_cn_synchronize_irqs(struct hbl_aux_dev *cn_aux_dev)
{
	struct hbl_cn_device *hdev = cn_aux_dev->priv;
	struct hbl_cn_asic_funcs *asic_funcs;

	asic_funcs = hdev->asic_funcs;

	asic_funcs->synchronize_irqs(hdev);
}

void hbl_cn_get_frac_info(u64 numerator, u64 denominator, u64 *integer, u64 *exp)
{
	u64 high_digit_n, high_digit_d, integer_tmp, exp_tmp;
	u8 num_digits_n, num_digits_d;
	int i;

	num_digits_d = hbl_cn_get_num_of_digits(denominator);
	high_digit_d = denominator;
	for (i = 0; i < num_digits_d - 1; i++)
		high_digit_d /= 10;

	integer_tmp = 0;
	exp_tmp = 0;

	if (numerator) {
		num_digits_n = hbl_cn_get_num_of_digits(numerator);
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

int hbl_cn_read_spmu_counters(struct hbl_cn_port *cn_port, u64 out_data[], u32 *num_out_data)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_stat *ignore;
	int rc;

	port_funcs = hdev->asic_funcs->port_funcs;

	port_funcs->spmu_get_stats_info(cn_port, &ignore, num_out_data);

	/* this function can be called from ethtool, get_statistics ioctl and FW status thread */
	mutex_lock(&cn_port->cnt_lock);
	rc = port_funcs->spmu_sample(cn_port, *num_out_data, out_data);
	mutex_unlock(&cn_port->cnt_lock);

	return rc;
}

static u32 hbl_cn_get_port_toggle_cnt(struct hbl_cn_port *cn_port)
{
	/* We should not count the first toggle, as it marks that port was brought up for
	 * the first time. In case port connection wasn't established, the counter should be 0.
	 */
	return cn_port->port_toggle_cnt ? cn_port->port_toggle_cnt - 1 : 0;
}

static int __hbl_cn_get_cnts_num(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;

	return pcs_counters_str_len +
		hdev->asic_funcs->port_funcs->get_cnts_num(cn_port);
}

static void __hbl_cn_get_cnts_names(struct hbl_cn_port *cn_port, u8 *data, bool ext)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	int i, len;

	len = ext ? HBL_IB_CNT_NAME_LEN : ETH_GSTRING_LEN;

	for (i = 0; i < pcs_counters_str_len; i++)
		memcpy(data + i * len, pcs_counters_str[i], ETH_GSTRING_LEN);
	data += i * len;

	hdev->asic_funcs->port_funcs->get_cnts_names(cn_port, data, ext);
}

static void __hbl_cn_get_cnts_values(struct hbl_cn_port *cn_port, u64 *data)
{
	struct hbl_cn_device *hdev = cn_port->hdev;

	data[0] = cn_port->pcs_local_fault_cnt;
	data[1] = cn_port->pcs_remote_fault_cnt;
	data[2] = cn_port->pcs_remote_fault_reconfig_cnt;
	data[3] = cn_port->pcs_link_restore_cnt;
	data[4] = hbl_cn_get_port_toggle_cnt(cn_port);

	data += pcs_counters_str_len;

	hdev->asic_funcs->port_funcs->get_cnts_values(cn_port, data);
}

static int __hbl_cn_port_hw_init(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;

	if (cn_port->disabled) {
		dev_err(hdev->dev, "Port %u is disabled\n", cn_port->port);
		return -EPERM;
	}

	hbl_cn_reset_stats_counters_port(hdev, cn_port->port);

	return hdev->asic_funcs->port_funcs->port_hw_init(cn_port);
}

static void __hbl_cn_port_hw_fini(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_asic_funcs *asic_funcs;

	asic_funcs = hdev->asic_funcs;

	/* in hard reset the QPs were stopped by hbl_cn_stop called from halt engines */
	if (hdev->operational)
		hbl_cn_qps_stop(cn_port);

	asic_funcs->port_funcs->port_hw_fini(cn_port);
}

bool hbl_cn_comp_device_operational(struct hbl_cn_device *hdev)
{
	struct hbl_aux_dev *aux_dev = hdev->cn_aux_dev;
	struct hbl_cn_aux_ops *aux_ops;

	aux_ops = aux_dev->aux_ops;

	return aux_ops->device_operational(aux_dev);
}

void hbl_cn_spmu_get_stats_info(struct hbl_cn_port *cn_port, struct hbl_cn_stat **stats,
				u32 *n_stats)
{
	struct hbl_cn_device *hdev = cn_port->hdev;

	hdev->asic_funcs->port_funcs->spmu_get_stats_info(cn_port, stats, n_stats);
}

int hbl_cn_reserve_dva_block(struct hbl_cn_ctx *ctx, u64 size, u64 *dva)
{
	struct hbl_cn_device *hdev = ctx->hdev;
	struct hbl_cn_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	return aux_ops->vm_reserve_dva_block(aux_dev, ctx->driver_vm_info.vm_handle, size, dva);
}

void hbl_cn_unreserve_dva_block(struct hbl_cn_ctx *ctx, u64 dva, u64 size)
{
	struct hbl_cn_device *hdev = ctx->hdev;
	struct hbl_cn_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	aux_ops->vm_unreserve_dva_block(aux_dev, ctx->driver_vm_info.vm_handle, dva, size);
}

int hbl_cn_get_hw_block_handle(struct hbl_cn_device *hdev, u64 address, u64 *handle)
{
	return hdev->asic_funcs->get_hw_block_handle(hdev, address, handle);
}

static int hbl_cn_get_hw_block_addr(struct hbl_cn_device *hdev, u64 handle, u64 *addr, u64 *size)
{
	return hdev->asic_funcs->get_hw_block_addr(hdev, handle, addr, size);
}

int hbl_cn_send_cpucp_packet(struct hbl_cn_device *hdev, u32 port, enum cpucp_packet_id pkt_id,
			     int val)
{
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return hdev->asic_funcs->port_funcs->send_cpucp_packet(cn_port, pkt_id, val);
}

static bool hbl_cn_device_operational(struct hbl_aux_dev *aux_dev)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);

	return hdev->operational;
}

static void hbl_cn_hw_access_lock(struct hbl_aux_dev *aux_dev)
	__acquires(&hdev->hw_access_lock)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);

	mutex_lock(&hdev->hw_access_lock);
}

static void hbl_cn_hw_access_unlock(struct hbl_aux_dev *aux_dev)
	__releases(&hdev->hw_access_lock)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);

	mutex_unlock(&hdev->hw_access_lock);
}

static bool hbl_cn_is_eth_lpbk(struct hbl_aux_dev *aux_dev)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);

	return hdev->eth_loopback;
}

static int hbl_cn_port_hw_init(struct hbl_aux_dev *aux_dev, u32 port)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return __hbl_cn_port_hw_init(cn_port);
}

static void hbl_cn_port_hw_fini(struct hbl_aux_dev *aux_dev, u32 port)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	__hbl_cn_port_hw_fini(cn_port);
}

static int hbl_cn_phy_port_init(struct hbl_aux_dev *aux_dev, u32 port)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return hdev->asic_funcs->port_funcs->phy_port_init(cn_port);
}

static void hbl_cn_phy_port_fini(struct hbl_aux_dev *aux_dev, u32 port)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	hdev->asic_funcs->port_funcs->phy_port_fini(cn_port);
}

static int hbl_cn_set_pfc(struct hbl_aux_dev *aux_dev, u32 port, bool enable)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	cn_port->pfc_enable = enable;

	return hdev->asic_funcs->port_funcs->set_pfc(cn_port);
}

static int hbl_cn_get_cnts_num(struct hbl_aux_dev *aux_dev, u32 port)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return __hbl_cn_get_cnts_num(cn_port);
}

static void hbl_cn_get_cnts_names(struct hbl_aux_dev *aux_dev, u32 port, u8 *data)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	__hbl_cn_get_cnts_names(cn_port, data, false);
}

static void hbl_cn_get_cnts_values(struct hbl_aux_dev *aux_dev, u32 port, u64 *data)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	__hbl_cn_get_cnts_values(cn_port, data);
}

static bool hbl_cn_get_mac_lpbk(struct hbl_aux_dev *aux_dev, u32 port)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return cn_port->mac_loopback;
}

static int hbl_cn_set_mac_lpbk(struct hbl_aux_dev *aux_dev, u32 port, bool enable)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

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

static int hbl_cn_update_mtu(struct hbl_aux_dev *aux_dev, u32 port, u32 mtu)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_port *cn_port;
	unsigned long qp_id = 0;
	struct hbl_cn_qp *qp;
	int rc = 0;

	cn_port = &hdev->cn_ports[port];
	port_funcs = hdev->asic_funcs->port_funcs;
	mtu += HBL_EN_MAX_HEADERS_SZ;

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

static int hbl_cn_qpc_write(struct hbl_aux_dev *aux_dev, u32 port, void *qpc,
			    struct qpc_mask *qpc_mask, u32 qpn, bool is_req)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_port *cn_port;
	int rc;

	cn_port = &hdev->cn_ports[port];
	port_funcs = hdev->asic_funcs->port_funcs;

	port_funcs->cfg_lock(cn_port);
	rc = port_funcs->qpc_write(cn_port, qpc, qpc_mask, qpn, is_req);
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static void hbl_cn_ctrl_lock(struct hbl_aux_dev *aux_dev, u32 port)
	__acquires(&cn_port->control_lock)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	mutex_lock(&cn_port->control_lock);
}

static void hbl_cn_ctrl_unlock(struct hbl_aux_dev *aux_dev, u32 port)
	__releases(&cn_port->control_lock)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	mutex_unlock(&cn_port->control_lock);
}

static int hbl_cn_dispatcher_register_qp(struct hbl_aux_dev *aux_dev, u32 port, u32 asid, u32 qp_id)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return hbl_cn_eq_dispatcher_register_qp(cn_port, asid, qp_id);
}

static int hbl_cn_dispatcher_unregister_qp(struct hbl_aux_dev *aux_dev, u32 port, u32 qp_id)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return hbl_cn_eq_dispatcher_unregister_qp(cn_port, qp_id);
}

static u32 hbl_cn_get_speed(struct hbl_aux_dev *aux_dev, u32 port)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	return cn_port->speed;
}

static void hbl_cn_track_ext_port_reset(struct hbl_aux_dev *aux_dev, u32 port, u32 syndrome)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	hbl_cn_track_port_reset(cn_port, syndrome);
}

static void hbl_cn_port_toggle_count(struct hbl_aux_dev *aux_dev, u32 port)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	cn_port->port_toggle_cnt++;
}

/* Check for initialized hbl IB device. */
bool hbl_cn_is_ibdev(struct hbl_cn_device *hdev)
{
	return !!hdev->ib_aux_dev.priv;
}

/* Check for opened hbl IB device. */
static bool hbl_cn_is_ibdev_opened(struct hbl_cn_device *hdev)
{
	return hdev->ib_aux_dev.priv && hdev->ib_device_opened;
}

static int hbl_cn_ib_alloc_ucontext(struct hbl_aux_dev *ib_aux_dev, int user_fd, void **cn_ib_ctx)
{
	struct hbl_cn_comp_vm_info *user_vm_info, *driver_vm_info;
	struct hbl_cn_device *hdev = HBL_AUX2NIC(ib_aux_dev);
	struct hbl_aux_dev *aux_dev = hdev->cn_aux_dev;
	struct hbl_cn_asic_funcs *asic_funcs;
	struct hbl_cn_aux_ops *aux_ops;
	struct hbl_cn_ctx *ctx;
	int rc;

	asic_funcs = hdev->asic_funcs;
	aux_ops = aux_dev->aux_ops;

	if (!hdev->multi_ctx_support && hdev->ctx) {
		dev_err(hdev->dev, "There is already an active user context\n");
		return -EBUSY;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->hdev = hdev;
	mutex_init(&ctx->lock);

	user_vm_info = &ctx->user_vm_info;
	driver_vm_info = &ctx->driver_vm_info;

	rc = aux_ops->register_cn_user_context(aux_dev, user_fd, ctx, &ctx->comp_handle,
					       &user_vm_info->vm_handle);
	if (rc) {
		dev_dbg(hdev->dev, "Failed to register user context with FD %d\n", user_fd);
		goto release_ctx;
	}

	if (user_vm_info->vm_handle != ctx->comp_handle) {
		rc = aux_ops->get_vm_info(aux_dev, user_vm_info->vm_handle, &user_vm_info->vm_info);
		if (rc) {
			dev_err(hdev->dev, "Failed to get user VM info for handle 0x%llx\n",
				user_vm_info->vm_handle);
			goto deregister_ctx;
		}

		if (user_vm_info->vm_info.mmu_mode == HBL_CN_MMU_MODE_NETWORK_TLB)
			ctx->user_asid = user_vm_info->vm_info.net_tlb.pasid;
		else
			ctx->user_asid = user_vm_info->vm_info.ext_mmu.work_id;
	} else {
		/* No data transfer in this mode */
		ctx->user_asid = -1;
	}

	rc = aux_ops->vm_create(aux_dev, ctx->comp_handle, 0, &driver_vm_info->vm_handle);
	if (rc) {
		dev_err(hdev->dev, "Failed to create driver VM for vompute handle 0x%llx\n",
			ctx->comp_handle);
		goto deregister_ctx;
	}

	rc = aux_ops->get_vm_info(aux_dev, driver_vm_info->vm_handle, &driver_vm_info->vm_info);
	if (rc) {
		dev_err(hdev->dev, "Failed to get driver VM info for handle 0x%llx\n",
			driver_vm_info->vm_handle);
		goto destroy_driver_vm;
	}

	if (driver_vm_info->vm_info.mmu_mode == HBL_CN_MMU_MODE_NETWORK_TLB)
		ctx->asid = driver_vm_info->vm_info.net_tlb.pasid;
	else
		ctx->asid = driver_vm_info->vm_info.ext_mmu.work_id;

	/* must be called before calling create_mem_ctx */
	rc = asic_funcs->ctx_init(ctx);
	if (rc) {
		dev_err(hdev->dev, "failed to init user context with ASID %d\n", ctx->asid);
		goto destroy_driver_vm;
	}

	if (ctx->user_asid != -1 && user_vm_info->vm_info.mmu_mode == HBL_CN_MMU_MODE_NETWORK_TLB) {
		rc = asic_funcs->create_mem_ctx(ctx, user_vm_info->vm_info.net_tlb.pasid,
						user_vm_info->vm_info.net_tlb.page_tbl_addr);
		if (rc) {
			dev_err(hdev->dev,
				"failed to create HW memory context for user VM, FD %d\n", user_fd);
			goto ctx_cleanup;
		}
	}

	if (driver_vm_info->vm_info.mmu_mode == HBL_CN_MMU_MODE_NETWORK_TLB) {
		rc = asic_funcs->create_mem_ctx(ctx, driver_vm_info->vm_info.net_tlb.pasid,
						driver_vm_info->vm_info.net_tlb.page_tbl_addr);
		if (rc) {
			dev_err(hdev->dev,
				"failed to create HW memory context for driver VM, FD %d\n",
				user_fd);
			goto user_vm_ctx_cleanup;
		}
	}

	*cn_ib_ctx = ctx;
	hdev->ib_device_opened = true;
	hdev->ctx = ctx;

	return 0;

user_vm_ctx_cleanup:
	if (ctx->user_asid != -1 && user_vm_info->vm_info.mmu_mode == HBL_CN_MMU_MODE_NETWORK_TLB)
		asic_funcs->destroy_mem_ctx(ctx, user_vm_info->vm_info.net_tlb.pasid,
					    user_vm_info->vm_info.net_tlb.page_tbl_addr);
ctx_cleanup:
	asic_funcs->ctx_fini(ctx);
destroy_driver_vm:
	aux_ops->vm_destroy(aux_dev, driver_vm_info->vm_handle);
deregister_ctx:
	aux_ops->deregister_cn_user_context(aux_dev, user_vm_info->vm_handle);
release_ctx:
	mutex_destroy(&ctx->lock);
	kfree(ctx);

	return rc;
}

static void hbl_cn_ib_dealloc_ucontext(struct hbl_aux_dev *ib_aux_dev, void *cn_ib_ctx)
{
	struct hbl_cn_comp_vm_info *user_vm_info, *driver_vm_info;
	struct hbl_cn_device *hdev = HBL_AUX2NIC(ib_aux_dev);
	struct hbl_aux_dev *aux_dev = hdev->cn_aux_dev;
	struct hbl_cn_asic_funcs *asic_funcs;
	struct hbl_cn_ctx *ctx = cn_ib_ctx;
	struct hbl_cn_aux_ops *aux_ops;

	aux_ops = aux_dev->aux_ops;
	asic_funcs = hdev->asic_funcs;
	user_vm_info = &ctx->user_vm_info;
	driver_vm_info = &ctx->driver_vm_info;

	dev_dbg(hdev->dev, "IB context dealloc\n");

	if (driver_vm_info->vm_info.mmu_mode == HBL_CN_MMU_MODE_NETWORK_TLB)
		asic_funcs->destroy_mem_ctx(ctx, driver_vm_info->vm_info.net_tlb.pasid,
					    driver_vm_info->vm_info.net_tlb.page_tbl_addr);

	if (ctx->user_asid != -1 && user_vm_info->vm_info.mmu_mode == HBL_CN_MMU_MODE_NETWORK_TLB)
		asic_funcs->destroy_mem_ctx(ctx, user_vm_info->vm_info.net_tlb.pasid,
					    user_vm_info->vm_info.net_tlb.page_tbl_addr);

	hbl_cn_ctx_resources_destroy(hdev, ctx);
	hdev->asic_funcs->ctx_fini(ctx);

	aux_ops->vm_destroy(aux_dev, driver_vm_info->vm_handle);
	aux_ops->deregister_cn_user_context(aux_dev, user_vm_info->vm_handle);

	hdev->ctx = NULL;
	mutex_destroy(&ctx->lock);
	kfree(ctx);

	hdev->ib_device_opened = false;
}

static void hbl_cn_ib_query_port(struct hbl_aux_dev *aux_dev, u32 port,
				 struct hbl_ib_port_attr *port_attr)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_asic_funcs *asic_funcs;
	struct hbl_cn_port *cn_port;

	asic_funcs = hdev->asic_funcs;
	cn_port = &hdev->cn_ports[port];

	port_attr->open = hbl_cn_is_port_open(cn_port);
	port_attr->link_up = cn_port->pcs_link;
	port_attr->speed = cn_port->speed;
	port_attr->max_msg_sz = asic_funcs->get_max_msg_sz(hdev);
	port_attr->num_lanes = hdev->lanes_per_port;
	port_attr->max_mtu = SZ_8K;
}

static inline void parse_fw_ver(struct hbl_cn_device *hdev, char *str, u32 *maj, u16 *min, u16 *sub)
{
	char *ver = strstr(str, "fw-");
	int ret;

	if (!ver)
		goto failure;

	ret = sscanf(ver, "fw-%d.%hu.%hu", maj, min, sub);
	if (ret < 3) {
failure:
		dev_dbg(hdev->dev, "Failed to read version string\n");
		*maj = *min = *sub = 0;
	}
}

static void hbl_cn_ib_query_device(struct hbl_aux_dev *aux_dev, struct hbl_ib_device_attr *dev_attr)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_properties *cn_props;
	struct hbl_ib_aux_data *aux_data;
	u16 minor, sub_ver;
	u32 major;

	aux_data = aux_dev->aux_data;
	cn_props = &hdev->cn_props;

	if (hdev->cpucp_fw) {
		parse_fw_ver(hdev, hdev->fw_ver, &major, &minor, &sub_ver);
		dev_attr->fw_ver = ((u64)major << 32) | ((u64)minor << 16) | sub_ver;
	}

	dev_attr->max_mr_size = aux_data->dram_size;

	dev_attr->page_size_cap = PAGE_SIZE;

	dev_attr->vendor_id = hdev->pdev->vendor;
	dev_attr->vendor_part_id = hdev->pdev->device;
	dev_attr->hw_ver = hdev->pdev->subsystem_device;

	dev_attr->max_qp = cn_props->max_qps_num;

	dev_attr->max_qp_wr = aux_data->max_num_of_wqes;
	dev_attr->max_cqe = cn_props->user_cq_max_entries;

	dev_attr->cqe_size = cn_props->cqe_size;
	dev_attr->min_cq_entries = cn_props->user_cq_min_entries;
}

static void hbl_cn_ib_set_ip_addr_encap(struct hbl_aux_dev *aux_dev, u32 ip_addr, u32 port)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_asic_funcs *asic_funcs;
	struct hbl_cn_port *cn_port;
	u32 encap_id;

	asic_funcs = hdev->asic_funcs;
	cn_port = &hdev->cn_ports[port];

	asic_funcs->port_funcs->set_ip_addr_encap(cn_port, &encap_id, ip_addr);
}

static char *hbl_cn_ib_qp_syndrome_to_str(struct hbl_aux_dev *aux_dev, u32 syndrome)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_asic_funcs *asic_funcs;

	asic_funcs = hdev->asic_funcs;

	return asic_funcs->qp_syndrome_to_str(syndrome);
}

static int hbl_cn_ib_verify_qp_id(struct hbl_aux_dev *aux_dev, u32 qp_id, u32 port)
{
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_port *cn_port;
	struct hbl_cn_device *hdev;
	struct hbl_cn_qp *qp;
	int rc = 0;

	hdev = HBL_AUX2NIC(aux_dev);
	port_funcs = hdev->asic_funcs->port_funcs;
	cn_port = &hdev->cn_ports[port];

	port_funcs->cfg_lock(cn_port);
	qp = xa_load(&cn_port->qp_ids, qp_id);

	if (IS_ERR_OR_NULL(qp)) {
		dev_dbg(hdev->dev, "Failed to find matching QP for handle %d, port %d\n", qp_id,
			port);
		rc = -EINVAL;
		goto cfg_unlock;
	}

	/* sanity test the port IDs */
	if (qp->port != port) {
		dev_dbg(hdev->dev, "QP port %d does not match requested port %d\n", qp->port, port);
		rc = -EINVAL;
		goto cfg_unlock;
	}

cfg_unlock:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int hbl_cn_ib_dump_qp(struct hbl_aux_dev *aux_dev, struct hbl_ib_dump_qp_attr *attr,
			     char *buf, size_t size)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_asic_funcs *asic_funcs;
	struct hbl_cn_qp_info qp_info = {};
	int rc;

	asic_funcs = hdev->asic_funcs;

	qp_info.port = attr->port;
	qp_info.qpn = attr->qpn;
	qp_info.req = attr->req;
	qp_info.full_print = attr->full;
	qp_info.force_read = attr->force;

	rc = asic_funcs->qp_read(hdev, &qp_info, buf, size);
	if (rc) {
		dev_err(hdev->dev, "Failed to read QP %u, port %u\n", attr->qpn, attr->port);
		return rc;
	}

	return 0;
}

static int hbl_cn_en_aux_data_init(struct hbl_cn_device *hdev)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	struct hbl_en_aux_data *en_aux_data;
	struct hbl_cn_properties *cn_props;
	struct hbl_en_aux_ops *en_aux_ops;
	struct hbl_aux_dev *en_aux_dev;
	char **mac_addr;
	int i;

	en_aux_dev = &hdev->en_aux_dev;
	en_aux_dev->type = HBL_AUX_DEV_ETH;
	en_aux_data = en_aux_dev->aux_data;
	en_aux_ops = en_aux_dev->aux_ops;
	cn_props = &hdev->cn_props;

	en_aux_data->pdev = hdev->pdev;
	en_aux_data->dev = hdev->dev;
	en_aux_data->ports_mask = hdev->ext_ports_mask;
	en_aux_data->auto_neg_mask = hdev->auto_neg_mask;
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
	en_aux_ops->device_operational = hbl_cn_device_operational;
	en_aux_ops->hw_access_lock = hbl_cn_hw_access_lock;
	en_aux_ops->hw_access_unlock = hbl_cn_hw_access_unlock;
	en_aux_ops->is_eth_lpbk = hbl_cn_is_eth_lpbk;
	/* port functions */
	en_aux_ops->port_hw_init = hbl_cn_port_hw_init;
	en_aux_ops->port_hw_fini = hbl_cn_port_hw_fini;
	en_aux_ops->phy_init = hbl_cn_phy_port_init;
	en_aux_ops->phy_fini = hbl_cn_phy_port_fini;
	en_aux_ops->set_pfc = hbl_cn_set_pfc;
	en_aux_ops->get_cnts_num = hbl_cn_get_cnts_num;
	en_aux_ops->get_cnts_names = hbl_cn_get_cnts_names;
	en_aux_ops->get_cnts_values = hbl_cn_get_cnts_values;
	en_aux_ops->get_mac_lpbk = hbl_cn_get_mac_lpbk;
	en_aux_ops->set_mac_lpbk = hbl_cn_set_mac_lpbk;
	en_aux_ops->update_mtu = hbl_cn_update_mtu;
	en_aux_ops->qpc_write = hbl_cn_qpc_write;
	en_aux_ops->ctrl_lock = hbl_cn_ctrl_lock;
	en_aux_ops->ctrl_unlock = hbl_cn_ctrl_unlock;
	en_aux_ops->eq_dispatcher_register_qp = hbl_cn_dispatcher_register_qp;
	en_aux_ops->eq_dispatcher_unregister_qp = hbl_cn_dispatcher_unregister_qp;
	en_aux_ops->get_speed = hbl_cn_get_speed;
	en_aux_ops->track_ext_port_reset = hbl_cn_track_ext_port_reset;
	en_aux_ops->port_toggle_count = hbl_cn_port_toggle_count;

	asic_funcs->set_en_data(hdev);

	return 0;
}

static void hbl_cn_en_aux_data_fini(struct hbl_cn_device *hdev)
{
	struct hbl_aux_dev *aux_dev = &hdev->en_aux_dev;
	struct hbl_en_aux_data *aux_data;

	aux_data = aux_dev->aux_data;

	kfree(aux_data->mac_addr);
	aux_data->mac_addr = NULL;
}

static int hbl_cn_ib_aux_data_init(struct hbl_cn_device *hdev)
{
	struct hbl_ib_port_cnts_data *cnts_data;
	struct hbl_ib_aux_data *ib_aux_data;
	struct hbl_ib_aux_ops *ib_aux_ops;
	struct hbl_aux_dev *ib_aux_dev;
	struct hbl_cn_port *cn_port;
	int rc, i;

	ib_aux_dev = &hdev->ib_aux_dev;
	ib_aux_dev->type = HBL_AUX_DEV_IB;
	ib_aux_data = ib_aux_dev->aux_data;
	ib_aux_ops = ib_aux_dev->aux_ops;

	ib_aux_data->pdev = hdev->pdev;
	ib_aux_data->dev = hdev->dev;
	ib_aux_data->ports_mask = hdev->ports_mask;
	ib_aux_data->ext_ports_mask = hdev->ext_ports_mask;
	ib_aux_data->max_num_of_wqes = hdev->cn_props.max_hw_user_wqs_num;
	ib_aux_data->max_num_of_ports = hdev->cn_props.max_num_of_ports;
	ib_aux_data->pending_reset_long_timeout = hdev->pending_reset_long_timeout;
	ib_aux_data->id = hdev->id;
	ib_aux_data->dram_size = hdev->dram_size;
	ib_aux_data->mixed_qp_wq_types = hdev->mixed_qp_wq_types;
	ib_aux_data->umr_support = hdev->umr_support;
	ib_aux_data->cc_support = hdev->cc_support;

	ib_aux_data->cnts_data = kcalloc(hdev->cn_props.max_num_of_ports,
					 sizeof(*ib_aux_data->cnts_data), GFP_KERNEL);
	if (!ib_aux_data->cnts_data)
		return -ENOMEM;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(ib_aux_data->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];
		cnts_data = &ib_aux_data->cnts_data[i];

		cnts_data->num = __hbl_cn_get_cnts_num(cn_port);

		cnts_data->names = kcalloc(cnts_data->num, HBL_IB_CNT_NAME_LEN, GFP_KERNEL);
		if (!cnts_data->names) {
			rc = -ENOMEM;
			goto free_cnts_data;
		}

		__hbl_cn_get_cnts_names(cn_port, cnts_data->names, true);
	}

	/* set ib -> cn ops */
	/* the following functions are used even if the IB verbs API is disabled */
	ib_aux_ops->device_operational = hbl_cn_device_operational;
	ib_aux_ops->hw_access_lock = hbl_cn_hw_access_lock;
	ib_aux_ops->hw_access_unlock = hbl_cn_hw_access_unlock;
	ib_aux_ops->alloc_ucontext = hbl_cn_ib_alloc_ucontext;
	ib_aux_ops->dealloc_ucontext = hbl_cn_ib_dealloc_ucontext;
	ib_aux_ops->query_port = hbl_cn_ib_query_port;
	ib_aux_ops->query_device = hbl_cn_ib_query_device;
	ib_aux_ops->set_ip_addr_encap = hbl_cn_ib_set_ip_addr_encap;
	ib_aux_ops->qp_syndrome_to_str = hbl_cn_ib_qp_syndrome_to_str;
	ib_aux_ops->verify_qp_id = hbl_cn_ib_verify_qp_id;
	ib_aux_ops->get_cnts_values = hbl_cn_get_cnts_values;
	ib_aux_ops->dump_qp = hbl_cn_ib_dump_qp;

	/* these functions are used only if the IB verbs API is enabled */
	ib_aux_ops->cmd_ctrl = hbl_cn_ib_cmd_ctrl;
	ib_aux_ops->query_mem_handle = hbl_cn_ib_query_mem_handle;

	return 0;

free_cnts_data:
	for (--i; i >= 0; i--) {
		if (!(ib_aux_data->ports_mask & BIT(i)))
			continue;

		kfree(ib_aux_data->cnts_data[i].names);
	}
	kfree(ib_aux_data->cnts_data);

	return rc;
}

static void hbl_cn_ib_aux_data_fini(struct hbl_cn_device *hdev)
{
	struct hbl_ib_aux_data *aux_data;
	struct hbl_aux_dev *aux_dev;
	int i;

	aux_dev = &hdev->ib_aux_dev;
	aux_data = aux_dev->aux_data;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(aux_data->ports_mask & BIT(i)))
			continue;

		kfree(aux_data->cnts_data[i].names);
	}
	kfree(aux_data->cnts_data);
}

static void eth_adev_release(struct device *dev)
{
	struct hbl_aux_dev *aux_dev = container_of(dev, struct hbl_aux_dev, adev.dev);
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);

	hdev->is_eth_aux_dev_initialized = false;
}

static int hbl_cn_en_aux_drv_init(struct hbl_cn_device *hdev)
{
	struct hbl_aux_dev *aux_dev = &hdev->en_aux_dev;
	struct auxiliary_device *adev;
	int rc;

	rc = hbl_cn_en_aux_data_init(hdev);
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
	hbl_cn_en_aux_data_fini(hdev);

	return rc;
}

static void hbl_cn_en_aux_drv_fini(struct hbl_cn_device *hdev)
{
	struct auxiliary_device *adev;

	if (!hdev->is_eth_aux_dev_initialized)
		return;

	adev = &hdev->en_aux_dev.adev;

	auxiliary_device_delete(adev);
	auxiliary_device_uninit(adev);

	hbl_cn_en_aux_data_fini(hdev);
}

static void ib_adev_release(struct device *dev)
{
	struct hbl_aux_dev *aux_dev = container_of(dev, struct hbl_aux_dev, adev.dev);
	struct hbl_cn_device *hdev;

	hdev = container_of(aux_dev, struct hbl_cn_device, ib_aux_dev);

	hdev->is_ib_aux_dev_initialized = false;
}

static int hbl_cn_ib_aux_drv_init(struct hbl_cn_device *hdev)
{
	struct hbl_aux_dev *aux_dev = &hdev->ib_aux_dev;
	struct auxiliary_device *adev;
	int rc;

	if (!hdev->ib_support)
		return 0;

	rc = hbl_cn_ib_aux_data_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "IB aux data init failed\n");
		return rc;
	}

	adev = &aux_dev->adev;
	adev->id = hdev->id;
	adev->name = "ib";
	adev->dev.parent = hdev->dev;
	adev->dev.release = ib_adev_release;

	rc = auxiliary_device_init(adev);
	if (rc) {
		dev_err(hdev->dev, "ib auxiliary_device_init failed\n");
		goto aux_data_free;
	}

	rc = auxiliary_device_add(adev);
	if (rc) {
		dev_err(hdev->dev, "ib auxiliary_device_add failed\n");
		goto uninit_adev;
	}

	hdev->is_ib_aux_dev_initialized = true;

	return 0;

uninit_adev:
	auxiliary_device_uninit(adev);
aux_data_free:
	hbl_cn_ib_aux_data_fini(hdev);

	return rc;
}

static void hbl_cn_ib_aux_drv_fini(struct hbl_cn_device *hdev)
{
	struct auxiliary_device *adev;

	if (!hdev->ib_support || !hdev->is_ib_aux_dev_initialized)
		return;

	adev = &hdev->ib_aux_dev.adev;

	auxiliary_device_delete(adev);
	auxiliary_device_uninit(adev);

	hbl_cn_ib_aux_data_fini(hdev);
}

void hbl_cn_internal_port_fini_locked(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_asic_funcs *asic_funcs;

	asic_funcs = hdev->asic_funcs;

	if (!cn_port->port_open)
		return;

	cn_port->port_open = false;

	/* verify that the port is marked as closed before continuing */
	mb();

	asic_funcs->port_funcs->phy_port_fini(cn_port);

	__hbl_cn_port_hw_fini(cn_port);
}

static void hbl_cn_internal_ports_fini(struct hbl_cn_device *hdev)
{
	struct hbl_cn_port *cn_port;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)) || (hdev->ext_ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		mutex_lock(&cn_port->control_lock);

		hbl_cn_internal_port_fini_locked(cn_port);

		mutex_unlock(&cn_port->control_lock);
	}
}

void hbl_cn_ports_cancel_status_work(struct hbl_cn_device *hdev)
{
	struct hbl_cn_port *cn_port;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		cancel_delayed_work_sync(&cn_port->fw_status_work);
	}
}

int hbl_cn_internal_port_init_locked(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_asic_funcs *asic_funcs;
	u32 port = cn_port->port;
	int rc;

	asic_funcs = hdev->asic_funcs;

	rc = __hbl_cn_port_hw_init(cn_port);
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
	__hbl_cn_port_hw_fini(cn_port);

	return rc;
}

static int hbl_cn_internal_ports_init(struct hbl_cn_device *hdev)
{
	struct hbl_cn_port *cn_port;
	u32 port;
	int rc, i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)) || (hdev->ext_ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];
		port = cn_port->port;

		mutex_lock(&cn_port->control_lock);

		rc = hbl_cn_internal_port_init_locked(cn_port);
		if (rc) {
			dev_err(hdev->dev, "Failed to configure the HW, port: %d, %d", port, rc);
			mutex_unlock(&cn_port->control_lock);
			goto port_init_fail;
		}

		mutex_unlock(&cn_port->control_lock);
	}

	return 0;

port_init_fail:
	hbl_cn_internal_ports_fini(hdev);

	return rc;
}

static int hbl_cn_kernel_ctx_init(struct hbl_cn_device *hdev)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	return asic_funcs->kernel_ctx_init(hdev, hdev->kernel_asid);
}

static void hbl_cn_kernel_ctx_fini(struct hbl_cn_device *hdev)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	asic_funcs->kernel_ctx_fini(hdev, hdev->kernel_asid);
}

static void hbl_cn_mac_loopback_init(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	u32 port = cn_port->port;
	bool enable;

	aux_dev = &hdev->en_aux_dev;
	aux_ops = aux_dev->aux_ops;

	enable = !!(hdev->mac_loopback & BIT(port));
	cn_port->mac_loopback = enable;

	if (cn_port->eth_enable && aux_ops->set_dev_lpbk)
		aux_ops->set_dev_lpbk(aux_dev, port, enable);
}

static int hbl_cn_core_init(struct hbl_cn_device *hdev)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	struct hbl_cn_macro *cn_macro;
	struct hbl_cn_port *cn_port;
	int rc, i, port_cnt = 0;
	u32 port;

	/* RX packet drop config is not preserved across hard reset. */
	hdev->rx_drop_percent = 0;

	if (hdev->load_phy_fw) {
		if (hdev->cn_props.is_phy_fw_binary) {
			rc = hbl_cn_phy_has_binary_fw(hdev);
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
	       hdev->cn_props.max_num_of_lanes * sizeof(struct hbl_cn_ber_info));

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
		cn_port->port_toggle_cnt_prev = 0;

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

		hbl_cn_spmu_init(cn_port, false);

		cn_port->auto_neg_enable = !!(hdev->auto_neg_mask & BIT(port));

		if (!hdev->in_reset)
			cn_port->eth_enable = !!(BIT(port) & hdev->ext_ports_mask);

		/* This function must be called after setting cn_port->eth_enable */
		hbl_cn_mac_loopback_init(cn_port);
	}

	return 0;

err:
	asic_funcs->core_fini(hdev);

	return rc;
}

static void hbl_cn_core_fini(struct hbl_cn_device *hdev)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	asic_funcs->core_fini(hdev);
}

static void wq_arrays_pool_destroy(struct hbl_cn_device *hdev)
{
	if (!hdev->wq_arrays_pool_enable)
		return;

	gen_pool_destroy(hdev->wq_arrays_pool);
}

static int wq_arrays_pool_alloc(struct hbl_cn_device *hdev)
{
	struct hbl_cn_properties *cn_props;
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

int __hbl_cn_ports_reopen(struct hbl_cn_device *hdev)
{
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *en_aux_dev;
	int rc;

	en_aux_dev = &hdev->en_aux_dev;
	aux_ops = en_aux_dev->aux_ops;

	rc = hbl_cn_kernel_ctx_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init kernel context\n");
		return rc;
	}

	rc = hbl_cn_core_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init core\n");
		goto core_init_fail;
	}

	rc = hbl_cn_internal_ports_init(hdev);
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
	hbl_cn_internal_ports_fini(hdev);
internal_ports_fail:
	hbl_cn_core_fini(hdev);
core_init_fail:
	hbl_cn_kernel_ctx_fini(hdev);

	return rc;
}

void __hbl_cn_stop(struct hbl_cn_device *hdev)
{
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *en_aux_dev;

	en_aux_dev = &hdev->en_aux_dev;
	aux_ops = en_aux_dev->aux_ops;

	/* Cancelling all outstanding works for all ports should be done first when stopping */
	hdev->asic_funcs->ports_cancel_status_work(hdev);

	qps_stop(hdev);

	if (aux_ops->ports_stop)
		aux_ops->ports_stop(en_aux_dev);

	hbl_cn_internal_ports_fini(hdev);
	hbl_cn_core_fini(hdev);
	hbl_cn_kernel_ctx_fini(hdev);
}

void __hbl_cn_hard_reset_prepare(struct hbl_cn_device *hdev, bool fw_reset, bool in_teardown)
{
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *en_aux_dev;

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

void hbl_cn_hard_reset_prepare(struct hbl_aux_dev *cn_aux_dev, bool fw_reset, bool in_teardown)
{
	struct hbl_cn_device *hdev = cn_aux_dev->priv;

	__hbl_cn_hard_reset_prepare(hdev, fw_reset, in_teardown);
}

int hbl_cn_send_port_cpucp_status(struct hbl_aux_dev *aux_dev, u32 port, u8 cmd, u8 period)
{
	struct hbl_cn_device *hdev = aux_dev->priv;
	struct hbl_cn_port *cn_port;

	cn_port = &hdev->cn_ports[port];

	if (cmd > HBL_CN_STATUS_PERIODIC_STOP) {
		dev_err(hdev->dev, "Received invalid CN status cmd (%d) from F/W, port %d", cmd,
			port);
		return -EINVAL;
	}

	hdev->status_cmd = cmd;
	hdev->status_period = (cmd == HBL_CN_STATUS_PERIODIC_START) ? period : 0;

	if (cmd == HBL_CN_STATUS_PERIODIC_STOP)
		cancel_delayed_work_sync(&cn_port->fw_status_work);
	else
		queue_delayed_work(cn_port->wq, &cn_port->fw_status_work, 0);

	return 0;
}

static void hbl_cn_get_cpucp_info(struct hbl_cn_device *hdev)
{
	struct hbl_cn_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	aux_ops->get_cpucp_info(aux_dev, hdev->cpucp_info);
}

static int hbl_cn_ports_reopen(struct hbl_aux_dev *aux_dev)
{
	struct hbl_cn_device *hdev = aux_dev->priv;
	int rc;

	/* update CPUCP info after device reset */
	hbl_cn_get_cpucp_info(hdev);

	rc = hbl_cn_request_irqs(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to request IRQs\n");
		return rc;
	}

	rc = __hbl_cn_ports_reopen(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to reopen ports\n");
		goto free_irqs;
	}

	return 0;

free_irqs:
	hbl_cn_free_irqs(hdev);

	return rc;
}

static void hbl_cn_stop(struct hbl_aux_dev *aux_dev)
{
	struct hbl_cn_device *hdev = aux_dev->priv;

	__hbl_cn_stop(hdev);

	hbl_cn_synchronize_irqs(aux_dev);
	hbl_cn_free_irqs(hdev);
}

static int hbl_cn_set_static_properties(struct hbl_cn_device *hdev)
{
	return hdev->asic_funcs->set_static_properties(hdev);
}

static int hbl_cn_set_dram_properties(struct hbl_cn_device *hdev)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	return asic_funcs->set_dram_properties(hdev);
}

static int hbl_cn_set_asic_funcs(struct hbl_cn_device *hdev)
{
	switch (hdev->asic_type) {
	case HBL_ASIC_GAUDI2:
	default:
		dev_err(hdev->dev, "Unrecognized ASIC type %d\n", hdev->asic_type);
		return -EINVAL;
	}

	return 0;
}

int hbl_cn_dev_init(struct hbl_cn_device *hdev)
{
	int rc;

	if (!hdev->ports_mask) {
		dev_err(hdev->dev, "All ports are disabled\n");
		return -EINVAL;
	}

	/* must be called first to init the ASIC funcs */
	rc = hbl_cn_set_asic_funcs(hdev);
	if (rc) {
		dev_err(hdev->dev, "failed to set ASIC aux ops\n");
		return rc;
	}

	/* get CPUCP info before initializing the device */
	hbl_cn_get_cpucp_info(hdev);

	/* init static cn properties */
	rc = hbl_cn_set_static_properties(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to set static properties\n");
		return rc;
	}

	/* init DRAM cn properties */
	rc = hbl_cn_set_dram_properties(hdev);
	if (rc) {
		dev_err(hdev->dev, "failed to set DRAM properties\n");
		return rc;
	}

	rc = hbl_cn_sw_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "SW init failed\n");
		return rc;
	}

	rc = hbl_cn_request_irqs(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to request IRQs\n");
		goto request_irqs_fail;
	}

	rc = hbl_cn_kernel_ctx_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init kernel context\n");
		goto kernel_ctx_init_fail;
	}

	rc = hbl_cn_core_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init core\n");
		goto core_init_fail;
	}

	rc = hbl_cn_internal_ports_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init internal ports\n");
		goto internal_ports_init_fail;
	}

	rc = wq_arrays_pool_alloc(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init WQ arrays pool\n");
		goto wq_arrays_pool_alloc_fail;
	}

	hbl_cn_mem_init(hdev);

	hdev->operational = true;

	rc = hbl_cn_en_aux_drv_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init Ethernet driver\n");
		goto en_aux_drv_fail;
	}

	rc = hbl_cn_ib_aux_drv_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init IB driver\n");
		goto ib_aux_drv_fail;
	}

	hbl_cn_late_init(hdev);

	hdev->is_initialized = true;

	return 0;

ib_aux_drv_fail:
	hbl_cn_en_aux_drv_fini(hdev);
en_aux_drv_fail:
	hdev->operational = false;
	hbl_cn_mem_fini(hdev);
	wq_arrays_pool_destroy(hdev);
wq_arrays_pool_alloc_fail:
	hbl_cn_internal_ports_fini(hdev);
internal_ports_init_fail:
	hbl_cn_core_fini(hdev);
core_init_fail:
	hbl_cn_kernel_ctx_fini(hdev);
kernel_ctx_init_fail:
	hbl_cn_free_irqs(hdev);
request_irqs_fail:
	hbl_cn_sw_fini(hdev);

	return rc;
}

void hbl_cn_dev_fini(struct hbl_cn_device *hdev)
{
	if (!hdev->is_initialized)
		return;

	hdev->is_initialized = false;

	if (hdev->hw_stop_during_teardown) {
		hbl_cn_hard_reset_prepare(hdev->cn_aux_dev, false, true);
		hbl_cn_stop(hdev->cn_aux_dev);
	}

	hbl_cn_late_fini(hdev);

	hbl_cn_ib_aux_drv_fini(hdev);
	/* must be called after MSI was disabled */
	hbl_cn_en_aux_drv_fini(hdev);
	hbl_cn_mem_fini(hdev);
	wq_arrays_pool_destroy(hdev);
	hbl_cn_sw_fini(hdev);
}

static int hbl_cn_cmd_port_check(struct hbl_cn_device *hdev, u32 port, u32 flags)
{
	bool check_open = flags & NIC_PORT_CHECK_OPEN,
		check_enable = (flags & NIC_PORT_CHECK_ENABLE) || check_open,
		print_on_err = flags & NIC_PORT_PRINT_ON_ERR;
	struct hbl_cn_port *cn_port;

	if (port >= hdev->cn_props.max_num_of_ports) {
		if (print_on_err)
			dev_dbg(hdev->dev, "Invalid port %d\n", port);
		return -EINVAL;
	}

	if (check_enable && !(hdev->ports_mask & BIT(port))) {
		if (print_on_err)
			dev_dbg(hdev->dev, "Port %d is disabled\n", port);
		return -ENODEV;
	}

	cn_port = &hdev->cn_ports[port];

	if (check_open && !hbl_cn_is_port_open(cn_port)) {
		if (print_on_err)
			dev_dbg(hdev->dev, "Port %d is closed\n", port);
		return -ENODEV;
	}

	return 0;
}

static void hbl_cn_get_qp_id_range(struct hbl_cn_port *cn_port, u32 *min_id, u32 *max_id)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_asic_funcs *asic_funcs;

	asic_funcs = hdev->asic_funcs;

	asic_funcs->port_funcs->get_qp_id_range(cn_port, min_id, max_id);

	/* Take the minimum between the max id supported by the port and the max id supported by
	 * the WQs number the user asked to allocate.
	 */
	*max_id = min(cn_port->qp_idx_offset + cn_port->num_of_wqs - 1, *max_id);
}

static void hbl_cn_qp_do_release(struct hbl_cn_qp *qp)
{
	struct hbl_cn_qpc_drain_attr drain_attr = { .wait_for_idle = false, };
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_port *cn_port;

	if (IS_ERR_OR_NULL(qp))
		return;

	cn_port = qp->cn_port;
	port_funcs = cn_port->hdev->asic_funcs->port_funcs;

	cancel_delayed_work(&qp->adaptive_tmr_reset);

	port_funcs->qp_pre_destroy(qp);

	/* QP was found before, hence use xa_store to replace the pointer but don't release index.
	 * xa_store should not fail in such scenario.
	 */
	xa_store(&qp->cn_port->qp_ids, qp->qp_id, NULL, GFP_KERNEL);

	/* drain the Req QP now in order to make sure that accesses to the WQ will not
	 * be performed from this point on.
	 * Waiting for the WQ to drain is performed in the reset work
	 */
	hbl_cn_qp_modify(cn_port, qp, CN_QP_STATE_SQD, &drain_attr);

	queue_work(cn_port->qp_wq, &qp->async_work);
}

static void qp_adaptive_tmr_reset(struct work_struct *work)
{
	struct hbl_cn_qp *qp = container_of(work, struct hbl_cn_qp, adaptive_tmr_reset.work);
	struct hbl_cn_port *cn_port = qp->cn_port;
	struct hbl_cn_device *hdev;

	hdev = cn_port->hdev;

	hdev->asic_funcs->port_funcs->adaptive_tmr_reset(qp);
}

static int alloc_qp(struct hbl_cn_device *hdev, struct hbl_cn_ctx *ctx,
		    struct hbl_cni_alloc_conn_in *in, struct hbl_cni_alloc_conn_out *out)
{
	struct hbl_cn_wq_array_properties *swq_arr_props, *rwq_arr_props;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_port *cn_port;
	struct xa_limit id_limit;
	u32 min_id, max_id, port;
	struct hbl_cn_qp *qp;
	int id, rc;

	port = in->port;

	rc = hbl_cn_cmd_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp)
		return -ENOMEM;

	port_funcs = hdev->asic_funcs->port_funcs;

	cn_port = &hdev->cn_ports[port];
	qp->cn_port = cn_port;
	qp->port = port;
	qp->ctx = ctx;
	qp->curr_state = CN_QP_STATE_RESET;
	INIT_WORK(&qp->async_work, qp_destroy_work);
	INIT_DELAYED_WORK(&qp->adaptive_tmr_reset, qp_adaptive_tmr_reset);

	hbl_cn_get_qp_id_range(cn_port, &min_id, &max_id);

	port_funcs->cfg_lock(cn_port);

	if (!cn_port->set_app_params) {
		dev_dbg(hdev->dev,
			"Failed to allocate QP, set_app_params wasn't called yet, port %d\n", port);
		rc = -EPERM;
		goto error_exit;
	}

	swq_arr_props = &cn_port->wq_arr_props[HBL_CNI_USER_WQ_SEND];
	rwq_arr_props = &cn_port->wq_arr_props[HBL_CNI_USER_WQ_RECV];

	if (!swq_arr_props->enabled || !rwq_arr_props->enabled) {
		dev_dbg(hdev->dev, "Failed to allocate QP as WQs are not configured, port %d\n",
			port);
		rc = -EPERM;
		goto error_exit;
	}

	if (swq_arr_props->under_unset || rwq_arr_props->under_unset) {
		dev_dbg(hdev->dev, "Failed to allocate QP as WQs are under unset, port %d\n", port);
		rc = -EPERM;
		goto error_exit;
	}

	id_limit = XA_LIMIT(min_id, max_id);
	rc = xa_alloc(&cn_port->qp_ids, &id, qp, id_limit, GFP_KERNEL);
	if (rc) {
		dev_dbg(hdev->dev, "Failed allocate QP IDR entry, port %d", port);
		goto error_exit;
	}

	qp->qp_id = id;

	rc = port_funcs->register_qp(cn_port, id, ctx->asid);
	if (rc) {
		dev_dbg(hdev->dev, "Failed to register QP %d, port %d\n", id, port);
		goto qp_register_error;
	}

	atomic_inc(&cn_port->num_of_allocated_qps);

	port_funcs->cfg_unlock(cn_port);

	out->conn_id = id;

	return 0;

qp_register_error:
	xa_erase(&qp->cn_port->qp_ids, qp->qp_id);
error_exit:
	port_funcs->cfg_unlock(cn_port);
	kfree(qp);
	return rc;
}

u32 hbl_cn_get_wq_array_type(bool is_send)
{
	return is_send ? HBL_CNI_USER_WQ_SEND : HBL_CNI_USER_WQ_RECV;
}

static int alloc_and_map_wq(struct hbl_cn_port *cn_port, struct hbl_cn_qp *qp, u32 n_wq,
			    bool is_swq)
{
	u32 wq_arr_type, wqe_size, qp_idx_offset, wq_idx;
	struct hbl_cn_wq_array_properties *wq_arr_props;
	struct hbl_cn_mem_data mem_data = {};
	struct hbl_cn_properties *cn_props;
	struct hbl_cn_device *hdev;
	struct hbl_cn_mem_buf *buf;
	u64 wq_arr_size, wq_size;
	int rc;

	hdev = cn_port->hdev;
	cn_props = &hdev->cn_props;
	qp_idx_offset = cn_port->qp_idx_offset;
	wq_idx = qp->qp_id - qp_idx_offset;

	wq_arr_type = hbl_cn_get_wq_array_type(is_swq);
	wq_arr_props = &cn_port->wq_arr_props[wq_arr_type];
	wqe_size = is_swq ? cn_port->swqe_size : cn_props->rwqe_size;

	if (wq_arr_props->dva_base) {
		mem_data.mem_id = HBL_CN_DRV_MEM_HOST_VIRTUAL;
		mem_data.size = PAGE_ALIGN(n_wq * wqe_size);

		/* Get offset into device VA block pre-allocated for SWQ.
		 *
		 * Note: HW indexes into SWQ array using qp_id.
		 * In general, it's HW requirement to leave holes in a WQ array if corresponding QP
		 * indexes are allocated on another WQ array.
		 */
		mem_data.device_va = wq_arr_props->dva_base + wq_arr_props->offset +
				     wq_arr_props->wq_size * wq_idx;

		/* Check for out of range. */
		if (mem_data.device_va + mem_data.size >
			wq_arr_props->dva_base + wq_arr_props->dva_size) {
			dev_dbg(hdev->dev,
				"Out of range device VA. device_va 0x%llx, size 0x%llx\n",
				mem_data.device_va, mem_data.size);
			return -EINVAL;
		}
	} else {
		/* DMA coherent allocate case. Memory for WQ array is already allocated in
		 * user_wq_arr_set(). Here we use the allocated base addresses and QP id to
		 * calculate the CPU & bus addresses of the WQ for current QP and return that
		 * handle to the user. User may mmap() this handle returned by set_req_qp_ctx()
		 * to write WQEs.
		 */
		mem_data.mem_id = HBL_CN_DRV_MEM_HOST_MAP_ONLY;

		buf = hbl_cn_mem_buf_get(hdev, wq_arr_props->handle);
		if (!buf) {
			dev_err(hdev->dev, "Failed to retrieve WQ arr handle for port %d\n",
				cn_port->port);
			return -EINVAL;
		}

		/* Actual size to allocate. Page aligned since we mmap to user. */
		mem_data.size = PAGE_ALIGN(n_wq * wqe_size);
		wq_size = wq_arr_props->wq_size;
		wq_arr_size = buf->mappable_size;

		 /* Get offset into kernel buffer block pre-allocated for SWQ. */
		mem_data.in.host_map_data.kernel_address = buf->kernel_address +
							   wq_arr_props->offset + wq_size * wq_idx;

		mem_data.in.host_map_data.bus_address = buf->bus_address + wq_arr_props->offset +
							wq_size * wq_idx;

		/* Check for out of range. */
		if ((u64)mem_data.in.host_map_data.kernel_address + mem_data.size >
		    (u64)buf->kernel_address + wq_arr_size) {
			dev_dbg(hdev->dev,
				"Out of range kernel addr. kernel addr 0x%p, size 0x%llx\n",
				mem_data.in.host_map_data.kernel_address, mem_data.size);
			return -EINVAL;
		}
	}

	/* Allocate host vmalloc memory and map its physical pages to PMMU. */
	rc = hbl_cn_mem_alloc(qp->ctx, &mem_data);
	if (rc) {
		dev_dbg(hdev->dev, "Failed to allocate %s. Port %d, QP %d\n",
			is_swq ? "SWQ" : "RWQ", cn_port->port, qp->qp_id);
		return rc;
	}

	/* Retrieve mmap handle. */
	if (is_swq) {
		qp->swq_handle = mem_data.handle;
		qp->swq_size = mem_data.size;
	} else {
		qp->rwq_handle = mem_data.handle;
		qp->rwq_size = mem_data.size;
	}

	return 0;
}

static int set_req_qp_ctx(struct hbl_cn_device *hdev, struct hbl_cni_req_conn_ctx_in *in,
			  struct hbl_cni_req_conn_ctx_out *out)
{
	struct hbl_cn_wq_array_properties *swq_arr_props, *rwq_arr_props;
	struct hbl_cn_encap_xarray_pdata *encap_data;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_asic_funcs *asic_funcs;
	u32 wq_size, port, max_wq_size;
	struct hbl_cn_port *cn_port;
	struct hbl_cn_qp *qp;
	int rc;

	port = in->port;

	rc = hbl_cn_cmd_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	asic_funcs = hdev->asic_funcs;
	port_funcs = asic_funcs->port_funcs;
	cn_port = &hdev->cn_ports[port];

	if (in->timer_granularity > NIC_TMR_TIMEOUT_MAX_GRAN) {
		dev_err(hdev->dev,
			"timer granularity %d is not supported\n", in->timer_granularity);
		return -EINVAL;
	}

	if (!in->timer_granularity && !hbl_cn_is_ibdev_opened(hdev))
		in->timer_granularity = NIC_TMR_TIMEOUT_DEFAULT_GRAN;

	port_funcs->cfg_lock(cn_port);
	qp = xa_load(&cn_port->qp_ids, in->conn_id);

	if (IS_ERR_OR_NULL(qp)) {
		dev_dbg(hdev->dev, "Failed to find matching QP for handle %d, port %d\n",
			in->conn_id, port);
		rc = -EINVAL;
		goto cfg_unlock;
	}

	/* sanity test the port IDs */
	if (qp->port != port) {
		dev_dbg(hdev->dev, "QP port %d does not match requested port %d\n", qp->port, port);
		rc = -EINVAL;
		goto cfg_unlock;
	}

	if (in->encap_en) {
		encap_data = xa_load(&cn_port->encap_ids, in->encap_id);
		if (!encap_data) {
			dev_dbg_ratelimited(hdev->dev,
					    "Encapsulation ID %d not found, ignoring\n",
					    in->encap_id);
			in->encap_en = 0;
			in->encap_id = 0;
		}
	}

	if (qp->is_req) {
		dev_dbg(hdev->dev, "Port %d, QP %d - Requester QP is already set\n", port,
			qp->qp_id);
		rc = -EINVAL;
		goto cfg_unlock;
	}

	wq_size = in->wq_size;

	/* verify that size does not exceed wq_array size */
	max_wq_size = cn_port->num_of_wq_entries;

	if (wq_size > max_wq_size) {
		dev_dbg(hdev->dev,
			"Port %d, Requester QP %d - requested size (%d) > max size (%d)\n", port,
			qp->qp_id, wq_size, max_wq_size);
		rc = -EINVAL;
		goto cfg_unlock;
	}

	swq_arr_props = &cn_port->wq_arr_props[HBL_CNI_USER_WQ_SEND];
	rwq_arr_props = &cn_port->wq_arr_props[HBL_CNI_USER_WQ_RECV];

	if (!swq_arr_props->on_device_mem) {
		rc = alloc_and_map_wq(cn_port, qp, wq_size, true);
		if (rc)
			goto cfg_unlock;

		out->swq_mem_handle = qp->swq_handle;
		out->swq_mem_size = qp->swq_size;
	}

	if (!rwq_arr_props->on_device_mem) {
		rc = alloc_and_map_wq(cn_port, qp, wq_size, false);
		if (rc)
			goto err_free_swq;

		out->rwq_mem_handle = qp->rwq_handle;
		out->rwq_mem_size = qp->rwq_size;
	}

	qp->remote_key = in->remote_key;

	rc = hbl_cn_qp_modify(cn_port, qp, CN_QP_STATE_RTS, in);
	if (rc)
		goto err_free_rwq;

	port_funcs->cfg_unlock(cn_port);

	return 0;

err_free_rwq:
	if (qp->rwq_handle) {
		hbl_cn_mem_destroy(hdev, qp->rwq_handle);
		qp->rwq_handle = 0;
		out->rwq_mem_handle = qp->rwq_handle;
		if (!rwq_arr_props->dva_base) {
			int ret;

			ret = hbl_cn_mem_buf_put_handle(hdev, rwq_arr_props->handle);
			if (ret == 1)
				rwq_arr_props->handle = 0;
		}
	}
err_free_swq:
	if (qp->swq_handle) {
		hbl_cn_mem_destroy(hdev, qp->swq_handle);
		qp->swq_handle = 0;
		out->swq_mem_handle = qp->swq_handle;
		if (!swq_arr_props->dva_base) {
			int ret;

			ret = hbl_cn_mem_buf_put_handle(hdev, swq_arr_props->handle);
			if (ret == 1)
				swq_arr_props->handle = 0;
		}
	}
cfg_unlock:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int set_res_qp_ctx(struct hbl_cn_device *hdev, struct hbl_cni_res_conn_ctx_in *in)
{
	struct hbl_cn_encap_xarray_pdata *encap_data;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_asic_funcs *asic_funcs;
	struct hbl_cn_port *cn_port;
	struct hbl_cn_qp *qp;
	u32 port;
	int rc;

	port = in->port;

	rc = hbl_cn_cmd_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	asic_funcs = hdev->asic_funcs;
	port_funcs = asic_funcs->port_funcs;
	cn_port = &hdev->cn_ports[port];

	port_funcs->cfg_lock(cn_port);
	qp = xa_load(&cn_port->qp_ids, in->conn_id);

	if (IS_ERR_OR_NULL(qp)) {
		dev_dbg(hdev->dev, "Failed to find matching QP for handle %d, port %d\n",
			in->conn_id, port);
		rc = -EINVAL;
		goto unlock_cfg;
	}

	if (in->encap_en) {
		encap_data = xa_load(&cn_port->encap_ids, in->encap_id);
		if (!encap_data) {
			dev_dbg_ratelimited(hdev->dev,
					    "Encapsulation ID %d not found, ignoring\n",
					    in->encap_id);
			in->encap_en = 0;
			in->encap_id = 0;
		}
	}

	if (qp->is_res) {
		dev_dbg(hdev->dev, "Port %d, QP %d - Responder QP is already set\n", port,
			qp->qp_id);
		rc = -EINVAL;
		goto unlock_cfg;
	}

	/* sanity test the port IDs */
	if (qp->port != port) {
		dev_dbg(hdev->dev, "QP port %d does not match requested port %d\n", qp->port, port);
		rc = -EINVAL;
		goto unlock_cfg;
	}

	qp->local_key = in->local_key;

	if (qp->curr_state == CN_QP_STATE_RESET) {
		rc = hbl_cn_qp_modify(cn_port, qp, CN_QP_STATE_INIT, NULL);
		if (rc)
			goto unlock_cfg;
	}

	/* all is well, we are ready to receive */
	rc = hbl_cn_qp_modify(cn_port, qp, CN_QP_STATE_RTR, in);

	port_funcs->cfg_unlock(cn_port);

	return rc;

unlock_cfg:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

/* must be called under the port cfg lock */
u32 hbl_cn_get_max_qp_id(struct hbl_cn_port *cn_port)
{
	int max_qp_id = cn_port->qp_idx_offset;
	unsigned long qp_id = 0;
	struct hbl_cn_qp *qp;

	xa_for_each(&cn_port->qp_ids, qp_id, qp)
		if (qp->qp_id > max_qp_id)
			max_qp_id = qp->qp_id;

	return max_qp_id;
}

static void qp_destroy_work(struct work_struct *work)
{
	struct hbl_cn_qp *qp = container_of(work, struct hbl_cn_qp, async_work);
	struct hbl_cn_wq_array_properties *swq_arr_props, *rwq_arr_props;
	struct hbl_cn_port *cn_port = qp->cn_port;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_qpc_drain_attr drain_attr;
	struct hbl_cn_qpc_reset_attr rst_attr;
	struct hbl_cn_ctx *ctx = qp->ctx;
	struct hbl_cn_device *hdev;
	int rc;

	hdev = cn_port->hdev;
	port_funcs = hdev->asic_funcs->port_funcs;

	if (!hdev->operational) {
		drain_attr.wait_for_idle = false;
		rst_attr.reset_mode = hdev->qp_reset_mode;
	} else {
		drain_attr.wait_for_idle = true;
		rst_attr.reset_mode = CN_QP_RESET_MODE_GRACEFUL;
	}

	/* Complete the wait for SQ to drain. To allow parallel QPs destruction, don't take the cfg
	 * lock here. This is safe because SQD->SQD QP transition is a simple wait to drain the QP
	 * without any access to the HW.
	 */
	if (qp->curr_state == CN_QP_STATE_SQD)
		hbl_cn_qp_modify(cn_port, qp, CN_QP_STATE_SQD, &drain_attr);

	port_funcs->cfg_lock(cn_port);

	hbl_cn_qp_modify(cn_port, qp, CN_QP_STATE_RESET, &rst_attr);

	port_funcs->unregister_qp(cn_port, qp->qp_id);

	swq_arr_props = &cn_port->wq_arr_props[HBL_CNI_USER_WQ_SEND];
	rwq_arr_props = &cn_port->wq_arr_props[HBL_CNI_USER_WQ_RECV];

	if (qp->swq_handle) {
		hbl_cn_mem_destroy(hdev, qp->swq_handle);
		qp->swq_handle = 0;
		if (!swq_arr_props->dva_base) {
			rc = hbl_cn_mem_buf_put_handle(hdev, swq_arr_props->handle);
			if (rc == 1)
				swq_arr_props->handle = 0;
		}
	}

	if (qp->rwq_handle) {
		hbl_cn_mem_destroy(hdev, qp->rwq_handle);
		qp->rwq_handle = 0;
		if (!rwq_arr_props->dva_base) {
			rc = hbl_cn_mem_buf_put_handle(hdev, rwq_arr_props->handle);
			if (rc == 1)
				rwq_arr_props->handle = 0;
		}
	}

	xa_erase(&cn_port->qp_ids, qp->qp_id);

	if (atomic_dec_and_test(&cn_port->num_of_allocated_qps)) {
		if (swq_arr_props->under_unset)
			__user_wq_arr_unset(ctx, cn_port, HBL_CNI_USER_WQ_SEND);

		if (rwq_arr_props->under_unset)
			__user_wq_arr_unset(ctx, cn_port, HBL_CNI_USER_WQ_RECV);
	}

	if (qp->req_user_cq)
		hbl_cn_user_cq_put(qp->req_user_cq);

	if (qp->res_user_cq)
		hbl_cn_user_cq_put(qp->res_user_cq);

	port_funcs->qp_post_destroy(qp);

	/* hbl_cn_mem_destroy should be included inside lock not due to protection.
	 * The handles (swq_handle and rwq_handle) are created based on QP id.
	 * Lock is to avoid concurrent memory access from a new handle created before freeing
	 * memory.
	 */
	port_funcs->cfg_unlock(cn_port);

	kfree(qp);
}

static void qps_drain_async_work(struct hbl_cn_device *hdev)
{
	struct hbl_cn_port *cn_port;
	int i, num_gen_qps;

	/* wait for the workers to complete */
	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		drain_workqueue(cn_port->qp_wq);

		num_gen_qps = atomic_read(&cn_port->num_of_allocated_qps);
		if (num_gen_qps)
			dev_warn(hdev->dev, "Port %d still has %d QPs alive\n", i, num_gen_qps);
	}
}

static inline int __must_check PTR_ERR_OR_EINVAL(__force const void *ptr)
{
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	else
		return -EINVAL;
}

static int destroy_qp(struct hbl_cn_device *hdev, struct hbl_cni_destroy_conn_in *in)
{
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_asic_funcs *asic_funcs;
	struct hbl_cn_port *cn_port;
	struct hbl_cn_qp *qp;
	u32 port, flags;
	int rc;

	port = in->port;

	if (port >= hdev->cn_props.max_num_of_ports) {
		dev_dbg(hdev->dev, "Invalid port %d\n", port);
		return -EINVAL;
	}

	cn_port = &hdev->cn_ports[port];

	/* in case of destroying QPs of external ports, the port may be already closed by a user
	 * issuing "ip link set down" command so we only check if the port is enabled in these
	 * ports.
	 */
	flags = cn_port->eth_enable ? NIC_PORT_CHECK_ENABLE : NIC_PORT_CHECK_OPEN;
	flags |= NIC_PORT_PRINT_ON_ERR;
	rc = hbl_cn_cmd_port_check(hdev, port, flags);
	if (rc)
		return rc;

	asic_funcs = hdev->asic_funcs;
	port_funcs = asic_funcs->port_funcs;

	/* prevent reentrancy by locking the whole process of destroy_qp */
	port_funcs->cfg_lock(cn_port);
	qp = xa_load(&cn_port->qp_ids, in->conn_id);

	if (IS_ERR_OR_NULL(qp)) {
		rc = PTR_ERR_OR_EINVAL(qp);
		goto out_err;
	}

	hbl_cn_qp_do_release(qp);

	port_funcs->cfg_unlock(cn_port);

	return 0;

out_err:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static void hbl_cn_qps_stop(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_asic_port_funcs *port_funcs = cn_port->hdev->asic_funcs->port_funcs;
	struct hbl_cn_qpc_drain_attr drain = { .wait_for_idle = false, };
	unsigned long qp_id = 0;
	struct hbl_cn_qp *qp;

	port_funcs->cfg_lock(cn_port);

	xa_for_each(&cn_port->qp_ids, qp_id, qp) {
		if (IS_ERR_OR_NULL(qp))
			continue;

		hbl_cn_qp_modify(cn_port, qp, CN_QP_STATE_QPD, (void *)&drain);
	}

	port_funcs->cfg_unlock(cn_port);
}

static void qps_stop(struct hbl_cn_device *hdev)
{
	struct hbl_cn_port *cn_port;
	int i;

	/* stop the QPs */
	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		hbl_cn_qps_stop(cn_port);
	}
}

static int user_wq_arr_set(struct hbl_cn_device *hdev, struct hbl_cni_user_wq_arr_set_in *in,
			   struct hbl_cni_user_wq_arr_set_out *out, struct hbl_cn_ctx *ctx)
{
	u32 port, type, num_of_wqs, num_of_wq_entries, min_wqs_per_port, mem_id;
	struct hbl_cn_wq_array_properties *wq_arr_props;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_properties *cn_props;
	struct hbl_cn_port *cn_port;
	char *type_str;
	int rc;

	if (in->swq_granularity > HBL_CNI_SWQE_GRAN_64B) {
		dev_dbg(hdev->dev, "Invalid send WQE granularity %d\n", in->swq_granularity);
		return -EINVAL;
	}

	port_funcs = hdev->asic_funcs->port_funcs;
	cn_props = &hdev->cn_props;

	type = in->type;

	if (type > cn_props->max_wq_arr_type) {
		dev_dbg(hdev->dev, "invalid type %d, can't set user WQ\n", type);
		return -EINVAL;
	}

	mem_id = in->mem_id;

	if (mem_id != HBL_CNI_MEM_HOST && mem_id != HBL_CNI_MEM_DEVICE) {
		dev_dbg(hdev->dev, "invalid memory type %d for user WQ\n", mem_id);
		return -EINVAL;
	}

	port = in->port;
	rc = hbl_cn_cmd_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];

	wq_arr_props = &cn_port->wq_arr_props[type];
	type_str = wq_arr_props->type_str;

	/* For generic WQs minimum number of wqs required is 2, one for raw eth and one for rdma */
	min_wqs_per_port = NIC_MIN_WQS_PER_PORT;
	if (in->num_of_wqs < min_wqs_per_port) {
		dev_dbg(hdev->dev, "number of %s WQs must be minimum %d, port %d\n", type_str,
			min_wqs_per_port, port);
		return -EINVAL;
	}

	/* H/W limitation */
	if (in->num_of_wqs > cn_props->max_hw_qps_num) {
		dev_dbg(hdev->dev, "number of %s WQs (0x%x) can't be bigger than 0x%x, port %d\n",
			type_str, in->num_of_wqs, cn_props->max_hw_qps_num, port);
		return -EINVAL;
	}

	if (!is_power_of_2(in->num_of_wq_entries)) {
		dev_dbg(hdev->dev,
			"number of %s WQ entries (0x%x) must be a power of 2, port %d\n", type_str,
			in->num_of_wq_entries, port);
		return -EINVAL;
	}

	/* H/W limitation */
	if (in->num_of_wq_entries < cn_props->min_hw_user_wqs_num) {
		dev_dbg(hdev->dev,
			"number of %s WQ entries (0x%x) must be at least %d, port %d\n", type_str,
			in->num_of_wq_entries, cn_props->min_hw_user_wqs_num, port);
		return -EINVAL;
	}

	/* H/W limitation */
	if (in->num_of_wq_entries > cn_props->max_hw_user_wqs_num) {
		dev_dbg(hdev->dev,
			"number of %s WQ entries (0x%x) can't be bigger than 0x%x, port %d\n",
			type_str, in->num_of_wq_entries, cn_props->max_hw_user_wqs_num, port);
		return -EINVAL;
	}

	port_funcs->cfg_lock(cn_port);

	if (!cn_port->set_app_params) {
		dev_dbg(hdev->dev,
			"Failed to set %s WQ array, set_app_params wasn't called yet, port %d\n",
			type_str, port);
		rc = -EPERM;
		goto out;
	}

	/* we first check the wq_under_unset condition since a prev WQ unset (async) operation may
	 * still be in progress, and since in such cases we would like to return -EAGAIN to the
	 * caller and not -EINVAL
	 */
	if (wq_arr_props->enabled && wq_arr_props->under_unset) {
		dev_dbg_ratelimited(hdev->dev,
				    "Retry to set %s WQ array as it is under unset, port %d\n",
				    type_str, port);
		rc = -EAGAIN;
		goto out;
	}

	if (wq_arr_props->enabled) {
		dev_dbg(hdev->dev, "%s WQ array is already enabled, port %d\n", type_str, port);
		rc = -EINVAL;
		goto out;
	}

	if (wq_arr_props->under_unset) {
		dev_dbg(hdev->dev,
			"Failed to set %s WQ array as it is not enabled and under unset, port %d\n",
			type_str, port);
		rc = -EPERM;
		goto out;
	}

	num_of_wq_entries = cn_port->num_of_wq_entries;
	num_of_wqs = cn_port->num_of_wqs;

	if (num_of_wq_entries && num_of_wq_entries != in->num_of_wq_entries) {
		dev_dbg(hdev->dev, "%s WQ number of entries (0x%x) should be 0x%x, port %d\n",
			type_str, in->num_of_wq_entries, num_of_wq_entries, port);
		rc = -EINVAL;
		goto out;
	}

	if (num_of_wqs && num_of_wqs != in->num_of_wqs) {
		dev_dbg(hdev->dev, "%s WQs number (0x%x) should be 0x%x, port %d\n",
			type_str, in->num_of_wqs, num_of_wqs, port);
		rc = -EINVAL;
		goto out;
	}

	rc = hdev->asic_funcs->user_wq_arr_set(hdev, in, out, ctx);
	if (rc) {
		dev_err(hdev->dev, "%s WQ array set failed, port %d, err %d\n", type_str, port, rc);
		goto out;
	}

	cn_port->num_of_wq_entries = in->num_of_wq_entries;
	cn_port->num_of_wqs = in->num_of_wqs;

	wq_arr_props->enabled = true;

out:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int __user_wq_arr_unset(struct hbl_cn_ctx *ctx, struct hbl_cn_port *cn_port, u32 type)
{
	struct hbl_cn_wq_array_properties *wq_arr_props;
	struct hbl_cn_device *hdev;
	char *type_str;
	u32 port;
	int rc;

	hdev = ctx->hdev;
	wq_arr_props = &cn_port->wq_arr_props[type];
	type_str = wq_arr_props->type_str;
	port = cn_port->port;

	rc = hdev->asic_funcs->port_funcs->user_wq_arr_unset(ctx, cn_port, type);
	if (rc)
		dev_err(hdev->dev, "%s WQ array unset failed, port %d, err %d\n", type_str, port,
			rc);

	wq_arr_props->enabled = false;
	wq_arr_props->under_unset = false;

	if (!cn_port->wq_arr_props[HBL_CNI_USER_WQ_SEND].enabled &&
	    !cn_port->wq_arr_props[HBL_CNI_USER_WQ_RECV].enabled) {
		cn_port->num_of_wq_entries = 0;
		cn_port->num_of_wqs = 0;
	}

	return rc;
}

static int user_wq_arr_unset(struct hbl_cn_device *hdev, struct hbl_cni_user_wq_arr_unset_in *in,
			     struct hbl_cn_ctx *ctx)
{
	struct hbl_cn_wq_array_properties *wq_arr_props;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_properties *cn_props;
	struct hbl_cn_port *cn_port;
	u32 port, type;
	char *type_str;
	int rc;

	port_funcs = hdev->asic_funcs->port_funcs;
	cn_props = &hdev->cn_props;

	type = in->type;

	if (type > cn_props->max_wq_arr_type) {
		dev_dbg(hdev->dev, "invalid type %d, can't unset user WQ\n", type);
		return -EINVAL;
	}

	port = in->port;

	/* No need to check if the port is open because internal ports are always open and external
	 * ports might be closed by a user command e.g. "ip link set down" after a WQ was
	 * configured, but we still want to unset it.
	 */
	rc = hbl_cn_cmd_port_check(hdev, port, NIC_PORT_CHECK_ENABLE | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];

	wq_arr_props = &cn_port->wq_arr_props[type];
	type_str = wq_arr_props->type_str;

	port_funcs->cfg_lock(cn_port);

	if (!wq_arr_props->enabled) {
		dev_dbg(hdev->dev, "%s WQ array is disabled, port %d\n", type_str, port);
		rc = -EINVAL;
		goto out;
	}

	if (wq_arr_props->under_unset) {
		dev_dbg(hdev->dev, "%s WQ array is already under unset, port %d\n", type_str, port);
		rc = -EPERM;
		goto out;
	}

	/* Allocated QPs might still use the WQ, hence unset the WQ once they are destroyed */
	if (atomic_read(&cn_port->num_of_allocated_qps)) {
		wq_arr_props->under_unset = true;
		rc = 0;
		goto out;
	}

	rc = __user_wq_arr_unset(ctx, cn_port, type);
out:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int alloc_user_cq_id(struct hbl_cn_device *hdev, struct hbl_cni_alloc_user_cq_id_in *in,
			    struct hbl_cni_alloc_user_cq_id_out *out, struct hbl_cn_ctx *ctx)
{
	struct hbl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	struct hbl_cn_properties *cn_props = &hdev->cn_props;
	u32 min_id, max_id, port, flags;
	struct hbl_cn_user_cq *user_cq;
	struct hbl_cn_port *cn_port;
	struct xa_limit id_limit;
	int id, rc;

	port = in->port;
	flags = NIC_PORT_PRINT_ON_ERR;

	if (!cn_props->force_cq)
		flags |= NIC_PORT_CHECK_OPEN;

	rc = hbl_cn_cmd_port_check(hdev, port, flags);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];

	user_cq = kzalloc(sizeof(*user_cq), GFP_KERNEL);
	if (!user_cq)
		return -ENOMEM;

	user_cq->state = USER_CQ_STATE_ALLOC;
	user_cq->ctx = ctx;
	user_cq->cn_port = cn_port;
	kref_init(&user_cq->refcount);

	port_funcs->get_cq_id_range(cn_port, &min_id, &max_id);

	port_funcs->cfg_lock(cn_port);

	if (!cn_port->set_app_params) {
		dev_dbg(hdev->dev,
			"Failed to allocate a CQ ID, set_app_params wasn't called yet, port %d\n",
			port);
		rc = -EPERM;
		goto cfg_unlock;
	}

	id_limit = XA_LIMIT(min_id, max_id);
	rc = xa_alloc(&cn_port->cq_ids, &id, user_cq, id_limit, GFP_KERNEL);
	if (rc) {
		dev_err(hdev->dev, "No available user CQ, port %d\n", port);
		goto cfg_unlock;
	}

	user_cq->id = id;

	mutex_init(&user_cq->overrun_lock);

	port_funcs->cfg_unlock(cn_port);

	dev_dbg(hdev->dev, "Allocating CQ id %d in port %d", id, port);

	out->id = id;

	return 0;

cfg_unlock:
	port_funcs->cfg_unlock(cn_port);
	kfree(user_cq);

	return rc;
}

static bool validate_cq_id_range(struct hbl_cn_port *cn_port, u32 cq_id)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_asic_port_funcs *port_funcs;
	u32 min_id, max_id;

	port_funcs = hdev->asic_funcs->port_funcs;

	port_funcs->get_cq_id_range(cn_port, &min_id, &max_id);

	return (cq_id >= min_id) && (cq_id <= max_id);
}

static int __user_cq_set(struct hbl_cn_device *hdev, struct hbl_cni_user_cq_set_in_params *in,
			 struct hbl_cni_user_cq_set_out_params *out)
{
	struct hbl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	struct hbl_cn_properties *cn_props = &hdev->cn_props;
	struct hbl_cn_user_cq *user_cq;
	struct hbl_cn_port *cn_port;
	u32 port, flags, id;
	int rc;

	id = in->id;
	port = in->port;

	flags = NIC_PORT_PRINT_ON_ERR;

	if (!cn_props->force_cq)
		flags |= NIC_PORT_CHECK_OPEN;

	rc = hbl_cn_cmd_port_check(hdev, port, flags);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];

	if (!validate_cq_id_range(cn_port, id)) {
		dev_dbg(hdev->dev, "user CQ %d is invalid, port %d\n", id, port);
		return -EINVAL;
	}

	if (in->num_of_cqes < cn_props->user_cq_min_entries) {
		dev_dbg(hdev->dev,
			"user CQ %d buffer length must be at least 0x%x entries, port %d\n",
			id, cn_props->user_cq_min_entries, port);
		return -EINVAL;
	}

	if (!is_power_of_2(in->num_of_cqes)) {
		dev_dbg(hdev->dev, "user CQ %d buffer length must be at power of 2, port %d\n",
			id, port);
		return -EINVAL;
	}

	if (in->num_of_cqes > cn_props->user_cq_max_entries) {
		dev_dbg(hdev->dev,
			"user CQ %d buffer length must not be more than 0x%x entries, port %d\n",
			id, cn_props->user_cq_max_entries, port);
		return -EINVAL;
	}

	port_funcs->cfg_lock(cn_port);

	/* Validate if user CQ is allocated. */
	user_cq = xa_load(&cn_port->cq_ids, id);
	if (!user_cq) {
		dev_dbg(hdev->dev, "user CQ %d wasn't allocated, port %d\n", id, port);
		rc = -EINVAL;
		goto out;
	}

	/* Validate that user CQ is in ALLOC state. */
	if (user_cq->state != USER_CQ_STATE_ALLOC) {
		dev_dbg(hdev->dev, "user CQ %d set failed, current state %d, port %d\n",
			id, user_cq->state, port);
		rc = -EINVAL;
		goto out;
	}

	rc = port_funcs->user_cq_set(user_cq, in, out);
	if (rc) {
		dev_dbg(hdev->dev, "user CQ %d set failed, port %d\n", id, port);
		goto out;
	}

	user_cq->state = USER_CQ_STATE_SET;
out:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int user_cq_id_set(struct hbl_cn_device *hdev, struct hbl_cni_user_cq_id_set_in *in,
			  struct hbl_cni_user_cq_id_set_out *out)
{
	struct hbl_cni_user_cq_set_out_params out2 = {};
	struct hbl_cni_user_cq_set_in_params in2 = {};
	int rc;

	in2.port = in->port;
	in2.num_of_cqes = in->num_of_cqes;
	in2.id = in->id;

	rc = __user_cq_set(hdev, &in2, &out2);
	if (rc)
		return rc;

	out->mem_handle = out2.mem_handle;
	out->pi_handle = out2.pi_handle;
	out->regs_handle = out2.regs_handle;
	out->regs_offset = out2.regs_offset;

	return 0;
}

static void user_cq_destroy(struct kref *kref)
{
	struct hbl_cn_user_cq *user_cq = container_of(kref, struct hbl_cn_user_cq, refcount);
	struct hbl_cn_port *cn_port = user_cq->cn_port;
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_asic_port_funcs *port_funcs;

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

struct hbl_cn_user_cq *hbl_cn_user_cq_get(struct hbl_cn_port *cn_port, u8 cq_id)
{
	struct hbl_cn_user_cq *user_cq;

	user_cq = xa_load(&cn_port->cq_ids, cq_id);
	if (!user_cq || user_cq->state != USER_CQ_STATE_SET)
		return NULL;

	kref_get(&user_cq->refcount);

	return user_cq;
}

int hbl_cn_user_cq_put(struct hbl_cn_user_cq *user_cq)
{
	return kref_put(&user_cq->refcount, user_cq_destroy);
}

static int user_cq_unset_locked(struct hbl_cn_user_cq *user_cq, bool warn_if_alive)
{
	struct hbl_cn_port *cn_port = user_cq->cn_port;
	struct hbl_cn_device *hdev = cn_port->hdev;
	u32 port = cn_port->port, id = user_cq->id;
	struct hbl_cn_asic_port_funcs *port_funcs;
	int rc = 0, ret;

	port_funcs = hdev->asic_funcs->port_funcs;

	/* Call unset only if the CQ has already been SET */
	if (user_cq->state == USER_CQ_STATE_SET) {
		rc = port_funcs->user_cq_unset(user_cq);
		if (rc)
			dev_dbg(hdev->dev, "user CQ %d unset failed, port %d\n", id, port);

		user_cq->state = USER_CQ_STATE_SET_TO_UNSET;
	} else {
		user_cq->state = USER_CQ_STATE_ALLOC_TO_UNSET;
	}

	/* we'd like to destroy even if the unset callback returned error */
	ret = hbl_cn_user_cq_put(user_cq);

	if (warn_if_alive && ret != 1)
		dev_warn(hdev->dev, "user CQ %d was not destroyed, port %d\n", id, port);

	return rc;
}

static int __user_cq_unset(struct hbl_cn_device *hdev, struct hbl_cni_user_cq_unset_in_params *in)
{
	struct hbl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	struct hbl_cn_properties *cn_props = &hdev->cn_props;
	struct hbl_cn_user_cq *user_cq;
	struct hbl_cn_port *cn_port;
	u32 port, flags, id;
	int rc;

	port = in->port;
	id = in->id;

	if (port >= cn_props->max_num_of_ports) {
		dev_dbg(hdev->dev, "Invalid port %d\n", port);
		return -EINVAL;
	}

	cn_port = &hdev->cn_ports[port];

	flags = NIC_PORT_PRINT_ON_ERR;

	/* Unless force_cq flag in enabled, in case of user CQ unset of external ports, the port
	 * may be already closed by the user, so we only check if the port is enabled.
	 */
	if (!cn_props->force_cq)
		flags |= cn_port->eth_enable ? NIC_PORT_CHECK_ENABLE : NIC_PORT_CHECK_OPEN;

	rc = hbl_cn_cmd_port_check(hdev, port, flags);
	if (rc)
		return rc;

	if (!validate_cq_id_range(cn_port, id)) {
		dev_dbg(hdev->dev, "user CQ %d is invalid, port %d\n", id, port);
		return -EINVAL;
	}

	port_funcs->cfg_lock(cn_port);

	/* Validate if user CQ is allocated. */
	user_cq = xa_load(&cn_port->cq_ids, id);
	if (!user_cq) {
		dev_dbg(hdev->dev, "user CQ %d wasn't allocated, port %d\n", id, port);
		rc = -EINVAL;
		goto out;
	}

	rc = user_cq_unset_locked(user_cq, false);
out:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int user_cq_id_unset(struct hbl_cn_device *hdev, struct hbl_cni_user_cq_id_unset_in *in)
{
	struct hbl_cni_user_cq_unset_in_params in2 = {};

	in2.port = in->port;
	in2.id = in->id;

	return __user_cq_unset(hdev, &in2);
}

static int user_set_app_params(struct hbl_cn_device *hdev,
			       struct hbl_cni_set_user_app_params_in *in, struct hbl_cn_ctx *ctx)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_port *cn_port;
	bool modify_wqe_checkers;
	u32 port;
	int rc;

	port_funcs = asic_funcs->port_funcs;

	port = in->port;

	rc = hbl_cn_cmd_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];

	/* We must take rtnl_lock here prior to taking cfg_lock, as we may land into flow that
	 * extracts the IP port and that can cause a deadlock in case an operation from the
	 * net subsystem that requires the cfg_lock is executed at the same time. As such operation
	 * will first obtain rtnl_lock and then will try to take a cfg_lock, hence a deadlock.
	 */
	rtnl_lock();
	port_funcs->cfg_lock(cn_port);

	rc = asic_funcs->user_set_app_params(hdev, in, &modify_wqe_checkers, ctx);
	if (rc)
		goto out;

	if (modify_wqe_checkers) {
		rc = hdev->asic_funcs->port_funcs->disable_wqe_index_checker(cn_port);
		if (rc) {
			dev_err(hdev->dev, "Failed disable wqe index checker, port %d rc %d\n",
				port, rc);
			goto out;
		}
	}

	cn_port->set_app_params = true;

out:
	port_funcs->cfg_unlock(cn_port);
	rtnl_unlock();

	return rc;
}

static int user_get_app_params(struct hbl_cn_device *hdev,
			       struct hbl_cni_get_user_app_params_in *in,
			       struct hbl_cni_get_user_app_params_out *out)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_port *cn_port;
	u32 port;
	int rc;

	port_funcs = asic_funcs->port_funcs;

	port = in->port;

	rc = hbl_cn_cmd_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];

	port_funcs->cfg_lock(cn_port);
	asic_funcs->user_get_app_params(hdev, in, out);
	port_funcs->cfg_unlock(cn_port);

	return 0;
}

static int eq_poll(struct hbl_cn_device *hdev, struct hbl_cn_ctx *ctx,
		   struct hbl_cni_eq_poll_in *in, struct hbl_cni_eq_poll_out *out)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	struct hbl_cn_port *cn_port;
	u32 port;
	int rc;

	port = in->port;
	rc = hbl_cn_cmd_port_check(hdev, port, NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];
	rc = asic_funcs->port_funcs->eq_poll(cn_port, ctx->asid, out);
	switch (rc) {
	case 0:
		out->status = HBL_CNI_EQ_POLL_STATUS_SUCCESS;
		break;
	case -EOPNOTSUPP:
		out->status = HBL_CNI_EQ_POLL_STATUS_ERR_UNSUPPORTED_OP;
		break;
	case -EINVAL:
		out->status = HBL_CNI_EQ_POLL_STATUS_ERR_NO_SUCH_PORT;
		break;
	case -ENXIO:
		out->status = HBL_CNI_EQ_POLL_STATUS_ERR_PORT_DISABLED;
		break;
	case -ENODATA:
		out->status = HBL_CNI_EQ_POLL_STATUS_EQ_EMPTY;
		break;
	case -ESRCH:
		out->status = HBL_CNI_EQ_POLL_STATUS_ERR_NO_SUCH_EQ;
		break;
	default:
		out->status = HBL_CNI_EQ_POLL_STATUS_ERR_UNDEF;
		break;
	}

	return 0;
}

static void get_user_db_fifo_id_range(struct hbl_cn_port *cn_port, u32 *min_id, u32 *max_id,
				      u32 id_hint)
{
	struct hbl_cn_asic_port_funcs *port_funcs;

	port_funcs = cn_port->hdev->asic_funcs->port_funcs;

	/* id_hint comes from user. Driver enforces allocation of the requested
	 * db fifo HW resource. i.e. driver fails if requested resource is not
	 * available. Reason, user stack has hard coded user fifo resource IDs.
	 */
	if (id_hint) {
		*min_id = id_hint;
		*max_id = id_hint;
	} else {
		port_funcs->get_db_fifo_id_range(cn_port, min_id, max_id);
	}
}

static int alloc_user_db_fifo(struct hbl_cn_device *hdev, struct hbl_cn_ctx *ctx,
			      struct hbl_cni_alloc_user_db_fifo_in *in,
			      struct hbl_cni_alloc_user_db_fifo_out *out)
{
	struct hbl_cn_db_fifo_xarray_pdata *xa_pdata;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_port *cn_port;
	struct xa_limit id_limit;
	u32 min_id, max_id;
	int rc, id;
	u32 port;

	port = in->port;
	rc = hbl_cn_cmd_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];
	port_funcs = hdev->asic_funcs->port_funcs;

	get_user_db_fifo_id_range(cn_port, &min_id, &max_id, in->id_hint);

	/* IDR private data. */
	xa_pdata = kzalloc(sizeof(*xa_pdata), GFP_KERNEL);
	if (!xa_pdata)
		return -ENOMEM;

	xa_pdata->asid = ctx->asid;
	xa_pdata->state = DB_FIFO_STATE_ALLOC;
	xa_pdata->port = port;

	port_funcs->cfg_lock(cn_port);

	if (!cn_port->set_app_params) {
		dev_dbg(hdev->dev,
			"Failed to allocate DB FIFO, set_app_params wasn't called yet, port %d\n",
			port);
		rc = -EPERM;
		goto cfg_unlock;
	}

	id_limit = XA_LIMIT(min_id, max_id);
	rc = xa_alloc(&cn_port->db_fifo_ids, &id, xa_pdata, id_limit, GFP_KERNEL);
	if (rc) {
		dev_dbg_ratelimited(hdev->dev, "DB FIFO ID allocation failed, port %d\n", port);
		goto cfg_unlock;
	}

	xa_pdata->id = id;

	port_funcs->cfg_unlock(cn_port);

	out->id = id;

	return 0;

cfg_unlock:
	port_funcs->cfg_unlock(cn_port);
	kfree(xa_pdata);
	return rc;
}

static int validate_db_fifo_id_range(struct hbl_cn_port *cn_port, u32 db_fifo_id)
{
	struct hbl_cn_asic_funcs *asic_funcs;
	struct hbl_cn_device *hdev;
	u32 min_id, max_id;

	hdev = cn_port->hdev;
	asic_funcs = hdev->asic_funcs;

	asic_funcs->port_funcs->get_db_fifo_id_range(cn_port, &min_id, &max_id);

	if (db_fifo_id < min_id || db_fifo_id > max_id) {
		dev_dbg_ratelimited(hdev->dev, "Invalid db fifo ID, %d, port: %d\n", db_fifo_id,
				    cn_port->port);
		return -EINVAL;
	}

	return 0;
}

static int validate_db_fifo_mode(struct hbl_cn_port *cn_port, u8 fifo_mode)
{
	struct hbl_cn_asic_funcs *asic_funcs;
	struct hbl_cn_device *hdev;
	u32 modes_mask;

	hdev = cn_port->hdev;
	asic_funcs = hdev->asic_funcs;

	asic_funcs->port_funcs->get_db_fifo_modes_mask(cn_port, &modes_mask);

	if (!(BIT(fifo_mode) & modes_mask)) {
		dev_dbg_ratelimited(hdev->dev, "Invalid db fifo mode, %d, port: %d\n", fifo_mode,
				    cn_port->port);
		return -EINVAL;
	}

	return 0;
}

static int validate_db_fifo_ioctl(struct hbl_cn_port *cn_port, u32 db_fifo_id)
{
	return validate_db_fifo_id_range(cn_port, db_fifo_id);
}

static int user_db_fifo_unset_and_free(struct hbl_cn_port *cn_port,
				       struct hbl_cn_db_fifo_xarray_pdata *xa_pdata)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_asic_funcs *asic_funcs;
	int rc = 0;

	asic_funcs = hdev->asic_funcs;

	asic_funcs->port_funcs->db_fifo_unset(cn_port, xa_pdata->id, xa_pdata);

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
		rc = hbl_cn_mem_destroy(hdev, xa_pdata->ci_mmap_handle);

	asic_funcs->port_funcs->db_fifo_free(cn_port, xa_pdata->db_pool_addr, xa_pdata->fifo_size);

	return rc;
}

static int user_db_fifo_set(struct hbl_cn_device *hdev, struct hbl_cn_ctx *ctx,
			    struct hbl_cni_user_db_fifo_set_in *in,
			    struct hbl_cni_user_db_fifo_set_out *out)
{
	u64 umr_block_addr, umr_mmap_handle, ci_mmap_handle = 0, ci_device_handle;
	struct hbl_cn_db_fifo_xarray_pdata *xa_pdata;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_mem_data mem_data = {};
	struct hbl_cn_port *cn_port;
	u32 umr_db_offset, port, id;
	int rc;

	port = in->port;
	rc = hbl_cn_cmd_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];
	port_funcs = hdev->asic_funcs->port_funcs;
	id = in->id;

	rc = validate_db_fifo_ioctl(cn_port, id);
	if (rc)
		return rc;

	/* Get allocated ID private data. Having meta data associated with IDR also helps validate
	 * that user do not trick kernel into configuring db fifo HW for an unallocated ID.
	 */
	port_funcs->cfg_lock(cn_port);
	xa_pdata = xa_load(&cn_port->db_fifo_ids, id);
	if (!xa_pdata) {
		dev_dbg_ratelimited(hdev->dev, "DB FIFO ID %d is not allocated, port: %d\n", id,
				    port);
		rc = -EINVAL;
		goto cfg_unlock;
	}

	rc = validate_db_fifo_mode(cn_port, in->mode);
	if (rc)
		goto cfg_unlock;

	xa_pdata->fifo_mode = in->mode;

	/* User may call db_fifo_set multiple times post db_fifo_alloc. So, before doing any
	 * further register changes, make sure to unset the previous settings for this id
	 */
	if (xa_pdata->state == DB_FIFO_STATE_SET) {
		rc = user_db_fifo_unset_and_free(cn_port, xa_pdata);
		if (rc) {
			dev_dbg(hdev->dev, "Fail to unset DB FIFO %d before set, port %d\n", id,
				port);
			goto cfg_unlock;
		}
	}

	rc = port_funcs->db_fifo_allocate(cn_port, xa_pdata);
	if (rc) {
		dev_dbg(hdev->dev, "DB FIFO %d allocation failed, port %d, mode %d\n", id, port,
			in->mode);
		goto cfg_unlock;
	}

	/* Get the user mapped register(UMR) block address and
	 * db fifo offset associated with the ID.
	 */
	port_funcs->get_db_fifo_umr(cn_port, id, &umr_block_addr, &umr_db_offset);

	/* Get mmap handle for UMR block. */
	rc = hbl_cn_get_hw_block_handle(hdev, umr_block_addr, &umr_mmap_handle);
	if (rc) {
		dev_dbg_ratelimited(hdev->dev,
				    "Failed to get UMR mmap handle of DB FIFO %d, port %d\n", id,
				    port);
		goto free_db_fifo;
	}

	/* Allocate a consumer-index(CI) buffer in host kernel.
	 * HW updates CI when it pops a db fifo. User mmaps CI buffer and may poll to read current
	 * CI.
	 * Allocate page size, else we risk exposing kernel data to userspace inadvertently.
	 */
	mem_data.mem_id = HBL_CN_DRV_MEM_HOST_DMA_COHERENT;
	mem_data.size = PAGE_SIZE;
	rc = hbl_cn_mem_alloc(ctx, &mem_data);
	if (rc) {
		dev_dbg_ratelimited(hdev->dev,
				    "DB FIFO id %d, CI buffer allocation failed, port %d\n",
				    id, port);
		goto free_db_fifo;
	}

	ci_mmap_handle = mem_data.handle;
	ci_device_handle = mem_data.addr;

	rc = port_funcs->db_fifo_set(cn_port, ctx, id, ci_device_handle, xa_pdata);
	if (rc) {
		dev_dbg_ratelimited(hdev->dev, "DB FIFO id %d, HW config failed, port %d\n", id,
				    port);
		goto free_ci;
	}

	/* Cache IDR metadata and init IOCTL out. */
	out->ci_handle = ci_mmap_handle;
	out->regs_handle = umr_mmap_handle;
	out->regs_offset = umr_db_offset;

	xa_pdata->ci_mmap_handle = out->ci_handle;
	xa_pdata->umr_mmap_handle = out->regs_handle;
	xa_pdata->umr_db_offset = out->regs_offset;
	xa_pdata->state = DB_FIFO_STATE_SET;

	out->fifo_size = xa_pdata->fifo_size;
	out->fifo_bp_thresh = xa_pdata->fifo_size / 2;

	port_funcs->cfg_unlock(cn_port);

	return 0;

free_ci:
	if (ci_mmap_handle)
		hbl_cn_mem_destroy(hdev, ci_mmap_handle);
free_db_fifo:
	port_funcs->db_fifo_free(cn_port, xa_pdata->db_pool_addr, xa_pdata->fifo_size);
cfg_unlock:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int __user_db_fifo_unset(struct hbl_cn_port *cn_port,
				struct hbl_cn_db_fifo_xarray_pdata *xa_pdata)
{
	u32 id = xa_pdata->id;
	int rc = 0;

	/* User may call unset or the context may be destroyed while a db fifo is still in
	 * allocated state. When we call alloc_user_db_fifo next time, we would skip that
	 * particular id. This way, the id is blocked indefinitely until a full reset is done.
	 * So to fix this issue, we maintain the state of the idr. Perform unset only if set had
	 * been previously done for the idr.
	 */
	if (xa_pdata->state == DB_FIFO_STATE_SET)
		rc = user_db_fifo_unset_and_free(cn_port, xa_pdata);

	kfree(xa_pdata);
	xa_erase(&cn_port->db_fifo_ids, id);

	return rc;
}

static int user_db_fifo_unset(struct hbl_cn_device *hdev, struct hbl_cni_user_db_fifo_unset_in *in)
{
	struct hbl_cn_db_fifo_xarray_pdata *xa_pdata;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_port *cn_port;
	int rc;
	u32 id;

	rc = hbl_cn_cmd_port_check(hdev, in->port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[in->port];
	port_funcs = hdev->asic_funcs->port_funcs;
	id = in->id;

	rc = validate_db_fifo_ioctl(cn_port, id);
	if (rc)
		return rc;

	port_funcs->cfg_lock(cn_port);

	xa_pdata = xa_load(&cn_port->db_fifo_ids, id);
	if (!xa_pdata) {
		dev_dbg_ratelimited(hdev->dev, "DB fifo ID %d is not allocated, port: %d\n", id,
				    in->port);
		rc = -EINVAL;
		goto out;
	}

	rc = __user_db_fifo_unset(cn_port, xa_pdata);
out:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int user_encap_alloc(struct hbl_cn_device *hdev, struct hbl_cni_user_encap_alloc_in *in,
			    struct hbl_cni_user_encap_alloc_out *out)
{
	struct hbl_cn_encap_xarray_pdata *xa_pdata;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_port *cn_port;
	struct xa_limit id_limit;
	u32 min_id, max_id;
	int rc, id;
	u32 port;

	port = in->port;
	rc = hbl_cn_cmd_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];
	port_funcs = hdev->asic_funcs->port_funcs;

	port_funcs->get_encap_id_range(cn_port, &min_id, &max_id);

	/* IDR private data. */
	xa_pdata = kzalloc(sizeof(*xa_pdata), GFP_KERNEL);
	if (!xa_pdata)
		return -ENOMEM;

	xa_pdata->port = port;

	port_funcs->cfg_lock(cn_port);

	if (!cn_port->set_app_params) {
		dev_dbg(hdev->dev,
			"Failed to allocate encapsulation ID, set_app_params wasn't called yet, port %d\n",
			port);
		rc = -EPERM;
		goto cfg_unlock;
	}

	id_limit = XA_LIMIT(min_id, max_id);
	rc = xa_alloc(&cn_port->encap_ids, &id, xa_pdata, id_limit, GFP_KERNEL);
	if (rc) {
		dev_dbg_ratelimited(hdev->dev, "Encapsulation ID allocation failed, port %d\n",
				    port);
		goto cfg_unlock;
	}

	xa_pdata->id = id;
	port_funcs->cfg_unlock(cn_port);

	out->id = id;

	return 0;

cfg_unlock:
	port_funcs->cfg_unlock(cn_port);
	kfree(xa_pdata);

	return rc;
}

static int validate_encap_id_range(struct hbl_cn_port *cn_port, u32 encap_id)
{
	struct hbl_cn_asic_funcs *asic_funcs;
	struct hbl_cn_device *hdev;
	u32 min_id, max_id;

	hdev = cn_port->hdev;
	asic_funcs = hdev->asic_funcs;

	asic_funcs->port_funcs->get_encap_id_range(cn_port, &min_id, &max_id);

	if (encap_id < min_id || encap_id > max_id) {
		dev_dbg_ratelimited(hdev->dev, "Invalid encapsulation ID, %d\n", encap_id);
		return -EINVAL;
	}

	return 0;
}

static int validate_encap_ioctl(struct hbl_cn_port *cn_port, u32 encap_id)
{
	return validate_encap_id_range(cn_port, encap_id);
}

static bool is_encap_supported(struct hbl_cn_device *hdev, struct hbl_cni_user_encap_set_in *in)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	return asic_funcs->is_encap_supported(hdev, in);
}

static int user_encap_set(struct hbl_cn_device *hdev, struct hbl_cni_user_encap_set_in *in)
{
	struct hbl_cn_encap_xarray_pdata *xa_pdata;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_port *cn_port;
	u32 id, encap_type_data = 0;
	void *encap_header = NULL;
	int rc;

	/* Check if the user request for encap set is supported */
	if (!is_encap_supported(hdev, in))
		return -EOPNOTSUPP;

	rc = hbl_cn_cmd_port_check(hdev, in->port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[in->port];
	port_funcs = hdev->asic_funcs->port_funcs;
	id = in->id;

	rc = validate_encap_ioctl(cn_port, id);
	if (rc)
		return rc;

	switch (in->encap_type) {
	case HBL_CNI_ENCAP_OVER_IPV4:
		encap_type_data = in->ip_proto;
		break;
	case HBL_CNI_ENCAP_OVER_UDP:
		encap_type_data = in->udp_dst_port;
		break;
	case HBL_CNI_ENCAP_NONE:
		/* No encapsulation/tunneling mode. Just set
		 * source IPv4 address and UDP protocol.
		 */
		encap_type_data = HBL_CN_IPV4_PROTOCOL_UDP;
		break;
	default:
		dev_dbg_ratelimited(hdev->dev, "Invalid encapsulation type, %d\n", in->encap_type);
		return -EINVAL;
	}

	port_funcs->cfg_lock(cn_port);

	xa_pdata = xa_load(&cn_port->encap_ids, id);
	if (!xa_pdata) {
		dev_dbg_ratelimited(hdev->dev, "Encapsulation ID %d is not allocated\n", id);
		rc = -EINVAL;
		goto cfg_unlock;
	}

	/* There could be a use case wherein the user allocates a encap ID and then calls encap_set
	 * with IPv4 encap. Now, without doing a unset, the user can call the encap_set with UDP
	 * encap or encap_none. In this case, we should be clearing the existing settings as well
	 * as freeing any allocated buffer. So, call unset API to clear the settings
	 */
	port_funcs->encap_unset(cn_port, id, xa_pdata);

	if (xa_pdata->encap_type != HBL_CNI_ENCAP_NONE)
		kfree(xa_pdata->encap_header);

	if (in->encap_type != HBL_CNI_ENCAP_NONE) {
		if (in->tnl_hdr_size > NIC_MAX_TNL_HDR_SIZE) {
			dev_dbg_ratelimited(hdev->dev, "Invalid tunnel header size, %d\n",
					    in->tnl_hdr_size);
			rc = -EINVAL;
			goto cfg_unlock;
		}

		/* Align encapsulation header to 32bit register fields. */
		encap_header = kzalloc(ALIGN(in->tnl_hdr_size, 4), GFP_KERNEL);
		if (!encap_header) {
			rc = -ENOMEM;
			goto cfg_unlock;
		}

		rc = copy_from_user(encap_header, u64_to_user_ptr(in->tnl_hdr_ptr),
				    in->tnl_hdr_size);
		if (rc) {
			dev_dbg_ratelimited(hdev->dev,
					    "Copy encapsulation header data failed, %d\n", rc);
			rc = -EFAULT;
			goto free_header;
		}

		xa_pdata->encap_header = encap_header;
		xa_pdata->encap_header_size = in->tnl_hdr_size;
	}

	xa_pdata->encap_type = in->encap_type;
	xa_pdata->encap_type_data = encap_type_data;
	xa_pdata->src_ip = in->ipv4_addr;
	xa_pdata->is_set = true;

	rc = port_funcs->encap_set(cn_port, id, xa_pdata);
	if (rc)
		goto free_header;

	port_funcs->cfg_unlock(cn_port);

	return 0;

free_header:
	if (in->encap_type != HBL_CNI_ENCAP_NONE)
		kfree(encap_header);
cfg_unlock:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int user_encap_unset(struct hbl_cn_device *hdev, struct hbl_cni_user_encap_unset_in *in)
{
	struct hbl_cn_encap_xarray_pdata *xa_pdata;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_port *cn_port;
	int rc;
	u32 id;

	rc = hbl_cn_cmd_port_check(hdev, in->port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[in->port];
	port_funcs = hdev->asic_funcs->port_funcs;
	id = in->id;

	rc = validate_encap_ioctl(cn_port, id);
	if (rc)
		return rc;

	port_funcs->cfg_lock(cn_port);

	xa_pdata = xa_load(&cn_port->encap_ids, id);
	if (!xa_pdata) {
		dev_dbg_ratelimited(hdev->dev, "Encapsulation ID %d is not allocated\n", id);
		rc = -EINVAL;
		goto out;
	}

	if (xa_pdata->is_set) {
		port_funcs->encap_unset(cn_port, id, xa_pdata);

		if (xa_pdata->encap_type != HBL_CNI_ENCAP_NONE)
			kfree(xa_pdata->encap_header);
	}

	xa_erase(&cn_port->encap_ids, id);
	kfree(xa_pdata);

out:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int user_ccq_set(struct hbl_cn_device *hdev, struct hbl_cni_user_ccq_set_in *in,
			struct hbl_cni_user_ccq_set_out *out, struct hbl_cn_ctx *ctx)
{
	struct hbl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	u64 ccq_mmap_handle, ccq_device_addr, pi_mmap_handle, pi_device_addr;
	struct hbl_cn_mem_data mem_data = {};
	struct hbl_cn_port *cn_port;
	u32 port, ccqn;
	int rc;

	rc = hbl_cn_cmd_port_check(hdev, in->port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	port = in->port;

	if (!hdev->mmu_bypass) {
		dev_dbg(hdev->dev, "Allocation of non physical dma-mem is not supported, port %d\n",
			port);
		return -EOPNOTSUPP;
	}

	if (!is_power_of_2(in->num_of_entries)) {
		dev_dbg(hdev->dev, "user CCQ buffer length must be at power of 2, port %d\n",
			port);
		return -EINVAL;
	}

	if (in->num_of_entries > USER_CCQ_MAX_ENTRIES ||
	    in->num_of_entries < USER_CCQ_MIN_ENTRIES) {
		dev_dbg(hdev->dev, "CCQ buffer length invalid 0x%x, port %d\n", in->num_of_entries,
			port);
		return -EINVAL;
	}

	cn_port = &hdev->cn_ports[port];

	port_funcs->cfg_lock(cn_port);

	if (!cn_port->set_app_params) {
		dev_dbg(hdev->dev,
			"Failed to set CCQ handler, set_app_params wasn't called yet, port %d\n",
			port);
		rc = -EPERM;
		goto cfg_unlock;
	}

	if (cn_port->ccq_enable) {
		dev_dbg(hdev->dev, "Failed setting CCQ handler - it is already set, port %d\n",
			port);
		rc = -EBUSY;
		goto cfg_unlock;
	}

	/* Allocate the queue memory buffer in host kernel */
	mem_data.mem_id = HBL_CN_DRV_MEM_HOST_DMA_COHERENT;
	mem_data.size = in->num_of_entries * CC_CQE_SIZE;
	rc = hbl_cn_mem_alloc(ctx, &mem_data);
	if (rc) {
		dev_err(hdev->dev, "CCQ memory buffer allocation failed, port %d\n", port);
		goto cfg_unlock;
	}

	ccq_mmap_handle = mem_data.handle;
	ccq_device_addr = mem_data.addr;

	/* Allocate a producer-index (PI) buffer in host kernel */
	memset(&mem_data, 0, sizeof(mem_data));
	mem_data.mem_id = HBL_CN_DRV_MEM_HOST_DMA_COHERENT;
	mem_data.size = PAGE_SIZE;
	rc = hbl_cn_mem_alloc(ctx, &mem_data);
	if (rc) {
		dev_err(hdev->dev, "CCQ PI buffer allocation failed, port %d\n", port);
		goto free_ccq;
	}

	pi_mmap_handle = mem_data.handle;
	pi_device_addr = mem_data.addr;

	port_funcs->user_ccq_set(cn_port, ccq_device_addr, pi_device_addr, in->num_of_entries,
				 &ccqn);

	rc = hbl_cn_eq_dispatcher_register_ccq(cn_port, ctx->asid, ccqn);
	if (rc) {
		dev_err(hdev->dev, "failed to register CCQ EQ handler, port %u, asid %u\n", port,
			ctx->asid);
		goto free_pi;
	}

	cn_port->ccq_handle = ccq_mmap_handle;
	cn_port->ccq_pi_handle = pi_mmap_handle;

	out->mem_handle = cn_port->ccq_handle;
	out->pi_handle = cn_port->ccq_pi_handle;
	out->id = ccqn;

	cn_port->ccq_enable = true;

	port_funcs->cfg_unlock(cn_port);

	return 0;

free_pi:
	hbl_cn_mem_destroy(hdev, pi_mmap_handle);
free_ccq:
	hbl_cn_mem_destroy(hdev, ccq_mmap_handle);
cfg_unlock:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int __user_ccq_unset(struct hbl_cn_device *hdev, struct hbl_cn_ctx *ctx, u32 port)
{
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_port *cn_port;
	bool has_errors = false;
	u32 ccqn;
	int rc;

	cn_port = &hdev->cn_ports[port];

	port_funcs = hdev->asic_funcs->port_funcs;
	port_funcs->user_ccq_unset(cn_port, &ccqn);

	rc = hbl_cn_mem_destroy(hdev, cn_port->ccq_pi_handle);
	if (rc) {
		dev_err(hdev->dev, "Failed to free CCQ PI memory, port %d\n", port);
		has_errors = true;
	}

	rc = hbl_cn_mem_destroy(hdev, cn_port->ccq_handle);
	if (rc) {
		dev_err(hdev->dev, "Failed to free CCQ memory, port %d\n", port);
		has_errors = true;
	}

	rc = hbl_cn_eq_dispatcher_unregister_ccq(cn_port, ctx->asid, ccqn);
	if (rc) {
		dev_err(hdev->dev, "Failed to unregister CCQ EQ handler, port %u, asid %u\n", port,
			ctx->asid);
		has_errors = true;
	}

	if (has_errors)
		return -EIO;

	cn_port->ccq_enable = false;

	return 0;
}

static int user_ccq_unset(struct hbl_cn_device *hdev, struct hbl_cni_user_ccq_unset_in *in,
			  struct hbl_cn_ctx *ctx)
{
	struct hbl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	struct hbl_cn_port *cn_port;
	u32 port;
	int rc;

	port = in->port;

	rc = hbl_cn_cmd_port_check(hdev, port, NIC_PORT_CHECK_ENABLE | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];

	port_funcs->cfg_lock(cn_port);

	if (!cn_port->ccq_enable) {
		dev_dbg(hdev->dev, "Failed unsetting CCQ handler - it is already unset, port %u\n",
			port);
		rc = -ENXIO;
		goto out;
	}

	rc = __user_ccq_unset(hdev, ctx, in->port);
out:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int dump_qp(struct hbl_cn_device *hdev, struct hbl_cni_dump_qp_in *in)
{
	struct hbl_cn_qp_info qp_info = {};
	u32 buf_size;
	char *buf;
	int rc;

	buf_size = in->user_buf_size;

	if (!buf_size || buf_size > NIC_DUMP_QP_SZ) {
		dev_err(hdev->dev, "Invalid buffer size %u\n", buf_size);
		return -EINVAL;
	}

	buf = kzalloc(buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	qp_info.port = in->port;
	qp_info.qpn = in->qpn;
	qp_info.req = in->req;
	qp_info.full_print = true;
	qp_info.force_read = true;

	rc = hdev->asic_funcs->qp_read(hdev, &qp_info, buf, buf_size);
	if (rc) {
		dev_err(hdev->dev, "Failed to read QP %u, port %u\n", in->qpn, in->port);
		goto out;
	}

	if (copy_to_user((void __user *)(uintptr_t)in->user_buf, buf, buf_size)) {
		dev_err(hdev->dev, "copy to user failed in debug ioctl\n");
		rc = -EFAULT;
		goto out;
	}

out:
	kfree(buf);
	return rc;
}

static int __hbl_cn_control(struct hbl_cn_device *hdev, u32 op, void *input, void *output,
			    struct hbl_cn_ctx *ctx)
{
	int rc;

	if (!(hdev->ctrl_op_mask & BIT(op))) {
		dev_dbg(hdev->dev, "CN control request %d is not supported on this device\n", op);
		return -EOPNOTSUPP;
	}

	switch (op) {
	case HBL_CNI_OP_ALLOC_CONN:
		rc = alloc_qp(hdev, ctx, input, output);
		break;
	case HBL_CNI_OP_SET_REQ_CONN_CTX:
		rc = set_req_qp_ctx(hdev, input, output);
		break;
	case HBL_CNI_OP_SET_RES_CONN_CTX:
		rc = set_res_qp_ctx(hdev, input);
		break;
	case HBL_CNI_OP_DESTROY_CONN:
		rc = destroy_qp(hdev, input);
		break;
	case HBL_CNI_OP_USER_WQ_SET:
		rc = user_wq_arr_set(hdev, input, output, ctx);
		break;
	case HBL_CNI_OP_USER_WQ_UNSET:
		rc = user_wq_arr_unset(hdev, input, ctx);
		break;
	case HBL_CNI_OP_ALLOC_USER_CQ_ID:
		rc = alloc_user_cq_id(hdev, input, output, ctx);
		break;
	case HBL_CNI_OP_SET_USER_APP_PARAMS:
		rc = user_set_app_params(hdev, input, ctx);
		break;
	case HBL_CNI_OP_GET_USER_APP_PARAMS:
		rc = user_get_app_params(hdev, input, output);
		break;
	case HBL_CNI_OP_EQ_POLL:
		rc = eq_poll(hdev, ctx, input, output);
		break;
	case HBL_CNI_OP_ALLOC_USER_DB_FIFO:
		rc = alloc_user_db_fifo(hdev, ctx, input, output);
		break;
	case HBL_CNI_OP_USER_DB_FIFO_SET:
		rc = user_db_fifo_set(hdev, ctx, input, output);
		break;
	case HBL_CNI_OP_USER_DB_FIFO_UNSET:
		rc = user_db_fifo_unset(hdev, input);
		break;
	case HBL_CNI_OP_USER_ENCAP_ALLOC:
		rc = user_encap_alloc(hdev, input, output);
		break;
	case HBL_CNI_OP_USER_ENCAP_SET:
		rc = user_encap_set(hdev, input);
		break;
	case HBL_CNI_OP_USER_ENCAP_UNSET:
		rc = user_encap_unset(hdev, input);
		break;
	case HBL_CNI_OP_USER_CCQ_SET:
		rc = user_ccq_set(hdev, input, output, ctx);
		break;
	case HBL_CNI_OP_USER_CCQ_UNSET:
		rc = user_ccq_unset(hdev, input, ctx);
		break;
	case HBL_CNI_OP_USER_CQ_ID_SET:
		rc = user_cq_id_set(hdev, input, output);
		break;
	case HBL_CNI_OP_USER_CQ_ID_UNSET:
		rc = user_cq_id_unset(hdev, input);
		break;
	case HBL_CNI_OP_DUMP_QP:
		rc = dump_qp(hdev, input);
		break;
	default:
		/* we shouldn't get here as we check the opcode mask before */
		dev_dbg(hdev->dev, "Invalid CN control request %d\n", op);
		return -EINVAL;
	}

	return rc;
}

static int hbl_cn_ib_cmd_ctrl(struct hbl_aux_dev *aux_dev, void *cn_ib_ctx, u32 op, void *input,
			      void *output)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(aux_dev);
	struct hbl_cn_ctx *ctx = cn_ib_ctx;
	int rc;

	mutex_lock(&ctx->lock);

	do
		rc = __hbl_cn_control(hdev, op, input, output, ctx);
	while (rc == -EAGAIN);

	mutex_unlock(&ctx->lock);

	return rc;
}

static enum hbl_ib_mem_type mem_id_to_mem_type(enum hbl_cn_drv_mem_id id)
{
	switch (id) {
	case HBL_CN_DRV_MEM_HOST_DMA_COHERENT:
		return HBL_IB_MEM_HOST_DMA_COHERENT;
	case HBL_CN_DRV_MEM_HOST_VIRTUAL:
		return HBL_IB_MEM_HOST_VIRTUAL;
	case HBL_CN_DRV_MEM_DEVICE:
		return HBL_IB_MEM_DEVICE;
	case HBL_CN_DRV_MEM_HOST_MAP_ONLY:
		return HBL_IB_MEM_HOST_MAP_ONLY;
	case HBL_CN_DRV_MEM_INVALID:
	default:
		return HBL_IB_MEM_INVALID;
	}
}

static int hbl_cn_ib_query_mem_handle(struct hbl_aux_dev *ib_aux_dev, u64 mem_handle,
				      struct hbl_ib_mem_info *info)
{
	struct hbl_cn_device *hdev = HBL_AUX2NIC(ib_aux_dev);
	struct hbl_cn_mem_buf *buf;
	u64 mem_type;

	mem_type = (mem_handle >> PAGE_SHIFT) & HBL_CN_MMAP_TYPE_MASK;

	memset(info, 0, sizeof(*info));
	info->mem_handle = mem_handle;

	switch (mem_type) {
	case HBL_CN_MMAP_TYPE_BLOCK:
		info->mtype = HBL_IB_MEM_HW_BLOCK;
		if (!hbl_cn_get_hw_block_addr(hdev, mem_handle, &info->bus_addr, &info->size))
			return 0;

		dev_err(hdev->dev, "NIC: No hw block address for handle %#llx\n", mem_handle);
		break;
	case HBL_CN_MMAP_TYPE_CN_MEM:
		buf = hbl_cn_mem_buf_get(hdev, mem_handle);
		if (!buf) {
			dev_err(hdev->dev, "NIC: No buffer for handle %#llx\n", mem_handle);
			break;
		}

		info->cpu_addr = buf->kernel_address;
		info->bus_addr = buf->bus_address;
		info->size = buf->mappable_size;
		info->vmalloc = false;
		info->mtype = mem_id_to_mem_type(buf->mem_id);

		hbl_cn_mem_buf_put(buf);
		return 0;
	default:
		dev_err(hdev->dev, "NIC: Invalid handle %#llx\n", mem_handle);
		break;
	}
	return -EINVAL;
}

static void qps_destroy(struct hbl_cn_device *hdev)
{
	struct hbl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	struct hbl_cn_port *cn_port;
	unsigned long qp_id = 0;
	struct hbl_cn_qp *qp;
	int i;

	/* destroy the QPs */
	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		/* protect against destroy_qp occurring in parallel */
		port_funcs->cfg_lock(cn_port);

		xa_for_each(&cn_port->qp_ids, qp_id, qp) {
			if (IS_ERR_OR_NULL(qp))
				continue;

			hbl_cn_qp_do_release(qp);
		}

		port_funcs->cfg_unlock(cn_port);
	}

	/* wait for the workers to complete */
	qps_drain_async_work(hdev);

	/* Verify the lists are empty */
	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		port_funcs->cfg_lock(cn_port);

		xa_for_each(&cn_port->qp_ids, qp_id, qp)
			dev_err_ratelimited(hdev->dev, "Port %d QP %ld is still alive\n",
					    cn_port->port, qp_id);

		port_funcs->cfg_unlock(cn_port);
	}
}

static void user_cqs_destroy(struct hbl_cn_ctx *ctx)
{
	struct hbl_cn_device *hdev = ctx->hdev;
	struct hbl_cn_properties *cn_props;
	struct hbl_cn_user_cq *user_cq;
	struct hbl_cn_port *cn_port;
	unsigned long id;
	int i;

	cn_props = &hdev->cn_props;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!cn_props->force_cq && !(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		xa_for_each(&cn_port->cq_ids, id, user_cq) {
			if (user_cq->state == USER_CQ_STATE_ALLOC)
				hbl_cn_user_cq_put(user_cq);
			else if (user_cq->state == USER_CQ_STATE_SET)
				user_cq_unset_locked(user_cq, true);
		}
	}
}

static void wq_arrs_destroy(struct hbl_cn_ctx *ctx)
{
	struct hbl_cn_wq_array_properties *wq_arr_props;
	struct hbl_cn_device *hdev = ctx->hdev;
	struct hbl_cn_port *cn_port;
	u32 type;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		wq_arr_props = cn_port->wq_arr_props;

		for (type = 0; type < HBL_CNI_USER_WQ_TYPE_MAX; type++) {
			if (wq_arr_props[type].enabled)
				__user_wq_arr_unset(ctx, cn_port, type);
		}
	}
}

static void ccqs_destroy(struct hbl_cn_ctx *ctx)
{
	struct hbl_cn_device *hdev = ctx->hdev;
	struct hbl_cn_port *cn_port;
	int port;

	for (port = 0; port < hdev->cn_props.max_num_of_ports; port++) {
		if (!(hdev->ports_mask & BIT(port)))
			continue;

		cn_port = &hdev->cn_ports[port];
		if (cn_port->ccq_enable)
			__user_ccq_unset(hdev, ctx, port);
	}
}

static void user_db_fifos_destroy(struct hbl_cn_ctx *ctx)
{
	struct hbl_cn_db_fifo_xarray_pdata *xa_pdata;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_port *cn_port;
	struct hbl_cn_device *hdev;
	unsigned long id;
	int i;

	hdev = ctx->hdev;
	port_funcs = hdev->asic_funcs->port_funcs;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		port_funcs->cfg_lock(cn_port);

		xa_for_each(&cn_port->db_fifo_ids, id, xa_pdata)
			if (xa_pdata->asid == ctx->asid)
				__user_db_fifo_unset(cn_port, xa_pdata);

		port_funcs->cfg_unlock(cn_port);
	}
}

static void encap_ids_destroy(struct hbl_cn_device *hdev)
{
	struct hbl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	struct hbl_cn_encap_xarray_pdata *xa_pdata;
	struct hbl_cn_port *cn_port;
	unsigned long encap_id;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		port_funcs->cfg_lock(cn_port);

		xa_for_each(&cn_port->encap_ids, encap_id, xa_pdata) {
			asic_funcs->port_funcs->encap_unset(cn_port, encap_id, xa_pdata);

			if (xa_pdata->encap_type != HBL_CNI_ENCAP_NONE)
				kfree(xa_pdata->encap_header);

			kfree(xa_pdata);
			xa_erase(&cn_port->encap_ids, encap_id);
		}

		port_funcs->cfg_unlock(cn_port);
	}
}

static void set_app_params_clear(struct hbl_cn_device *hdev)
{
	struct hbl_cn_asic_funcs *asic_funcs;
	struct hbl_cn_port *cn_port;
	u32 max_num_of_ports, port;

	asic_funcs = hdev->asic_funcs;
	max_num_of_ports = hdev->cn_props.max_num_of_ports;

	asic_funcs->app_params_clear(hdev);

	for (port = 0; port < max_num_of_ports; port++) {
		if (!(hdev->ports_mask & BIT(port)))
			continue;

		cn_port = &hdev->cn_ports[port];
		cn_port->set_app_params = false;
	}
}

void hbl_cn_ctx_resources_destroy(struct hbl_cn_device *hdev, struct hbl_cn_ctx *ctx)
{
	qps_destroy(hdev);
	user_cqs_destroy(ctx);
	wq_arrs_destroy(ctx);
	ccqs_destroy(ctx);
	user_db_fifos_destroy(ctx);
	encap_ids_destroy(hdev);
	set_app_params_clear(hdev);
}

int hbl_cn_alloc_ring(struct hbl_cn_device *hdev, struct hbl_cn_ring *ring, int elem_size,
		      int count)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	int rc;

	ring->count = count;
	ring->elem_size = elem_size;
	ring->asid = hdev->kernel_asid;

	RING_BUF_SIZE(ring) = elem_size * count;
	RING_BUF_ADDRESS(ring) = hbl_cn_dma_alloc_coherent(hdev, RING_BUF_SIZE(ring),
							   &RING_BUF_DMA_ADDRESS(ring), GFP_KERNEL);
	if (!RING_BUF_ADDRESS(ring))
		return -ENOMEM;

	/* ring's idx_ptr shall point on pi/ci address */
	RING_PI_SIZE(ring) = sizeof(u64);
	RING_PI_ADDRESS(ring) = hbl_cn_dma_pool_zalloc(hdev, RING_PI_SIZE(ring),
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

void hbl_cn_free_ring(struct hbl_cn_device *hdev, struct hbl_cn_ring *ring)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	asic_funcs->dma_pool_free(hdev, RING_PI_ADDRESS(ring), RING_PI_DMA_ADDRESS(ring));

	asic_funcs->dma_free_coherent(hdev, RING_BUF_SIZE(ring), RING_BUF_ADDRESS(ring),
				      RING_BUF_DMA_ADDRESS(ring));
}

static void hbl_cn_randomize_status_cnts(struct hbl_cn_port *cn_port,
					 struct hbl_cn_cpucp_status *status)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	u32 port = cn_port->port;

	RAND_STAT_CNT(status->high_ber_reinit);
	RAND_STAT_CNT(status->correctable_err_cnt);
	RAND_STAT_CNT(status->uncorrectable_err_cnt);
	RAND_STAT_CNT(status->bad_format_cnt);
	RAND_STAT_CNT(status->responder_out_of_sequence_psn_cnt);
}

static void hbl_cn_get_status(struct hbl_cn_port *cn_port, struct hbl_cn_cpucp_status *status)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	u32 port = cn_port->port;

	/* Port toggle counter should always be filled regardless of the logical state of the
	 * port.
	 */
	status->port_toggle_cnt = hbl_cn_get_port_toggle_cnt(cn_port);

	status->port = port;
	status->up = hbl_cn_is_port_open(cn_port);

	if (!status->up)
		return;

	status->pcs_link = cn_port->pcs_link;
	status->phy_ready = cn_port->phy_fw_tuned;
	status->auto_neg = cn_port->auto_neg_enable;

	if (hdev->rand_status) {
		hbl_cn_randomize_status_cnts(cn_port, status);
		return;
	}

	status->high_ber_reinit = cn_port->pcs_remote_fault_reconfig_cnt;

	/* Each ASIC will fill the rest of the statistics */
	hdev->asic_funcs->port_funcs->get_status(cn_port, status);
}

static void hbl_cn_convert_cpucp_status(struct cpucp_nic_status *to,
					struct hbl_cn_cpucp_status *from)
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

static int hbl_cn_send_cpucp_status(struct hbl_cn_device *hdev, u32 port,
				    struct hbl_cn_cpucp_status *cn_status)
{
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_asic_funcs *asic_funcs;
	struct cpucp_nic_status_packet *pkt;
	struct cpucp_nic_status status = {};
	struct hbl_cn_properties *cn_props;
	size_t total_pkt_size, data_size;
	struct hbl_cn_port *cn_port;
	u64 result;
	int rc;

	cn_props = &hdev->cn_props;
	data_size = cn_props->status_packet_size;
	asic_funcs = hdev->asic_funcs;
	port_funcs = asic_funcs->port_funcs;
	cn_port = &hdev->cn_ports[port];

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

	hbl_cn_convert_cpucp_status(&status, cn_status);

	pkt->length = cpu_to_le32(data_size / sizeof(u32));
	memcpy(&pkt->data, &status, data_size);

	pkt->cpucp_pkt.ctl = cpu_to_le32(CPUCP_PACKET_NIC_STATUS << CPUCP_PKT_CTL_OPCODE_SHIFT);

	rc = asic_funcs->send_cpu_message(hdev, (u32 *)pkt, total_pkt_size, 0, &result);
	if (rc)
		dev_err(hdev->dev, "failed to send NIC status, port %d\n", port);

	kfree(pkt);
out:
	port_funcs->post_send_status(cn_port);

	return rc;
}

void hbl_cn_fw_status_work(struct work_struct *work)
{
	struct hbl_cn_port *cn_port = container_of(work, struct hbl_cn_port, fw_status_work.work);
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_cpucp_status status = {};
	u32 port = cn_port->port;
	int rc;

	hbl_cn_get_status(cn_port, &status);

	rc = hbl_cn_send_cpucp_status(hdev, port, &status);
	if (rc)
		return;

	if (hdev->status_cmd == HBL_CN_STATUS_PERIODIC_START)
		queue_delayed_work(cn_port->wq, &cn_port->fw_status_work,
				   msecs_to_jiffies(hdev->status_period * 1000));
}

static void cn_port_sw_fini(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_asic_funcs *asic_funcs = cn_port->hdev->asic_funcs;

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

static void cn_wq_arr_props_init(struct hbl_cn_wq_array_properties *wq_arr_props)
{
	wq_arr_props[HBL_CNI_USER_WQ_SEND].type_str = "send";
	wq_arr_props[HBL_CNI_USER_WQ_SEND].is_send = true;

	wq_arr_props[HBL_CNI_USER_WQ_RECV].type_str = "recv";
	wq_arr_props[HBL_CNI_USER_WQ_RECV].is_send = false;
}

static int cn_port_sw_init(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_wq_array_properties *wq_arr_props;
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_reset_tracker *reset_tracker;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_asic_funcs *asic_funcs;
	u32 port, max_qp_error_syndromes;
	char wq_name[32] = {0};
	int rc;

	port = cn_port->port;
	asic_funcs = hdev->asic_funcs;
	port_funcs = asic_funcs->port_funcs;
	wq_arr_props = cn_port->wq_arr_props;
	reset_tracker = NULL;

	snprintf(wq_name, sizeof(wq_name) - 1, "hbl%u-cn%d-wq", hdev->id, port);
	cn_port->wq = alloc_workqueue(wq_name, 0, 0);
	if (!cn_port->wq) {
		dev_err(hdev->dev, "Failed to create WQ, port: %d\n", port);
		return -ENOMEM;
	}

	snprintf(wq_name, sizeof(wq_name) - 1, "hbl%u-cn%d-qp-wq", hdev->id, port);
	cn_port->qp_wq = alloc_workqueue(wq_name, WQ_UNBOUND, 0);
	if (!cn_port->qp_wq) {
		dev_err(hdev->dev, "Failed to create QP WQ, port: %d\n", port);
		rc = -ENOMEM;
		goto qp_wq_err;
	}

	max_qp_error_syndromes = hdev->cn_props.max_qp_error_syndromes;
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

static int cn_macro_sw_init(struct hbl_cn_macro *cn_macro)
{
	struct hbl_cn_asic_funcs *asic_funcs;

	asic_funcs = cn_macro->hdev->asic_funcs;

	return asic_funcs->macro_sw_init(cn_macro);
}

static void cn_macro_sw_fini(struct hbl_cn_macro *cn_macro)
{
	struct hbl_cn_asic_funcs *asic_funcs;

	asic_funcs = cn_macro->hdev->asic_funcs;

	asic_funcs->macro_sw_fini(cn_macro);
}

static void hbl_cn_sw_fini(struct hbl_cn_device *hdev)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++)
		cn_port_sw_fini(&hdev->cn_ports[i]);

	for (i = 0; i < hdev->cn_props.num_of_macros; i++)
		cn_macro_sw_fini(&hdev->cn_macros[i]);

	asic_funcs->sw_fini(hdev);

	kfree(hdev->ib_aux_dev.aux_data);
	kfree(hdev->ib_aux_dev.aux_ops);
	kfree(hdev->en_aux_dev.aux_data);
	kfree(hdev->en_aux_dev.aux_ops);
	kfree(hdev->mac_lane_remap);
	kfree(hdev->phy_ber_info);
	kfree(hdev->phy_tx_taps);
	kfree(hdev->cn_macros);
	kfree(hdev->cn_ports);
}

static int hbl_cn_sw_init(struct hbl_cn_device *hdev)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	struct hbl_cn_macro *cn_macro, *cn_macros;
	int rc, i, macro_cnt = 0, port_cnt = 0;
	struct hbl_cn_port *cn_port, *cn_ports;
	struct hbl_en_aux_data *en_aux_data;
	struct hbl_ib_aux_data *ib_aux_data;
	struct hbl_en_aux_ops *en_aux_ops;
	struct hbl_ib_aux_ops *ib_aux_ops;
	struct hbl_cn_ber_info *ber_info;
	struct hbl_cn_tx_taps *tx_taps;
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

	ib_aux_data = kzalloc(sizeof(*ib_aux_data), GFP_KERNEL);
	if (!ib_aux_data) {
		rc = -ENOMEM;
		goto ib_aux_data_alloc_fail;
	}

	ib_aux_ops = kzalloc(sizeof(*ib_aux_ops), GFP_KERNEL);
	if (!ib_aux_ops) {
		rc = -ENOMEM;
		goto ib_aux_ops_alloc_fail;
	}

	hdev->en_aux_dev.aux_data = en_aux_data;
	hdev->en_aux_dev.aux_ops = en_aux_ops;
	hdev->ib_aux_dev.aux_data = ib_aux_data;
	hdev->ib_aux_dev.aux_ops = ib_aux_ops;

	hdev->phy_tx_taps = tx_taps;
	hdev->phy_ber_info = ber_info;
	hdev->mac_lane_remap = mac_lane_remap;
	hdev->phy_config_fw = !hdev->pldm && !hdev->skip_phy_init;
	hdev->mmu_bypass = true;
	hdev->phy_calc_ber_wait_sec = 30;

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
	kfree(ib_aux_ops);
ib_aux_ops_alloc_fail:
	kfree(ib_aux_data);
ib_aux_data_alloc_fail:
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

static void hbl_cn_late_init(struct hbl_cn_device *hdev)
{
	struct hbl_cn_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	/* compute2cn */
	aux_ops->ports_reopen = hbl_cn_ports_reopen;
	aux_ops->ports_stop_prepare = hbl_cn_hard_reset_prepare;
	aux_ops->ports_stop = hbl_cn_stop;
	aux_ops->synchronize_irqs = hbl_cn_synchronize_irqs;

	hdev->asic_funcs->late_init(hdev);
}

static void hbl_cn_late_fini(struct hbl_cn_device *hdev)
{
	struct hbl_cn_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	/* compute2cn */
	aux_ops->ports_reopen = NULL;
	aux_ops->ports_stop_prepare = NULL;
	aux_ops->ports_stop = NULL;
	aux_ops->synchronize_irqs = NULL;

	hdev->asic_funcs->late_fini(hdev);
}

bool hbl_cn_is_port_open(struct hbl_cn_port *cn_port)
{
	struct hbl_aux_dev *aux_dev = &cn_port->hdev->en_aux_dev;
	struct hbl_en_aux_ops *aux_ops = aux_dev->aux_ops;
	u32 port = cn_port->port;

	if (cn_port->eth_enable && aux_ops->is_port_open)
		return aux_ops->is_port_open(aux_dev, port);

	return cn_port->port_open;
}

u32 hbl_cn_get_pflags(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	u32 port = cn_port->port;

	aux_dev = &hdev->en_aux_dev;
	aux_ops = aux_dev->aux_ops;

	if (cn_port->eth_enable && aux_ops->get_pflags)
		return aux_ops->get_pflags(aux_dev, port);

	return cn_port->pflags;
}

u8 hbl_cn_get_num_of_digits(u64 num)
{
	u8 n_digits = 0;

	while (num) {
		n_digits++;
		num /= 10;
	}

	return n_digits;
}

static void hbl_cn_spmu_init(struct hbl_cn_port *cn_port, bool full)
{
	u32 spmu_events[NIC_SPMU_STATS_LEN_MAX], num_event_types, port = cn_port->port;
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_stat *event_types;
	int rc, i;

	if (!hdev->supports_coresight)
		return;

	port_funcs = hdev->asic_funcs->port_funcs;

	port_funcs->spmu_get_stats_info(cn_port, &event_types, &num_event_types);
	num_event_types = min_t(u32, num_event_types, NIC_SPMU_STATS_LEN_MAX);

	for (i = 0; i < num_event_types; i++)
		spmu_events[i] = event_types[i].lo_offset;

	if (full) {
		rc = port_funcs->spmu_config(cn_port, num_event_types, spmu_events, false);
		if (rc)
			dev_err(hdev->dev, "Failed to disable spmu for port %d\n", port);
	}

	rc = port_funcs->spmu_config(cn_port, num_event_types, spmu_events, true);
	if (rc)
		dev_err(hdev->dev, "Failed to enable spmu for port %d\n", port);
}

static void hbl_cn_reset_stats_counters_port(struct hbl_cn_device *hdev, u32 port)
{
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_cn_port *cn_port;
	struct hbl_aux_dev *aux_dev;

	cn_port = &hdev->cn_ports[port];
	aux_dev = &hdev->en_aux_dev;
	aux_ops = aux_dev->aux_ops;
	port_funcs = hdev->asic_funcs->port_funcs;

	/* Ethernet */
	if (cn_port->eth_enable && aux_ops->reset_stats)
		aux_ops->reset_stats(aux_dev, port);

	/* MAC */
	port_funcs->reset_mac_stats(cn_port);

	/* SPMU */
	hbl_cn_spmu_init(cn_port, true);

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

void hbl_cn_reset_stats_counters(struct hbl_cn_device *hdev)
{
	struct hbl_cn_port *cn_port;
	u32 port;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		if (!hbl_cn_is_port_open(cn_port))
			continue;

		port = cn_port->port;

		hbl_cn_reset_stats_counters_port(hdev, port);
	}
}

void hbl_cn_reset_ports_toggle_counters(struct hbl_cn_device *hdev)
{
	struct hbl_cn_port *cn_port;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		cn_port->port_toggle_cnt = 0;
		cn_port->port_toggle_cnt_prev = 0;
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

struct hbl_cn_ev_dq *hbl_cn_cqn_to_dq(struct hbl_cn_ev_dqs *ev_dqs, u32 cqn,
				      struct hbl_cn_device *hdev)
{
	struct hbl_cn_properties *cn_prop = &hdev->cn_props;
	struct hbl_cn_ev_dq *dq;

	if (cqn >= cn_prop->max_cqs)
		return NULL;

	dq = ev_dqs->cq_dq[cqn];
	if (!dq || !dq->associated)
		return NULL;

	return dq;
}

struct hbl_cn_ev_dq *hbl_cn_ccqn_to_dq(struct hbl_cn_ev_dqs *ev_dqs, u32 ccqn,
				       struct hbl_cn_device *hdev)
{
	struct hbl_cn_properties *cn_prop = &hdev->cn_props;
	struct hbl_cn_ev_dq *dq;

	if (ccqn >= cn_prop->max_ccqs)
		return NULL;

	dq = ev_dqs->ccq_dq[ccqn];
	if (!dq || !dq->associated)
		return NULL;

	return dq;
}

struct hbl_cn_dq_qp_info *hbl_cn_get_qp_info(struct hbl_cn_ev_dqs *ev_dqs, u32 qpn)
{
	struct hbl_cn_dq_qp_info *qp_info = NULL;

	hash_for_each_possible(ev_dqs->qps, qp_info, node, qpn)
		if (qpn == qp_info->qpn)
			return qp_info;

	return NULL;
}

struct hbl_cn_ev_dq *hbl_cn_qpn_to_dq(struct hbl_cn_ev_dqs *ev_dqs, u32 qpn)
{
	struct hbl_cn_dq_qp_info *qp_info = hbl_cn_get_qp_info(ev_dqs, qpn);

	if (qp_info)
		return qp_info->dq;

	return NULL;
}

struct hbl_cn_ev_dq *hbl_cn_dbn_to_dq(struct hbl_cn_ev_dqs *ev_dqs, u32 dbn,
				      struct hbl_cn_device *hdev)
{
	struct hbl_cn_properties *cn_prop = &hdev->cn_props;
	struct hbl_cn_ev_dq *dq;

	if (dbn >= cn_prop->max_db_fifos)
		return NULL;

	dq = ev_dqs->db_dq[dbn];
	if (!dq || !dq->associated)
		return NULL;

	return dq;
}

struct hbl_cn_ev_dq *hbl_cn_asid_to_dq(struct hbl_cn_ev_dqs *ev_dqs, u32 asid)
{
	struct hbl_cn_ev_dq *dq;
	int i;

	for (i = 0; i < NIC_NUM_CONCUR_ASIDS; i++) {
		dq = &ev_dqs->edq[i];
		if (dq->associated && dq->asid == asid)
			return dq;
	}

	return NULL;
}

static void hbl_cn_dq_reset(struct hbl_cn_ev_dq *dq)
{
	struct hbl_cn_eq_raw_buf *buf = &dq->buf;

	dq->overflow = 0;
	buf->tail = 0;
	buf->head = buf->tail;
	buf->events_count = 0;
	memset(buf->events, 0, sizeof(buf->events));
}

bool hbl_cn_eq_dispatcher_is_empty(struct hbl_cn_ev_dq *dq)
{
	return (dq->buf.events_count == 0);
}

bool hbl_cn_eq_dispatcher_is_full(struct hbl_cn_ev_dq *dq)
{
	return (dq->buf.events_count == (NIC_EQ_INFO_BUF_SIZE - 1));
}

void hbl_cn_eq_dispatcher_init(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	int i;

	hash_init(ev_dqs->qps);
	mutex_init(&ev_dqs->lock);

	hbl_cn_dq_reset(&ev_dqs->default_edq);

	for (i = 0; i < NIC_NUM_CONCUR_ASIDS; i++)
		hbl_cn_dq_reset(&ev_dqs->edq[i]);

	for (i = 0; i < NIC_DRV_MAX_CQS_NUM; i++)
		ev_dqs->cq_dq[i] = NULL;

	for (i = 0; i < NIC_DRV_NUM_DB_FIFOS; i++)
		ev_dqs->db_dq[i] = NULL;
}

void hbl_cn_eq_dispatcher_fini(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_ev_dqs *edqs = ev_dqs;
	struct hbl_cn_dq_qp_info *qp_info;
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

void hbl_cn_eq_dispatcher_reset(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hbl_cn_ev_dqs *edqs = ev_dqs;
	int i;

	mutex_lock(&edqs->lock);

	hbl_cn_dq_reset(&edqs->default_edq);

	for (i = 0; i < NIC_NUM_CONCUR_ASIDS; i++)
		hbl_cn_dq_reset(&edqs->edq[i]);

	mutex_unlock(&edqs->lock);
}

int hbl_cn_eq_dispatcher_associate_dq(struct hbl_cn_port *cn_port, u32 asid)
{
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hbl_cn_ev_dq *dq;
	int i, rc = -ENOSPC;

	mutex_lock(&ev_dqs->lock);

	dq = hbl_cn_asid_to_dq(ev_dqs, asid);
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

int hbl_cn_eq_dispatcher_dissociate_dq(struct hbl_cn_port *cn_port, u32 asid)
{
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hbl_cn_ev_dq *dq;

	mutex_lock(&ev_dqs->lock);

	dq = hbl_cn_asid_to_dq(ev_dqs, asid);
	if (!dq)
		goto exit;

	hbl_cn_dq_reset(dq);
	dq->associated = false;
	dq->asid = U32_MAX;

exit:
	mutex_unlock(&ev_dqs->lock);

	return 0;
}

int hbl_cn_eq_dispatcher_register_qp(struct hbl_cn_port *cn_port, u32 asid, u32 qp_id)
{
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hbl_cn_dq_qp_info *qp_info;
	struct hbl_cn_ev_dq *dq;
	int rc = 0;

	mutex_lock(&ev_dqs->lock);

	/* check if such qp is already registered and if with the same asid */
	dq = hbl_cn_qpn_to_dq(ev_dqs, qp_id);
	if (dq) {
		if (dq->asid != asid)
			rc = -EINVAL;

		goto exit;
	}

	/* find the dq associated with the given asid */
	dq = hbl_cn_asid_to_dq(ev_dqs, asid);
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

int hbl_cn_eq_dispatcher_unregister_qp(struct hbl_cn_port *cn_port, u32 qp_id)
{
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hbl_cn_dq_qp_info *qp_info;

	mutex_lock(&ev_dqs->lock);

	qp_info = hbl_cn_get_qp_info(ev_dqs, qp_id);
	if (qp_info) {
		hash_del(&qp_info->node);
		kfree(qp_info);
	}

	mutex_unlock(&ev_dqs->lock);

	return 0;
}

int hbl_cn_eq_dispatcher_register_cq(struct hbl_cn_port *cn_port, u32 asid, u32 cqn)
{
	struct hbl_cn_properties *cn_prop = &cn_port->hdev->cn_props;
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hbl_cn_ev_dq *dq;
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
	dq = hbl_cn_asid_to_dq(ev_dqs, asid);
	if (!dq) {
		rc = -ENODATA;
		goto exit;
	}

	ev_dqs->cq_dq[cqn] = dq;

exit:
	mutex_unlock(&ev_dqs->lock);

	return rc;
}

int hbl_cn_eq_dispatcher_unregister_cq(struct hbl_cn_port *cn_port, u32 cqn)
{
	struct hbl_cn_properties *cn_prop = &cn_port->hdev->cn_props;
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;

	if (cqn >= cn_prop->max_cqs)
		return -EINVAL;

	mutex_lock(&ev_dqs->lock);

	ev_dqs->cq_dq[cqn] = NULL;

	mutex_unlock(&ev_dqs->lock);

	return 0;
}

int hbl_cn_eq_dispatcher_register_ccq(struct hbl_cn_port *cn_port, u32 asid, u32 ccqn)
{
	struct hbl_cn_properties *cn_prop = &cn_port->hdev->cn_props;
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hbl_cn_ev_dq *dq;
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
	dq = hbl_cn_asid_to_dq(ev_dqs, asid);
	if (!dq) {
		rc = -ENODATA;
		goto exit;
	}

	ev_dqs->ccq_dq[ccqn] = dq;

exit:
	mutex_unlock(&ev_dqs->lock);
	return rc;
}

int hbl_cn_eq_dispatcher_unregister_ccq(struct hbl_cn_port *cn_port, u32 asid, u32 ccqn)
{
	struct hbl_cn_properties *cn_prop = &cn_port->hdev->cn_props;
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;

	if (ccqn >= cn_prop->max_ccqs)
		return -EINVAL;

	if (!hbl_cn_asid_to_dq(ev_dqs, asid))
		return -ENODATA;

	mutex_lock(&ev_dqs->lock);

	ev_dqs->ccq_dq[ccqn] = NULL;

	mutex_unlock(&ev_dqs->lock);

	return 0;
}

int hbl_cn_eq_dispatcher_register_db(struct hbl_cn_port *cn_port, u32 asid, u32 dbn)
{
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hbl_cn_ev_dq *dq;
	u32 min, max;
	int rc = 0;

	cn_port->hdev->asic_funcs->port_funcs->get_db_fifo_hw_id_range(cn_port, &min, &max);
	if (dbn < min || dbn > max) {
		dev_err(cn_port->hdev->dev,
			"Failed to register dbn %u to the dispatcher (valid range %u-%u)\n", dbn,
			min, max);
		return -EINVAL;
	}

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
	dq = hbl_cn_asid_to_dq(ev_dqs, asid);
	if (!dq) {
		rc = -ENODATA;
		goto exit;
	}

	ev_dqs->db_dq[dbn] = dq;

exit:
	mutex_unlock(&ev_dqs->lock);

	return rc;
}

int hbl_cn_eq_dispatcher_unregister_db(struct hbl_cn_port *cn_port, u32 dbn)
{
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	u32 min, max;

	cn_port->hdev->asic_funcs->port_funcs->get_db_fifo_hw_id_range(cn_port, &min, &max);
	if (dbn < min || dbn > max) {
		dev_err(cn_port->hdev->dev,
			"Failed to unregister dbn %u from the dispatcher (valid range %u-%u)\n",
			dbn, min, max);
		return -EINVAL;
	}

	mutex_lock(&ev_dqs->lock);

	ev_dqs->db_dq[dbn] = NULL;

	mutex_unlock(&ev_dqs->lock);

	return 0;
}

static int __hbl_cn_eq_dispatcher_enqueue(struct hbl_cn_port *cn_port, struct hbl_cn_ev_dq *dq,
					  const struct hbl_cn_eqe *eqe)
{
	struct hbl_aux_dev *aux_dev = &cn_port->hdev->ib_aux_dev;
	struct hbl_ib_aux_ops *aux_ops = aux_dev->aux_ops;

	if (hbl_cn_eq_dispatcher_is_full(dq)) {
		dq->overflow++;
		return -ENOSPC;
	}

	memcpy(&dq->buf.events[dq->buf.head], eqe, min(sizeof(*eqe), sizeof(dq->buf.events[0])));
	dq->buf.head = (dq->buf.head + 1) & (NIC_EQ_INFO_BUF_SIZE - 1);
	dq->buf.events_count++;

	/* If IB device exist, call work scheduler for hbl to poll eq */
	if (aux_ops->eqe_work_schd)
		aux_ops->eqe_work_schd(aux_dev, cn_port->port);

	return 0;
}

/* Broadcast event to all user ASIDs */
int hbl_cn_eq_dispatcher_enqueue_bcast(struct hbl_cn_port *cn_port, const struct hbl_cn_eqe *eqe)
{
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_ev_dq *dq;
	int i, rc = 0;

	if (!hbl_cn_is_port_open(cn_port))
		return 0;

	mutex_lock(&ev_dqs->lock);

	for (i = 0; i < NIC_NUM_CONCUR_ASIDS; i++) {
		if (i == hdev->kernel_asid)
			continue;

		dq = hbl_cn_asid_to_dq(ev_dqs, i);
		if (!dq)
			continue;

		rc = __hbl_cn_eq_dispatcher_enqueue(cn_port, dq, eqe);
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

int hbl_cn_eq_dispatcher_enqueue(struct hbl_cn_port *cn_port, const struct hbl_cn_eqe *eqe)
{
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hbl_cn_asic_port_funcs *port_funcs;
	struct hbl_cn_ev_dq *dq;
	int rc;

	if (!hbl_cn_is_port_open(cn_port))
		return 0;

	port_funcs = cn_port->hdev->asic_funcs->port_funcs;

	mutex_lock(&ev_dqs->lock);

	dq = port_funcs->eq_dispatcher_select_dq(cn_port, eqe);
	if (!dq) {
		rc = -ENODATA;
		goto exit;
	}

	rc = __hbl_cn_eq_dispatcher_enqueue(cn_port, dq, eqe);
	if (rc)
		dev_dbg_ratelimited(cn_port->hdev->dev,
				    "Port %d, failed to enqueue dispatcher. %d\n", cn_port->port,
				    rc);

exit:
	mutex_unlock(&ev_dqs->lock);
	return rc;
}

int hbl_cn_eq_dispatcher_dequeue(struct hbl_cn_port *cn_port, u32 asid, struct hbl_cn_eqe *eqe,
				 bool is_default)
{
	struct hbl_cn_ev_dqs *ev_dqs = &cn_port->ev_dqs;
	struct hbl_cn_ev_dq *dq;
	int rc;

	mutex_lock(&ev_dqs->lock);

	if (is_default)
		dq = &ev_dqs->default_edq;
	else
		dq = hbl_cn_asid_to_dq(ev_dqs, asid);

	if (!dq) {
		rc = -ESRCH;
		goto exit;
	}

	if (hbl_cn_eq_dispatcher_is_empty(dq)) {
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

u32 hbl_cn_dram_readl(struct hbl_cn_device *hdev, u64 addr)
{
	struct hbl_cn_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	return aux_ops->dram_readl(aux_dev, addr);
}

void hbl_cn_dram_writel(struct hbl_cn_device *hdev, u32 val, u64 addr)
{
	struct hbl_cn_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	aux_ops->dram_writel(aux_dev, val, addr);
}

u32 hbl_cn_rreg(struct hbl_cn_device *hdev, u32 reg)
{
	struct hbl_cn_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	return aux_ops->rreg(aux_dev, reg);
}

void hbl_cn_wreg(struct hbl_cn_device *hdev, u32 reg, u32 val)
{
	struct hbl_cn_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	return aux_ops->wreg(aux_dev, reg, val);
}

int hbl_cn_reserve_wq_dva(struct hbl_cn_ctx *ctx, struct hbl_cn_port *cn_port, u64 wq_arr_size,
			  u32 type, u64 *dva)
{
	struct hbl_cn_wq_array_properties *wq_arr_props;
	int rc;

	/* The Device VA block for WQ array is just reserved here. It will be backed by host
	 * physical pages once the MMU mapping is done via hbl_map_vmalloc_range inside the
	 * alloc_and_map_wq. Using host page alignment ensures we start with offset 0, both
	 * on host and device side.
	 */
	rc = hbl_cn_reserve_dva_block(ctx, wq_arr_size, dva);
	if (rc)
		return rc;

	wq_arr_props = &cn_port->wq_arr_props[type];

	wq_arr_props->dva_base = *dva;
	wq_arr_props->dva_size = wq_arr_size;

	return 0;
}

void hbl_cn_unreserve_wq_dva(struct hbl_cn_ctx *ctx, struct hbl_cn_port *cn_port, u32 type)
{
	struct hbl_cn_wq_array_properties *wq_arr_props = &cn_port->wq_arr_props[type];

	hbl_cn_unreserve_dva_block(ctx, wq_arr_props->dva_base, wq_arr_props->dva_size);
	wq_arr_props->dva_base = 0;
}

void hbl_cn_track_port_reset(struct hbl_cn_port *cn_port, u32 syndrome)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct hbl_cn_reset_tracker *reset_tracker;
	unsigned long timestamp_jiffies = jiffies;
	u32 max_qp_error_syndromes;

	max_qp_error_syndromes = hdev->cn_props.max_qp_error_syndromes;
	if (syndrome >= max_qp_error_syndromes) {
		dev_dbg(hdev->dev, "Invalid syndrome %u\n", syndrome);
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

void hbl_cn_eq_handler(struct hbl_cn_port *cn_port)
{
	struct hbl_en_aux_ops *en_aux_ops;
	struct hbl_aux_dev *aux_dev;
	struct hbl_cn_device *hdev;
	struct hbl_cn_eqe eqe;
	u32 port;

	if (!cn_port->eq_handler_enable)
		return;

	hdev = cn_port->hdev;
	aux_dev = &hdev->en_aux_dev;
	en_aux_ops = aux_dev->aux_ops;
	port = cn_port->port;

	mutex_lock(&cn_port->control_lock);

	if (!hbl_cn_is_port_open(cn_port)) {
		dev_dbg(hdev->dev, "ignoring events while port %d closed", port);
		goto out;
	}

	if (en_aux_ops->handle_eqe)
		while (!hbl_cn_eq_dispatcher_dequeue(cn_port, hdev->kernel_asid, &eqe, false))
			en_aux_ops->handle_eqe(aux_dev, port, &eqe);

out:
	mutex_unlock(&cn_port->control_lock);
}

void hbl_cn_get_self_hw_block_handle(struct hbl_cn_device *hdev, u64 address, u64 *handle)
{
	*handle = lower_32_bits(address) | (HBL_CN_MMAP_TYPE_BLOCK);
	*handle <<= PAGE_SHIFT;
}

u32 hbl_cn_hw_block_handle_to_addr32(struct hbl_cn_device *hdev, u64 handle)
{
	return lower_32_bits(handle >> PAGE_SHIFT);
}

void *__hbl_cn_dma_alloc_coherent(struct hbl_cn_device *hdev, size_t size, dma_addr_t *dma_handle,
				  gfp_t flag, const char *caller)
{
	const struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	return asic_funcs->dma_alloc_coherent(hdev, size, dma_handle, flag);
}

void __hbl_cn_dma_free_coherent(struct hbl_cn_device *hdev, size_t size, void *cpu_addr,
				dma_addr_t dma_addr, const char *caller)
{
	const struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	asic_funcs->dma_free_coherent(hdev, size, cpu_addr, dma_addr);
}

void *__hbl_cn_dma_pool_zalloc(struct hbl_cn_device *hdev, size_t size, gfp_t mem_flags,
			       dma_addr_t *dma_handle, const char *caller)
{
	const struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	return asic_funcs->dma_pool_zalloc(hdev, size, mem_flags, dma_handle);
}

void __hbl_cn_dma_pool_free(struct hbl_cn_device *hdev, void *vaddr, dma_addr_t dma_addr,
			    const char *caller)
{
	const struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	asic_funcs->dma_pool_free(hdev, vaddr, dma_addr);
}

int hbl_cn_get_reg_pcie_addr(struct hbl_cn_device *hdev, u8 bar_id, u32 reg, u64 *pci_addr)
{
	struct hbl_cn_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	u64 offset;
	int rc;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	rc = aux_ops->get_reg_pcie_addr(aux_dev, reg, &offset);
	if (rc)
		return rc;

	*pci_addr = pci_resource_start(hdev->pdev, bar_id) + offset;

	return 0;
}

int hbl_cn_get_src_ip(struct hbl_cn_port *cn_port, u32 *src_ip)
{
	struct hbl_aux_dev *aux_dev = &cn_port->hdev->en_aux_dev;
	struct hbl_en_aux_ops *aux_ops = aux_dev->aux_ops;
	u32 port = cn_port->port;

	if (cn_port->eth_enable && aux_ops->get_src_ip)
		return aux_ops->get_src_ip(aux_dev, port, src_ip);

	*src_ip = 0;

	return 0;
}
