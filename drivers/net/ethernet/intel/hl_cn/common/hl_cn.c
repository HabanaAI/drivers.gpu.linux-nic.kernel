// SPDX-License-Identifier: GPL-2.0

/* Copyright 2021-2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "habanalabs_cn.h"

#include <linux/overflow.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/genalloc.h>

#define NIC_PCS_FAIL_TIME_FRAME_SEC	(60 * 5) /* 5 minutes */
#define NIC_PCS_FAIL_THRESHOLD		8
#define NIC_MIN_WQS_PER_PORT		2
#define NIC_MIN_COLL_WQS_PER_PORT	1

#define NIC_SEQ_RESETS_TIMEOUT_MS	15000 /* 15 seconds */
#define NIC_MAX_SEQ_RESETS		3

#define HL_CN_IPV4_PROTOCOL_UDP		17

#define NIC_CTX_ACTIVE_OPS (BIT(HL_CNI_OP_SET_REQ_CONN_CTX) | BIT(HL_CNI_OP_SET_RES_CONN_CTX) | \
			    BIT(HL_CNI_OP_USER_DB_FIFO_SET))

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

#define HL_AUX2NIC(aux_dev)	\
	({ \
		struct hl_aux_dev *__aux_dev = (aux_dev); \
		((__aux_dev)->type == HL_AUX_DEV_ETH) ? \
		container_of(__aux_dev, struct hl_cn_device, en_aux_dev) : \
		container_of(__aux_dev, struct hl_cn_device, ib_aux_dev); \
	})

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
static void qp_destroy_work(struct work_struct *work);
static int __user_wq_arr_unset(struct hl_cn_ctx *ctx, struct hl_cn_port *cn_port, u32 type);
static void user_cq_destroy(struct kref *kref);
static void set_app_params_clear(struct hl_cn_device *hdev);
static int hl_cn_ib_cmd_ctrl(struct hl_aux_dev *aux_dev, void *cn_ib_ctx, u32 op, void *input,
			     void *output);
static int hl_cn_ib_mmap(struct hl_aux_dev *aux_dev, void *cn_ib_ctx,
			 struct vm_area_struct *vma);
static void hl_cn_reset_stats_counters_port(struct hl_cn_device *hdev, u32 port);
static void hl_cn_late_init(struct hl_cn_device *hdev);
static void hl_cn_late_fini(struct hl_cn_device *hdev);
static int hl_cn_sw_init(struct hl_cn_device *hdev);
static void hl_cn_sw_fini(struct hl_cn_device *hdev);
static void hl_cn_spmu_init(struct hl_cn_port *cn_port, bool full);
static int hl_cn_ioctl_port_check(struct hl_cn_device *hdev, u32 port, u32 flags);
static void hl_cn_qps_stop(struct hl_cn_port *cn_port);
static void __hl_cn_ctx_fini(struct hl_cn_device *hdev, struct hl_cn_ctx *ctx);

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

static void __hl_cn_get_cnts_names(struct hl_cn_port *cn_port, u8 *data, bool ext)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	int i, len;

	len = ext ? HL_IB_CNT_NAME_LEN : ETH_GSTRING_LEN;

	for (i = 0; i < pcs_counters_str_len; i++)
		memcpy(data + i * len, pcs_counters_str[i], ETH_GSTRING_LEN);
	data += i * len;

	hdev->asic_funcs->port_funcs->get_cnts_names(cn_port, data, ext);
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

	__hl_cn_get_cnts_names(cn_port, data, false);
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

/* Check for initialized HL IB device. */
bool hl_cn_is_ibdev(struct hl_cn_device *hdev)
{
	return !!hdev->ib_aux_dev.priv;
}

/* Check for opened HL IB device. */
static bool hl_cn_is_ibdev_opened(struct hl_cn_device *hdev)
{
	return hdev->ib_aux_dev.priv && hdev->ib_device_opened;
}

static int hl_cn_ib_alloc_ucontext(struct hl_aux_dev *ib_aux_dev, int user_fd, void **cn_ib_ctx)
{
	struct hl_cn_comp_vm_info *user_vm_info, *driver_vm_info;
	struct hl_cn_device *hdev = HL_AUX2NIC(ib_aux_dev);
	struct hl_aux_dev *aux_dev = hdev->cn_aux_dev;
	struct hl_cn_asic_funcs *asic_funcs;
	struct hl_cn_aux_ops *aux_ops;
	struct hl_cn_ctx *ctx;
	int rc;

	asic_funcs = hdev->asic_funcs;
	aux_ops = aux_dev->aux_ops;

	if (hdev->multi_ctx_support || !hdev->ctx) {
		ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
		if (!ctx)
			return -ENOMEM;

		ctx->hdev = hdev;
		mutex_init(&ctx->lock);
		ctx->ib_allocated = true;
	} else {
		ctx = hdev->ctx;
	}

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

		if (user_vm_info->vm_info.mmu_mode == HL_CN_MMU_MODE_NETWORK_TLB)
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

	if (driver_vm_info->vm_info.mmu_mode == HL_CN_MMU_MODE_NETWORK_TLB)
		ctx->asid = driver_vm_info->vm_info.net_tlb.pasid;
	else
		ctx->asid = driver_vm_info->vm_info.ext_mmu.work_id;

	if (ctx->ib_allocated) {
		/* must be called before calling create_mem_ctx */
		rc = asic_funcs->ctx_init(ctx);
		if (rc) {
			dev_err(hdev->dev, "failed to init user context with ASID %d\n", ctx->asid);
			goto destroy_driver_vm;
		}
	}

	if (ctx->user_asid != -1 && user_vm_info->vm_info.mmu_mode == HL_CN_MMU_MODE_NETWORK_TLB) {
		rc = asic_funcs->create_mem_ctx(ctx, user_vm_info->vm_info.net_tlb.pasid,
						user_vm_info->vm_info.net_tlb.page_tbl_addr);
		if (rc) {
			dev_err(hdev->dev,
				"failed to create HW memory context for user VM, FD %d\n", user_fd);
			goto ctx_cleanup;
		}
	}

	if (driver_vm_info->vm_info.mmu_mode == HL_CN_MMU_MODE_NETWORK_TLB) {
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

	if (ctx->ib_allocated)
		hdev->ctx = ctx;

	return 0;

user_vm_ctx_cleanup:
	if (ctx->user_asid != -1 && user_vm_info->vm_info.mmu_mode == HL_CN_MMU_MODE_NETWORK_TLB)
		asic_funcs->destroy_mem_ctx(ctx, user_vm_info->vm_info.net_tlb.pasid,
					    user_vm_info->vm_info.net_tlb.page_tbl_addr);
ctx_cleanup:
	if (ctx->ib_allocated)
		asic_funcs->ctx_fini(ctx);
destroy_driver_vm:
	aux_ops->vm_destroy(aux_dev, driver_vm_info->vm_handle);
deregister_ctx:
	aux_ops->deregister_cn_user_context(aux_dev, user_vm_info->vm_handle);
release_ctx:
	if (ctx->ib_allocated) {
		mutex_destroy(&ctx->lock);
		kfree(ctx);
	}

	return rc;
}

static void hl_cn_ib_dealloc_ucontext(struct hl_aux_dev *ib_aux_dev, void *cn_ib_ctx)
{
	struct hl_cn_comp_vm_info *user_vm_info, *driver_vm_info;
	struct hl_cn_device *hdev = HL_AUX2NIC(ib_aux_dev);
	struct hl_aux_dev *aux_dev = hdev->cn_aux_dev;
	struct hl_cn_asic_funcs *asic_funcs;
	struct hl_cn_ctx *ctx = cn_ib_ctx;
	struct hl_cn_aux_ops *aux_ops;
	bool should_destroy;

	aux_ops = aux_dev->aux_ops;
	asic_funcs = hdev->asic_funcs;
	user_vm_info = &ctx->user_vm_info;
	driver_vm_info = &ctx->driver_vm_info;

	dev_dbg(hdev->dev, "IB context dealloc\n");

	mutex_lock(&ctx->lock);

	if (driver_vm_info->vm_info.mmu_mode == HL_CN_MMU_MODE_NETWORK_TLB)
		asic_funcs->destroy_mem_ctx(ctx, driver_vm_info->vm_info.net_tlb.pasid,
					    driver_vm_info->vm_info.net_tlb.page_tbl_addr);

	if (ctx->user_asid != -1 && user_vm_info->vm_info.mmu_mode == HL_CN_MMU_MODE_NETWORK_TLB)
		asic_funcs->destroy_mem_ctx(ctx, user_vm_info->vm_info.net_tlb.pasid,
					    user_vm_info->vm_info.net_tlb.page_tbl_addr);

	if (ctx->ib_allocated)
		__hl_cn_ctx_fini(hdev, ctx);
	else
		set_app_params_clear(hdev);

	aux_ops->vm_destroy(aux_dev, driver_vm_info->vm_handle);
	aux_ops->deregister_cn_user_context(aux_dev, user_vm_info->vm_handle);

	ctx->deallocated = true;

	/* Currently a context can be created from the old ctx_init() flow or from the new
	 * alloc_ucontext() flow. Only if the context was created via the new flow we should destroy
	 * it here. Otherwise it will be destroyed in ctx_fini().
	 * Moreover, if mutiple contexts are supported then a context should be killed before it is
	 * destroyed. Hence we should destroy a context here only if it was already killed,
	 * otherwise it will be destroyed as part of ctx_kill().
	 */
	should_destroy = ctx->ib_allocated && (!hdev->multi_ctx_support || ctx->killed);

	mutex_unlock(&ctx->lock);

	if (should_destroy) {
		mutex_destroy(&ctx->lock);
		kfree(ctx);
	}

	hdev->ib_device_opened = false;
}

static void hl_cn_ib_query_port(struct hl_aux_dev *aux_dev, u32 port,
				struct hl_ib_port_attr *port_attr)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_properties *cn_prop;
	struct hl_cn_asic_funcs *asic_funcs;
	struct hl_cn_port *cn_port;

	asic_funcs = hdev->asic_funcs;
	cn_prop = &hdev->cn_props;
	cn_port = &hdev->cn_ports[port];

	port_attr->open = hl_cn_is_port_open(cn_port);
	port_attr->link_up = cn_port->pcs_link;
	port_attr->speed = cn_port->speed;
	port_attr->max_msg_sz = asic_funcs->get_max_msg_sz(hdev);
	port_attr->num_lanes = hdev->lanes_per_port;
	port_attr->max_mtu = SZ_8K;
	port_attr->swqe_size = cn_port->swqe_size;
	port_attr->rwqe_size = cn_prop->rwqe_size;
}

static inline void parse_fw_ver(struct hl_cn_device *hdev, char *str, u32 *maj, u16 *min, u16 *sub)
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

static void hl_cn_ib_query_device(struct hl_aux_dev *aux_dev, struct hl_ib_device_attr *dev_attr)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_properties *cn_props;
	struct hl_ib_aux_data *aux_data;
	u16 minor, sub_ver;
	u32 major;

	aux_data = aux_dev->aux_data;
	cn_props = &hdev->cn_props;

	if (hdev->cpucp_fw) {
		parse_fw_ver(hdev, aux_data->fw_ver, &major, &minor, &sub_ver);
		dev_attr->fw_ver = ((u64)major << 32) | ((u64)minor << 16) | sub_ver;
	}

	/* IB restriction. Memory region must be > PAGE_SIZE. */
	dev_attr->max_mr_size = hdev->dram_enable ? aux_data->dram_size : (2 * PAGE_SIZE);

	dev_attr->page_size_cap = PAGE_SIZE;

	if (hdev->pdev) {
		dev_attr->vendor_id = hdev->pdev->vendor;
		dev_attr->vendor_part_id = hdev->pdev->device;
		dev_attr->hw_ver = hdev->pdev->subsystem_device;
	} else {
		dev_attr->vendor_id = hdev->vendor_id;
		dev_attr->vendor_part_id = hdev->pci_id;
	}

	/* TODO: SW-99351: handle QPs per port */
	dev_attr->max_qp = cn_props->max_qps_num;

	dev_attr->max_qp_wr = aux_data->max_num_of_wqes;
	dev_attr->max_cqe = cn_props->user_cq_max_entries;

	dev_attr->cqe_size = cn_props->cqe_size;
	dev_attr->min_cq_entries = cn_props->user_cq_min_entries;
}

static void hl_cn_ib_set_ip_addr_encap(struct hl_aux_dev *aux_dev, u32 ip_addr, u32 port)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_asic_funcs *asic_funcs;
	struct hl_cn_port *cn_port;
	u32 encap_id;

	asic_funcs = hdev->asic_funcs;
	cn_port = &hdev->cn_ports[port];

	asic_funcs->port_funcs->set_ip_addr_encap(cn_port, &encap_id, ip_addr);
}

static char *hl_cn_ib_qp_syndrome_to_str(struct hl_aux_dev *aux_dev, u32 syndrome)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_asic_funcs *asic_funcs;

	asic_funcs = hdev->asic_funcs;

	return asic_funcs->qp_syndrome_to_str(syndrome);
}

static int hl_cn_ib_verify_qp_id(struct hl_aux_dev *aux_dev, u32 qp_id, u32 port, u8 is_coll)
{
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_port *cn_port;
	struct hl_cn_device *hdev;
	struct hl_cn_qp *qp;
	int rc = 0;

	hdev = HL_AUX2NIC(aux_dev);
	port_funcs = hdev->asic_funcs->port_funcs;
	cn_port = &hdev->cn_ports[port];

	if (is_coll) {
		hl_cn_cfg_lock_all(hdev);
		qp = hl_cn_get_qp_from_coll_conn_id(cn_port, qp_id);
	} else {
		port_funcs->cfg_lock(cn_port);
		qp = xa_load(&cn_port->qp_ids, qp_id);
	}

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
	if (is_coll)
		hl_cn_cfg_unlock_all(hdev);
	else
		port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int hl_cn_ib_dump_qp(struct hl_aux_dev *aux_dev, struct hl_ib_dump_qp_attr *attr, char *buf,
			    size_t size)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_qp_info *qp_info = &hdev->qp_info;
	struct hl_cn_asic_funcs *asic_funcs;
	int rc;

	asic_funcs = hdev->asic_funcs;

	qp_info->port = attr->port;
	qp_info->qpn = attr->qpn;
	qp_info->req = attr->req;
	qp_info->full_print = attr->full;
	qp_info->force_read = attr->force;
	qp_info->exts_print = attr->exts;

	rc = asic_funcs->qp_read(hdev, buf, size);
	if (rc) {
		dev_err(hdev->dev, "Failed to read QP %u, port %u\n", attr->qpn, attr->port);
		return rc;
	}

	return 0;
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
	en_aux_data->driver_ver = hdev->driver_ver;
	en_aux_data->ports_mask = hdev->ext_ports_mask;
	en_aux_data->auto_neg_mask = hdev->auto_neg_mask;
	en_aux_data->minor = hdev->minor;
	en_aux_data->id = hdev->id;
	en_aux_data->fw_ver = hdev->fw_ver;
	en_aux_data->qsfp_eeprom = hdev->cpucp_info->qsfp_eeprom;
	en_aux_data->sb_base_addr = cn_props->sb_base_addr;
	en_aux_data->sb_base_size = cn_props->sb_base_size;
	en_aux_data->swq_base_addr = cn_props->swq_base_addr;
	en_aux_data->swq_base_size = cn_props->swq_base_size;
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

static int hl_cn_ib_aux_data_init(struct hl_cn_device *hdev)
{
	struct hl_ib_port_cnts_data *cnts_data;
	struct hl_ib_aux_data *ib_aux_data;
	struct hl_ib_aux_ops *ib_aux_ops;
	struct hl_aux_dev *ib_aux_dev;
	struct hl_cn_port *cn_port;
	int rc, i;

	ib_aux_dev = &hdev->ib_aux_dev;
	ib_aux_dev->type = HL_AUX_DEV_IB;
	ib_aux_data = ib_aux_dev->aux_data;
	ib_aux_ops = ib_aux_dev->aux_ops;

	ib_aux_data->pdev = hdev->pdev;
	ib_aux_data->dev = hdev->dev;
	ib_aux_data->fw_ver = hdev->fw_ver;
	ib_aux_data->ports_mask = hdev->ports_mask;
	ib_aux_data->ext_ports_mask = hdev->ext_ports_mask;
	ib_aux_data->max_num_of_wqes = hdev->cn_props.max_hw_user_wqs_num;
	ib_aux_data->max_num_of_ports = hdev->cn_props.max_num_of_ports;
	ib_aux_data->pending_reset_long_timeout = hdev->pending_reset_long_timeout;
	ib_aux_data->id = hdev->id;
	ib_aux_data->dram_size = hdev->dram_size;
	ib_aux_data->mixed_qp_wq_types = hdev->mixed_qp_wq_types;
	ib_aux_data->umr_support = hdev->umr_support;

	/* SIMULATOR CODE */
	if (!hdev->pdev) {
		ib_aux_data->sim_mac_addr = kcalloc(hdev->cn_props.max_num_of_ports,
						    sizeof(*ib_aux_data->sim_mac_addr),
						    GFP_KERNEL);
		if (!ib_aux_data->sim_mac_addr)
			return -ENOMEM;

		for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
			if (!(ib_aux_data->ext_ports_mask & BIT(i)))
				continue;

			ib_aux_data->sim_mac_addr[i] = hdev->cpucp_info->mac_addrs[i].mac_addr;
		}
	}
	/* END OF SIMULATOR CODE */

	ib_aux_data->cnts_data = kcalloc(hdev->cn_props.max_num_of_ports,
					 sizeof(*ib_aux_data->cnts_data), GFP_KERNEL);
	if (!ib_aux_data->cnts_data) {
		rc = -ENOMEM;
		goto free_mac_addr;
	}

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(ib_aux_data->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];
		cnts_data = &ib_aux_data->cnts_data[i];

		cnts_data->num = __hl_cn_get_cnts_num(cn_port);

		cnts_data->names = kcalloc(cnts_data->num, HL_IB_CNT_NAME_LEN, GFP_KERNEL);
		if (!cnts_data->names) {
			rc = -ENOMEM;
			goto free_cnts_data;
		}

		__hl_cn_get_cnts_names(cn_port, cnts_data->names, true);
	}

	/* set ib -> cn ops */
	/* the following functions are used even if the IB verbs API is disabled */
	ib_aux_ops->device_operational = hl_cn_device_operational;
	ib_aux_ops->hw_access_lock = hl_cn_hw_access_lock;
	ib_aux_ops->hw_access_unlock = hl_cn_hw_access_unlock;
	ib_aux_ops->alloc_ucontext = hl_cn_ib_alloc_ucontext;
	ib_aux_ops->dealloc_ucontext = hl_cn_ib_dealloc_ucontext;
	ib_aux_ops->query_port = hl_cn_ib_query_port;
	ib_aux_ops->query_device = hl_cn_ib_query_device;
	ib_aux_ops->set_ip_addr_encap = hl_cn_ib_set_ip_addr_encap;
	ib_aux_ops->qp_syndrome_to_str = hl_cn_ib_qp_syndrome_to_str;
	ib_aux_ops->verify_qp_id = hl_cn_ib_verify_qp_id;
	ib_aux_ops->get_cnts_values = hl_cn_get_cnts_values;
	ib_aux_ops->dump_qp = hl_cn_ib_dump_qp;

	/* these functions are used only if the IB verbs API is enabled */
	ib_aux_ops->cmd_ctrl = hl_cn_ib_cmd_ctrl;
	ib_aux_ops->mmap = hl_cn_ib_mmap;

	return 0;

free_cnts_data:
	for (--i; i >= 0; i--) {
		if (!(ib_aux_data->ports_mask & BIT(i)))
			continue;

		kfree(ib_aux_data->cnts_data[i].names);
	}
	kfree(ib_aux_data->cnts_data);
free_mac_addr:
	if (!hdev->pdev)
		kfree(ib_aux_data->sim_mac_addr);

	return rc;
}

static void hl_cn_ib_aux_data_fini(struct hl_cn_device *hdev)
{
	struct hl_ib_aux_data *aux_data;
	struct hl_aux_dev *aux_dev;
	int i;

	aux_dev = &hdev->ib_aux_dev;
	aux_data = aux_dev->aux_data;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(aux_data->ports_mask & BIT(i)))
			continue;

		kfree(aux_data->cnts_data[i].names);
	}
	kfree(aux_data->cnts_data);

	if (!hdev->pdev)
		kfree(aux_data->sim_mac_addr);
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

static void ib_adev_release(struct device *dev)
{
	struct hl_aux_dev *aux_dev = container_of(dev, struct hl_aux_dev, adev.dev);
	struct hl_cn_device *hdev;

	hdev = container_of(aux_dev, struct hl_cn_device, ib_aux_dev);

	hdev->is_ib_aux_dev_initialized = false;
}

static int hl_cn_ib_aux_drv_init(struct hl_cn_device *hdev)
{
	struct hl_aux_dev *aux_dev = &hdev->ib_aux_dev;
	struct auxiliary_device *adev;
	int rc;

	if (!hdev->ib_support)
		return 0;

	rc = hl_cn_ib_aux_data_init(hdev);
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
	hl_cn_ib_aux_data_fini(hdev);

	return rc;
}

static void hl_cn_ib_aux_drv_fini(struct hl_cn_device *hdev)
{
	struct auxiliary_device *adev;

	if (!hdev->ib_support || !hdev->is_ib_aux_dev_initialized)
		return;

	adev = &hdev->ib_aux_dev.adev;

	auxiliary_device_delete(adev);
	auxiliary_device_uninit(adev);

	hl_cn_ib_aux_data_fini(hdev);
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

	if (!hdev->dram_enable)
		return 0;

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

	rc = hl_cn_ib_aux_drv_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init IB driver\n");
		goto ib_aux_drv_fail;
	}

	hl_cn_late_init(hdev);

	hl_cn_debugfs_dev_init(hdev);

	hdev->is_initialized = true;

	return 0;

ib_aux_drv_fail:
	hl_cn_en_aux_drv_fini(hdev);
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

	hl_cn_ib_aux_drv_fini(hdev);
	/* must be called after MSI was disabled */
	hl_cn_en_aux_drv_fini(hdev);
	hl_cn_mem_fini(hdev);
	wq_arrays_pool_destroy(hdev);
	hl_cn_sw_fini(hdev);
}

static int hl_cn_ioctl_port_check(struct hl_cn_device *hdev, u32 port, u32 flags)
{
	bool check_open = flags & NIC_PORT_CHECK_OPEN,
		check_enable = (flags & NIC_PORT_CHECK_ENABLE) || check_open,
		print_on_err = flags & NIC_PORT_PRINT_ON_ERR,
		check_internal = flags & NIC_PORT_CHECK_INTERNAL;
	struct hl_cn_port *cn_port;

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

	if (check_internal && cn_port->eth_enable) {
		if (print_on_err)
			dev_dbg(hdev->dev, "Port %d is external\n", port);
		return -EINVAL;
	}

	if (check_open && !hl_cn_is_port_open(cn_port)) {
		if (print_on_err)
			dev_dbg(hdev->dev, "Port %d is closed\n", port);
		return -ENODEV;
	}

	return 0;
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

/* This function must be called after taking cfg_lock for all the ports */
static struct hl_cn_coll_qp *get_coll_qp_from_conn_id(struct hl_cn_port *cn_port, u32 conn_id)
{
	struct hl_cn_asic_port_funcs *port_funcs;
	u32 coll_conn_id, coll_conn_type;
	struct hl_cn_coll_qp *coll_qp;
	struct hl_cn_device *hdev;

	hdev = cn_port->hdev;
	port_funcs = hdev->asic_funcs->port_funcs;

	coll_conn_type = (conn_id >= cn_port->scale_out_coll_qp_idx_offset) ?
			 HL_CN_COLL_CONN_TYPE_SCALE_OUT : HL_CN_COLL_CONN_TYPE_NON_SCALE_OUT;

	coll_conn_id = conn_id - port_funcs->get_coll_qps_offset(cn_port);

	coll_qp = xa_load(&hdev->coll_props[coll_conn_type].coll_qp_ids, coll_conn_id);

	return coll_qp;
}

/* This function must be called after taking cfg_lock for all the ports */
struct hl_cn_qp *hl_cn_get_qp_from_coll_conn_id(struct hl_cn_port *cn_port, u32 conn_id)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_coll_qp *coll_qp;
	u32 port = cn_port->port;

	coll_qp = get_coll_qp_from_conn_id(cn_port, conn_id);
	if (IS_ERR_OR_NULL(coll_qp)) {
		dev_dbg(hdev->dev,
			"Failed to find matching collective QP for conn_id %u, port %u\n", conn_id,
			port);
		return NULL;
	}

	return coll_qp->qps_array[port];
}

bool hl_cn_is_scale_out_coll_type(u32 coll_conn_type)
{
	return coll_conn_type == HL_CN_COLL_CONN_TYPE_SCALE_OUT;
}

static void hl_cn_get_qp_id_range(struct hl_cn_port *cn_port, u32 *min_id, u32 *max_id)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_asic_funcs *asic_funcs;

	asic_funcs = hdev->asic_funcs;

	asic_funcs->port_funcs->get_qp_id_range(cn_port, min_id, max_id);

	/* Take the minimum between the max id supported by the port and the max id supported by
	 * the WQs number the user asked to allocate.
	 */
	*max_id = min(cn_port->qp_idx_offset + cn_port->num_of_wqs - 1, *max_id);
}

static void hl_cn_get_coll_qp_id_range(struct hl_cn_device *hdev, bool is_scale_out_conn,
				       u32 *min_id, u32 *max_id)
{
	u32 coll_conn_type;

	hdev->asic_funcs->get_coll_qp_id_range(hdev, is_scale_out_conn, min_id, max_id);

	coll_conn_type = is_scale_out_conn ?
			 HL_CN_COLL_CONN_TYPE_SCALE_OUT : HL_CN_COLL_CONN_TYPE_NON_SCALE_OUT;

	/* Take the minimum between the max id supported by the port and the max id supported by
	 * the WQs number the user asked to allocate.
	 */
	*max_id = min(*min_id + hdev->coll_props[coll_conn_type].num_of_coll_wqs - 1, *max_id);
}

static void hl_cn_qp_do_release(struct hl_cn_qp *qp)
{
	struct hl_cn_qpc_drain_attr drain_attr = { .wait_for_idle = false, };
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_port *cn_port;

	if (IS_ERR_OR_NULL(qp))
		return;

	cn_port = qp->cn_port;
	port_funcs = cn_port->hdev->asic_funcs->port_funcs;

	port_funcs->qp_pre_destroy(qp);

	if (qp->is_coll) {
		struct hl_cn_coll_qp *coll_qp = get_coll_qp_from_conn_id(cn_port, qp->qp_id);

		coll_qp->qps_array[cn_port->port] = NULL;
	} else {
		/* QP was found before, hence use xa_store to replace the pointer but don't release
		 * index. xa_store should not fail in such scenario.
		 */
		xa_store(&qp->cn_port->qp_ids, qp->qp_id, NULL, GFP_KERNEL);
	}

	/* drain the Req QP now in order to make sure that accesses to the WQ will not
	 * be performed from this point on.
	 * Waiting for the WQ to drain is performed in the reset work
	 */
	hl_cn_qp_modify(cn_port, qp, CN_QP_STATE_SQD, &drain_attr);

	queue_work(cn_port->qp_wq, &qp->async_work);
}

static int alloc_qp(struct hl_cn_device *hdev, struct hl_cn_ctx *ctx,
		    struct hl_cni_alloc_conn_in *in, struct hl_cni_alloc_conn_out *out)
{
	struct hl_cn_wq_array_properties *swq_arr_props, *rwq_arr_props;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_port *cn_port;
	struct xa_limit id_limit;
	u32 min_id, max_id, port;
	struct hl_cn_qp *qp;
	int id, rc;

	if (!in || !out) {
		dev_dbg(hdev->dev, "Missing parameters for allocating a QP\n");
		return -EINVAL;
	}

	port = in->port;

	rc = hl_cn_ioctl_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
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

	/* TODO: handle local/remote keys */

	hl_cn_get_qp_id_range(cn_port, &min_id, &max_id);

	port_funcs->cfg_lock(cn_port);

	if (!cn_port->set_app_params) {
		dev_dbg(hdev->dev,
			"Failed to allocate QP, set_app_params wasn't called yet, port %d\n", port);
		rc = -EPERM;
		goto error_exit;
	}

	swq_arr_props = &cn_port->wq_arr_props[HL_CNI_USER_WQ_SEND];
	rwq_arr_props = &cn_port->wq_arr_props[HL_CNI_USER_WQ_RECV];

	if (!swq_arr_props->enable || !rwq_arr_props->enable) {
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

static int alloc_coll_qp(struct hl_cn_device *hdev, struct hl_cn_ctx *ctx,
			 struct hl_cni_alloc_coll_conn_in *in,
			 struct hl_cni_alloc_coll_conn_out *out)
{
	u32 min_id, max_id, port, _port, coll_conn_type;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_asic_funcs *asic_funcs;
	struct hl_cn_coll_qp *coll_qp;
	struct hl_cn_port *cn_port;
	struct xa_limit id_limit;
	bool is_scale_out_conn;
	struct hl_cn_qp *qp;
	u8 max_num_of_ports;
	int id, rc;

	if (!in || !out) {
		dev_dbg(hdev->dev, "Missing parameters for allocating a collective QP\n");
		return -EINVAL;
	}

	max_num_of_ports = hdev->cn_props.max_num_of_ports;

	is_scale_out_conn = in->is_scale_out;

	/* Return with failure in case not all ports are UP */
	for (port = 0; port < max_num_of_ports; port++) {
		if (!(hdev->ports_mask & BIT(port)))
			continue;

		cn_port = &hdev->cn_ports[port];

		/* Skip of checking ports that are not of the requested collective type */
		if (is_scale_out_conn ^ cn_port->eth_enable)
			continue;

		rc = hl_cn_ioctl_port_check(hdev, port,
					    NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
		if (rc)
			return rc;
	}

	coll_qp = kzalloc(sizeof(*coll_qp), GFP_KERNEL);
	if (!coll_qp)
		return -ENOMEM;

	coll_qp->qps_array = kcalloc(max_num_of_ports, sizeof(*coll_qp->qps_array), GFP_KERNEL);
	if (!coll_qp->qps_array) {
		kfree(coll_qp);
		return -ENOMEM;
	}

	asic_funcs = hdev->asic_funcs;
	port_funcs = asic_funcs->port_funcs;

	coll_qp->hdev = hdev;
	atomic_set(&coll_qp->num_of_initialized_qps, 0);
	atomic_set(&coll_qp->num_of_allocated_qps, 0);

	hl_cn_get_coll_qp_id_range(hdev, is_scale_out_conn, &min_id, &max_id);

	coll_conn_type = is_scale_out_conn ?
			 HL_CN_COLL_CONN_TYPE_SCALE_OUT : HL_CN_COLL_CONN_TYPE_NON_SCALE_OUT;

	hl_cn_cfg_lock_all(hdev);

	id_limit = XA_LIMIT(min_id, max_id);
	rc = xa_alloc(&hdev->coll_props[coll_conn_type].coll_qp_ids, &id, coll_qp, id_limit,
		      GFP_KERNEL);
	if (rc) {
		dev_dbg(hdev->dev, "Failed to allocate coll QP\n");
		goto cfg_unlock_all;
	}

	coll_qp->id = id;
	coll_qp->coll_conn_type = coll_conn_type;

	for (port = 0; port < max_num_of_ports; port++) {
		if (!(hdev->ports_mask & BIT(port)))
			continue;

		cn_port = &hdev->cn_ports[port];

		/* Skip ports that are not of the requested collective type */
		if (is_scale_out_conn ^ cn_port->eth_enable)
			continue;

		qp = kzalloc(sizeof(*qp), GFP_KERNEL);
		if (!qp) {
			rc = -ENOMEM;
			goto free_qps;
		}

		coll_qp->qps_array[port] = qp;

		qp->is_coll = true;
		qp->coll_conn_type = coll_conn_type;
		qp->cn_port = cn_port;
		qp->port = port;
		qp->ctx = ctx;
		qp->curr_state = CN_QP_STATE_RESET;
		INIT_WORK(&qp->async_work, qp_destroy_work);

		/* TODO: handle local/remote keys */

		qp->qp_id = id + port_funcs->get_coll_qps_offset(cn_port);

		if (is_scale_out_conn)
			atomic_inc(&cn_port->num_of_allocated_scale_out_coll_qps);
		else
			atomic_inc(&cn_port->num_of_allocated_coll_qps);

		atomic_inc(&coll_qp->num_of_allocated_qps);
	}

	/* Register all the QPs to the dispatcher */
	for (port = 0; port < max_num_of_ports; port++) {
		if (!(hdev->ports_mask & BIT(port)))
			continue;

		cn_port = &hdev->cn_ports[port];

		/* Skip ports that are not of the requested collective type */
		if (is_scale_out_conn ^ cn_port->eth_enable)
			continue;

		qp = coll_qp->qps_array[port];

		rc = port_funcs->register_qp(cn_port, qp->qp_id, ctx->asid);
		if (rc) {
			dev_dbg(hdev->dev,
				"Failed to register collective QP %u for port %u\n",
				qp->qp_id, port);
			goto qp_register_error;
		}
	}

	hl_cn_cfg_unlock_all(hdev);

	out->conn_id = id;

	return 0;

qp_register_error:
	for (_port = 0; _port < port; _port++) {
		if (!(hdev->ports_mask & BIT(_port)))
			continue;

		qp = coll_qp->qps_array[port];
		cn_port = &hdev->cn_ports[_port];

		port_funcs->unregister_qp(cn_port, qp->qp_id);
	}

	port = max_num_of_ports;
free_qps:
	for (_port = 0; _port < port; _port++) {
		if (!(hdev->ports_mask & BIT(_port)))
			continue;

		cn_port = &hdev->cn_ports[_port];

		if (is_scale_out_conn)
			atomic_dec(&cn_port->num_of_allocated_scale_out_coll_qps);
		else
			atomic_dec(&cn_port->num_of_allocated_coll_qps);

		qp = coll_qp->qps_array[port];
		coll_qp->qps_array[port] = NULL;
		kfree(qp);
	}

	xa_erase(&hdev->coll_props[coll_conn_type].coll_qp_ids, coll_qp->id);
cfg_unlock_all:
	hl_cn_cfg_unlock_all(hdev);
	kfree(coll_qp->qps_array);
	kfree(coll_qp);

	return rc;
}

u32 hl_cn_get_wq_array_type(bool is_send, bool is_coll, bool is_scale_out_conn)
{
	u32 type;

	if (is_send)
		if (is_coll)
			type = is_scale_out_conn ? HL_CNI_USER_COLL_SCALE_OUT_WQ_SEND :
			       HL_CNI_USER_COLL_WQ_SEND;
		else
			type = HL_CNI_USER_WQ_SEND;
	else
		if (is_coll)
			type = is_scale_out_conn ? HL_CNI_USER_COLL_SCALE_OUT_WQ_RECV :
			       HL_CNI_USER_COLL_WQ_RECV;
		else
			type = HL_CNI_USER_WQ_RECV;

	return type;
}

static int alloc_and_map_wq(struct hl_cn_port *cn_port, struct hl_cn_qp *qp, u32 n_wq, bool is_swq)
{
	u32 wq_arr_type, wqe_size, qp_idx_offset, wq_idx;
	struct hl_cn_wq_array_properties *wq_arr_props;
	struct hl_cn_mem_data mem_data = {};
	struct hl_cn_properties *cn_props;
	bool is_coll, is_scale_out_conn;
	struct hl_cn_device *hdev;
	struct hl_cn_mem_buf *buf;
	u64 wq_arr_size, wq_size;
	int rc;

	hdev = cn_port->hdev;
	cn_props = &hdev->cn_props;

	is_coll = qp->is_coll;
	is_scale_out_conn = hl_cn_is_scale_out_coll_type(qp->coll_conn_type);

	if (is_coll)
		qp_idx_offset = is_scale_out_conn ? cn_port->scale_out_coll_qp_idx_offset :
				cn_port->coll_qp_idx_offset;
	else
		qp_idx_offset = cn_port->qp_idx_offset;

	wq_idx = qp->qp_id - qp_idx_offset;

	wq_arr_type = hl_cn_get_wq_array_type(is_swq, is_coll, is_scale_out_conn);
	wq_arr_props = &cn_port->wq_arr_props[wq_arr_type];
	wqe_size = is_swq ? cn_port->swqe_size : cn_props->rwqe_size;

	if (wq_arr_props->dva_base) {
		mem_data.mem_id = HL_CN_DRV_MEM_HOST_VIRTUAL;
		mem_data.size = PAGE_ALIGN(n_wq * wqe_size);

		/* Get offset into device VA block pre-allocated for SWQ.
		 *
		 * Note: HW indexes into SWQ array using qp_id.
		 * In general, it's HW requirement to leave holes in a WQ array if corresponding QP
		 * indexes are allocated on another WQ array.
		 */
		mem_data.device_va = wq_arr_props->dva_base + wq_arr_props->wq_size * wq_idx;

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
		mem_data.mem_id = HL_CN_DRV_MEM_HOST_MAP_ONLY;

		buf = hl_cn_mem_buf_get(hdev, wq_arr_props->handle);
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
		mem_data.in.host_map_data.kernel_address =
				(void *)(buf->kernel_address + wq_size * wq_idx);

		mem_data.in.host_map_data.bus_address = (buf->bus_address + wq_size * wq_idx);

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
	rc = hl_cn_mem_alloc(hdev, &mem_data);
	if (rc) {
		dev_dbg(hdev->dev, "Failed to allocate %s. Port %d, QP %d\n",
			is_swq ? "SWQ" : "RWQ", cn_port->port, qp->qp_id);
		return rc;
	}

	/* Retrieve mmap handle. */
	if (is_swq)
		qp->swq_handle = mem_data.handle;
	else
		qp->rwq_handle = mem_data.handle;

	return 0;
}

static int set_req_qp_ctx(struct hl_cn_device *hdev, struct hl_cni_req_conn_ctx_in *in,
			  struct hl_cni_req_conn_ctx_out *out)
{
	struct hl_cn_wq_array_properties *swq_arr_props, *rwq_arr_props;
	struct hl_cn_encap_xarray_pdata *encap_data;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_asic_funcs *asic_funcs;
	u32 wq_size, port, max_wq_size;
	struct hl_cn_port *cn_port;
	struct hl_cn_qp *qp;
	bool is_coll_conn;
	int rc, i;

	if (!in) {
		dev_dbg(hdev->dev, "Missing parameters for setting a requester QPC\n");
		return -EINVAL;
	}

	if (in->reserved) {
		dev_dbg(hdev->dev, "Reserved bytes must be 0\n");
		return -EINVAL;
	}

	for (i = 0; i < sizeof(in->pad); i++)
		if (in->pad[i]) {
			dev_dbg(hdev->dev, "Padding bytes must be 0\n");
			return -EINVAL;
		}

	port = in->port;

	rc = hl_cn_ioctl_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	asic_funcs = hdev->asic_funcs;
	port_funcs = asic_funcs->port_funcs;
	cn_port = &hdev->cn_ports[port];

	is_coll_conn = asic_funcs->is_coll_conn_id(hdev, in->conn_id);

	if (in->timer_granularity > NIC_TMR_TIMEOUT_MAX_GRAN) {
		dev_err(hdev->dev,
			"timer granularity %d is not supported\n", in->timer_granularity);
		return -EINVAL;
	}

	if (!in->timer_granularity && !hl_cn_is_ibdev_opened(hdev))
		in->timer_granularity = NIC_TMR_TIMEOUT_DEFAULT_GRAN;

	/* We must take rtnl_lock here prior to taking cfg_lock, as we may land into flow that
	 * extracts the IP port and that can cause a deadlock in case an operation from the
	 * net subsystem that requires the cfg_lock is executed at the same time. As such operation
	 * will first obtain rtnl_lock and then will try to take a cfg_lock, hence a deadlock.
	 */
	rtnl_lock();

	if (is_coll_conn) {
		hl_cn_cfg_lock_all(hdev);

		/* For collective QPs we check that set_app_params was called for this port here
		 * and not in alloc_coll_qp.
		 * The reason is that alloc_coll_qp is being called for all the ports even though
		 * some of the ports are not necessarily part of the collective group.
		 */
		if (!cn_port->set_app_params) {
			dev_dbg(hdev->dev,
				"Failed to set requester for conn_id %u, set_app_params wasn't called yet, port %d\n",
				in->conn_id, port);
			rc = -EPERM;
			goto cfg_unlock;
		}

		qp = hl_cn_get_qp_from_coll_conn_id(cn_port, in->conn_id);
	} else {
		port_funcs->cfg_lock(cn_port);
		qp = xa_load(&cn_port->qp_ids, in->conn_id);
	}

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

	/* TODO: w/a SW-99462 remove when HCL stops using the prev ctx structure */
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

	/* For backward compatibility, use 'last_index' if 'wq_size' is not set. */
	if (in->wq_size) {
		wq_size = in->wq_size;
	} else if (check_add_overflow(in->last_index, (u32)1, &wq_size)) {
		dev_dbg(hdev->dev,
			"Port %d, Requester QP %d - QP WQ last index (0x%x) is invalid\n", port,
			qp->qp_id, in->last_index);
		rc = -EINVAL;
		goto cfg_unlock;
	}

	/* verify that size does not exceed wq_array size */
	max_wq_size = qp->is_coll ? hdev->coll_props[qp->coll_conn_type].num_of_coll_wq_entries :
		      cn_port->num_of_wq_entries;

	if (wq_size > max_wq_size) {
		dev_dbg(hdev->dev,
			"Port %d, Requester QP %d - requested size (%d) > max size (%d)\n", port,
			qp->qp_id, wq_size, max_wq_size);
		rc = -EINVAL;
		goto cfg_unlock;
	}

	if (qp->is_coll) {
		struct hl_cn_coll_properties *coll_props = &hdev->coll_props[qp->coll_conn_type];

		swq_arr_props = &cn_port->wq_arr_props[coll_props->swq_type];
		rwq_arr_props = &cn_port->wq_arr_props[coll_props->rwq_type];
	} else {
		swq_arr_props = &cn_port->wq_arr_props[HL_CNI_USER_WQ_SEND];
		rwq_arr_props = &cn_port->wq_arr_props[HL_CNI_USER_WQ_RECV];
	}

	if (!swq_arr_props->on_device_mem) {
		rc = alloc_and_map_wq(cn_port, qp, wq_size, true);
		if (rc)
			goto cfg_unlock;

		out->swq_mem_handle = qp->swq_handle;
	}

	if (!rwq_arr_props->on_device_mem) {
		rc = alloc_and_map_wq(cn_port, qp, wq_size, false);
		if (rc)
			goto err_free_swq;

		out->rwq_mem_handle = qp->rwq_handle;
	}

	qp->remote_key = in->remote_key;

	rc = hl_cn_qp_modify(cn_port, qp, CN_QP_STATE_RTS, in);
	if (rc)
		goto err_free_rwq;

	if (is_coll_conn)
		hl_cn_cfg_unlock_all(hdev);
	else
		port_funcs->cfg_unlock(cn_port);

	rtnl_unlock();

	return 0;

err_free_rwq:
	if (qp->rwq_handle) {
		hl_cn_mem_destroy(hdev, qp->rwq_handle);
		qp->rwq_handle = 0;
		out->rwq_mem_handle = qp->rwq_handle;
		if (!rwq_arr_props->dva_base) {
			int ret;

			ret = hl_cn_mem_buf_put_handle(hdev, rwq_arr_props->handle);
			if (ret == 1)
				rwq_arr_props->handle = 0;
		}
	}
err_free_swq:
	if (qp->swq_handle) {
		hl_cn_mem_destroy(hdev, qp->swq_handle);
		qp->swq_handle = 0;
		out->swq_mem_handle = qp->swq_handle;
		if (!swq_arr_props->dva_base) {
			int ret;

			ret = hl_cn_mem_buf_put_handle(hdev, swq_arr_props->handle);
			if (ret == 1)
				swq_arr_props->handle = 0;
		}
	}
cfg_unlock:
	if (is_coll_conn)
		hl_cn_cfg_unlock_all(hdev);
	else
		port_funcs->cfg_unlock(cn_port);

	rtnl_unlock();

	return rc;
}

static int set_res_qp_ctx(struct hl_cn_device *hdev, struct hl_cni_res_conn_ctx_in *in)
{
	struct hl_cn_encap_xarray_pdata *encap_data;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_asic_funcs *asic_funcs;
	struct hl_cn_port *cn_port;
	struct hl_cn_qp *qp;
	bool is_coll_conn;
	int rc, i;
	u32 port;

	if (!in) {
		dev_dbg(hdev->dev, "Missing parameters for setting a responder QPC\n");
		return -EINVAL;
	}

	for (i = 0; i < sizeof(in->pad); i++)
		if (in->pad[i]) {
			dev_dbg(hdev->dev, "Padding bytes must be 0\n");
			return -EINVAL;
		}

	port = in->port;

	rc = hl_cn_ioctl_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	asic_funcs = hdev->asic_funcs;
	port_funcs = asic_funcs->port_funcs;
	cn_port = &hdev->cn_ports[port];

	is_coll_conn = asic_funcs->is_coll_conn_id(hdev, in->conn_id);

	/* We must take rtnl_lock here prior to taking cfg_lock, as we may land into flow that
	 * extracts the IP port and that can cause a deadlock in case an operation from the
	 * net subsystem that requires the cfg_lock is executed at the same time. As such operation
	 * will first obtain rtnl_lock and then will try to take a cfg_lock, hence a deadlock.
	 */
	rtnl_lock();

	if (is_coll_conn) {
		hl_cn_cfg_lock_all(hdev);

		/* For collective QPs we check that set_app_params was called for this port here
		 * and not in alloc_coll_qp.
		 * The reason is that alloc_coll_qp is being called for all the ports even though
		 * some of the ports are not necessarily part of the collective group.
		 */
		if (!cn_port->set_app_params) {
			dev_dbg(hdev->dev,
				"Failed to set responder for conn_id %u, set_app_params wasn't called yet, port %d\n",
				in->conn_id, port);
			rc = -EPERM;
			goto unlock_cfg;
		}

		qp = hl_cn_get_qp_from_coll_conn_id(cn_port, in->conn_id);
	} else {
		port_funcs->cfg_lock(cn_port);
		qp = xa_load(&cn_port->qp_ids, in->conn_id);
	}

	if (IS_ERR_OR_NULL(qp)) {
		dev_dbg(hdev->dev, "Failed to find matching QP for handle %d, port %d\n",
			in->conn_id, port);
		rc = -EINVAL;
		goto unlock_cfg;
	}

	/* TODO: w/a SW-99462 remove when HCL stops using the prev ctx structure */
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
		goto unregister_coll_qp;
	}

	qp->local_key = in->local_key;

	 /* TODO: w/a SW-62591, modify when fixed in synapse */
	if (qp->curr_state == CN_QP_STATE_RESET) {
		rc = hl_cn_qp_modify(cn_port, qp, CN_QP_STATE_INIT, NULL);
		if (rc)
			goto unregister_coll_qp;

		if (is_coll_conn) {
			struct hl_cn_coll_qp *coll_qp = get_coll_qp_from_conn_id(cn_port,
										 qp->qp_id);

			atomic_inc(&coll_qp->num_of_initialized_qps);
		}
	}

	/* all is well, we are ready to receive */
	rc = hl_cn_qp_modify(cn_port, qp, CN_QP_STATE_RTR, in);

	if (is_coll_conn)
		hl_cn_cfg_unlock_all(hdev);
	else
		port_funcs->cfg_unlock(cn_port);

	rtnl_unlock();

	return rc;

unregister_coll_qp:
	if (is_coll_conn) {
		struct hl_cn_coll_qp *coll_qp = get_coll_qp_from_conn_id(cn_port, qp->qp_id);

		port_funcs->unregister_qp(cn_port, qp->qp_id);
		atomic_dec(&coll_qp->num_of_initialized_qps);
	}
unlock_cfg:
	if (is_coll_conn)
		hl_cn_cfg_unlock_all(hdev);
	else
		port_funcs->cfg_unlock(cn_port);

	rtnl_unlock();

	return rc;
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

static void hl_cn_unset_coll_qps_destroy(struct hl_cn_coll_qp *coll_qp)
{
	struct hl_cn_device *hdev = coll_qp->hdev;
	u32 port;

	/* Go over all the ports and call the QP release function for the collective QP of each
	 * one. In that way, all the QPs will go through the same release flow.
	 */
	for (port = 0; port < hdev->cn_props.max_num_of_ports; port++) {
		if (!(hdev->ports_mask & BIT(port)))
			continue;

		hl_cn_qp_do_release(coll_qp->qps_array[port]);
	}
}

static void hl_cn_coll_qp_free(struct hl_cn_coll_qp *coll_qp)
{
	struct hl_cn_device *hdev = coll_qp->hdev;

	xa_erase(&hdev->coll_props[coll_qp->coll_conn_type].coll_qp_ids, coll_qp->id);
	kfree(coll_qp->qps_array);
	kfree(coll_qp);
}

static void qp_destroy_work(struct work_struct *work)
{
	struct hl_cn_qp *qp = container_of(work, struct hl_cn_qp, async_work);
	struct hl_cn_wq_array_properties *swq_arr_props, *rwq_arr_props;
	struct hl_cn_coll_properties *coll_props = NULL;
	struct hl_cn_port *cn_port = qp->cn_port;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_qpc_drain_attr drain_attr;
	struct hl_cn_qpc_reset_attr rst_attr;
	struct hl_cn_ctx *ctx = qp->ctx;
	struct hl_cn_device *hdev;
	int rc;

	hdev = cn_port->hdev;
	port_funcs = hdev->asic_funcs->port_funcs;

	/* always perform orderly reset in simulator */
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
		hl_cn_qp_modify(cn_port, qp, CN_QP_STATE_SQD, &drain_attr);

	if (qp->is_coll)
		hl_cn_cfg_lock_all(hdev);
	else
		port_funcs->cfg_lock(cn_port);

	if (qp->is_coll) {
		struct hl_cn_coll_qp *coll_qp = get_coll_qp_from_conn_id(cn_port, qp->qp_id);

		/* If this QP is not in reset (i.e., was set), we can decrement the number of
		 * initialized QPs under this collective QP.
		 */
		if (qp->curr_state != CN_QP_STATE_RESET)
			atomic_dec(&coll_qp->num_of_initialized_qps);

		/* If there are no initialized QPs left, we can destroy all the rest of the QPs
		 * with the same collective ID.
		 */
		if (atomic_read(&coll_qp->num_of_initialized_qps) == 0)
			hl_cn_unset_coll_qps_destroy(coll_qp);

		/* If this is the last QP with a collective ID, we can destroy the collective QP
		 * and remove its ID from the collective idr.
		 */
		if (atomic_dec_and_test(&coll_qp->num_of_allocated_qps))
			hl_cn_coll_qp_free(coll_qp);
	}

	hl_cn_qp_modify(cn_port, qp, CN_QP_STATE_RESET, &rst_attr);

	port_funcs->unregister_qp(cn_port, qp->qp_id);

	if (qp->is_coll) {
		coll_props = &hdev->coll_props[qp->coll_conn_type];

		swq_arr_props = &cn_port->wq_arr_props[coll_props->swq_type];
		rwq_arr_props = &cn_port->wq_arr_props[coll_props->rwq_type];
	} else {
		swq_arr_props = &cn_port->wq_arr_props[HL_CNI_USER_WQ_SEND];
		rwq_arr_props = &cn_port->wq_arr_props[HL_CNI_USER_WQ_RECV];
	}

	if (qp->swq_handle) {
		hl_cn_mem_destroy(hdev, qp->swq_handle);
		qp->swq_handle = 0;
		if (!swq_arr_props->dva_base) {
			rc = hl_cn_mem_buf_put_handle(hdev, swq_arr_props->handle);
			if (rc == 1)
				swq_arr_props->handle = 0;
		}
	}

	if (qp->rwq_handle) {
		hl_cn_mem_destroy(hdev, qp->rwq_handle);
		qp->rwq_handle = 0;
		if (!rwq_arr_props->dva_base) {
			rc = hl_cn_mem_buf_put_handle(hdev, rwq_arr_props->handle);
			if (rc == 1)
				rwq_arr_props->handle = 0;
		}
	}

	if (qp->is_coll) {
		atomic_t *num_of_allocated_coll_qps =
						hl_cn_is_scale_out_coll_type(qp->coll_conn_type) ?
						&cn_port->num_of_allocated_scale_out_coll_qps :
						&cn_port->num_of_allocated_coll_qps;

		if (atomic_dec_and_test(num_of_allocated_coll_qps)) {
			if (swq_arr_props->under_unset)
				__user_wq_arr_unset(ctx, cn_port, coll_props->swq_type);

			if (rwq_arr_props->under_unset)
				__user_wq_arr_unset(ctx, cn_port, coll_props->rwq_type);
		}
	} else {
		xa_erase(&cn_port->qp_ids, qp->qp_id);

		if (atomic_dec_and_test(&cn_port->num_of_allocated_qps)) {
			if (swq_arr_props->under_unset)
				__user_wq_arr_unset(ctx, cn_port, HL_CNI_USER_WQ_SEND);

			if (rwq_arr_props->under_unset)
				__user_wq_arr_unset(ctx, cn_port, HL_CNI_USER_WQ_RECV);
		}
	}

	if (qp->req_user_cq)
		hl_cn_user_cq_put(qp->req_user_cq);

	if (qp->res_user_cq)
		hl_cn_user_cq_put(qp->res_user_cq);

	port_funcs->qp_post_destroy(qp);

	/* hl_cn_mem_destroy should be included inside lock not due to protection.
	 * The handles (swq_handle and rwq_handle) are created based on QP id.
	 * Lock is to avoid concurrent memory access from a new handle created
	 * before freeing memory
	 */
	if (qp->is_coll)
		hl_cn_cfg_unlock_all(hdev);
	else
		port_funcs->cfg_unlock(cn_port);

	kfree(qp);
}

static void qps_drain_async_work(struct hl_cn_device *hdev)
{
	int i, num_gen_qps, num_coll_qps, num_scale_out_coll_qps;
	struct hl_cn_port *cn_port;

	/* wait for the workers to complete */
	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		drain_workqueue(cn_port->qp_wq);

		num_gen_qps = atomic_read(&cn_port->num_of_allocated_qps);
		if (num_gen_qps)
			dev_warn(hdev->dev, "Port %d still has %d QPs alive\n", i, num_gen_qps);

		num_coll_qps = atomic_read(&cn_port->num_of_allocated_coll_qps);
		if (num_coll_qps)
			dev_warn(hdev->dev, "Port %d still has %d collective QPs alive\n", i,
				 num_coll_qps);

		num_scale_out_coll_qps =
			atomic_read(&cn_port->num_of_allocated_scale_out_coll_qps);
		if (num_scale_out_coll_qps)
			dev_warn(hdev->dev, "Port %d still has %d scale-out collective QPs alive\n",
				 i, num_scale_out_coll_qps);
	}
}

static inline int __must_check PTR_ERR_OR_EINVAL(__force const void *ptr)
{
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	else
		return -EINVAL;
}

static int destroy_qp(struct hl_cn_device *hdev, struct hl_cni_destroy_conn_in *in)
{
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_asic_funcs *asic_funcs;
	struct hl_cn_port *cn_port;
	struct hl_cn_qp *qp;
	bool is_coll_conn;
	u32 port, flags;
	int rc;

	if (!in) {
		dev_dbg(hdev->dev, "Missing parameters for destroying a QP\n");
		return -EINVAL;
	}

	port = in->port;

	if (port >= hdev->cn_props.max_num_of_ports) {
		dev_dbg(hdev->dev, "Invalid port %d\n", port);
		return -EINVAL;
	}

	cn_port = &hdev->cn_ports[port];

	/* in case of destroying QPs of external ports the port may be already closed
	 * by a user issuing "ip link set down" command so we only check if the port
	 * is enabled in these ports
	 */
	flags = cn_port->eth_enable ? NIC_PORT_CHECK_ENABLE : NIC_PORT_CHECK_OPEN;
	flags |= NIC_PORT_PRINT_ON_ERR;
	rc = hl_cn_ioctl_port_check(hdev, port, flags);
	if (rc)
		return rc;

	asic_funcs = hdev->asic_funcs;
	port_funcs = asic_funcs->port_funcs;

	is_coll_conn = asic_funcs->is_coll_conn_id(hdev, in->conn_id);

	/* prevent reentrancy by locking the whole process of destroy_qp */
	if (is_coll_conn) {
		hl_cn_cfg_lock_all(hdev);
		qp = hl_cn_get_qp_from_coll_conn_id(cn_port, in->conn_id);
	} else {
		port_funcs->cfg_lock(cn_port);
		qp = xa_load(&cn_port->qp_ids, in->conn_id);
	}

	if (IS_ERR_OR_NULL(qp)) {
		rc = PTR_ERR_OR_EINVAL(qp);
		goto out_err;
	}

	hl_cn_qp_do_release(qp);

	if (is_coll_conn)
		hl_cn_cfg_unlock_all(hdev);
	else
		port_funcs->cfg_unlock(cn_port);

	return 0;

out_err:
	if (is_coll_conn)
		hl_cn_cfg_unlock_all(hdev);
	else
		port_funcs->cfg_unlock(cn_port);

	return rc;
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

static void qps_destroy(struct hl_cn_device *hdev)
{
	struct hl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	struct hl_cn_coll_qp *coll_qp;
	struct hl_cn_port *cn_port;
	unsigned long qp_id = 0;
	int i, coll_conn_type;
	struct hl_cn_qp *qp;

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

			hl_cn_qp_do_release(qp);
		}

		port_funcs->cfg_unlock(cn_port);
	}

	hl_cn_cfg_lock_all(hdev);

	for (coll_conn_type = 0; coll_conn_type < HL_CN_COLL_CONN_TYPE_MAX; coll_conn_type++) {
		xa_for_each(&hdev->coll_props[coll_conn_type].coll_qp_ids, qp_id, coll_qp) {
			if (IS_ERR_OR_NULL(coll_qp))
				continue;

			for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
				if (!(hdev->ports_mask & BIT(i)))
					continue;

				qp = coll_qp->qps_array[i];
				hl_cn_qp_do_release(qp);
			}
		}
	}

	hl_cn_cfg_unlock_all(hdev);

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

	hl_cn_cfg_lock_all(hdev);

	for (coll_conn_type = 0; coll_conn_type < HL_CN_COLL_CONN_TYPE_MAX; coll_conn_type++) {
		xa_for_each(&hdev->coll_props[coll_conn_type].coll_qp_ids, qp_id, coll_qp)
			dev_err_ratelimited(hdev->dev, "Collective QP %ld is still alive\n", qp_id);
	}

	hl_cn_cfg_unlock_all(hdev);
}

static void qps_halt(struct hl_cn_ctx *ctx)
{
	struct hl_cn_qpc_drain_attr drain_attr = { .wait_for_idle = false, };
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_device *hdev = ctx->hdev;
	struct hl_cn_coll_qp *coll_qp;
	struct hl_cn_port *cn_port;
	unsigned long qp_id = 0;
	int i, coll_conn_type;
	struct hl_cn_qp *qp;

	port_funcs = hdev->asic_funcs->port_funcs;

	/* destroy the QPs */
	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		/* protect against destroy_qp occurring in parallel */
		port_funcs->cfg_lock(cn_port);

		xa_for_each(&cn_port->qp_ids, qp_id, qp) {
			if (IS_ERR_OR_NULL(qp) || qp->ctx->user_asid != ctx->user_asid)
				continue;

			/* drain the Req QP now in order to make sure that accesses to the WQ will
			 * not be performed from this point on.
			 */
			hl_cn_qp_modify(cn_port, qp, CN_QP_STATE_SQD, &drain_attr);
		}

		port_funcs->cfg_unlock(cn_port);
	}

	hl_cn_cfg_lock_all(hdev);

	for (coll_conn_type = 0; coll_conn_type < HL_CN_COLL_CONN_TYPE_MAX; coll_conn_type++) {
		xa_for_each(&hdev->coll_props[coll_conn_type].coll_qp_ids, qp_id, coll_qp) {
			if (IS_ERR_OR_NULL(coll_qp))
				continue;

			for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
				if (!(hdev->ports_mask & BIT(i)))
					continue;

				qp = coll_qp->qps_array[i];

				if (qp->ctx->user_asid != ctx->user_asid)
					break;

				/* drain the Req QP now in order to make sure that accesses to the
				 * WQ will not be performed from this point on.
				 */
				hl_cn_qp_modify(qp->cn_port, qp, CN_QP_STATE_SQD, &drain_attr);
			}
		}
	}

	hl_cn_cfg_unlock_all(hdev);
}

static void wq_arrs_destroy(struct hl_cn_ctx *ctx)
{
	struct hl_cn_wq_array_properties *wq_arr_props;
	struct hl_cn_device *hdev = ctx->hdev;
	struct hl_cn_port *cn_port;
	u32 type;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		wq_arr_props = cn_port->wq_arr_props;

		for (type = 0; type < HL_CNI_USER_WQ_TYPE_MAX; type++) {
			if (wq_arr_props[type].enable)
				__user_wq_arr_unset(ctx, cn_port, type);
		}
	}
}

static void encap_ids_destroy(struct hl_cn_device *hdev)
{
	struct hl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	struct hl_cn_encap_xarray_pdata *xa_pdata;
	struct hl_cn_port *cn_port;
	unsigned long encap_id;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		port_funcs->cfg_lock(cn_port);

		xa_for_each(&cn_port->encap_ids, encap_id, xa_pdata) {
			asic_funcs->port_funcs->encap_unset(cn_port, encap_id, xa_pdata);

			if (xa_pdata->encap_type != HL_CNI_ENCAP_NONE)
				kfree(xa_pdata->encap_header);

			kfree(xa_pdata);
			xa_erase(&cn_port->encap_ids, encap_id);
		}

		port_funcs->cfg_unlock(cn_port);
	}
}

static int user_wq_arr_set(struct hl_cn_device *hdev, struct hl_cni_user_wq_arr_set_in *in,
			   struct hl_cni_user_wq_arr_set_out *out, struct hl_cn_ctx *ctx)
{
	u32 port, type, num_of_wqs, num_of_wq_entries, min_wqs_per_port, mem_id;
	struct hl_cn_coll_properties *coll_props = NULL;
	struct hl_cn_wq_array_properties *wq_arr_props;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_properties *cn_props;
	struct hl_cn_port *cn_port;
	char *type_str;
	int rc, i;

	if (!in || !out) {
		dev_dbg(hdev->dev, "missing parameters, can't set user WQ\n");
		return -EINVAL;
	}

	for (i = 0; i < sizeof(in->pad); i++)
		if (in->pad[i]) {
			dev_dbg(hdev->dev, "Padding bytes must be 0\n");
			return -EINVAL;
	}

	if (in->swq_granularity > HL_CNI_SWQE_GRAN_64B) {
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

	if (mem_id != HL_CNI_MEM_HOST && mem_id != HL_CNI_MEM_DEVICE) {
		dev_dbg(hdev->dev, "invalid memory type %d for user WQ\n", mem_id);
		return -EINVAL;
	}

	port = in->port;
	rc = hl_cn_ioctl_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];

	wq_arr_props = &cn_port->wq_arr_props[type];
	type_str = wq_arr_props->type_str;

	if (wq_arr_props->is_coll)
		coll_props = &hdev->coll_props[wq_arr_props->coll_wq_type];

	/* For generic WQs minimum number of wqs required is 2, one for raw eth and one for rdma */
	min_wqs_per_port = wq_arr_props->is_coll ? NIC_MIN_COLL_WQS_PER_PORT : NIC_MIN_WQS_PER_PORT;
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
	if (wq_arr_props->enable && wq_arr_props->under_unset) {
		dev_dbg_ratelimited(hdev->dev,
				    "Retry to set %s WQ array as it is under unset, port %d\n",
				    type_str, port);
		rc = -EAGAIN;
		goto out;
	}

	if (wq_arr_props->enable) {
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

	if (wq_arr_props->is_coll) {
		num_of_wq_entries = coll_props->num_of_coll_wq_entries;
		num_of_wqs = coll_props->num_of_coll_wqs;

		if (!hl_cn_is_scale_out_coll_type(wq_arr_props->coll_wq_type) &&
		    in->num_of_wqs > NIC_MAX_NON_SCALE_OUT_COLL_CONNS) {
			dev_dbg(hdev->dev,
				"Too many WQs (%u) for non scale-out collective WQ - should be max %u, port %d\n",
				in->num_of_wqs, NIC_MAX_NON_SCALE_OUT_COLL_CONNS, port);
			rc = -EINVAL;
			goto out;
		}
	} else {
		num_of_wq_entries = cn_port->num_of_wq_entries;
		num_of_wqs = cn_port->num_of_wqs;
	}

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

	if (wq_arr_props->is_coll) {
		/* num_of_coll_wq_entries and num_of_coll_wqs are global hence will be set for the
		 * first requested WQ array.
		 */
		if (atomic_read(&coll_props->num_of_coll_wq_arrays) == 0) {
			coll_props->num_of_coll_wq_entries = in->num_of_wq_entries;
			coll_props->num_of_coll_wqs = in->num_of_wqs;
		}

		atomic_inc(&coll_props->num_of_coll_wq_arrays);
	} else {
		cn_port->num_of_wq_entries = in->num_of_wq_entries;
		cn_port->num_of_wqs = in->num_of_wqs;
	}

	wq_arr_props->enable = true;

out:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int __user_wq_arr_unset(struct hl_cn_ctx *ctx, struct hl_cn_port *cn_port, u32 type)
{
	struct hl_cn_coll_properties *coll_props = NULL;
	struct hl_cn_wq_array_properties *wq_arr_props;
	struct hl_cn_device *hdev;
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

	if (wq_arr_props->is_coll)
		coll_props = &hdev->coll_props[wq_arr_props->coll_wq_type];

	wq_arr_props->enable = false;
	wq_arr_props->under_unset = false;

	if (!cn_port->wq_arr_props[HL_CNI_USER_WQ_SEND].enable &&
	    !cn_port->wq_arr_props[HL_CNI_USER_WQ_RECV].enable) {
		cn_port->num_of_wq_entries = 0;
		cn_port->num_of_wqs = 0;
	}

	if (wq_arr_props->is_coll && atomic_dec_and_test(&coll_props->num_of_coll_wq_arrays)) {
		coll_props->num_of_coll_wq_entries = 0;
		coll_props->num_of_coll_wqs = 0;
	}

	return rc;
}

static int user_wq_arr_unset(struct hl_cn_device *hdev, struct hl_cni_user_wq_arr_unset_in *in,
			     struct hl_cn_ctx *ctx)
{
	struct hl_cn_wq_array_properties *wq_arr_props;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_properties *cn_props;
	struct hl_cn_port *cn_port;
	u32 port, type;
	char *type_str;
	int rc;

	if (!in) {
		dev_dbg(hdev->dev, "missing parameters, can't unset user WQ\n");
		return -EINVAL;
	}

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
	rc = hl_cn_ioctl_port_check(hdev, port, NIC_PORT_CHECK_ENABLE | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];

	wq_arr_props = &cn_port->wq_arr_props[type];
	type_str = wq_arr_props->type_str;

	port_funcs->cfg_lock(cn_port);

	if (!wq_arr_props->enable) {
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
	if (wq_arr_props->is_coll) {
		atomic_t *num_of_allocated_coll_qps =
					hl_cn_is_scale_out_coll_type(wq_arr_props->coll_wq_type) ?
					&cn_port->num_of_allocated_scale_out_coll_qps :
					&cn_port->num_of_allocated_coll_qps;

		if (atomic_read(num_of_allocated_coll_qps)) {
			wq_arr_props->under_unset = true;
			rc = 0;
			goto out;
		}
	} else {
		if (atomic_read(&cn_port->num_of_allocated_qps)) {
			wq_arr_props->under_unset = true;
			rc = 0;
			goto out;
		}
	}

	rc = __user_wq_arr_unset(ctx, cn_port, type);
out:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int alloc_user_cq_id(struct hl_cn_device *hdev, struct hl_cni_alloc_user_cq_id_in *in,
			    struct hl_cni_alloc_user_cq_id_out *out, struct hl_cn_ctx *ctx)
{
	struct hl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	struct hl_cn_properties *cn_props = &hdev->cn_props;
	u32 min_id, max_id, port, flags;
	struct hl_cn_user_cq *user_cq;
	struct hl_cn_port *cn_port;
	struct xa_limit id_limit;
	int id, rc;

	if (!in || !out) {
		dev_dbg(hdev->dev, "Missing parameters to allocate a user CQ\n");
		return -EINVAL;
	}

	if (in->pad) {
		dev_dbg(hdev->dev, "Padding bytes must be 0\n");
		return -EINVAL;
	}

	port = in->port;
	flags = NIC_PORT_PRINT_ON_ERR;

	if (!cn_props->force_cq)
		flags |= NIC_PORT_CHECK_OPEN;

	rc = hl_cn_ioctl_port_check(hdev, port, flags);
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

static bool validate_cq_id_range(struct hl_cn_port *cn_port, u32 cq_id)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_asic_port_funcs *port_funcs;
	u32 min_id, max_id;

	port_funcs = hdev->asic_funcs->port_funcs;

	port_funcs->get_cq_id_range(cn_port, &min_id, &max_id);

	return (cq_id >= min_id) && (cq_id <= max_id);
}

static int __user_cq_set(struct hl_cn_device *hdev, struct hl_cni_user_cq_set_in_params *in,
			 struct hl_cni_user_cq_set_out_params *out)
{
	struct hl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	struct hl_cn_properties *cn_props = &hdev->cn_props;
	struct hl_cn_user_cq *user_cq;
	struct hl_cn_port *cn_port;
	u32 port, flags, id;
	int rc;

	if (!in || !out) {
		dev_dbg(hdev->dev, "missing parameters, can't set user CQ ID\n");
		return -EINVAL;
	}

	id = in->id;
	port = in->port;

	flags = NIC_PORT_PRINT_ON_ERR;

	if (!cn_props->force_cq)
		flags |= NIC_PORT_CHECK_OPEN;

	rc = hl_cn_ioctl_port_check(hdev, port, flags);
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

/* used for backward compatibility, shouldn't be used by new ASICs */
static int user_cq_set(struct hl_cn_device *hdev, struct hl_cni_user_cq_set_in *in,
		       struct hl_cn_ctx *ctx)
{
	struct hl_cni_alloc_user_cq_id_out alloc_out = {};
	struct hl_cni_user_cq_set_out_params set_out = {};
	struct hl_cni_alloc_user_cq_id_in alloc_in = {};
	struct hl_cni_user_cq_set_in_params set_in = {};
	u32 port;
	int rc;

	if (!in) {
		dev_dbg(hdev->dev, "missing parameters, can't set user CQ\n");
		return -EINVAL;
	}

	port = in->port;

	/* Legacy user CQ API had no allocation stage prior to the actual setting. Hence need to
	 * call it manually.
	 */
	alloc_in.port = port;
	rc = alloc_user_cq_id(hdev, &alloc_in, &alloc_out, ctx);
	if (rc) {
		dev_dbg(hdev->dev, "failed to allocate user CQ with ID 0, port %d\n", port);
		return -EINVAL;
	}

	/* Legacy user CQ has a single user CQ (ID 0) per port */
	if (alloc_out.id)
		dev_crit(hdev->dev, "user CQ with a non zero ID was allocated (%d), port %d\n",
			 alloc_out.id, port);

	set_in.addr = in->addr;
	set_in.port = port;
	set_in.num_of_cqes = in->num_of_cqes;
	/* This function is used for Gaudi only which supports a single CQ per port */
	set_in.id = 0;

	return __user_cq_set(hdev, &set_in, &set_out);
}

static int user_cq_id_set(struct hl_cn_device *hdev, struct hl_cni_user_cq_id_set_in *in,
			  struct hl_cni_user_cq_id_set_out *out)
{
	struct hl_cni_user_cq_set_out_params out2 = {};
	struct hl_cni_user_cq_set_in_params in2 = {};
	int rc;

	if (!in || !out) {
		dev_dbg(hdev->dev, "missing parameters, can't set user CQ ID\n");
		return -EINVAL;
	}

	if (in->pad) {
		dev_dbg(hdev->dev, "Padding bytes must be 0\n");
		return -EINVAL;
	}

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

static int user_cq_unset_locked(struct hl_cn_user_cq *user_cq, bool warn_if_alive)
{
	struct hl_cn_port *cn_port = user_cq->cn_port;
	u32 port = cn_port->port, id = user_cq->id;
	struct hl_cn_device *hdev = cn_port->hdev;
	struct hl_cn_asic_port_funcs *port_funcs;
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
	ret = hl_cn_user_cq_put(user_cq);

	if (warn_if_alive && ret != 1)
		dev_warn(hdev->dev, "user CQ %d was not destroyed, port %d\n", id, port);

	return rc;
}

static int __user_cq_unset(struct hl_cn_device *hdev, struct hl_cni_user_cq_unset_in_params *in)
{
	struct hl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	struct hl_cn_properties *cn_props = &hdev->cn_props;
	struct hl_cn_user_cq *user_cq;
	struct hl_cn_port *cn_port;
	u32 port, flags, id;
	int rc;

	if (!in) {
		dev_dbg(hdev->dev, "missing parameters, can't unset user CQ\n");
		return -EINVAL;
	}

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

	rc = hl_cn_ioctl_port_check(hdev, port, flags);
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

/* used for backward compatibility, shouldn't be used by new ASICs */
static int user_cq_unset(struct hl_cn_device *hdev, struct hl_cni_user_cq_unset_in *in)
{
	struct hl_cni_user_cq_unset_in_params in2 = {};

	if (!in) {
		dev_dbg(hdev->dev, "missing parameters, can't unset user CQ\n");
		return -EINVAL;
	}

	if (in->pad) {
		dev_dbg(hdev->dev, "Padding bytes must be 0\n");
		return -EINVAL;
	}

	in2.port = in->port;
	/* This function is used for Gaudi only which supports a single CQ per port */
	in2.id = 0;

	return __user_cq_unset(hdev, &in2);
}

static int user_cq_id_unset(struct hl_cn_device *hdev, struct hl_cni_user_cq_id_unset_in *in)
{
	struct hl_cni_user_cq_unset_in_params in2 = {};

	if (!in) {
		dev_dbg(hdev->dev, "missing parameters, can't set user CQ ID\n");
		return -EINVAL;
	}

	in2.port = in->port;
	in2.id = in->id;

	return __user_cq_unset(hdev, &in2);
}

static void user_cqs_destroy(struct hl_cn_ctx *ctx)
{
	struct hl_cn_device *hdev = ctx->hdev;
	struct hl_cn_properties *cn_props;
	struct hl_cn_user_cq *user_cq;
	struct hl_cn_port *cn_port;
	unsigned long id;
	int i;

	cn_props = &hdev->cn_props;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!cn_props->force_cq && !(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		xa_for_each(&cn_port->cq_ids, id, user_cq) {
			if (user_cq->state == USER_CQ_STATE_ALLOC)
				hl_cn_user_cq_put(user_cq);
			else if (user_cq->state == USER_CQ_STATE_SET)
				user_cq_unset_locked(user_cq, true);
		}
	}
}

/* used for backward compatibility, shouldn't be used by new ASICs */
static int user_cq_update_ci(struct hl_cn_device *hdev, struct hl_cni_user_cq_update_ci_in *in)
{
	struct hl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	struct hl_cn_properties *cn_props = &hdev->cn_props;
	struct hl_cn_user_cq *user_cq;
	struct hl_cn_port *cn_port;
	u32 port, flags;
	int rc;

	if (!in) {
		dev_dbg(hdev->dev, "missing parameters, can't set user CQ\n");
		return -EINVAL;
	}

	flags = NIC_PORT_PRINT_ON_ERR;
	if (!cn_props->force_cq)
		flags |= NIC_PORT_CHECK_OPEN;

	port = in->port;
	rc = hl_cn_ioctl_port_check(hdev, port, flags);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];

	/* This lock prevents concurrent CI updates for different ports which is undesirable, but we
	 * need to protect here from user_cq_unset so this lock is essential. But the penalty is not
	 * so big as the CI updates should happen only once in half cycle and not after each packet.
	 */
	port_funcs->cfg_lock(cn_port);

	/* This function is used for Gaudi only which supports a single CQ per port */
	user_cq = xa_load(&cn_port->cq_ids, 0);
	if (!user_cq) {
		dev_dbg(hdev->dev, "user CQ 0 wasn't allocated, can't update CI, port %d\n",
			port);
		rc = -EINVAL;
		goto out;
	}

	if (user_cq->state != USER_CQ_STATE_SET) {
		dev_dbg(hdev->dev, "user CQ 0 is disabled, can't update CI, port %d\n", port);
		rc = -EINVAL;
		goto out;
	}

	port_funcs->user_cq_update_ci(cn_port, in->ci);

out:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int user_set_app_params(struct hl_cn_device *hdev,
			       struct hl_cni_set_user_app_params_in *in, struct hl_cn_ctx *ctx)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_port *cn_port;
	bool modify_wqe_checkers;
	u32 port;
	int rc;

	port_funcs = asic_funcs->port_funcs;

	if (!in) {
		dev_dbg(hdev->dev, "Missing [in] parameter for set_app_param\n");
		return -EINVAL;
	}

	if (in->pad1 || in->pad2) {
		dev_dbg(hdev->dev, "Padding bytes must be 0\n");
		return -EINVAL;
	}

	port = in->port;

	rc = hl_cn_ioctl_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
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

static int user_get_app_params(struct hl_cn_device *hdev, struct hl_cni_get_user_app_params_in *in,
			       struct hl_cni_get_user_app_params_out *out)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_port *cn_port;
	int rc, i;
	u32 port;

	port_funcs = asic_funcs->port_funcs;

	if (!in || !out) {
		dev_dbg(hdev->dev, "Missing [in|out] parameters for get_app_param\n");
		return -EINVAL;
	}

	for (i = 0; i < sizeof(in->pad); i++)
		if (in->pad[i]) {
			dev_dbg(hdev->dev, "Padding bytes must be 0\n");
			return -EINVAL;
		}

	port = in->port;

	rc = hl_cn_ioctl_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];

	port_funcs->cfg_lock(cn_port);
	asic_funcs->user_get_app_params(hdev, in, out);
	port_funcs->cfg_unlock(cn_port);

	return 0;
}

static int eq_poll(struct hl_cn_device *hdev, struct hl_cn_ctx *ctx,
		   struct hl_cni_eq_poll_in *in, struct hl_cni_eq_poll_out *out)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	struct hl_cn_port *cn_port;
	u32 port;
	int rc;

	if (!in || !out) {
		dev_dbg_ratelimited(hdev->dev, "Missing parameters to poll on EQ\n");
		return -EINVAL;
	}

	if (in->pad) {
		dev_dbg(hdev->dev, "Padding bytes must be 0\n");
		return -EINVAL;
	}

	port = in->port;
	rc = hl_cn_ioctl_port_check(hdev, port, NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];
	rc = asic_funcs->port_funcs->eq_poll(cn_port, ctx->asid, out);
	switch (rc) {
	case 0:
		out->status = HL_CNI_EQ_POLL_STATUS_SUCCESS;
		break;
	case -EOPNOTSUPP:
		out->status = HL_CNI_EQ_POLL_STATUS_ERR_UNSUPPORTED_OP;
		break;
	case -EINVAL:
		out->status = HL_CNI_EQ_POLL_STATUS_ERR_NO_SUCH_PORT;
		break;
	case -ENXIO:
		out->status = HL_CNI_EQ_POLL_STATUS_ERR_PORT_DISABLED;
		break;
	case -ENODATA:
		out->status = HL_CNI_EQ_POLL_STATUS_EQ_EMPTY;
		break;
	case -ESRCH:
		out->status = HL_CNI_EQ_POLL_STATUS_ERR_NO_SUCH_EQ;
		break;
	default:
		out->status = HL_CNI_EQ_POLL_STATUS_ERR_UNDEF;
		break;
	}

	return 0;
}

static void get_user_db_fifo_id_range(struct hl_cn_port *cn_port, u32 *min_id, u32 *max_id,
				      u32 id_hint)
{
	struct hl_cn_asic_port_funcs *port_funcs;

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

static int alloc_user_db_fifo(struct hl_cn_device *hdev, struct hl_cn_ctx *ctx,
			      struct hl_cni_alloc_user_db_fifo_in *in,
			      struct hl_cni_alloc_user_db_fifo_out *out)
{
	struct hl_cn_db_fifo_xarray_pdata *xa_pdata;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_port *cn_port;
	struct xa_limit id_limit;
	u32 min_id, max_id;
	int rc, id;
	u32 port;

	if (!in || !out) {
		dev_dbg(hdev->dev, "Missing in/out param for allocating db fifo ID\n");
		return -EINVAL;
	}

	port = in->port;
	rc = hl_cn_ioctl_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
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
	port_funcs->cfg_unlock(cn_port);

	if (rc) {
		dev_dbg_ratelimited(hdev->dev, "DB FIFO ID allocation failed, port %d\n", port);
		goto free_xa_pdata;
	}

	out->id = id;

	return 0;

cfg_unlock:
	port_funcs->cfg_unlock(cn_port);
free_xa_pdata:
	kfree(xa_pdata);
	return rc;
}

static int validate_db_fifo_id_range(struct hl_cn_port *cn_port, u32 db_fifo_id)
{
	struct hl_cn_asic_funcs *asic_funcs;
	struct hl_cn_device *hdev;
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

static int validate_db_fifo_mode(struct hl_cn_port *cn_port, u8 fifo_mode)
{
	struct hl_cn_asic_funcs *asic_funcs;
	struct hl_cn_device *hdev;
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

static int validate_db_fifo_ioctl(struct hl_cn_port *cn_port, u32 db_fifo_id)
{
	return validate_db_fifo_id_range(cn_port, db_fifo_id);
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
	 * Note: Not all DB fifo modes need CI memory buffer. e.g. Collective operations
	 * track CI via sync objects.
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

static int user_db_fifo_set(struct hl_cn_device *hdev, struct hl_cn_ctx *ctx,
			    struct hl_cni_user_db_fifo_set_in *in,
			    struct hl_cni_user_db_fifo_set_out *out)
{
	u64 umr_block_addr, umr_mmap_handle, ci_mmap_handle = 0, ci_device_handle;
	struct hl_cn_db_fifo_xarray_pdata *xa_pdata;
	struct hl_cn_asic_port_funcs *port_funcs;
	u32 umr_db_offset, port, id, sob_payload;
	struct hl_cn_mem_data mem_data = {};
	struct hl_cn_port *cn_port;
	bool is_coll_ops;
	int rc, i;

	if (!in || !out) {
		dev_dbg(hdev->dev, "Missing in/out param for DB FIFO set\n");
		return -EINVAL;
	}

	for (i = 0; i < sizeof(in->pad); i++)
		if (in->pad[i]) {
			dev_dbg(hdev->dev, "Padding bytes must be 0\n");
			return -EINVAL;
		}

	port = in->port;
	rc = hl_cn_ioctl_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
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

	is_coll_ops = (in->mode == HL_CNI_DB_FIFO_TYPE_COLL_OPS_SHORT) ||
		      (in->mode == HL_CNI_DB_FIFO_TYPE_COLL_OPS_LONG) ||
		      (in->mode == HL_CNI_DB_FIFO_TYPE_COLL_DIR_OPS_SHORT) ||
		      (in->mode == HL_CNI_DB_FIFO_TYPE_COLL_DIR_OPS_LONG);
	xa_pdata->fifo_mode = in->mode;

	/* User may call db_fifo_set multiple times post db_fifo_alloc. So, before doing any
	 * further register changes, make sure to unset the previous settings for this id
	 */
	if (xa_pdata->state == DB_FIFO_STATE_SET) {
		rc = user_db_fifo_unset_and_free(cn_port, id, xa_pdata);
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
	rc = hl_cn_get_hw_block_handle(hdev, umr_block_addr, &umr_mmap_handle);
	if (rc) {
		dev_dbg_ratelimited(hdev->dev,
				    "Failed to get UMR mmap handle of DB FIFO %d, port %d\n", id,
				    port);
		goto free_db_fifo;
	}

	if (is_coll_ops && in->num_sobs) {
		xa_pdata->base_sob_addr = in->base_sob_addr;
		xa_pdata->num_sobs = in->num_sobs;

		/* SOB operation increment with value 1. */
		sob_payload = FIELD_PREP(NIC_SOB_INC_MASK, 1) | FIELD_PREP(NIC_SOB_VAL_MASK, 1);

		/* Track DB fifo CI using sync objects.
		 * Lower 32 bits: SOB offset from LBW base.
		 * Upper 32 bits: LBW SOB payload.
		 */
		ci_device_handle = (((u64)sob_payload) << 32) | xa_pdata->base_sob_addr;
	} else {
		/* Allocate a consumer-index(CI) buffer in host kernel.
		 * HW updates CI when it pops a db fifo. User mmaps CI
		 * buffer and may poll to read current CI.
		 *
		 * Allocate page size, else we risk exposing kernel data
		 * to userspace inadvertently.
		 */
		mem_data.mem_id = HL_CN_DRV_MEM_HOST_DMA_COHERENT;
		mem_data.size = PAGE_SIZE;
		rc = hl_cn_mem_alloc(hdev, &mem_data);
		if (rc) {
			dev_dbg_ratelimited(hdev->dev,
					    "DB FIFO id %d, CI buffer allocation failed, port %d\n",
					    id, port);
			goto free_db_fifo;
		}

		ci_mmap_handle = mem_data.handle;
		ci_device_handle = mem_data.addr;
	}

	xa_pdata->dir_dup_ports_mask = in->dir_dup_ports_mask;

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
		hl_cn_mem_destroy(hdev, ci_mmap_handle);
free_db_fifo:
	port_funcs->db_fifo_free(cn_port, xa_pdata->db_pool_addr, xa_pdata->fifo_size);
cfg_unlock:
	port_funcs->cfg_unlock(cn_port);

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

static int user_db_fifo_unset(struct hl_cn_device *hdev, struct hl_cni_user_db_fifo_unset_in *in)
{
	struct hl_cn_db_fifo_xarray_pdata *xa_pdata;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_port *cn_port;
	int rc;
	u32 id;

	if (!in) {
		dev_dbg(hdev->dev, "Missing in param for db fifo unset\n");
		return -EINVAL;
	}

	rc = hl_cn_ioctl_port_check(hdev, in->port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
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

	rc = __user_db_fifo_unset(cn_port, id, xa_pdata);
out:
	port_funcs->cfg_unlock(cn_port);

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

static int user_encap_alloc(struct hl_cn_device *hdev, struct hl_cni_user_encap_alloc_in *in,
			    struct hl_cni_user_encap_alloc_out *out)
{
	struct hl_cn_encap_xarray_pdata *xa_pdata;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_port *cn_port;
	struct xa_limit id_limit;
	u32 min_id, max_id;
	int rc, id;
	u32 port;

	if (!in || !out) {
		dev_dbg_ratelimited(hdev->dev,
				    "Missing in/out params for allocating encapsulation ID\n");
		return -EINVAL;
	}

	if (in->pad) {
		dev_dbg(hdev->dev, "Padding bytes must be 0\n");
		return -EINVAL;
	}

	port = in->port;
	rc = hl_cn_ioctl_port_check(hdev, port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
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

static int validate_encap_id_range(struct hl_cn_port *cn_port, u32 encap_id)
{
	struct hl_cn_asic_funcs *asic_funcs;
	struct hl_cn_device *hdev;
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

static int validate_encap_ioctl(struct hl_cn_port *cn_port, u32 encap_id)
{
	return validate_encap_id_range(cn_port, encap_id);
}

static bool is_encap_supported(struct hl_cn_device *hdev, struct hl_cni_user_encap_set_in *in)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	return asic_funcs->is_encap_supported(hdev, in);
}

static int user_encap_set(struct hl_cn_device *hdev, struct hl_cni_user_encap_set_in *in)
{
	struct hl_cn_encap_xarray_pdata *xa_pdata;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_port *cn_port;
	void *encap_header = NULL;
	u32 encap_type_data = 0;
	int rc, i;
	u32 id;

	if (!in) {
		dev_dbg_ratelimited(hdev->dev, "Missing in param for encapsulation set\n");
		return -EINVAL;
	}

	for (i = 0; i < sizeof(in->pad); i++)
		if (in->pad[i]) {
			dev_dbg(hdev->dev, "Padding bytes must be 0\n");
			return -EINVAL;
		}

	/* Check if the user requeset for encap set is supported */
	if (!is_encap_supported(hdev, in))
		return -EOPNOTSUPP;

	rc = hl_cn_ioctl_port_check(hdev, in->port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[in->port];
	port_funcs = hdev->asic_funcs->port_funcs;
	id = in->id;

	rc = validate_encap_ioctl(cn_port, id);
	if (rc)
		return rc;

	switch (in->encap_type) {
	case HL_CNI_ENCAP_OVER_IPV4:
		encap_type_data = in->ip_proto;
		break;
	case HL_CNI_ENCAP_OVER_UDP:
		encap_type_data = in->udp_dst_port;
		break;
	case HL_CNI_ENCAP_NONE:
		/* No encapsulation/tunneling mode. Just set
		 * source IPv4 address and UDP protocol.
		 */
		encap_type_data = HL_CN_IPV4_PROTOCOL_UDP;
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

	if (xa_pdata->encap_type != HL_CNI_ENCAP_NONE)
		kfree(xa_pdata->encap_header);

	if (in->encap_type != HL_CNI_ENCAP_NONE) {
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
	if (in->encap_type != HL_CNI_ENCAP_NONE)
		kfree(encap_header);
cfg_unlock:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int user_encap_unset(struct hl_cn_device *hdev, struct hl_cni_user_encap_unset_in *in)
{
	struct hl_cn_encap_xarray_pdata *xa_pdata;
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_port *cn_port;
	int rc;
	u32 id;

	if (!in) {
		dev_dbg_ratelimited(hdev->dev, "Missing in param for encapsulation unset\n");
		return -EINVAL;
	}

	rc = hl_cn_ioctl_port_check(hdev, in->port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
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

		if (xa_pdata->encap_type != HL_CNI_ENCAP_NONE)
			kfree(xa_pdata->encap_header);
	}

	xa_erase(&cn_port->encap_ids, id);
	kfree(xa_pdata);

out:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int hl_cn_get_port_link_state(struct hl_aux_dev *aux_dev, u32 port, bool *up)
{
	struct hl_cn_device *hdev = aux_dev->priv;
	int rc;

	rc = hl_cn_ioctl_port_check(hdev, port, NIC_PORT_CHECK_ENABLE | NIC_PORT_PRINT_ON_ERR);
	if (rc)
		return rc;

	*up = hdev->cn_ports[port].pcs_link;

	return 0;
}

static int hl_cn_get_port_statistics(struct hl_aux_dev *aux_dev, u32 port,
				     struct hl_cn_port_statistics *out)
{
	struct hl_cn_device *hdev = aux_dev->priv;
	void __user *usr_str_buf, *usr_val_buf;
	struct hl_cn_port *cn_port;
	char *drv_str_buf;
	u64 *drv_val_buf;
	u32 num_of_stat;
	int rc;

	if (!out) {
		dev_dbg(hdev->dev, "Missing parameters to get CN statistics\n");
		return -EINVAL;
	}

	usr_str_buf = (void __user *)(uintptr_t)out->str_buf_ptr;
	usr_val_buf = (void __user *)(uintptr_t)out->val_buf_ptr;

	if (!usr_str_buf || !usr_val_buf) {
		dev_dbg(hdev->dev, "Can't get CN statistics, out buffer is NULL\n");
		return -EINVAL;
	}

	rc = hl_cn_ioctl_port_check(hdev, port, NIC_PORT_CHECK_ALL);
	if (rc)
		return rc;

	cn_port = &hdev->cn_ports[port];

	num_of_stat = __hl_cn_get_cnts_num(cn_port);

	drv_str_buf = kcalloc(num_of_stat, HL_CNI_STAT_STR_LEN, GFP_KERNEL);
	if (!drv_str_buf)
		return -ENOMEM;

	drv_val_buf = kcalloc(num_of_stat, sizeof(u64), GFP_KERNEL);
	if (!drv_val_buf) {
		rc = -ENOMEM;
		goto out;
	}

	__hl_cn_get_cnts_names(cn_port, drv_str_buf, false);
	__hl_cn_get_cnts_values(cn_port, drv_val_buf);

	rc = copy_to_user(usr_str_buf, drv_str_buf, HL_CNI_STAT_STR_LEN * num_of_stat);
	if (rc) {
		dev_err(hdev->dev, "Can't get CN statistics, failed to copy strings to user\n");
		rc = -EFAULT;
		goto out;
	}

	rc = copy_to_user(usr_val_buf, drv_val_buf, sizeof(u64) * num_of_stat);
	if (rc) {
		dev_err(hdev->dev, "Can't get CN statistics, failed to copy values to user\n");
		rc = -EFAULT;
		goto out;
	}

	out->num_of_stat = num_of_stat;

out:
	kfree(drv_val_buf);
	kfree(drv_str_buf);

	return rc;
}

static int user_ccq_set(struct hl_cn_device *hdev, struct hl_cni_user_ccq_set_in *in,
			struct hl_cni_user_ccq_set_out *out, struct hl_cn_ctx *ctx)
{
	struct hl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	u64 ccq_mmap_handle, ccq_device_addr, pi_mmap_handle, pi_device_addr;
	struct hl_cn_mem_data mem_data = {};
	struct hl_cn_port *cn_port;
	u32 port, ccqn;
	int rc;

	if (!out || !in) {
		dev_dbg(hdev->dev, "Missing parameters to CCQ set\n");
		return -EINVAL;
	}

	rc = hl_cn_ioctl_port_check(hdev, in->port, NIC_PORT_CHECK_OPEN | NIC_PORT_PRINT_ON_ERR);
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
	mem_data.mem_id = HL_CN_DRV_MEM_HOST_DMA_COHERENT;
	mem_data.size = in->num_of_entries * CC_CQE_SIZE;
	rc = hl_cn_mem_alloc(hdev, &mem_data);
	if (rc) {
		dev_err(hdev->dev, "CCQ memory buffer allocation failed, port %d\n", port);
		goto cfg_unlock;
	}

	ccq_mmap_handle = mem_data.handle;
	ccq_device_addr = mem_data.addr;

	/* Allocate a producer-index (PI) buffer in host kernel */
	memset(&mem_data, 0, sizeof(mem_data));
	mem_data.mem_id = HL_CN_DRV_MEM_HOST_DMA_COHERENT;
	mem_data.size = PAGE_SIZE;
	rc = hl_cn_mem_alloc(hdev, &mem_data);
	if (rc) {
		dev_err(hdev->dev, "CCQ PI buffer allocation failed, port %d\n", port);
		goto free_ccq;
	}

	pi_mmap_handle = mem_data.handle;
	pi_device_addr = mem_data.addr;

	port_funcs->user_ccq_set(cn_port, ccq_device_addr, pi_device_addr, in->num_of_entries,
				 &ccqn);

	rc = hl_cn_eq_dispatcher_register_ccq(cn_port, ctx->asid, ccqn);
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
	hl_cn_mem_destroy(hdev, pi_mmap_handle);
free_ccq:
	hl_cn_mem_destroy(hdev, ccq_mmap_handle);
cfg_unlock:
	port_funcs->cfg_unlock(cn_port);

	return rc;
}

static int __user_ccq_unset(struct hl_cn_device *hdev, struct hl_cn_ctx *ctx, u32 port)
{
	struct hl_cn_asic_port_funcs *port_funcs;
	struct hl_cn_port *cn_port;
	bool has_errors = false;
	u32 ccqn;
	int rc;

	cn_port = &hdev->cn_ports[port];

	port_funcs = hdev->asic_funcs->port_funcs;
	port_funcs->user_ccq_unset(cn_port, &ccqn);

	rc = hl_cn_mem_destroy(hdev, cn_port->ccq_pi_handle);
	if (rc) {
		dev_err(hdev->dev, "Failed to free CCQ PI memory, port %d\n", port);
		has_errors = true;
	}

	rc = hl_cn_mem_destroy(hdev, cn_port->ccq_handle);
	if (rc) {
		dev_err(hdev->dev, "Failed to free CCQ memory, port %d\n", port);
		has_errors = true;
	}

	rc = hl_cn_eq_dispatcher_unregister_ccq(cn_port, ctx->asid, ccqn);
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

static int user_ccq_unset(struct hl_cn_device *hdev, struct hl_cni_user_ccq_unset_in *in,
			  struct hl_cn_ctx *ctx)
{
	struct hl_cn_asic_port_funcs *port_funcs = hdev->asic_funcs->port_funcs;
	struct hl_cn_port *cn_port;
	u32 port;
	int rc;

	if (!in) {
		dev_dbg(hdev->dev, "Missing parameters to CCQ unset\n");
		return -EINVAL;
	}

	if (in->pad) {
		dev_dbg(hdev->dev, "Padding bytes must be 0\n");
		return -EINVAL;
	}

	port = in->port;

	rc = hl_cn_ioctl_port_check(hdev, port, NIC_PORT_CHECK_ENABLE | NIC_PORT_PRINT_ON_ERR);
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

static int dump_qp(struct hl_cn_device *hdev, struct hl_cni_dump_qp_in *in)
{
	struct hl_cn_qp_info *qp_info;
	u32 buf_size;
	char *buf;
	int i, rc;

	if (!in) {
		dev_dbg(hdev->dev, "Missing parameters for dumping a QP\n");
		return -EINVAL;
	}

	for (i = 0; i < sizeof(in->pad); i++)
		if (in->pad[i]) {
			dev_dbg(hdev->dev, "Padding bytes must be 0\n");
			return -EINVAL;
		}

	buf_size = in->user_buf_size;

	if (!buf_size || buf_size > NIC_DUMP_QP_SZ) {
		dev_err(hdev->dev, "Invalid buffer size %u\n", buf_size);
		return -EINVAL;
	}

	buf = kzalloc(buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	qp_info = &hdev->qp_info;

	qp_info->port = in->port;
	qp_info->qpn = in->qpn;
	qp_info->req = in->req;
	qp_info->full_print = true;
	qp_info->force_read = true;
	qp_info->exts_print = true;

	rc = hdev->asic_funcs->qp_read(hdev, buf, buf_size);
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

static int __hl_cn_control(struct hl_cn_device *hdev, u32 op, void *input, void *output,
			   struct hl_cn_ctx *ctx)
{
	int rc;

	if (!(hdev->ctrl_op_mask & BIT(op))) {
		dev_dbg(hdev->dev, "CN control request %d is not supported on this device\n", op);
		return -EOPNOTSUPP;
	}

	if ((op & NIC_CTX_ACTIVE_OPS) && ctx->killed) {
		dev_dbg(hdev->dev, "CN control request %d demands an active context, ASID %d\n", op,
			ctx->asid);
		return -EACCES;
	}

	switch (op) {
	case HL_CNI_OP_ALLOC_CONN:
		rc = alloc_qp(hdev, ctx, input, output);
		break;
	case HL_CNI_OP_SET_REQ_CONN_CTX:
		rc = set_req_qp_ctx(hdev, input, output);
		break;
	case HL_CNI_OP_SET_RES_CONN_CTX:
		rc = set_res_qp_ctx(hdev, input);
		break;
	case HL_CNI_OP_DESTROY_CONN:
		rc = destroy_qp(hdev, input);
		break;
	case HL_CNI_OP_USER_WQ_SET:
		rc = user_wq_arr_set(hdev, input, output, ctx);
		break;
	case HL_CNI_OP_USER_WQ_UNSET:
		rc = user_wq_arr_unset(hdev, input, ctx);
		break;
	case HL_CNI_OP_USER_CQ_SET:
		rc = user_cq_set(hdev, input, ctx);
		break;
	case HL_CNI_OP_USER_CQ_UNSET:
		rc = user_cq_unset(hdev, input);
		break;
	case HL_CNI_OP_USER_CQ_UPDATE_CI:
		rc = user_cq_update_ci(hdev, input);
		break;
	case HL_CNI_OP_ALLOC_USER_CQ_ID:
		rc = alloc_user_cq_id(hdev, input, output, ctx);
		break;
	case HL_CNI_OP_SET_USER_APP_PARAMS:
		rc = user_set_app_params(hdev, input, ctx);
		break;
	case HL_CNI_OP_GET_USER_APP_PARAMS:
		rc = user_get_app_params(hdev, input, output);
		break;
	case HL_CNI_OP_EQ_POLL:
		rc = eq_poll(hdev, ctx, input, output);
		break;
	case HL_CNI_OP_ALLOC_USER_DB_FIFO:
		rc = alloc_user_db_fifo(hdev, ctx, input, output);
		break;
	case HL_CNI_OP_USER_DB_FIFO_SET:
		rc = user_db_fifo_set(hdev, ctx, input, output);
		break;
	case HL_CNI_OP_USER_DB_FIFO_UNSET:
		rc = user_db_fifo_unset(hdev, input);
		break;
	case HL_CNI_OP_USER_ENCAP_ALLOC:
		rc = user_encap_alloc(hdev, input, output);
		break;
	case HL_CNI_OP_USER_ENCAP_SET:
		rc = user_encap_set(hdev, input);
		break;
	case HL_CNI_OP_USER_ENCAP_UNSET:
		rc = user_encap_unset(hdev, input);
		break;
	case HL_CNI_OP_USER_CCQ_SET:
		rc = user_ccq_set(hdev, input, output, ctx);
		break;
	case HL_CNI_OP_USER_CCQ_UNSET:
		rc = user_ccq_unset(hdev, input, ctx);
		break;
	case HL_CNI_OP_USER_CQ_ID_SET:
		rc = user_cq_id_set(hdev, input, output);
		break;
	case HL_CNI_OP_USER_CQ_ID_UNSET:
		rc = user_cq_id_unset(hdev, input);
		break;
	case HL_CNI_OP_ALLOC_COLL_CONN:
		rc = alloc_coll_qp(hdev, ctx, input, output);
		break;
	case HL_CNI_OP_DUMP_QP:
		rc = dump_qp(hdev, input);
		break;
	default:
		/* we shouldn't get here as we check the opcode mask before */
		dev_dbg(hdev->dev, "Invalid CN control request %d\n", op);
		return -EINVAL;
	}

	return rc;
}

static int hl_cn_ib_cmd_ctrl(struct hl_aux_dev *aux_dev, void *cn_ib_ctx, u32 op, void *input,
			     void *output)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(aux_dev);
	struct hl_cn_ctx *ctx = cn_ib_ctx;
	int rc;

	mutex_lock(&ctx->lock);

	do
		rc = __hl_cn_control(hdev, op, input, output, ctx);
	while (rc == -EAGAIN);

	mutex_unlock(&ctx->lock);

	return rc;
}

static int hl_cn_ib_mmap(struct hl_aux_dev *ib_aux_dev, void *cn_ib_ctx,
			 struct vm_area_struct *vma)
{
	struct hl_cn_device *hdev = HL_AUX2NIC(ib_aux_dev);

	return hdev->asic_funcs->user_mmap(hdev, cn_ib_ctx, vma);
}

static int hl_cn_cmd_control(struct hl_aux_dev *aux_dev, u32 op, void *input, void *output,
			     u32 asid)
{
	struct hl_cn_device *hdev = aux_dev->priv;
	struct hl_cn_ctx *ctx = hdev->ctx;
	int rc;

	do
		rc = __hl_cn_control(hdev, op, input, output, ctx);
	while (rc == -EAGAIN);

	return rc;
}

int hl_cn_ctx_init(struct hl_aux_dev *aux_dev, u32 asid)
{
	struct hl_cn_device *hdev = aux_dev->priv;
	struct hl_cn_ctx *ctx;
	int rc;

	if (hdev->ctx) {
		dev_err(hdev->dev,
			"user context already initialized, current ASID %d, requested ASID %d\n",
			hdev->ctx->asid, asid);
		return -EBUSY;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->hdev = hdev;
	ctx->asid = asid;
	ctx->user_asid = asid;

	rc = hdev->asic_funcs->ctx_init(ctx);
	if (rc) {
		dev_err(hdev->dev, "failed to init user context with ASID %d\n", asid);
		goto ctx_init_err;
	}

	mutex_init(&ctx->lock);
	hdev->ctx = ctx;

	return 0;

ctx_init_err:
	kfree(ctx);

	return rc;
}

static void ccqs_destroy(struct hl_cn_ctx *ctx)
{
	struct hl_cn_device *hdev = ctx->hdev;
	struct hl_cn_port *cn_port;
	int port;

	for (port = 0; port < hdev->cn_props.max_num_of_ports; port++) {
		if (!(hdev->ports_mask & BIT(port)))
			continue;

		cn_port = &hdev->cn_ports[port];
		if (cn_port->ccq_enable)
			__user_ccq_unset(hdev, ctx, port);
	}
}

static void set_app_params_clear(struct hl_cn_device *hdev)
{
	struct hl_cn_asic_funcs *asic_funcs;
	struct hl_cn_port *cn_port;
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

static void __hl_cn_ctx_fini(struct hl_cn_device *hdev, struct hl_cn_ctx *ctx)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	qps_destroy(hdev);
	user_cqs_destroy(ctx);
	wq_arrs_destroy(ctx);
	ccqs_destroy(ctx);
	asic_funcs->ctx_fini(ctx);
	encap_ids_destroy(hdev);
	set_app_params_clear(hdev);
}

void hl_cn_ctx_fini(struct hl_aux_dev *aux_dev, u32 asid)
{
	struct hl_cn_device *hdev = aux_dev->priv;
	struct hl_cn_ctx *ctx = hdev->ctx;

	__hl_cn_ctx_fini(hdev, ctx);
	hdev->ctx = NULL;
	mutex_destroy(&ctx->lock);
	kfree(ctx);
}

static void dispatch_fatal_ib_event(struct hl_cn_ctx *ctx)
{
	struct hl_aux_dev *aux_dev = &ctx->hdev->ib_aux_dev;
	struct hl_ib_aux_ops *aux_ops = aux_dev->aux_ops;

	if (aux_ops->dispatch_fatal_event)
		aux_ops->dispatch_fatal_event(aux_dev, ctx->asid);
}

static void hl_cn_ctx_kill(struct hl_aux_dev *aux_dev, void *cn_ctx)
{
	struct hl_cn_ctx *ctx = cn_ctx;
	bool should_destroy;

	mutex_lock(&ctx->lock);

	/* We should destroy a context here only if it was already deallocated. Otherwise, we should
	 * halt the QPs from accessing the killed VM and notify the user to close its IB context.
	 * Then the context will be destroyed as part of dealloc_ucontext().
	 */
	if (ctx->deallocated) {
		should_destroy = true;
	} else {
		qps_halt(ctx);
		dispatch_fatal_ib_event(ctx);
		ctx->killed = true;
		should_destroy = false;
	}

	mutex_unlock(&ctx->lock);

	if (should_destroy) {
		mutex_destroy(&ctx->lock);
		kfree(ctx);
	}
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
	wq_arr_props[HL_CNI_USER_WQ_SEND].is_coll = false;

	wq_arr_props[HL_CNI_USER_WQ_RECV].type_str = "recv";
	wq_arr_props[HL_CNI_USER_WQ_RECV].is_send = false;
	wq_arr_props[HL_CNI_USER_WQ_RECV].is_coll = false;

	wq_arr_props[HL_CNI_USER_COLL_WQ_SEND].type_str = "collective send";
	wq_arr_props[HL_CNI_USER_COLL_WQ_SEND].is_send = true;
	wq_arr_props[HL_CNI_USER_COLL_WQ_SEND].is_coll = true;
	wq_arr_props[HL_CNI_USER_COLL_WQ_SEND].coll_wq_type = HL_CN_COLL_CONN_TYPE_NON_SCALE_OUT;

	wq_arr_props[HL_CNI_USER_COLL_WQ_RECV].type_str = "collective recv";
	wq_arr_props[HL_CNI_USER_COLL_WQ_RECV].is_send = false;
	wq_arr_props[HL_CNI_USER_COLL_WQ_RECV].is_coll = true;
	wq_arr_props[HL_CNI_USER_COLL_WQ_RECV].coll_wq_type = HL_CN_COLL_CONN_TYPE_NON_SCALE_OUT;

	wq_arr_props[HL_CNI_USER_COLL_SCALE_OUT_WQ_SEND].type_str = "collective scale-out send";
	wq_arr_props[HL_CNI_USER_COLL_SCALE_OUT_WQ_SEND].is_send = true;
	wq_arr_props[HL_CNI_USER_COLL_SCALE_OUT_WQ_SEND].is_coll = true;
	wq_arr_props[HL_CNI_USER_COLL_SCALE_OUT_WQ_SEND].coll_wq_type =
						HL_CN_COLL_CONN_TYPE_SCALE_OUT;

	wq_arr_props[HL_CNI_USER_COLL_SCALE_OUT_WQ_RECV].type_str = "collective scale-out recv";
	wq_arr_props[HL_CNI_USER_COLL_SCALE_OUT_WQ_RECV].is_send = false;
	wq_arr_props[HL_CNI_USER_COLL_SCALE_OUT_WQ_RECV].is_coll = true;
	wq_arr_props[HL_CNI_USER_COLL_SCALE_OUT_WQ_RECV].coll_wq_type =
						HL_CN_COLL_CONN_TYPE_SCALE_OUT;
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

static void cn_coll_props_init(struct hl_cn_coll_properties *coll_props)
{
	xa_init_flags(&coll_props[HL_CN_COLL_CONN_TYPE_NON_SCALE_OUT].coll_qp_ids, XA_FLAGS_ALLOC);
	atomic_set(&coll_props[HL_CN_COLL_CONN_TYPE_NON_SCALE_OUT].num_of_coll_wq_arrays, 0);
	coll_props[HL_CN_COLL_CONN_TYPE_NON_SCALE_OUT].swq_type = HL_CNI_USER_COLL_WQ_SEND;
	coll_props[HL_CN_COLL_CONN_TYPE_NON_SCALE_OUT].rwq_type = HL_CNI_USER_COLL_WQ_RECV;

	xa_init_flags(&coll_props[HL_CN_COLL_CONN_TYPE_SCALE_OUT].coll_qp_ids, XA_FLAGS_ALLOC);
	atomic_set(&coll_props[HL_CN_COLL_CONN_TYPE_SCALE_OUT].num_of_coll_wq_arrays, 0);
	coll_props[HL_CN_COLL_CONN_TYPE_SCALE_OUT].swq_type = HL_CNI_USER_COLL_SCALE_OUT_WQ_SEND;
	coll_props[HL_CN_COLL_CONN_TYPE_SCALE_OUT].rwq_type = HL_CNI_USER_COLL_SCALE_OUT_WQ_RECV;
}

static void cn_coll_props_fini(struct hl_cn_coll_properties *coll_props)
{
	xa_destroy(&coll_props[HL_CN_COLL_CONN_TYPE_NON_SCALE_OUT].coll_qp_ids);
	xa_destroy(&coll_props[HL_CN_COLL_CONN_TYPE_SCALE_OUT].coll_qp_ids);
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

	cn_coll_props_fini(hdev->coll_props);

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

static int hl_cn_sw_init(struct hl_cn_device *hdev)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	struct hl_cn_macro *cn_macro, *cn_macros;
	int rc, i, macro_cnt = 0, port_cnt = 0;
	struct hl_cn_port *cn_port, *cn_ports;
	struct hl_en_aux_data *en_aux_data;
	struct hl_ib_aux_data *ib_aux_data;
	struct hl_en_aux_ops *en_aux_ops;
	struct hl_ib_aux_ops *ib_aux_ops;
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
	hdev->pcs_fail_time_frame = NIC_PCS_FAIL_TIME_FRAME_SEC;
	hdev->pcs_fail_threshold = NIC_PCS_FAIL_THRESHOLD;
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

	cn_coll_props_init(hdev->coll_props);

	/* At this stage, we don't know how many ports we have, so we must
	 * allocate for the maximum number of ports (and also free all of them
	 * in sw_fini)
	 */
	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++, port_cnt++) {
		cn_port = &hdev->cn_ports[i];
		cn_port->hdev = hdev;
		cn_port->port = i;
		atomic_set(&cn_port->num_of_allocated_qps, 0);
		atomic_set(&cn_port->num_of_allocated_coll_qps, 0);
		atomic_set(&cn_port->num_of_allocated_scale_out_coll_qps, 0);
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

	cn_coll_props_fini(hdev->coll_props);
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
#ifndef HL_XE
	aux_ops->ctx_init = hl_cn_ctx_init;
	aux_ops->ctx_fini = hl_cn_ctx_fini;
#endif
	aux_ops->ctx_kill = hl_cn_ctx_kill;
	aux_ops->send_port_cpucp_status = hl_cn_send_port_cpucp_status;
	aux_ops->mmap = hl_cn_mmap;
	aux_ops->get_port_state = hl_cn_get_port_link_state;
	aux_ops->get_port_statistics = hl_cn_get_port_statistics;
	aux_ops->cmd_control = hl_cn_cmd_control;

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
#ifndef HL_XE
	aux_ops->ctx_init = NULL;
	aux_ops->ctx_fini = NULL;
#endif
	aux_ops->ctx_kill = NULL;
	aux_ops->send_port_cpucp_status = NULL;
	aux_ops->mmap = NULL;
	aux_ops->get_port_state = NULL;
	aux_ops->get_port_statistics = NULL;
	aux_ops->cmd_control = NULL;

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

/* Driver increments context reference for every HW block mapped in order
 * to prevent user from closing FD without unmapping first
 */
static int hl_cn_hw_block_mmap(struct hl_cn_device *hdev, struct hl_cn_ctx *ctx,
			       struct vm_area_struct *vma)
{
	u32 address, block_size;
	int rc;

	/* We use the page offset to hold the address and thus we need to clear it before doing the
	 * mmap itself.
	 */
	address = vma->vm_pgoff;
	vma->vm_pgoff = 0;

	/* Driver only allows mapping of a complete HW block */
	block_size = vma->vm_end - vma->vm_start;

	if (!access_ok((void __user *)(uintptr_t)vma->vm_start, block_size)) {
		dev_err(hdev->dev, "user pointer is invalid - 0x%lx\n", vma->vm_start);
		return -EINVAL;
	}

	rc = hdev->asic_funcs->hw_block_mmap(hdev, vma, address, block_size);
	if (rc)
		return rc;

	vma->vm_pgoff = address;

	return 0;
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
	struct hl_aux_dev *aux_dev = &cn_port->hdev->ib_aux_dev;
	struct hl_ib_aux_ops *aux_ops = aux_dev->aux_ops;

	if (hl_cn_eq_dispatcher_is_full(dq)) {
		dq->overflow++;
		return -ENOSPC;
	}

	memcpy(&dq->buf.events[dq->buf.head], eqe, min(sizeof(*eqe), sizeof(dq->buf.events[0])));
	dq->buf.head = (dq->buf.head + 1) & (NIC_EQ_INFO_BUF_SIZE - 1);
	dq->buf.events_count++;

	/* If IB device exist, call work scheduler for hlib to poll eq */
	if (aux_ops->eqe_work_schd)
		aux_ops->eqe_work_schd(aux_dev, cn_port->port);

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

void hl_cn_set_priv_assertions(struct hl_cn_device *hdev, bool enable)
{
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	aux_ops->set_priv_assertions(aux_dev, enable);
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

void hl_cn_get_self_hw_block_handle(struct hl_cn_device *hdev, u64 address, u64 *handle)
{
	*handle = lower_32_bits(address) | (HL_CN_MMAP_TYPE_BLOCK);
	*handle <<= PAGE_SHIFT;
}

int hl_cn_user_mmap(struct hl_cn_device *hdev, struct hl_cn_ctx *ctx, struct vm_area_struct *vma)
{
	unsigned long vm_pgoff, type_mask;

	vm_pgoff = vma->vm_pgoff;
	type_mask = vm_pgoff & HL_CN_MMAP_TYPE_MASK;

	switch (type_mask) {
	case HL_CN_MMAP_TYPE_BLOCK:
		vma->vm_pgoff = HL_CN_MMAP_OFFSET_VALUE_GET(vm_pgoff);
		return hl_cn_hw_block_mmap(hdev, ctx, vma);

	case HL_CN_MMAP_TYPE_CN_MEM:
		return hl_cn_mmap(hdev->cn_aux_dev, ctx->asid, vma);

	default:
		dev_err(hdev->dev, "Invalid type mask %ld for asid %u.\n",
			type_mask >> HL_CN_MMAP_TYPE_SHIFT, ctx->asid);
		break;
	}

	return -EINVAL;
}
