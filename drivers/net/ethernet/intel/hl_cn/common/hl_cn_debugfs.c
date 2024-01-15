// SPDX-License-Identifier: GPL-2.0

/* Copyright (C) 2023-2024, Intel Corporation.
 * Copyright 2021 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "habanalabs_cn.h"

#ifdef CONFIG_DEBUG_FS

#include <linux/debugfs.h>
#include <linux/nospec.h>

#define POLARITY_KBUF_SIZE		8
#define TX_TAPS_KBUF_SIZE		25
#define KBUF_IN_SIZE			18
#define KBUF_OUT_SIZE			BIT(12)
#define KBUF_OUT_BIG_SIZE		BIT(14)
#define MAC_LANE_REMAP_READ_SIZE	10
#define MAX_INT_PORT_STS_KBUF_SIZE	20
#define HL_CN_DEBUGFS_CREATE_FILE(op, perm, dir, dev, fops) \
	do { \
		enum hl_cn_debugfs_files_idx __op = op; \
		if (hdev->debugfs_supp_mask & BIT(__op)) \
			debugfs_create_file(hl_cn_debugfs_names[__op], perm, dir, dev, fops); \
	} while (0)

#define HL_CN_DEBUGFS_CREATE_U8(op, perm, dir, fops) \
	do { \
		enum hl_cn_debugfs_files_idx __op = op; \
		if (hdev->debugfs_supp_mask & BIT(__op)) \
			debugfs_create_u8(hl_cn_debugfs_names[__op], perm, dir, fops); \
	} while (0)

#define HL_CN_DEBUGFS_CREATE_U16(op, perm, dir, fops) \
	do { \
		enum hl_cn_debugfs_files_idx __op = op; \
		if (hdev->debugfs_supp_mask & BIT(__op)) \
			debugfs_create_u16(hl_cn_debugfs_names[__op], perm, dir, fops); \
	} while (0)

static char hl_cn_debugfs_names[][NAME_MAX] = {
	[NIC_MAC_LOOPBACK] = "nic_mac_loopback",
	[NIC_PCS_FAIL_TIME_FRAME] = "nic_pcs_fail_time_frame",
	[NIC_PCS_FAIL_THRESHOLD] = "nic_pcs_fail_threshold",
	[NIC_PAM4_TX_TAPS] = "nic_pam4_tx_taps",
	[NIC_NRZ_TX_TAPS] = "nic_nrz_tx_taps",
	[NIC_POLARITY] = "nic_polarity",
	[NIC_QP] = "nic_qp",
	[NIC_WQE] = "nic_wqe",
	[NIC_RESET_CNT] = "nic_reset_cnt",
	[NIC_MAC_LANE_REMAP] = "nic_mac_lane_remap",
	[NIC_RAND_STATUS] = "nic_rand_status",
	[NIC_MMU_BYPASS] = "nic_mmu_bypass",
	[NIC_ETH_LOOPBACK] = "nic_eth_loopback",
	[NIC_PHY_REGS_PRINT] = "nic_phy_regs_print",
	[NIC_SHOW_INTERNAL_PORTS_STATUS] = "nic_show_internal_ports_status",
	[NIC_PRINT_FEC_STATS] = "nic_print_fec_stats",
	[NIC_DISABLE_DECAP] = "nic_disable_decap",
	[NIC_PHY_SET_NRZ] = "nic_phy_set_nrz",
	[NIC_COLL_LAG_SIZE] = "nic_coll_lag_size",
	[NIC_PHY_DUMP_SERDES_PARAMS] = "nic_phy_dump_serdes_params",
	[NIC_INJECT_RX_ERR] = "nic_inject_rx_err",
	[NIC_PHY_CALC_BER] = "nic_phy_calc_ber",
	[NIC_PHY_CALC_BER_WAIT_SEC] = "nic_phy_calc_ber_wait_sec",
	[NIC_OVERRIDE_PORT_STATUS] = "nic_override_port_status",
	[NIC_WQE_INDEX_CHECKER] = "nic_wqe_index_checker",
	[NIC_PHY_SPEED_RATE] = "nic_phy_speed_rate",
	[NIC_PHY_TRAINING_TYPE] = "nic_phy_training_type",
	[NIC_ACCUMULATE_FEC_DURATION] = "nic_accumulate_fec_duration"
};

static struct dentry *hl_cn_debug_root;

static int hl_device_hard_reset_sync(struct hl_cn_device *hdev)
{
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;
	ktime_t timeout;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	aux_ops->device_reset(aux_dev);

	timeout = ktime_add_ms(ktime_get(), hdev->pending_reset_long_timeout * 1000ull);
	while (!hl_cn_comp_device_operational(hdev) && !READ_ONCE(hdev->in_teardown)) {
		ssleep(1);
		if (ktime_compare(ktime_get(), timeout) > 0) {
			dev_crit(hdev->dev, "Timed out waiting for hard reset to finish\n");
			return -ETIMEDOUT;
		}
	}

	return 0;
}

static ssize_t debugfs_pam4_tx_taps_write(struct file *f, const char __user *buf, size_t count,
					  loff_t *ppos)
{
	s32 tx_pre2, tx_pre1, tx_main, tx_post1, tx_post2, *taps;
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	char kbuf[TX_TAPS_KBUF_SIZE];
	u32 lane, max_num_of_lanes;
	char *c1, *c2;
	ssize_t rc;

	max_num_of_lanes = hdev->cn_props.max_num_of_lanes;

	if (count > sizeof(kbuf) - 1)
		goto err;
	if (copy_from_user(kbuf, buf, count))
		goto err;
	kbuf[count] = '\0';

	c1 = kbuf;
	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtou32(c1, 10, &lane);
	if (rc)
		goto err;

	if (lane >= max_num_of_lanes) {
		dev_err(hdev->dev, "lane max value is %d\n", max_num_of_lanes - 1);
		return -EINVAL;
	}

	/* Turn off speculation due to Spectre vulnerability */
	lane = array_index_nospec(lane, max_num_of_lanes);

	c1 = c2 + 1;

	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtos32(c1, 10, &tx_pre2);
	if (rc)
		goto err;

	c1 = c2 + 1;

	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtos32(c1, 10, &tx_pre1);
	if (rc)
		goto err;

	c1 = c2 + 1;

	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtos32(c1, 10, &tx_main);
	if (rc)
		goto err;

	c1 = c2 + 1;

	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtos32(c1, 10, &tx_post1);
	if (rc)
		goto err;

	c1 = c2 + 1;

	rc = kstrtos32(c1, 10, &tx_post2);
	if (rc)
		goto err;

	taps = hdev->phy_tx_taps[lane].pam4_taps;
	taps[0] = tx_pre2;
	taps[1] = tx_pre1;
	taps[2] = tx_main;
	taps[3] = tx_post1;
	taps[4] = tx_post2;

	return count;
err:
	dev_err(hdev->dev,
		"usage: echo <lane> <tx_pre2> <tx_pre1> <tx_main> <tx_post1> <tx_post2> > nic_pam4_tx_taps\n");

	return -EINVAL;
}

static ssize_t debugfs_pam4_tx_taps_read(struct file *f, char __user *buf, size_t count,
					 loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	u32 lane, max_num_of_lanes;
	char *kbuf;
	ssize_t rc, len;
	s32 *taps;

	max_num_of_lanes = hdev->cn_props.max_num_of_lanes;

	if (*ppos)
		return 0;

	kbuf = kzalloc(KBUF_OUT_SIZE, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	sprintf(kbuf + strlen(kbuf), "PAM4 tx taps:\n");

	for (lane = 0; lane < max_num_of_lanes; lane++) {
		taps = hdev->phy_tx_taps[lane].pam4_taps;
		len = strlen(kbuf);
		if ((KBUF_OUT_SIZE - len) <= 1) {
			rc = -EFBIG;
			goto out;
		}
		snprintf(kbuf + len, KBUF_OUT_SIZE - len, "lane %u: %d %d %d %d %d\n", lane,
			 taps[0], taps[1], taps[2], taps[3], taps[4]);
	}

	rc = simple_read_from_buffer(buf, count, ppos, kbuf, strlen(kbuf) + 1);

out:
	kfree(kbuf);

	return rc;
}

static const struct file_operations debugfs_pam4_tx_taps_fops = {
	.owner = THIS_MODULE,
	.write = debugfs_pam4_tx_taps_write,
	.read = debugfs_pam4_tx_taps_read,
};

static ssize_t debugfs_nrz_tx_taps_write(struct file *f, const char __user *buf, size_t count,
					 loff_t *ppos)
{
	s32 tx_pre2, tx_pre1, tx_main, tx_post1, tx_post2, *taps;
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	char kbuf[TX_TAPS_KBUF_SIZE];
	u32 lane, max_num_of_lanes;
	char *c1, *c2;
	ssize_t rc;

	max_num_of_lanes = hdev->cn_props.max_num_of_lanes;

	if (count > sizeof(kbuf) - 1)
		goto err;
	if (copy_from_user(kbuf, buf, count))
		goto err;
	kbuf[count] = '\0';

	c1 = kbuf;
	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtou32(c1, 10, &lane);
	if (rc)
		goto err;

	if (lane >= max_num_of_lanes) {
		dev_err(hdev->dev, "lane max value is %d\n", max_num_of_lanes - 1);
		return -EINVAL;
	}

	/* Turn off speculation due to Spectre vulnerability */
	lane = array_index_nospec(lane, max_num_of_lanes);

	c1 = c2 + 1;

	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtos32(c1, 10, &tx_pre2);
	if (rc)
		goto err;

	c1 = c2 + 1;

	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtos32(c1, 10, &tx_pre1);
	if (rc)
		goto err;

	c1 = c2 + 1;

	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtos32(c1, 10, &tx_main);
	if (rc)
		goto err;

	c1 = c2 + 1;

	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtos32(c1, 10, &tx_post1);
	if (rc)
		goto err;

	c1 = c2 + 1;

	rc = kstrtos32(c1, 10, &tx_post2);
	if (rc)
		goto err;

	taps = hdev->phy_tx_taps[lane].nrz_taps;
	taps[0] = tx_pre2;
	taps[1] = tx_pre1;
	taps[2] = tx_main;
	taps[3] = tx_post1;
	taps[4] = tx_post2;

	return count;
err:
	dev_err(hdev->dev,
		"usage: echo <lane> <tx_pre2> <tx_pre1> <tx_main> <tx_post1> <tx_post2> > nic_nrz_tx_taps\n");

	return -EINVAL;
}

static ssize_t debugfs_nrz_tx_taps_read(struct file *f, char __user *buf, size_t count,
					loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	u32 lane, max_num_of_lanes;
	char *kbuf;
	ssize_t rc, len;
	s32 *taps;

	max_num_of_lanes = hdev->cn_props.max_num_of_lanes;

	if (*ppos)
		return 0;

	kbuf = kzalloc(KBUF_OUT_SIZE, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	sprintf(kbuf + strlen(kbuf), "NRZ tx taps:\n");

	for (lane = 0; lane < max_num_of_lanes; lane++) {
		taps = hdev->phy_tx_taps[lane].nrz_taps;
		len = strlen(kbuf);
		if ((KBUF_OUT_SIZE - len) <= 1) {
			rc = -EFBIG;
			goto out;
		}
		snprintf(kbuf + len, KBUF_OUT_SIZE - len, "lane %u: %d %d %d %d %d\n", lane,
			 taps[0], taps[1], taps[2], taps[3], taps[4]);
	}

	rc = simple_read_from_buffer(buf, count, ppos, kbuf, strlen(kbuf) + 1);

out:
	kfree(kbuf);

	return rc;
}

static const struct file_operations debugfs_nrz_tx_taps_fops = {
	.owner = THIS_MODULE,
	.write = debugfs_nrz_tx_taps_write,
	.read = debugfs_nrz_tx_taps_read,
};

static ssize_t debugfs_polarity_write(struct file *f, const char __user *buf, size_t count,
				      loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_cpucp_info *cpucp_info;
	char kbuf[POLARITY_KBUF_SIZE];
	u32 lane, max_num_of_lanes;
	u8 pol_tx, pol_rx;
	char *c1, *c2;
	ssize_t rc;
	u64 val;

	max_num_of_lanes = hdev->cn_props.max_num_of_lanes;
	cpucp_info = hdev->cpucp_info;

	if (count > sizeof(kbuf) - 1)
		goto err;
	if (copy_from_user(kbuf, buf, count))
		goto err;
	kbuf[count] = '\0';

	c1 = kbuf;
	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtou32(c1, 10, &lane);
	if (rc)
		goto err;

	if (lane >= max_num_of_lanes) {
		dev_err(hdev->dev, "lane max value is %d\n", max_num_of_lanes - 1);
		return -EINVAL;
	}

	c1 = c2 + 1;

	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtou8(c1, 10, &pol_tx);
	if (rc)
		goto err;

	c1 = c2 + 1;

	rc = kstrtou8(c1, 10, &pol_rx);
	if (rc)
		goto err;

	if ((pol_tx & ~1) || (pol_rx & ~1)) {
		dev_err(hdev->dev, "pol_tx and pol_rx should be 0 or 1\n");
		goto err;
	}

	val = cpucp_info->pol_tx_mask[0];
	val &= ~BIT_ULL(lane);
	val |= ((u64) pol_tx) << lane;
	cpucp_info->pol_tx_mask[0] = val;

	val = cpucp_info->pol_rx_mask[0];
	val &= ~BIT_ULL(lane);
	val |= ((u64) pol_rx) << lane;
	cpucp_info->pol_rx_mask[0] = val;

	return count;
err:
	dev_err(hdev->dev, "usage: echo <lane> <pol_tx> <pol_rx> > nic_polarity\n");

	return -EINVAL;
}

static const struct file_operations debugfs_polarity_fops = {
	.owner = THIS_MODULE,
	.write = debugfs_polarity_write,
};

static ssize_t debugfs_qp_read(struct file *f, char __user *buf, size_t count, loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_asic_funcs *asic_funcs;
	char *kbuf;
	ssize_t rc;

	asic_funcs = hdev->asic_funcs;

	if (*ppos)
		return 0;

	kbuf = kzalloc(KBUF_OUT_SIZE, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	rc = asic_funcs->qp_read(hdev, kbuf, KBUF_OUT_SIZE);
	if (rc)
		goto out;

	rc = simple_read_from_buffer(buf, count, ppos, kbuf, strlen(kbuf) + 1);

out:
	kfree(kbuf);

	return rc;
}

static ssize_t debugfs_qp_write(struct file *f, const char __user *buf, size_t count, loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_qp_info *qp_info = &hdev->qp_info;
	u32 port, qpn, max_num_of_ports;
	u8 req, full_print, force_read;
	char kbuf[KBUF_IN_SIZE];
	char *c1, *c2;
	ssize_t rc;

	max_num_of_ports = hdev->cn_props.max_num_of_ports;

	if (count > sizeof(kbuf) - 1)
		goto err;
	if (copy_from_user(kbuf, buf, count))
		goto err;
	kbuf[count] = '\0';

	c1 = kbuf;
	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtou32(c1, 10, &port);
	if (rc)
		goto err;

	if (port >= max_num_of_ports) {
		dev_err(hdev->dev, "port max value is %d\n", max_num_of_ports - 1);
		return -EINVAL;
	}

	c1 = c2 + 1;

	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtou32(c1, 10, &qpn);
	if (rc)
		goto err;

	c1 = c2 + 1;

	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtou8(c1, 10, &req);
	if (rc)
		goto err;

	if (req & ~1) {
		dev_err(hdev->dev, "req should be 0 or 1\n");
		goto err;
	}

	c1 = c2 + 1;

	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtou8(c1, 10, &full_print);
	if (rc)
		goto err;

	if (full_print & ~1) {
		dev_err(hdev->dev, "full_print should be 0 or 1\n");
		goto err;
	}

	c1 = c2 + 1;

	/* may not be the last element due to the optional params */
	c2 = strchr(c1, ' ');
	if (c2)
		*c2 = '\0';

	rc = kstrtou8(c1, 10, &force_read);
	if (rc)
		goto err;

	if (force_read & ~1) {
		dev_err(hdev->dev, "force_read should be 0 or 1\n");
		goto err;
	}

	qp_info->port = port;
	qp_info->qpn = qpn;
	qp_info->req = req;
	qp_info->full_print = full_print;
	qp_info->force_read = force_read;

	return count;
err:
	dev_err(hdev->dev,
		"usage: echo <port> <qpn> <is_req> <is_full_print> <force_read> [<exts_print>] > nic_qp\n");

	return -EINVAL;
}

static const struct file_operations debugfs_qp_fops = {
	.owner = THIS_MODULE,
	.read = debugfs_qp_read,
	.write = debugfs_qp_write
};

static ssize_t debugfs_wqe_read(struct file *f, char __user *buf, size_t count, loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_asic_funcs *asic_funcs;
	char *kbuf;
	ssize_t rc;

	asic_funcs = hdev->asic_funcs;

	if (*ppos)
		return 0;

	kbuf = kzalloc(KBUF_OUT_SIZE, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	rc = asic_funcs->wqe_read(hdev, kbuf, KBUF_OUT_SIZE);
	if (rc)
		goto out;

	rc = simple_read_from_buffer(buf, count, ppos, kbuf, strlen(kbuf) + 1);

out:
	kfree(kbuf);

	return rc;
}

static ssize_t debugfs_wqe_write(struct file *f, const char __user *buf, size_t count, loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_wqe_info *wqe_info = &hdev->wqe_info;
	u32 port, qpn, wqe_idx, max_num_of_lanes;
	char kbuf[KBUF_IN_SIZE];
	char *c1, *c2;
	ssize_t rc;
	u8 tx;

	max_num_of_lanes = hdev->cn_props.max_num_of_lanes;

	if (count > sizeof(kbuf) - 1)
		goto err;
	if (copy_from_user(kbuf, buf, count))
		goto err;
	kbuf[count] = '\0';

	c1 = kbuf;
	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtou32(c1, 10, &port);
	if (rc)
		goto err;

	if (port >= max_num_of_lanes) {
		dev_err(hdev->dev, "port max value is %d\n", max_num_of_lanes - 1);
		return -EINVAL;
	}

	c1 = c2 + 1;

	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtou32(c1, 10, &qpn);
	if (rc)
		goto err;

	c1 = c2 + 1;

	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtou32(c1, 10, &wqe_idx);
	if (rc)
		goto err;

	c1 = c2 + 1;

	rc = kstrtou8(c1, 10, &tx);
	if (rc)
		goto err;

	if (tx & ~1) {
		dev_err(hdev->dev, "tx should be 0 or 1\n");
		goto err;
	}

	wqe_info->port = port;
	wqe_info->qpn = qpn;
	wqe_info->wqe_idx = wqe_idx;
	wqe_info->tx = tx;

	return count;
err:
	dev_err(hdev->dev, "usage: echo <port> <qpn> <wqe_idx> <is_tx> > nic_wqe\n");

	return -EINVAL;
}

static const struct file_operations debugfs_wqe_fops = {
	.owner = THIS_MODULE,
	.read = debugfs_wqe_read,
	.write = debugfs_wqe_write
};

static ssize_t debugfs_reset_cnt_write(struct file *f, const char __user *buf, size_t count,
				       loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	ssize_t rc;
	u32 val;

	rc = kstrtou32_from_user(buf, count, 10, &val);
	if (rc)
		return rc;

	hl_cn_reset_ports_toggle_counters(hdev);
	hl_cn_reset_stats_counters(hdev);

	return count;
}

static const struct file_operations debugfs_reset_cnt_fops = {
	.owner = THIS_MODULE,
	.write = debugfs_reset_cnt_write
};

static int parse_user_mac_lane_remap_data(u32 *dest_arr, int *dest_arr_cnt, char *buf, int count)
{
	int i = 0, j = 0, rc;
	int offset;
	u32 val;

	while (i < count) {
		offset = strcspn(&buf[i], " ");
		buf[i + offset] = '\0';

		rc = kstrtou32(&buf[i], 16, &val);
		if (rc)
			return rc;

		dest_arr[j++] = val;
		i += (offset + 1);
	}

	*dest_arr_cnt = j;

	return 0;
}

static ssize_t debugfs_mac_lane_remap_write(struct file *f, const char __user *buf, size_t count,
					    loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_properties *cn_props;
	u32 *mac_lane_remap_buf;
	int rc, n_parsed = 0;
	char *kbuf;

	cn_props = &hdev->cn_props;

	kbuf = kcalloc(count + 1, sizeof(*buf), GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	mac_lane_remap_buf = kcalloc(cn_props->num_of_macros, sizeof(*mac_lane_remap_buf),
				     GFP_KERNEL);
	if (!mac_lane_remap_buf) {
		rc = -ENOMEM;
		goto err_free_kbuf;
	}

	rc = copy_from_user(kbuf, buf, count);
	if (rc)
		goto err_free_mac_lane_remap_buf;

	/* Add trailing space to simplify parsing user data. */
	kbuf[count] = ' ';

	rc = parse_user_mac_lane_remap_data(mac_lane_remap_buf, &n_parsed, kbuf, count + 1);
	if (rc || n_parsed != cn_props->num_of_macros) {
		rc = -EINVAL;
		goto err_parse;
	}

	memcpy(hdev->mac_lane_remap, mac_lane_remap_buf,
	       sizeof(*mac_lane_remap_buf) * cn_props->num_of_macros);

	rc = hl_device_hard_reset_sync(hdev);
	if (rc)
		goto err_free_mac_lane_remap_buf;

	kfree(mac_lane_remap_buf);
	kfree(kbuf);

	return count;
err_parse:
	dev_err_ratelimited(hdev->dev,
			    "usage: echo macro0 macr1 macro2 ... macroX > mac_lane_remap\n");
err_free_mac_lane_remap_buf:
	kfree(mac_lane_remap_buf);
err_free_kbuf:
	kfree(kbuf);
	return -EINVAL;
}

static ssize_t debugfs_mac_lane_remap_read(struct file *f, char __user *buf, size_t count,
					   loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_properties *cn_props;
	char kbuf[MAC_LANE_REMAP_READ_SIZE];
	int i, j;

	cn_props = &hdev->cn_props;

	if (*ppos)
		return 0;

	for (i = 0, j = 0; i < cn_props->num_of_macros; i++, j += MAC_LANE_REMAP_READ_SIZE) {
		memset(kbuf, 0, MAC_LANE_REMAP_READ_SIZE);
		sprintf(kbuf, "0x%x ", hdev->mac_lane_remap[i]);

		if (copy_to_user(&buf[j], kbuf, MAC_LANE_REMAP_READ_SIZE)) {
			dev_err(hdev->dev, "error in copying lane info to user\n");
			return -EFAULT;
		}

		*ppos += MAC_LANE_REMAP_READ_SIZE;
	}

	return j + 1;
}

static ssize_t debugfs_eth_loopback_write(struct file *f, const char __user *buf, size_t count,
					  loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	u32 val = 0;
	int rc;

	rc = kstrtou32_from_user(buf, count, 10, &val);
	if (rc)
		return rc;

	hdev->eth_loopback = !!val;

	dev_info(hdev->dev, "%s eth_loopback\n", hdev->eth_loopback ? "enable" : "disable");

	return count;
}

static ssize_t debugfs_eth_loopback_read(struct file *f, char __user *buf, size_t count,
					 loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	u32 val = 0;
	ssize_t rc;

	if (*ppos)
		return 0;

	snprintf((char *)&val, sizeof(val), "%u", hdev->eth_loopback);

	rc = simple_read_from_buffer(buf, count, ppos, &val, sizeof(val));

	return rc;
}

static const struct file_operations debugfs_mac_lane_remap_fops = {
	.owner = THIS_MODULE,
	.write = debugfs_mac_lane_remap_write,
	.read = debugfs_mac_lane_remap_read,
};

static const struct file_operations debugfs_eth_loopback_fops = {
	.owner = THIS_MODULE,
	.write = debugfs_eth_loopback_write,
	.read = debugfs_eth_loopback_read,
};

static ssize_t debugfs_phy_regs_print_write(struct file *f, const char __user *buf, size_t count,
					    loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	u32 val = 0;
	int rc;

	rc = kstrtou32_from_user(buf, count, 10, &val);
	if (rc)
		return rc;

	hdev->phy_regs_print = !!val;

	dev_info(hdev->dev,
		"%s printing PHY registers\n", hdev->phy_regs_print ? "enable" : "disable");

	return count;
}

static ssize_t debugfs_phy_regs_print_read(struct file *f, char __user *buf, size_t count,
					   loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	u32 val = 0;
	ssize_t rc;

	if (*ppos)
		return 0;

	snprintf((char *)&val, sizeof(val), "%u", hdev->phy_regs_print);

	rc = simple_read_from_buffer(buf, count, ppos, &val, sizeof(val));

	return rc;
}

static const struct file_operations debugfs_phy_regs_print_fops = {
	.owner = THIS_MODULE,
	.write = debugfs_phy_regs_print_write,
	.read = debugfs_phy_regs_print_read,
};

static ssize_t debugfs_show_internal_ports_status_read(struct file *f, char __user *buf,
						       size_t count, loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	char kbuf[MAX_INT_PORT_STS_KBUF_SIZE];
	struct hl_cn_port *cn_port;
	int i, cnt, total_cnt;

	if (*ppos)
		return 0;

	total_cnt = 0;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)) || (hdev->ext_ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		memset(kbuf, 0, MAX_INT_PORT_STS_KBUF_SIZE);
		cnt = sprintf(kbuf, "Port %-2u: %s\n",
			      cn_port->port, cn_port->pcs_link ? "UP" : "DOWN");

		if (copy_to_user(&buf[total_cnt], kbuf, cnt)) {
			dev_err(hdev->dev, "error in copying info to user\n");
			return -EFAULT;
		}

		total_cnt += cnt;
		*ppos += cnt;
	}

	if (!total_cnt) {
		char *msg = "No internal ports found\n";

		return simple_read_from_buffer(buf, count, ppos, msg, strlen(msg));
	}

	return total_cnt + 1;
}

static const struct file_operations debugfs_show_internal_ports_status_fops = {
	.owner = THIS_MODULE,
	.read = debugfs_show_internal_ports_status_read,
};

static ssize_t debugfs_print_fec_stats_read(struct file *f, char __user *buf, size_t count,
					    loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_asic_funcs *asic_funcs;
	struct hl_cn_port *cn_port;
	char *kbuf;
	int i, rc;

	asic_funcs = hdev->asic_funcs;

	if (*ppos)
		return 0;

	kbuf = kzalloc(KBUF_OUT_BIG_SIZE, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	sprintf(kbuf + strlen(kbuf), "Card %u FEC stats:\n", hdev->card_location);

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		asic_funcs->port_funcs->collect_fec_stats(cn_port, kbuf, KBUF_OUT_BIG_SIZE);
	}

	rc = simple_read_from_buffer(buf, count, ppos, kbuf, strlen(kbuf) + 1);

	kfree(kbuf);

	return rc;
}

static const struct file_operations debugfs_print_fec_stats_fops = {
	.owner = THIS_MODULE,
	.read = debugfs_print_fec_stats_read,
};

static ssize_t debugfs_phy_set_nrz_write(struct file *f, const char __user *buf, size_t count,
					 loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	bool val;
	int rc;

	rc = kstrtobool_from_user(buf, count, &val);
	if (rc)
		return rc;

	if (val == hdev->phy_set_nrz)
		return count;

	hdev->phy_set_nrz = val;
	hdev->skip_phy_default_tx_taps_cfg = 0;

	dev_info(hdev->dev, "%s NRZ mode\n", hdev->phy_set_nrz ? "Enable" : "Disable");

	rc = hl_device_hard_reset_sync(hdev);
	if (rc)
		return -EINVAL;

	return count;
}

static const struct file_operations debugfs_phy_set_nrz_fops = {
	.owner = THIS_MODULE,
	.write = debugfs_phy_set_nrz_write,
};

static ssize_t debugfs_write_coll_lag_size(struct file *f, const char __user *buf, size_t count,
					   loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_asic_funcs *asic_funcs;
	u32 val;
	int rc;

	asic_funcs = hdev->asic_funcs;

	/* For ASICs that don't support this feature, return an error */
	if (!asic_funcs->write_coll_lag_size)
		return -EINVAL;

	rc = kstrtou32_from_user(buf, count, 10, &val);
	if (rc)
		return rc;

	rc = asic_funcs->write_coll_lag_size(hdev, val);
	if (rc)
		return rc;

	return count;
}

static ssize_t debugfs_read_coll_lag_size(struct file *f, char __user *buf, size_t count,
					  loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_asic_funcs *asic_funcs;
	u32 coll_lag_size;
	ssize_t rc;

	asic_funcs = hdev->asic_funcs;

	if (*ppos)
		return 0;

	/* For ASICs that don't support this feature, return an error */
	if (!asic_funcs->read_coll_lag_size)
		return -EINVAL;

	rc = asic_funcs->read_coll_lag_size(hdev, &coll_lag_size);
	if (rc)
		return rc;

	rc = simple_read_from_buffer(buf, count, ppos, &coll_lag_size, sizeof(coll_lag_size));

	return rc;
}

static const struct file_operations debugfs_coll_lag_size_fops = {
	.owner = THIS_MODULE,
	.write = debugfs_write_coll_lag_size,
	.read = debugfs_read_coll_lag_size,
};

static ssize_t debugfs_phy_dump_serdes_params_read(struct file *f, char __user *buf, size_t count,
						   loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_asic_funcs *asic_funcs;
	char *kbuf;
	ssize_t rc;

	asic_funcs = hdev->asic_funcs;

	if (*ppos)
		return 0;

	/* For ASICs that don't support this feature, return an error */
	if (!asic_funcs->phy_dump_serdes_params)
		return -EINVAL;

	kbuf = kzalloc(KBUF_OUT_BIG_SIZE, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	asic_funcs->phy_dump_serdes_params(hdev, kbuf, KBUF_OUT_BIG_SIZE);

	rc = simple_read_from_buffer(buf, count, ppos, kbuf, strlen(kbuf) + 1);

	kfree(kbuf);

	return rc;
}

static ssize_t debugfs_phy_dump_serdes_params_write(struct file *f, const char __user *buf,
						    size_t count, loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_asic_funcs *asic_funcs;
	u32 port;
	int rc;

	asic_funcs = hdev->asic_funcs;

	/* For ASICs that don't support this feature, return an error */
	if (!asic_funcs->phy_dump_serdes_params)
		return -EINVAL;

	rc = kstrtou32_from_user(buf, count, 10, &port);
	if (rc)
		return rc;

	if (port >= hdev->cn_props.max_num_of_ports) {
		dev_err(hdev->dev, "Invalid port number %u\n", port);
		return -EINVAL;
	}

	hdev->phy_port_to_dump = port;

	return count;
}

static const struct file_operations debugfs_phy_dump_serdes_params_fops = {
	.owner = THIS_MODULE,
	.read = debugfs_phy_dump_serdes_params_read,
	.write = debugfs_phy_dump_serdes_params_write,
};

static ssize_t debugfs_inject_rx_err_read(struct file *f, char __user *buf, size_t count,
					  loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	u32 val;

	if (*ppos)
		return 0;

	snprintf((char *)&val, sizeof(val), "%u", hdev->rx_drop_percent);

	return simple_read_from_buffer(buf, count, ppos, &val, sizeof(val));
}

static ssize_t debugfs_inject_rx_err_write(struct file *f, const char __user *buf, size_t count,
					   loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_asic_funcs *asic_funcs;
	u32 val;
	int rc;

	asic_funcs = hdev->asic_funcs;

	if (*ppos)
		return 0;

	rc = kstrtou32_from_user(buf, count, 10, &val);
	if (rc)
		return rc;

	if (val > 100) {
		dev_dbg_ratelimited(hdev->dev, "Invalid drop percentage %d\n", val);
		return -EINVAL;
	}

	asic_funcs->inject_rx_err(hdev, val);

	return count;
}

static const struct file_operations debugfs_inject_rx_err_fops = {
	.owner = THIS_MODULE,
	.read = debugfs_inject_rx_err_read,
	.write = debugfs_inject_rx_err_write,
};

static ssize_t debugfs_override_port_status_write(struct file *f, const char __user *buf,
						  size_t count, loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_port *cn_port;
	u32 port, max_num_of_ports;
	char kbuf[KBUF_IN_SIZE];
	char *c1, *c2;
	ssize_t rc;
	u8 up;

	max_num_of_ports = hdev->cn_props.max_num_of_ports;

	if (count > sizeof(kbuf) - 1)
		goto err;
	if (copy_from_user(kbuf, buf, count))
		goto err;
	kbuf[count] = '\0';

	c1 = kbuf;
	c2 = strchr(c1, ' ');
	if (!c2)
		goto err;
	*c2 = '\0';

	rc = kstrtou32(c1, 10, &port);
	if (rc)
		goto err;

	if (port >= max_num_of_ports) {
		dev_err(hdev->dev, "port max value is %d\n", max_num_of_ports - 1);
		return -EINVAL;
	}

	/* Turn off speculation due to Spectre vulnerability */
	port = array_index_nospec(port, max_num_of_ports);

	c1 = c2 + 1;

	rc = kstrtou8(c1, 10, &up);
	if (rc)
		goto err;

	if (hdev->ports_mask & BIT(port)) {
		cn_port = &hdev->cn_ports[port];

		cn_port->pcs_link = !!up;
		hl_cn_phy_set_port_status(cn_port, !!up);
	}

	return count;
err:
	dev_err(hdev->dev, "usage: echo <port> <status> > nic_override_port_status\n");

	return -EINVAL;
}

static const struct file_operations debugfs_override_port_status_fops = {
	.owner = THIS_MODULE,
	.write = debugfs_override_port_status_write,
};

static ssize_t debugfs_write_wqe_index_checker(struct file *f, const char __user *buf, size_t count,
					       loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_asic_funcs *asic_funcs;
	u32 val;
	int rc;

	asic_funcs = hdev->asic_funcs;

	/* For ASICs that don't support this feature, return an error */
	if (!asic_funcs->set_wqe_index_checker)
		return -EINVAL;

	rc = kstrtou32_from_user(buf, count, 10, &val);
	if (rc)
		return rc;

	rc = asic_funcs->set_wqe_index_checker(hdev, !!val);
	if (rc)
		return rc;

	return count;
}

static ssize_t debugfs_read_wqe_index_checker(struct file *f, char __user *buf, size_t count,
					      loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_asic_funcs *asic_funcs;
	u32 val;

	asic_funcs = hdev->asic_funcs;

	/* For ASICs that don't support this feature, return an error */
	if (!asic_funcs->get_wqe_index_checker)
		return -EINVAL;

	snprintf((char *)&val, sizeof(val), "%u", asic_funcs->get_wqe_index_checker(hdev));

	return simple_read_from_buffer(buf, count, ppos, &val, sizeof(val));
}

static const struct file_operations debugfs_wqe_index_checker_fops = {
	.owner = THIS_MODULE,
	.write = debugfs_write_wqe_index_checker,
	.read = debugfs_read_wqe_index_checker,
};

static ssize_t debugfs_phy_speed_rate_write(struct file *f, const char __user *buf, size_t count,
					    loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_asic_funcs *asic_funcs;
	u32 val, curr_phy_speed_rate;
	int rc;

	 asic_funcs = hdev->asic_funcs;

	/* For ASICs that don't support this feature, return an error */
	if (!asic_funcs->phy_speed_rate_write || !asic_funcs->phy_speed_rate_read)
		return -EINVAL;

	rc = kstrtou32_from_user(buf, count, 10, &val);
	if (rc)
		return rc;

	curr_phy_speed_rate = asic_funcs->phy_speed_rate_read(hdev);

	if (curr_phy_speed_rate == val)
		return count;

	rc = asic_funcs->phy_speed_rate_write(hdev, val);
	if (rc)
		return rc;

	dev_info(hdev->dev, "PHY speed rate set to %d\n", val);

	rc = hl_device_hard_reset_sync(hdev);
	if (rc)
		return rc;

	return count;
}

static ssize_t debugfs_phy_speed_rate_read(struct file *f, char __user *buf, size_t count,
					   loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_asic_funcs *asic_funcs;
	u32 phy_speed_rate;
	char tmp_buf[32];
	ssize_t rc;

	asic_funcs = hdev->asic_funcs;

	if (*ppos)
		return 0;

	 /* For ASICs that don't support this feature, return an error */
	if (!asic_funcs->phy_speed_rate_read)
		return -EINVAL;

	phy_speed_rate = asic_funcs->phy_speed_rate_read(hdev);

	snprintf(tmp_buf, sizeof(tmp_buf), "%u\n", phy_speed_rate);
	rc = simple_read_from_buffer(buf, strlen(tmp_buf) + 1, ppos, tmp_buf,
				     strlen(tmp_buf) + 1);

	return rc;
}

static const struct file_operations debugfs_phy_speed_rate_fops = {
	.owner = THIS_MODULE,
	.write = debugfs_phy_speed_rate_write,
	.read = debugfs_phy_speed_rate_read,
};

static ssize_t debugfs_phy_training_type_write(struct file *f, const char __user *buf,
					       size_t count, loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_asic_funcs *asic_funcs;
	u32 val, curr_phy_training_type;
	int rc;

	 asic_funcs = hdev->asic_funcs;

	/* For ASICs that don't support this feature, return an error */
	if (!asic_funcs->phy_training_type_write || !asic_funcs->phy_training_type_read)
		return -EINVAL;

	rc = kstrtou32_from_user(buf, count, 10, &val);
	if (rc)
		return rc;

	curr_phy_training_type = asic_funcs->phy_training_type_read(hdev);

	if (curr_phy_training_type == val)
		return count;

	rc = asic_funcs->phy_training_type_write(hdev, val);
	if (rc)
		return rc;

	dev_info(hdev->dev, "PHY training type set to %d\n", val);

	rc = hl_device_hard_reset_sync(hdev);
	if (rc)
		return rc;

	return count;
}

static ssize_t debugfs_phy_training_type_read(struct file *f, char __user *buf, size_t count,
					      loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	struct hl_cn_asic_funcs *asic_funcs;
	u32 phy_training_type;
	char tmp_buf[32];
	ssize_t rc;

	asic_funcs = hdev->asic_funcs;

	if (*ppos)
		return 0;

	 /* For ASICs that don't support this feature, return an error */
	if (!asic_funcs->phy_training_type_read)
		return -EINVAL;

	phy_training_type = asic_funcs->phy_training_type_read(hdev);

	snprintf(tmp_buf, sizeof(tmp_buf), "%u\n", phy_training_type);
	rc = simple_read_from_buffer(buf, strlen(tmp_buf) + 1, ppos, tmp_buf,
				     strlen(tmp_buf) + 1);

	return rc;
}

static const struct file_operations debugfs_phy_training_type_fops = {
	.owner = THIS_MODULE,
	.write = debugfs_phy_training_type_write,
	.read = debugfs_phy_training_type_read,
};

static ssize_t debugfs_accumulate_fec_duration_write(struct file *f, const char __user *buf,
						     size_t count, loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	u32 val = 0;
	int rc;

	rc = kstrtou32_from_user(buf, count, 10, &val);
	if (rc)
		return rc;

	if (!val || val > ACCUMULATE_FEC_STATS_DURATION_MS_MAX)
		return -EINVAL;

	hdev->accumulate_fec_duration = val;

	return count;
}

static ssize_t debugfs_accumulate_fec_duration_read(struct file *f, char __user *buf, size_t count,
						    loff_t *ppos)
{
	struct hl_cn_device *hdev = file_inode(f)->i_private;
	u32 val = 0;
	ssize_t rc;

	if (*ppos)
		return 0;

	snprintf((char *)&val, sizeof(val), "%u\n", hdev->accumulate_fec_duration);

	rc = simple_read_from_buffer(buf, count, ppos, &val, sizeof(val));

	return rc;
}

static const struct file_operations debugfs_accumulate_fec_duration_fops = {
	.owner = THIS_MODULE,
	.write = debugfs_accumulate_fec_duration_write,
	.read = debugfs_accumulate_fec_duration_read,
};

#define NIC_DEBUGFS(X, fmt, do_reset) \
static ssize_t debugfs_##X##_read(struct file *f, char __user *buf, size_t count, loff_t *ppos) \
{ \
	struct hl_cn_device *hdev = file_inode(f)->i_private; \
	char tmp_buf[32]; \
	ssize_t rc; \
\
	if (*ppos) \
		return 0; \
\
	snprintf(tmp_buf, sizeof(tmp_buf), fmt "\n", hdev->X); \
	rc = simple_read_from_buffer(buf, strlen(tmp_buf) + 1, ppos, tmp_buf, \
				     strlen(tmp_buf) + 1); \
\
	return rc; \
} \
\
static ssize_t debugfs_##X##_write(struct file *f, const char __user *buf, size_t count, \
				   loff_t *ppos) \
{ \
	struct hl_cn_device *hdev = file_inode(f)->i_private; \
	u64 val, base; \
	ssize_t ret; \
	int rc; \
\
	if (!strcmp(fmt, "%d")) \
		base = 10; \
	else \
		base = 16; \
\
	ret = kstrtoull_from_user(buf, count, base, &val); \
	if (ret) \
		return ret; \
\
	if (val == hdev->X) \
		return count; \
\
	if (do_reset && hdev->debugfs_reset) { \
		hdev->X = val; \
		rc = hl_device_hard_reset_sync(hdev); \
		if (rc) \
			return rc; \
\
		return count; \
	} \
\
	dev_info(hdev->dev, "CN reset for %s started\n", __stringify(X)); \
\
	__hl_cn_hard_reset_prepare(hdev, false, false); \
\
	__hl_cn_stop(hdev); \
\
	hdev->X = val; \
\
	rc = __hl_cn_ports_reopen(hdev); \
	if (rc) \
		dev_err(hdev->dev, "Failed to reopen CN device, %d\n", rc); \
\
	dev_info(hdev->dev, "CN reset for %s finished\n", __stringify(X)); \
\
	return count; \
} \
\
static const struct file_operations debugfs_##X##_fops = { \
	.owner = THIS_MODULE, \
	.read = debugfs_##X##_read, \
	.write = debugfs_##X##_write, \
}

NIC_DEBUGFS(mac_loopback, "0x%llx", true);
NIC_DEBUGFS(pcs_fail_time_frame, "%d", false);
NIC_DEBUGFS(pcs_fail_threshold, "%d", false);

static void __hl_cn_debugfs_dev_init(struct hl_cn_device *hdev, struct dentry *root_dir)
{
	HL_CN_DEBUGFS_CREATE_FILE(NIC_MAC_LOOPBACK, 0644, root_dir, hdev,
				  &debugfs_mac_loopback_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_PCS_FAIL_TIME_FRAME, 0644, root_dir, hdev,
				  &debugfs_pcs_fail_time_frame_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_PCS_FAIL_THRESHOLD, 0644, root_dir, hdev,
				  &debugfs_pcs_fail_threshold_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_PAM4_TX_TAPS, 0444, root_dir, hdev,
				  &debugfs_pam4_tx_taps_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_NRZ_TX_TAPS, 0444, root_dir, hdev,
				  &debugfs_nrz_tx_taps_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_POLARITY, 0444, root_dir, hdev, &debugfs_polarity_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_QP, 0444, root_dir, hdev, &debugfs_qp_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_WQE, 0444, root_dir, hdev, &debugfs_wqe_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_RESET_CNT, 0444, root_dir, hdev,
				  &debugfs_reset_cnt_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_MAC_LANE_REMAP, 0644, root_dir, hdev,
				  &debugfs_mac_lane_remap_fops);

	HL_CN_DEBUGFS_CREATE_U8(NIC_RAND_STATUS, 0644, root_dir, &hdev->rand_status);

	HL_CN_DEBUGFS_CREATE_U8(NIC_MMU_BYPASS, 0644, root_dir, &hdev->mmu_bypass);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_ETH_LOOPBACK, 0644, root_dir, hdev,
				  &debugfs_eth_loopback_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_PHY_REGS_PRINT, 0444, root_dir, hdev,
				  &debugfs_phy_regs_print_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_SHOW_INTERNAL_PORTS_STATUS, 0444, root_dir, hdev,
				  &debugfs_show_internal_ports_status_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_PRINT_FEC_STATS, 0444, root_dir, hdev,
				  &debugfs_print_fec_stats_fops);

	HL_CN_DEBUGFS_CREATE_U8(NIC_DISABLE_DECAP, 0644, root_dir, &hdev->is_decap_disabled);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_PHY_SET_NRZ, 0444, root_dir, hdev,
				  &debugfs_phy_set_nrz_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_COLL_LAG_SIZE, 0644, root_dir, hdev,
				  &debugfs_coll_lag_size_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_PHY_DUMP_SERDES_PARAMS, 0444, root_dir, hdev,
				  &debugfs_phy_dump_serdes_params_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_INJECT_RX_ERR, 0444, root_dir, hdev,
				  &debugfs_inject_rx_err_fops);

	HL_CN_DEBUGFS_CREATE_U8(NIC_PHY_CALC_BER, 0644, root_dir, &hdev->phy_calc_ber);

	HL_CN_DEBUGFS_CREATE_U16(NIC_PHY_CALC_BER_WAIT_SEC, 0644, root_dir,
				 &hdev->phy_calc_ber_wait_sec);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_OVERRIDE_PORT_STATUS, 0200, root_dir, hdev,
				  &debugfs_override_port_status_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_WQE_INDEX_CHECKER, 0644, root_dir, hdev,
				  &debugfs_wqe_index_checker_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_PHY_SPEED_RATE, 0644, root_dir, hdev,
				  &debugfs_phy_speed_rate_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_PHY_TRAINING_TYPE, 0644, root_dir, hdev,
				  &debugfs_phy_training_type_fops);

	HL_CN_DEBUGFS_CREATE_FILE(NIC_ACCUMULATE_FEC_DURATION, 0644, root_dir, hdev,
				  &debugfs_accumulate_fec_duration_fops);
}

void hl_cn_debugfs_dev_init(struct hl_cn_device *hdev)
{
	char name[64] = {0};

	snprintf(name, sizeof(name), "hl_cn%d", hdev->id);
	hdev->cn_dentry = debugfs_create_dir(name, hl_cn_debug_root);
	__hl_cn_debugfs_dev_init(hdev, hdev->cn_dentry);
}

void hl_cn_debugfs_dev_fini(struct hl_cn_device *hdev)
{
	debugfs_remove_recursive(hdev->cn_dentry);
}

void __init hl_cn_debugfs_init(void)
{
	hl_cn_debug_root = debugfs_create_dir(HL_CN_NAME, NULL);
}

void hl_cn_debugfs_fini(void)
{
	debugfs_remove_recursive(hl_cn_debug_root);
}

#else

void hl_cn_debugfs_dev_init(struct hl_cn_device *hdev)
{
}

void hl_cn_debugfs_dev_fini(struct hl_cn_device *hdev)
{
}

void __init hl_cn_debugfs_init(void)
{
}

void hl_cn_debugfs_fini(void)
{
}

#endif /* CONFIG_DEBUG_FS */
