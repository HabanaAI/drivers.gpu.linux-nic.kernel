// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#define pr_fmt(fmt)		"habanalabs_cn: " fmt

#include "hbl_cn.h"

#include <linux/module.h>
#include <linux/auxiliary_bus.h>
#include <linux/sched/clock.h>

#define HBL_DRIVER_AUTHOR	"HabanaLabs Kernel Driver Team"

#define HBL_DRIVER_DESC		"HabanaLabs AI accelerators Core Network driver"

MODULE_AUTHOR(HBL_DRIVER_AUTHOR);
MODULE_DESCRIPTION(HBL_DRIVER_DESC);
MODULE_LICENSE("GPL");

/* QP drain time in seconds */
#define HBL_CN_QP_DRAIN_TIME		5

static bool poll_enable;
static uint qp_drain_time = HBL_CN_QP_DRAIN_TIME;

module_param(poll_enable, bool, 0444);
MODULE_PARM_DESC(poll_enable,
		 "Enable driver in polling mode rather than IRQ (0 = no, 1 = yes, default: no)");

module_param(qp_drain_time, uint, 0444);
MODULE_PARM_DESC(qp_drain_time, "QP drain time in seconds after QP invalidation (default: 2)");

static int hdev_init(struct hbl_aux_dev *aux_dev)
{
	struct hbl_cn_aux_data *aux_data = aux_dev->aux_data;
	struct hbl_cn_device *hdev;
	int rc;

	hdev = kzalloc(sizeof(*hdev), GFP_KERNEL);
	if (!hdev)
		return -ENOMEM;

	hdev->cpucp_info = kzalloc(sizeof(*hdev->cpucp_info), GFP_KERNEL);
	if (!hdev->cpucp_info) {
		rc = -ENOMEM;
		goto free_hdev;
	}

	aux_dev->priv = hdev;
	hdev->cn_aux_dev = aux_dev;
	hdev->pdev = aux_data->pdev;
	hdev->dev = aux_data->dev;
	hdev->asic_type = aux_data->asic_type;
	hdev->pending_reset_long_timeout = aux_data->pending_reset_long_timeout;
	hdev->pldm = aux_data->pldm;
	hdev->skip_phy_init = aux_data->skip_phy_init;
	hdev->cpucp_fw = aux_data->cpucp_fw;
	hdev->load_phy_fw = aux_data->load_phy_fw;
	hdev->supports_coresight = aux_data->supports_coresight;
	hdev->use_fw_serdes_info = aux_data->use_fw_serdes_info;
	hdev->fw_ver = aux_data->fw_ver;
	hdev->id = aux_data->id;
	hdev->dram_size = aux_data->dram_size;
	hdev->ports_mask = aux_data->ports_mask;
	hdev->ext_ports_mask = aux_data->ext_ports_mask;
	hdev->phys_auto_neg_mask = aux_data->auto_neg_mask;
	hdev->cache_line_size = aux_data->cache_line_size;
	hdev->kernel_asid = aux_data->kernel_asid;
	hdev->qp_drain_time = qp_drain_time;
	hdev->card_location = aux_data->card_location;
	hdev->mmu_enable = aux_data->mmu_enable;
	hdev->lanes_per_port = aux_data->lanes_per_port;
	hdev->device_timeout = aux_data->device_timeout;
	hdev->fw_major_version = aux_data->fw_major_version;
	hdev->fw_minor_version = aux_data->fw_minor_version;
	hdev->fw_app_cpu_boot_dev_sts0 = aux_data->fw_app_cpu_boot_dev_sts0;
	hdev->fw_app_cpu_boot_dev_sts1 = aux_data->fw_app_cpu_boot_dev_sts1;
	hdev->cpucp_checkers_shift = aux_data->cpucp_checkers_shift;
	hdev->accumulate_fec_duration = ACCUMULATE_FEC_STATS_DURATION_MS;
	hdev->poll_enable = poll_enable;

	mutex_init(&hdev->hw_access_lock);

	return 0;

free_hdev:
	kfree(hdev);
	return rc;
}

static void hdev_fini(struct hbl_aux_dev *aux_dev)
{
	struct hbl_cn_device *hdev = aux_dev->priv;

	mutex_destroy(&hdev->hw_access_lock);

	kfree(hdev->cpucp_info);
	kfree(hdev);
	aux_dev->priv = NULL;
}

static const struct auxiliary_device_id hbl_cn_id_table[] = {
	{ .name = "habanalabs.cn", },
	{},
};

MODULE_DEVICE_TABLE(auxiliary, hbl_cn_id_table);

static int hbl_cn_probe(struct auxiliary_device *adev, const struct auxiliary_device_id *id)
{
	struct hbl_aux_dev *aux_dev = container_of(adev, struct hbl_aux_dev, adev);
	struct hbl_cn_aux_ops *aux_ops = aux_dev->aux_ops;
	struct hbl_cn_device *hdev;
	ktime_t timeout;
	int rc;

	rc = hdev_init(aux_dev);
	if (rc) {
		dev_err(&aux_dev->adev.dev, "Failed to init hdev\n");
		return -EIO;
	}

	hdev = aux_dev->priv;

	/* don't allow module unloading while it is attached */
	if (!try_module_get(THIS_MODULE)) {
		dev_err(hdev->dev, "Failed to increment %s module refcount\n",
			module_name(THIS_MODULE));
		rc = -EIO;
		goto module_get_err;
	}

	timeout = ktime_add_ms(ktime_get(), hdev->pending_reset_long_timeout * MSEC_PER_SEC);
	while (1) {
		aux_ops->hw_access_lock(aux_dev);

		/* if the device is operational, proceed to actual init while holding the lock in
		 * order to prevent concurrent hard reset
		 */
		if (aux_ops->device_operational(aux_dev))
			break;

		aux_ops->hw_access_unlock(aux_dev);

		if (ktime_compare(ktime_get(), timeout) > 0) {
			dev_err(hdev->dev, "Timeout while waiting for hard reset to finish\n");
			rc = -EBUSY;
			goto timeout_err;
		}

		dev_notice_once(hdev->dev, "Waiting for hard reset to finish before probing CN\n");

		msleep_interruptible(MSEC_PER_SEC);
	}

	rc = hbl_cn_dev_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init CN device\n");
		goto dev_init_err;
	}

	aux_ops->hw_access_unlock(aux_dev);

	return 0;

dev_init_err:
	aux_ops->hw_access_unlock(aux_dev);
timeout_err:
	module_put(THIS_MODULE);
module_get_err:
	hdev_fini(aux_dev);

	return rc;
}

/* This function can be called only from the compute driver when deleting the aux bus, because we
 * incremented the module refcount on probing. Hence no need to protect here from hard reset.
 */
static void hbl_cn_remove(struct auxiliary_device *adev)
{
	struct hbl_aux_dev *aux_dev = container_of(adev, struct hbl_aux_dev, adev);
	struct hbl_cn_device *hdev = aux_dev->priv;

	if (!hdev)
		return;

	hbl_cn_dev_fini(hdev);

	/* allow module unloading as now it is detached */
	module_put(THIS_MODULE);

	hdev_fini(aux_dev);
}

static struct auxiliary_driver hbl_cn_driver = {
	.name = "cn",
	.probe = hbl_cn_probe,
	.remove = hbl_cn_remove,
	.id_table = hbl_cn_id_table,
};

static int __init hbl_cn_init(void)
{
	pr_info("loading driver\n");

	return auxiliary_driver_register(&hbl_cn_driver);
}

static void __exit hbl_cn_exit(void)
{
	auxiliary_driver_unregister(&hbl_cn_driver);

	pr_info("driver removed\n");
}

module_init(hbl_cn_init);
module_exit(hbl_cn_exit);
