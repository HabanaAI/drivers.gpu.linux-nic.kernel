// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#define pr_fmt(fmt)		"habanalabs_en: " fmt

#include "hbl_en.h"

#include <linux/module.h>
#include <linux/auxiliary_bus.h>

#define HBL_DRIVER_AUTHOR	"HabanaLabs Kernel Driver Team"

#define HBL_DRIVER_DESC		"HabanaLabs AI accelerators Ethernet driver"

MODULE_AUTHOR(HBL_DRIVER_AUTHOR);
MODULE_DESCRIPTION(HBL_DRIVER_DESC);
MODULE_LICENSE("GPL");

static bool poll_enable;

module_param(poll_enable, bool, 0444);
MODULE_PARM_DESC(poll_enable,
		 "Enable Rx polling rather than IRQ + NAPI (0 = no, 1 = yes, default: no)");

static int hdev_init(struct hbl_aux_dev *aux_dev)
{
	struct hbl_en_aux_data *aux_data = aux_dev->aux_data;
	struct hbl_en_port *ports, *port;
	struct hbl_en_device *hdev;
	int rc, i;

	hdev = kzalloc(sizeof(*hdev), GFP_KERNEL);
	if (!hdev)
		return -ENOMEM;

	ports = kcalloc(aux_data->max_num_of_ports, sizeof(*ports), GFP_KERNEL);
	if (!ports) {
		rc = -ENOMEM;
		goto ports_alloc_fail;
	}

	aux_dev->priv = hdev;
	hdev->aux_dev = aux_dev;
	hdev->ports = ports;
	hdev->pdev = aux_data->pdev;
	hdev->dev = aux_data->dev;
	hdev->ports_mask = aux_data->ports_mask;
	hdev->auto_neg_mask = aux_data->auto_neg_mask;
	hdev->max_num_of_ports = aux_data->max_num_of_ports;
	hdev->core_dev_id = aux_data->id;
	hdev->fw_ver = aux_data->fw_ver;
	hdev->qsfp_eeprom = aux_data->qsfp_eeprom;
	hdev->asic_type = aux_data->asic_type;
	hdev->pending_reset_long_timeout = aux_data->pending_reset_long_timeout;
	hdev->max_frm_len = aux_data->max_frm_len;
	hdev->raw_elem_size = aux_data->raw_elem_size;
	hdev->max_raw_mtu = aux_data->max_raw_mtu;
	hdev->min_raw_mtu = aux_data->min_raw_mtu;
	hdev->pad_size = ETH_ZLEN;
	hdev->has_eq = aux_data->has_eq;
	hdev->dma_map_support = true;
	hdev->poll_enable = poll_enable;

	for (i = 0; i < hdev->max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		port = &hdev->ports[i];
		port->hdev = hdev;
		port->idx = i;
		port->pfc_enable = true;
		port->pflags = PFLAGS_PCS_LINK_CHECK | PFLAGS_PHY_AUTO_NEG_LPBK;
		port->mac_addr = aux_data->mac_addr[i];
		port->auto_neg_enable = !!(aux_data->auto_neg_mask & BIT(i));
	}

	return 0;

ports_alloc_fail:
	kfree(hdev);

	return rc;
}

static void hdev_fini(struct hbl_aux_dev *aux_dev)
{
	struct hbl_en_device *hdev = aux_dev->priv;

	kfree(hdev->ports);
	kfree(hdev);
	aux_dev->priv = NULL;
}

static const struct auxiliary_device_id hbl_en_id_table[] = {
	{ .name = "habanalabs_cn.en", },
	{},
};

MODULE_DEVICE_TABLE(auxiliary, hbl_en_id_table);

static int hbl_en_probe(struct auxiliary_device *adev, const struct auxiliary_device_id *id)
{
	struct hbl_aux_dev *aux_dev = container_of(adev, struct hbl_aux_dev, adev);
	struct hbl_en_aux_ops *aux_ops = aux_dev->aux_ops;
	struct hbl_en_device *hdev;
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
		dev_err(hdev->dev, "Failed to increment %s module refcount\n", HBL_EN_NAME);
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

		dev_notice_once(hdev->dev, "Waiting for hard reset to finish before probing en\n");

		msleep_interruptible(MSEC_PER_SEC);
	}

	rc = hbl_en_dev_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init en device\n");
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

/* This function can be called only from the CN driver when deleting the aux bus, because we
 * incremented the module refcount on probing. Hence no need to protect here from hard reset.
 */
static void hbl_en_remove(struct auxiliary_device *adev)
{
	struct hbl_aux_dev *aux_dev = container_of(adev, struct hbl_aux_dev, adev);
	struct hbl_en_device *hdev = aux_dev->priv;

	if (!hdev)
		return;

	hbl_en_dev_fini(hdev);

	/* allow module unloading as now it is detached */
	module_put(THIS_MODULE);

	hdev_fini(aux_dev);
}

static struct auxiliary_driver hbl_en_driver = {
	.name = "eth",
	.probe = hbl_en_probe,
	.remove = hbl_en_remove,
	.id_table = hbl_en_id_table,
};

static int __init hbl_en_init(void)
{
	pr_info("loading driver\n");

	return auxiliary_driver_register(&hbl_en_driver);
}

static void __exit hbl_en_exit(void)
{
	auxiliary_driver_unregister(&hbl_en_driver);

	pr_info("driver removed\n");
}

module_init(hbl_en_init);
module_exit(hbl_en_exit);
