// SPDX-License-Identifier: GPL-2.0

/* Copyright 2021-2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#define pr_fmt(fmt)		"habanalabs_en: " fmt

#include "habanalabs_en.h"
#include <linux/version.h>

#include <linux/module.h>
#include <linux/auxiliary_bus.h>

#define HL_DRIVER_AUTHOR	"HabanaLabs Kernel Driver Team"

#define HL_DRIVER_DESC		"Habanalabs AI accelerators Ethernet driver"

#define HL_MODULE_VERSION	__stringify(HL_DRIVER_MAJOR) "."\
				__stringify(HL_DRIVER_MINOR) "."\
				__stringify(HL_DRIVER_PATCHLEVEL) "-"\
				__stringify(HL_DRIVER_GIT_SHA)

MODULE_AUTHOR(HL_DRIVER_AUTHOR);
MODULE_DESCRIPTION(HL_DRIVER_DESC);
MODULE_LICENSE("GPL v2");
MODULE_VERSION(HL_MODULE_VERSION);

static int poll_enable = 1;

static bool poll_enable_param_was_set;

static int poll_enable_param_set(const char *val, const struct kernel_param *kp)
{
	int rc = param_set_int(val, kp);

	if (!rc)
		poll_enable_param_was_set = true;

	return rc;
}

static const struct kernel_param_ops poll_enable_cb_ops = {
	.set = poll_enable_param_set,
	.get = param_get_int,
};

module_param_cb(poll_enable, &poll_enable_cb_ops, &poll_enable, 0444);
MODULE_PARM_DESC(poll_enable,
		 "Enable Rx polling rather than IRQ + NAPI (0 = no, 1 = yes, default yes)");

static int set_rx_poll(struct hl_en_device *hdev)
{
	if (!poll_enable_param_was_set && hdev->pdev)
		hdev->poll_enable = false;
	else
		hdev->poll_enable = poll_enable;

	/* On simulator we can't read/write registers in atomic context, hence we cannot use NAPI */
	if (!hdev->poll_enable && !hdev->pdev) {
		dev_err(hdev->dev, "Simulator mode, Rx polling must be enabled\n");
		return -EINVAL;
	}

	return 0;
}

static int hdev_init(struct hl_aux_dev *aux_dev)
{
	struct hl_en_aux_data *aux_data = aux_dev->aux_data;
	struct hl_en_port *ports, *port;
	struct hl_en_device *hdev;
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
	hdev->driver_ver = aux_data->driver_ver;
	hdev->ports_mask = aux_data->ports_mask;
	hdev->auto_neg_mask = aux_data->auto_neg_mask;
	hdev->max_num_of_ports = aux_data->max_num_of_ports;
	hdev->core_dev_minor = aux_data->minor;
	hdev->core_dev_id = aux_data->id;
	hdev->is_threaded_tx = false;
	hdev->fw_ver = aux_data->fw_ver;
	hdev->qsfp_eeprom = aux_data->qsfp_eeprom;
	hdev->asic_type = aux_data->asic_type;
	hdev->sb_base_addr = aux_data->sb_base_addr;
	hdev->sb_base_size = aux_data->sb_base_size;
	hdev->swq_base_addr = aux_data->swq_base_addr;
	hdev->swq_base_size = aux_data->swq_base_size;
	hdev->pending_reset_long_timeout = aux_data->pending_reset_long_timeout;
	hdev->max_frm_len = aux_data->max_frm_len;
	hdev->raw_elem_size = aux_data->raw_elem_size;
	hdev->max_raw_mtu = aux_data->max_raw_mtu;
	hdev->min_raw_mtu = aux_data->min_raw_mtu;
	hdev->pad_size = ETH_ZLEN;
	hdev->has_eq = aux_data->has_eq;
	hdev->dma_map_support = true;

	rc = set_rx_poll(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to set Rx polling\n");
		goto rx_poll_fail;
	}

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

	/* SIMULATOR CODE */
	if (!hdev->pdev) {
		/* on simulator we can't access registers in atomic context, hence use a thread */
		hdev->is_threaded_tx = true;
		hdev->dma_map_support = false;
	}
	/* END OF SIMULATOR CODE */

	return 0;

rx_poll_fail:
	kfree(ports);
ports_alloc_fail:
	kfree(hdev);

	return rc;
}

static void hdev_fini(struct hl_aux_dev *aux_dev)
{
	struct hl_en_device *hdev = aux_dev->priv;

	kfree(hdev->ports);
	kfree(hdev);
	aux_dev->priv = NULL;
}

static const struct auxiliary_device_id hl_en_id_table[] = {
	{ .name = "habanalabs_cn.en", },
	{},
};

MODULE_DEVICE_TABLE(auxiliary, hl_en_id_table);

static int hl_en_probe(struct auxiliary_device *adev, const struct auxiliary_device_id *id)
{
	struct hl_aux_dev *aux_dev = container_of(adev, struct hl_aux_dev, adev);
	struct hl_en_aux_ops *aux_ops = aux_dev->aux_ops;
	struct hl_en_device *hdev;
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
		dev_err(hdev->dev, "Failed to increment %s module refcount\n", HL_EN_NAME);
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

	rc = hl_en_dev_init(hdev);
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
static void hl_en_remove(struct auxiliary_device *adev)
{
	struct hl_aux_dev *aux_dev = container_of(adev, struct hl_aux_dev, adev);
	struct hl_en_device *hdev = aux_dev->priv;

	if (!hdev)
		return;

	hl_en_dev_fini(hdev);

	/* allow module unloading as now it is detached */
	module_put(THIS_MODULE);

	hdev_fini(aux_dev);
}

static struct auxiliary_driver hl_en_driver = {
	.name = "eth",
	.probe = hl_en_probe,
	.remove = hl_en_remove,
	.id_table = hl_en_id_table,
};

static int __init hl_en_init(void)
{
	pr_info("loading driver, version: %s\n", HL_MODULE_VERSION);

	return auxiliary_driver_register(&hl_en_driver);
}

static void __exit hl_en_exit(void)
{
	auxiliary_driver_unregister(&hl_en_driver);

	pr_info("driver removed\n");
}

module_init(hl_en_init);
module_exit(hl_en_exit);
