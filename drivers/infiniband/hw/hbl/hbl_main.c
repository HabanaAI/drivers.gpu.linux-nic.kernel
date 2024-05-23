// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2022-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#define pr_fmt(fmt)		"habanalabs_ib: " fmt

#include "hbl.h"

#include <linux/module.h>
#include <linux/auxiliary_bus.h>

#define HBL_DRIVER_AUTHOR	"HabanaLabs Kernel Driver Team"

#define HBL_DRIVER_DESC		"HabanaLabs AI accelerators InfiniBand driver"

MODULE_AUTHOR(HBL_DRIVER_AUTHOR);
MODULE_DESCRIPTION(HBL_DRIVER_DESC);
MODULE_LICENSE("GPL");

#define MTU_DEFAULT	SZ_4K

static const struct uapi_definition hbl_defs[] = {
#if IS_ENABLED(CONFIG_INFINIBAND_USER_ACCESS)
	UAPI_DEF_CHAIN(hbl_usr_fifo_defs),
	UAPI_DEF_CHAIN(hbl_set_port_ex_defs),
	UAPI_DEF_CHAIN(hbl_query_port_defs),
	UAPI_DEF_CHAIN(hbl_encap_defs),
#endif
	{}
};

static void hbl_ib_port_event(struct ib_device *ibdev, u32 port_num, enum ib_event_type reason)
{
	struct ib_event event;

	event.device = ibdev;
	event.element.port_num = port_num;
	event.event = reason;

	ib_dispatch_event(&event);
}

static void hbl_ib_port_mtu_update(struct ib_device *ibdev, u32 hbl_port, u32 mtu)
{
	struct hbl_ib_device *hdev = to_hbl_ib_dev(ibdev);

	hdev->ib_port[hbl_port].mtu = mtu;
}

static bool hbl_ib_match_netdev(struct ib_device *ibdev, struct net_device *netdev)
{
	struct hbl_ib_device *hdev = to_hbl_ib_dev(ibdev);
	struct hbl_ib_aux_data *aux_data;
	struct hbl_aux_dev *aux_dev;

	aux_dev = hdev->aux_dev;
	aux_data = aux_dev->aux_data;

	/* IB and EN share the same PCI device, hence we can find the correct netdev to bind to
	 * ibdev through the pointer to this device and port index.
	 */
	if (&hdev->pdev->dev == netdev->dev.parent)
		return true;

	return false;
}

static int hbl_ib_netdev_event(struct notifier_block *notifier, unsigned long event, void *ptr)
{
	struct hbl_ib_device *hdev = container_of(notifier, struct hbl_ib_device, netdev_notifier);
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct ib_device *ibdev = &hdev->ibdev;
	u32 ib_port;

	if (hbl_ib_match_netdev(ibdev, netdev))
		ib_port = hbl_to_ib_port_num(hdev, netdev->dev_port);
	else
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
		hbl_ib_port_event(ibdev, ib_port, IB_EVENT_PORT_ACTIVE);
		break;
	case NETDEV_DOWN:
		hbl_ib_port_event(ibdev, ib_port, IB_EVENT_PORT_ERR);
		break;
	case NETDEV_REGISTER:
		ib_device_set_netdev(ibdev, netdev, ib_port);
		hbl_ib_port_mtu_update(ibdev, netdev->dev_port, netdev->mtu);
		break;
	case NETDEV_UNREGISTER:
		hbl_ib_port_mtu_update(ibdev, netdev->dev_port, MTU_DEFAULT);
		ib_device_set_netdev(ibdev, NULL, ib_port);
		break;
	case NETDEV_CHANGEMTU:
		hbl_ib_port_mtu_update(ibdev, netdev->dev_port, netdev->mtu);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static void hbl_ib_dispatch_fatal_event(struct hbl_aux_dev *aux_dev, u32 asid)
{
	struct hbl_ib_device *hdev = aux_dev->priv;
	struct ib_event ibev = {};

	atomic_inc(&hdev->dev_stats.fatal_event);

	hbl_ibdev_err(&hdev->ibdev, "raising fatal event for context with ASID %d\n", asid);

	ibev.device = &hdev->ibdev;
	ibev.event = IB_EVENT_DEVICE_FATAL;
	ibev.element.port_num = HBL_IB_EQ_PORT_FIELD_MASK | (asid << HBL_IB_EQ_PORT_FIELD_SIZE);
	ib_dispatch_event(&ibev);
}

static void hbl_ib_set_aux_ops(struct hbl_ib_device *hdev, bool enable)
{
	struct hbl_aux_dev *aux_dev = hdev->aux_dev;
	struct hbl_ib_aux_ops *aux_ops;

	aux_ops = aux_dev->aux_ops;

	/* map cn2ib functions */
	if (enable)
		aux_ops->eqe_work_schd = hbl_ib_eqe_null_work;
	else
		aux_ops->eqe_work_schd = NULL;

	aux_ops->dispatch_fatal_event = hbl_ib_dispatch_fatal_event;
}

static int hbl_ib_dev_init(struct hbl_ib_device *hdev)
{
	char name[IB_DEVICE_NAME_MAX] = {0};
	struct ib_device *ibdev;
	u32 max_num_of_ports;
	int rc, i, port_cnt;

	ibdev = &hdev->ibdev;

	ibdev->node_type = RDMA_NODE_UNSPECIFIED;
	ibdev->dev.parent = &hdev->pdev->dev;

	max_num_of_ports = hdev->max_num_of_ports;

	/* Allocation of the mapping array between hbl<->ib ports.
	 * We don't need to initialize this array with some special value as 0 is an invalid value
	 * for IB port.
	 */
	hdev->hbl_to_ib_port_map = kcalloc(max_num_of_ports, sizeof(u32), GFP_KERNEL);
	if (!hdev->hbl_to_ib_port_map)
		return -ENOMEM;

	port_cnt = 0;
	for (i = 0; i < max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		port_cnt++;
		hdev->hbl_to_ib_port_map[i] = port_cnt;
	}

	ibdev->phys_port_cnt = port_cnt;

	/* The number of Completion vectors (i.e. MSI-X vectors) available for this RDMA device.
	 * For now have it as '1'
	 */
	ibdev->num_comp_vectors = 1;

	ib_set_device_ops(ibdev, &hbl_ib_dev_ops);

	if (IS_ENABLED(CONFIG_INFINIBAND_USER_ACCESS))
		ibdev->driver_def = hbl_defs;
	else
		dev_info(hdev->dev, "IB user access is disabled\n");

	/* The CN driver might start calling the aux functions after registering the device so set
	 * the callbacks here.
	 */
	hbl_ib_set_aux_ops(hdev, true);

	snprintf(name, sizeof(name), "hbl_%d", hdev->id);

	rc = ib_register_device(ibdev, name, &hdev->pdev->dev);
	if (rc) {
		dev_err(hdev->dev, "Failed to register IB device, err %d\n", rc);
		goto ibdev_register_fail;
	}

	hdev->netdev_notifier.notifier_call = hbl_ib_netdev_event;

	rc = register_netdevice_notifier(&hdev->netdev_notifier);
	if (rc) {
		hbl_ibdev_err(ibdev, "Failed to register netdev notifier, err %d\n", rc);
		goto notifier_register_fail;
	}

	hbl_ibdev_info(ibdev, "IB device registered\n");

	return 0;

notifier_register_fail:
	ib_unregister_device(ibdev);
ibdev_register_fail:
	hbl_ib_set_aux_ops(hdev, false);
	kfree(hdev->hbl_to_ib_port_map);
	return rc;
}

static void hbl_ib_dev_fini(struct hbl_ib_device *hdev)
{
	struct ib_device *ibdev = &hdev->ibdev;

	hbl_ibdev_info(ibdev, "Unregister IB device\n");
	unregister_netdevice_notifier(&hdev->netdev_notifier);
	ib_unregister_device(ibdev);
	hbl_ib_set_aux_ops(hdev, false);
	kfree(hdev->hbl_to_ib_port_map);
}

/* Initialize an array of strings to hold the counters names.
 * We get the names as one long spaced string and then we convert it to an array of strings like the
 * IB counters API expects.
 */
static int hbl_ib_cnts_init(struct hbl_ib_device *hdev, int port)
{
	struct hbl_ib_port_cnts_data *cnts_data;
	struct hbl_ib_port_stats *port_stats;
	struct rdma_stat_desc *stat_desc;
	struct hbl_ib_aux_data *aux_data;
	u8 *ptr, *data, **data2;
	int cnt_num, i;

	aux_data = hdev->aux_dev->aux_data;
	port_stats = &hdev->port_stats[port];
	cnts_data = &aux_data->cnts_data[port];
	cnt_num = cnts_data->num;

	/* array for strings and pointers for them */
	data = kcalloc(cnt_num, (sizeof(u8 *) + HBL_IB_CNT_NAME_LEN), GFP_KERNEL);
	if (!data)
		goto exit_err;

	stat_desc = kcalloc(cnt_num, sizeof(*stat_desc), GFP_KERNEL);
	if (!stat_desc)
		goto free_data;

	/* copy the strings after the pointers to them */
	ptr = data + cnt_num * sizeof(u8 *);
	memcpy(ptr, cnts_data->names, cnt_num * HBL_IB_CNT_NAME_LEN);

	data2 = (u8 **)data;

	/* set the pointers to the strings */
	for (i = 0; i < cnt_num; i++)
		data2[i] = ptr + i * HBL_IB_CNT_NAME_LEN;

	port_stats->num = cnt_num;
	port_stats->names = data2;

	for (i = 0; i < cnt_num; i++)
		stat_desc[i].name = data2[i];

	port_stats->stat_desc = stat_desc;

	return 0;

free_data:
	kfree(data);
exit_err:
	return -ENOMEM;
}

static void hbl_ib_cnts_fini(struct hbl_ib_device *hdev, int port)
{
	kfree(hdev->port_stats[port].stat_desc);
	kfree(hdev->port_stats[port].names);
}

static int hdev_init(struct hbl_aux_dev *aux_dev)
{
	struct hbl_ib_aux_data *aux_data = aux_dev->aux_data;
	struct hbl_ib_device *hdev;
	int rc, i;

	hdev = ib_alloc_device(hbl_ib_device, ibdev);
	if (!hdev)
		return -ENOMEM;

	aux_dev->priv = hdev;
	hdev->aux_dev = aux_dev;
	hdev->pdev = aux_data->pdev;
	hdev->dev = aux_data->dev;
	hdev->ports_mask = aux_data->ports_mask;
	hdev->ext_ports_mask = aux_data->ext_ports_mask;
	hdev->pending_reset_long_timeout = aux_data->pending_reset_long_timeout;
	hdev->id = aux_data->id;
	hdev->max_num_of_ports = aux_data->max_num_of_ports;
	hdev->mixed_qp_wq_types = aux_data->mixed_qp_wq_types;
	hdev->umr_support = aux_data->umr_support;
	hdev->cc_support = aux_data->cc_support;

	/* Allocate port structs */
	hdev->ib_port = kcalloc(hdev->max_num_of_ports, sizeof(*hdev->ib_port), GFP_KERNEL);
	if (!hdev->ib_port) {
		rc = -ENOMEM;
		goto free_device;
	}

	/* Set default MTU value that can be overridden later by netdev */
	for (i = 0; i < hdev->max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		hdev->ib_port[i].mtu = MTU_DEFAULT;
	}

	hdev->port_stats = kcalloc(hdev->max_num_of_ports, sizeof(*hdev->port_stats), GFP_KERNEL);
	if (!hdev->port_stats) {
		rc = -ENOMEM;
		goto free_ports;
	}

	for (i = 0; i < hdev->max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		rc = hbl_ib_cnts_init(hdev, i);
		if (rc)
			goto free_cnts;
	}

	return 0;

free_cnts:
	for (--i; i >= 0; i--) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		hbl_ib_cnts_fini(hdev, i);
	}
	kfree(hdev->port_stats);
free_ports:
	kfree(hdev->ib_port);
free_device:
	aux_dev->priv = NULL;
	ib_dealloc_device(&hdev->ibdev);

	return rc;
}

static void hdev_fini(struct hbl_aux_dev *aux_dev)
{
	struct hbl_ib_device *hdev = aux_dev->priv;
	int i;

	for (i = 0; i < hdev->max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		hbl_ib_cnts_fini(hdev, i);
	}
	kfree(hdev->port_stats);

	kfree(hdev->ib_port);

	aux_dev->priv = NULL;
	ib_dealloc_device(&hdev->ibdev);
}

static const struct auxiliary_device_id hbl_ib_id_table[] = {
	{ .name = "habanalabs_cn.ib", },
	{},
};

MODULE_DEVICE_TABLE(auxiliary, hbl_ib_id_table);

static int hbl_ib_probe(struct auxiliary_device *adev, const struct auxiliary_device_id *id)
{
	struct hbl_aux_dev *aux_dev = container_of(adev, struct hbl_aux_dev, adev);
	struct hbl_ib_aux_ops *aux_ops = aux_dev->aux_ops;
	struct hbl_ib_device *hdev;
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

		dev_notice_once(hdev->dev, "Waiting for hard reset to finish before probing IB\n");

		msleep_interruptible(MSEC_PER_SEC);
	}

	rc = hbl_ib_dev_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init ib device\n");
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
static void hbl_ib_remove(struct auxiliary_device *adev)
{
	struct hbl_aux_dev *aux_dev = container_of(adev, struct hbl_aux_dev, adev);
	struct hbl_ib_device *hdev = aux_dev->priv;

	if (!hdev)
		return;

	hbl_ib_dev_fini(hdev);

	/* allow module unloading as now it is detached */
	module_put(THIS_MODULE);

	hdev_fini(aux_dev);
}

static struct auxiliary_driver hbl_ib_driver = {
	.name = "ib",
	.probe = hbl_ib_probe,
	.remove = hbl_ib_remove,
	.id_table = hbl_ib_id_table,
};

static int __init hbl_ib_init(void)
{
	pr_info("loading driver\n");

	return auxiliary_driver_register(&hbl_ib_driver);
}

static void __exit hbl_ib_exit(void)
{
	auxiliary_driver_unregister(&hbl_ib_driver);

	pr_info("driver removed\n");
}

module_init(hbl_ib_init);
module_exit(hbl_ib_exit)
