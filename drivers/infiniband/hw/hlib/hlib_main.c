// SPDX-License-Identifier: GPL-2.0

/* Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#define pr_fmt(fmt)		"habanalabs_ib: " fmt

#include "hlib.h"
#include "../../../net/ethernet/intel/hl_cn/common/version.h"

#include <linux/module.h>
#ifdef _HAS_AUX_BUS_H
#include <linux/auxiliary_bus.h>
#endif

#define HL_DRIVER_AUTHOR	"HabanaLabs Kernel Driver Team"

#define HL_DRIVER_DESC		"Habanalabs AI accelerators InfiniBand driver"

#define HL_MODULE_VERSION	__stringify(HL_DRIVER_MAJOR) "."\
				__stringify(HL_DRIVER_MINOR) "."\
				__stringify(HL_DRIVER_PATCHLEVEL) "-"\
				__stringify(HL_DRIVER_GIT_SHA)

MODULE_AUTHOR(HL_DRIVER_AUTHOR);
MODULE_DESCRIPTION(HL_DRIVER_DESC);
MODULE_LICENSE("GPL v2");
MODULE_VERSION(HL_MODULE_VERSION);

#define MTU_DEFAULT	SZ_4K

/* for backward compatibility */
static void bc_set_cmd_mask(struct ib_device *ibdev)
{
#ifdef _HAS_EX_CMD_MASK
	ibdev->uverbs_cmd_mask =
		(1ull << IB_USER_VERBS_CMD_GET_CONTEXT) |
		(1ull << IB_USER_VERBS_CMD_QUERY_DEVICE) |
		(1ull << IB_USER_VERBS_CMD_QUERY_PORT) |
		(1ull << IB_USER_VERBS_CMD_ALLOC_PD) |
		(1ull << IB_USER_VERBS_CMD_DEALLOC_PD) |
		(1ull << IB_USER_VERBS_CMD_REG_MR) |
		(1ull << IB_USER_VERBS_CMD_DEREG_MR) |
		(1ull << IB_USER_VERBS_CMD_CREATE_CQ) |
		(1ull << IB_USER_VERBS_CMD_DESTROY_CQ) |
		(1ull << IB_USER_VERBS_CMD_CREATE_QP) |
		(1ull << IB_USER_VERBS_CMD_QUERY_QP) |
		(1ull << IB_USER_VERBS_CMD_DESTROY_QP);

	ibdev->uverbs_ex_cmd_mask =
		(1ull << IB_USER_VERBS_EX_CMD_QUERY_DEVICE) |
		(1ull << IB_USER_VERBS_EX_CMD_MODIFY_QP);
#endif
}

static const struct uapi_definition hlib_defs[] = {
#if IS_ENABLED(CONFIG_INFINIBAND_USER_ACCESS)
	UAPI_DEF_CHAIN(hlib_usr_fifo_defs),
	UAPI_DEF_CHAIN(hlib_set_port_ex_defs),
	UAPI_DEF_CHAIN(hlib_query_port_defs),
	UAPI_DEF_CHAIN(hlib_collective_qp_defs),
	UAPI_DEF_CHAIN(hlib_encap_defs),
#endif
	{}
};

static void hl_ib_port_event(struct ib_device *ibdev, u32 port_num, enum ib_event_type reason)
{
	struct ib_event event;

	event.device = ibdev;
#ifdef _HAS_EX_RDMA_PORTS
	event.element.port_num = port_num;
#else
	event.element.port_num = (u8) port_num;
#endif
	event.event = reason;

	ib_dispatch_event(&event);
}

static void hl_ib_port_mtu_update(struct ib_device *ibdev, u32 hl_port, u32 mtu)
{
	struct hl_ib_device *hdev = to_hl_ib_dev(ibdev);

	hdev->ib_port[hl_port].mtu = mtu;
}

static bool hl_ib_match_netdev(struct ib_device *ibdev, struct net_device *netdev)
{
	struct hl_ib_device *hdev = to_hl_ib_dev(ibdev);
	struct hl_ib_aux_data *aux_data;
	struct hl_aux_dev *aux_dev;

	aux_dev = hdev->aux_dev;
	aux_data = aux_dev->aux_data;

	/* IB and EN share the same PCI device, hence we can find the correct
	 * netdev to bind to ibdevice through the pointer to this device and
	 * port index.
	 */
	if (hdev->pdev && (&hdev->pdev->dev == netdev->dev.parent))
		return true;
	/* SIMULATOR CODE */
	/* Simulator don't have PCI address, hence we will find the device according to the
	 * MAC addresses.
	 */
	else if (!hdev->pdev && (hdev->ext_ports_mask & BIT(netdev->dev_port)) &&
		 ether_addr_equal(netdev->dev_addr, aux_data->sim_mac_addr[netdev->dev_port]))
		return true;
	/* END OF SIMULATOR CODE */

	return false;
}

static int hl_ib_netdev_event(struct notifier_block *notifier, unsigned long event, void *ptr)
{
	struct hl_ib_device *hdev = container_of(notifier, struct hl_ib_device, netdev_notifier);
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct ib_device *ibdev = &hdev->ibdev;
	u32 ib_port;

	if (hl_ib_match_netdev(ibdev, netdev))
		ib_port = hl_to_ib_port_num(hdev, netdev->dev_port);
	else
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
		hl_ib_port_event(ibdev, ib_port, IB_EVENT_PORT_ACTIVE);
		break;
	case NETDEV_DOWN:
		hl_ib_port_event(ibdev, ib_port, IB_EVENT_PORT_ERR);
		break;
	case NETDEV_REGISTER:
		ib_device_set_netdev(ibdev, netdev, ib_port);
		hl_ib_port_mtu_update(ibdev, netdev->dev_port, netdev->mtu);
		break;
	case NETDEV_UNREGISTER:
		hl_ib_port_mtu_update(ibdev, netdev->dev_port, MTU_DEFAULT);
		ib_device_set_netdev(ibdev, NULL, ib_port);
		break;
	case NETDEV_CHANGEMTU:
		hl_ib_port_mtu_update(ibdev, netdev->dev_port, netdev->mtu);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static void hl_ib_dispatch_fatal_event(struct hl_aux_dev *aux_dev, u32 asid)
{
	struct hl_ib_device *hdev = aux_dev->priv;
	struct ib_event ibev = {};

	ibev.device = &hdev->ibdev;

	hl_ibdev_err(&hdev->ibdev, "raising fatal event for context with ASID %d\n", asid);

	ibev.event = IB_EVENT_DEVICE_FATAL;
	ibev.element.port_num = HL_IB_EQ_PORT_FIELD_MASK | (asid << HL_IB_EQ_PORT_FIELD_SIZE);
	ib_dispatch_event(&ibev);
}

static void hl_ib_set_aux_ops(struct hl_ib_device *hdev, bool enable)
{
	struct hl_aux_dev *aux_dev = hdev->aux_dev;
	struct hl_ib_aux_ops *aux_ops;

	aux_ops = aux_dev->aux_ops;

	/* map cn2ib funcions */
	if (enable)
		aux_ops->eqe_work_schd = hl_ib_eqe_null_work;
	else
		aux_ops->eqe_work_schd = NULL;

	aux_ops->dispatch_fatal_event = hl_ib_dispatch_fatal_event;
}

static int hl_ib_dev_init(struct hl_ib_device *hdev)
{
	char name[IB_DEVICE_NAME_MAX] = {0};
	struct ib_device *ibdev;
	u32 max_num_of_ports;
	int rc, i, port_cnt;

	ibdev = &hdev->ibdev;

#ifndef _HAS_DEVICE_OPS_INFO
	ibdev->owner = THIS_MODULE;
	ibdev->driver_id = RDMA_DRIVER_HLIB;
	ibdev->uverbs_abi_ver = HL_IB_UVERBS_ABI_VERSION;
#endif
	ibdev->node_type = RDMA_NODE_UNSPECIFIED;
	ibdev->dev.parent = hdev->pdev ? &hdev->pdev->dev : hdev->dev;

	max_num_of_ports = hdev->max_num_of_ports;

	/* Allocation of the mapping array between hl<->ib ports.
	 * We don't need to initialize this array with some special value as 0 is an invalid value
	 * for IB port.
	 */
	hdev->hl_to_ib_port_map = kcalloc(max_num_of_ports, sizeof(u32), GFP_KERNEL);
	if (!hdev->hl_to_ib_port_map)
		return -ENOMEM;

	port_cnt = 0;
	for (i = 0; i < max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		port_cnt++;
		hdev->hl_to_ib_port_map[i] = port_cnt;
	}

	ibdev->phys_port_cnt = port_cnt;

	/* The number of Completion vectors (i.e. MSI-X vectors) available for this RDMA device.
	 * For now have it as '1'
	 */
	ibdev->num_comp_vectors = 1;

	bc_set_cmd_mask(ibdev);

	ib_set_device_ops(ibdev, &hl_ib_dev_ops);

	if (IS_ENABLED(CONFIG_INFINIBAND_USER_ACCESS))
		ibdev->driver_def = hlib_defs;
	else
		dev_info(hdev->dev, "IB user access is disabled\n");

	/* The CN driver might start calling the aux functions after registering the device so set
	 * the callbacks here.
	 */
	hl_ib_set_aux_ops(hdev, true);

	snprintf(name, sizeof(name), "hlib_%d", hdev->id);

#ifdef _HAS_DMA_IB_REGISTER_DEVICE
	rc = ib_register_device(ibdev, name, hdev->pdev ? &hdev->pdev->dev : NULL);
#else
	rc = ib_register_device(ibdev, name);
#endif
	if (rc) {
		dev_err(hdev->dev, "Failed to register netdev notifier, err %d\n", rc);
		goto ibdev_register_fail;
	}

	hdev->netdev_notifier.notifier_call = hl_ib_netdev_event;

	rc = register_netdevice_notifier(&hdev->netdev_notifier);
	if (rc) {
		hl_ibdev_err(ibdev, "Failed to register netdev notifier, err %d\n", rc);
		goto notifier_register_fail;
	}

	rc = hl_ib_sysfs_init(hdev);
	if (rc) {
		hl_ibdev_err(ibdev, "Failed to initialize sysfs, err %d\n", rc);
		goto sysfs_fail;
	}

	hl_ibdev_info(ibdev, "IB device registered\n");

	return 0;

sysfs_fail:
	unregister_netdevice_notifier(&hdev->netdev_notifier);
notifier_register_fail:
	ib_unregister_device(ibdev);
ibdev_register_fail:
	hl_ib_set_aux_ops(hdev, false);
	kfree(hdev->hl_to_ib_port_map);
	return rc;
}

static void hl_ib_dev_fini(struct hl_ib_device *hdev)
{
	struct ib_device *ibdev = &hdev->ibdev;

	hl_ibdev_info(ibdev, "Unregister IB device\n");
	hl_ib_sysfs_fini(hdev);
	unregister_netdevice_notifier(&hdev->netdev_notifier);
	ib_unregister_device(ibdev);
	hl_ib_set_aux_ops(hdev, false);
	kfree(hdev->hl_to_ib_port_map);
}

/* Initialize an array of strings to hold the counters names.
 * We get the names as one long spaced string and then we convert it to an array of strings like the
 * IB counters API expects.
 */
static int hl_ib_cnts_init(struct hl_ib_device *hdev, int port)
{
	struct hl_ib_port_cnts_data *cnts_data;
	struct hl_ib_port_stats	*port_stats;
#ifdef _HAS_STRUCT_RDMA_STAT_DESC
	struct rdma_stat_desc *stat_desc;
#endif
	struct hl_ib_aux_data *aux_data;
	u8 *ptr, *data, **data2;
	int cnt_num, i;

	aux_data = hdev->aux_dev->aux_data;
	port_stats = &hdev->port_stats[port];
	cnts_data = &aux_data->cnts_data[port];
	cnt_num = cnts_data->num;

	/* array for strings and pointers for them */
	data = kzalloc(cnt_num * (sizeof(u8 *) + HL_IB_CNT_NAME_LEN), GFP_KERNEL);
	if (!data)
		goto exit_err;

#ifdef _HAS_STRUCT_RDMA_STAT_DESC
	stat_desc = kzalloc(cnt_num * sizeof(*stat_desc), GFP_KERNEL);
	if (!stat_desc)
		goto free_data;
#endif
	/* copy the strings after the pointers to them */
	ptr = data + cnt_num * sizeof(u8 *);
	memcpy(ptr, cnts_data->names, cnt_num * HL_IB_CNT_NAME_LEN);

	data2 = (u8 **)data;

	/* set the pointers to the strings */
	for (i = 0; i < cnt_num; i++)
		data2[i] = ptr + i * HL_IB_CNT_NAME_LEN;

	port_stats->num = cnt_num;
	port_stats->names = data2;

#ifdef _HAS_STRUCT_RDMA_STAT_DESC
	for (i = 0; i < cnt_num; i++)
		stat_desc[i].name = data2[i];

	port_stats->stat_desc = stat_desc;
#endif

	return 0;
#ifdef _HAS_STRUCT_RDMA_STAT_DESC
free_data:
	kfree(data);
#endif
exit_err:
	return -ENOMEM;
}

static void hl_ib_cnts_fini(struct hl_ib_device *hdev, int port)
{
#ifdef _HAS_STRUCT_RDMA_STAT_DESC
	kfree(hdev->port_stats[port].stat_desc);
#endif
	kfree(hdev->port_stats[port].names);
}

static int hdev_init(struct hl_aux_dev *aux_dev)
{
	struct hl_ib_aux_data *aux_data = aux_dev->aux_data;
	struct hl_ib_device *hdev;
	int rc, i;

#ifdef _HAS_SAFE_IB_ALLOC_DEVICE
	hdev = ib_alloc_device(hl_ib_device, ibdev);
#else
	hdev = (struct hl_ib_device *)ib_alloc_device(sizeof(*hdev));
#endif
	if (!hdev)
		return -ENOMEM;

	aux_dev->priv = hdev;
	hdev->aux_dev = aux_dev;
	hdev->pdev = aux_data->pdev;
	hdev->dev = aux_data->dev;
	hdev->fw_ver = aux_data->fw_ver;
	hdev->ports_mask = aux_data->ports_mask;
	hdev->ext_ports_mask = aux_data->ext_ports_mask;
	hdev->pending_reset_long_timeout = aux_data->pending_reset_long_timeout;
	hdev->id = aux_data->id;
	hdev->max_num_of_ports = aux_data->max_num_of_ports;
	hdev->mixed_qp_wq_types = aux_data->mixed_qp_wq_types;
	hdev->umr_support = aux_data->umr_support;

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

		rc = hl_ib_cnts_init(hdev, i);
		if (rc)
			goto free_cnts;
	}

	return 0;

free_cnts:
	for (--i; i >= 0; i--) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		hl_ib_cnts_fini(hdev, i);
	}
	kfree(hdev->port_stats);
free_ports:
	kfree(hdev->ib_port);
free_device:
	aux_dev->priv = NULL;
	ib_dealloc_device(&hdev->ibdev);

	return rc;
}

static void hdev_fini(struct hl_aux_dev *aux_dev)
{
	struct hl_ib_device *hdev = aux_dev->priv;
	int i;

	for (i = 0; i < hdev->max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		hl_ib_cnts_fini(hdev, i);
	}
	kfree(hdev->port_stats);

	kfree(hdev->ib_port);

	aux_dev->priv = NULL;
	ib_dealloc_device(&hdev->ibdev);
}

#ifdef _HAS_AUX_BUS_H
static const struct auxiliary_device_id hl_ib_id_table[] = {
	{ .name = "habanalabs_cn.ib", },
	{},
};

MODULE_DEVICE_TABLE(auxiliary, hl_ib_id_table);

static int hl_ib_probe(struct auxiliary_device *adev, const struct auxiliary_device_id *id)
{
	struct hl_aux_dev *aux_dev = container_of(adev, struct hl_aux_dev, adev);
	struct hl_ib_aux_ops *aux_ops = aux_dev->aux_ops;
	struct hl_ib_device *hdev;
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
		dev_err(hdev->dev, "Failed to increment %s module refcount\n", HL_IB_NAME);
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

	rc = hl_ib_dev_init(hdev);
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
#ifdef _HAS_AUX_VOID_REMOVE_H
static void hl_ib_remove(struct auxiliary_device *adev)
{
	struct hl_aux_dev *aux_dev = container_of(adev, struct hl_aux_dev, adev);
	struct hl_ib_device *hdev = aux_dev->priv;

	if (!hdev)
		return;

	hl_ib_dev_fini(hdev);

	/* allow module unloading as now it is detached */
	module_put(THIS_MODULE);

	hdev_fini(aux_dev);
}
#else
static int hl_ib_remove(struct auxiliary_device *adev)
{
	struct hl_aux_dev *aux_dev = container_of(adev, struct hl_aux_dev, adev);
	struct hl_ib_device *hdev = aux_dev->priv;

	if (!hdev)
		return 0;

	hl_ib_dev_fini(hdev);

	/* allow module unloading as now it is detached */
	module_put(THIS_MODULE);

	hdev_fini(aux_dev);

	return 0;
}
#endif

static struct auxiliary_driver hl_ib_driver = {
	.name = "ib",
	.probe = hl_ib_probe,
	.remove = hl_ib_remove,
	.id_table = hl_ib_id_table,
};

static int __init hl_ib_init(void)
{
	pr_info("loading driver, version: %s\n", HL_MODULE_VERSION);

	return auxiliary_driver_register(&hl_ib_driver);
}

static void __exit hl_ib_exit(void)
{
	auxiliary_driver_unregister(&hl_ib_driver);

	pr_info("driver removed\n");
}
#else
int hl_ib_probe(struct hl_aux_dev *aux_dev)
{
	struct hl_ib_aux_data *aux_data = aux_dev->aux_data;
	struct hl_ib_device *hdev;
	int rc;

	rc = hdev_init(aux_dev);
	if (rc) {
		dev_err(aux_data->dev, "Failed to init ib hdev\n");
		return rc;
	}

	hdev = aux_dev->priv;

	if (!try_module_get(THIS_MODULE)) {
		dev_err(hdev->dev, "Failed to increment %s module refcount\n", HL_IB_NAME);
		rc = -EIO;
		goto module_get_fail;
	}

	rc = hl_ib_dev_init(hdev);
	if (rc) {
		dev_err(hdev->dev, "Failed to init ib device\n");
		goto dev_init_fail;
	}

	return 0;

dev_init_fail:
	module_put(THIS_MODULE);
module_get_fail:
	hdev_fini(aux_dev);

	return rc;
}
EXPORT_SYMBOL_GPL(hl_ib_probe);

void hl_ib_remove(struct hl_aux_dev *aux_dev)
{
	struct hl_ib_device *hdev = aux_dev->priv;

	if (!hdev)
		return;

	hl_ib_dev_fini(hdev);
	module_put(THIS_MODULE);
	hdev_fini(aux_dev);
}
EXPORT_SYMBOL_GPL(hl_ib_remove);

static int __init hl_ib_init(void)
{
	pr_info("loading driver, version: %s\n", HL_MODULE_VERSION);

	return 0;
}

static void __exit hl_ib_exit(void)
{
	pr_info("driver removed\n");
}
#endif

module_init(hl_ib_init);
module_exit(hl_ib_exit)
