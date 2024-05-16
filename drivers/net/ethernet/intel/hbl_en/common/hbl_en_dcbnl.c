// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#include "hbl_en.h"

#define PFC_PRIO_MASK_ALL	GENMASK(HBL_EN_PFC_PRIO_NUM - 1, 0)
#define PFC_PRIO_MASK_NONE	0

#ifdef CONFIG_DCB
static int hbl_en_dcbnl_ieee_getpfc(struct net_device *netdev, struct ieee_pfc *pfc)
{
	struct hbl_en_port *port = hbl_netdev_priv(netdev);
	struct hbl_en_device *hdev;
	u32 port_idx;

	hdev = port->hdev;
	port_idx = port->idx;

	if (atomic_cmpxchg(&port->in_reset, 0, 1)) {
		dev_dbg_ratelimited(hdev->dev, "port %d is in reset, can't get PFC", port_idx);
		return -EBUSY;
	}

	pfc->pfc_en = port->pfc_enable ? PFC_PRIO_MASK_ALL : PFC_PRIO_MASK_NONE;
	pfc->pfc_cap = HBL_EN_PFC_PRIO_NUM;

	hdev->asic_funcs.get_pfc_cnts(port, pfc);

	atomic_set(&port->in_reset, 0);

	return 0;
}

static int hbl_en_dcbnl_ieee_setpfc(struct net_device *netdev, struct ieee_pfc *pfc)
{
	struct hbl_en_port *port = hbl_netdev_priv(netdev);
	struct hbl_en_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;
	struct hbl_en_device *hdev;
	u8 curr_pfc_en;
	u32 port_idx;
	int rc = 0;

	hdev = port->hdev;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	port_idx = port->idx;

	if (pfc->pfc_en & ~PFC_PRIO_MASK_ALL) {
		dev_dbg_ratelimited(hdev->dev, "PFC supports %d priorities only, port %d\n",
				    HBL_EN_PFC_PRIO_NUM, port_idx);
		return -EINVAL;
	}

	if (pfc->pfc_en != PFC_PRIO_MASK_NONE && pfc->pfc_en != PFC_PRIO_MASK_ALL) {
		dev_dbg_ratelimited(hdev->dev,
				    "PFC should be enabled/disabled on all priorities, port %d\n",
				    port_idx);
		return -EINVAL;
	}

	if (atomic_cmpxchg(&port->in_reset, 0, 1)) {
		dev_dbg_ratelimited(hdev->dev, "port %d is in reset, can't set PFC", port_idx);
		return -EBUSY;
	}

	curr_pfc_en = port->pfc_enable ? PFC_PRIO_MASK_ALL : PFC_PRIO_MASK_NONE;

	if (pfc->pfc_en == curr_pfc_en)
		goto out;

	port->pfc_enable = !port->pfc_enable;

	rc = aux_ops->set_pfc(aux_dev, port_idx, port->pfc_enable);

out:
	atomic_set(&port->in_reset, 0);

	return rc;
}

static u8 hbl_en_dcbnl_getdcbx(struct net_device *netdev)
{
	return DCB_CAP_DCBX_HOST | DCB_CAP_DCBX_VER_IEEE;
}

static u8 hbl_en_dcbnl_setdcbx(struct net_device *netdev, u8 mode)
{
	return !(mode == (DCB_CAP_DCBX_HOST | DCB_CAP_DCBX_VER_IEEE));
}

const struct dcbnl_rtnl_ops hbl_en_dcbnl_ops = {
	.ieee_getpfc	= hbl_en_dcbnl_ieee_getpfc,
	.ieee_setpfc	= hbl_en_dcbnl_ieee_setpfc,
	.getdcbx	= hbl_en_dcbnl_getdcbx,
	.setdcbx	= hbl_en_dcbnl_setdcbx
};
#endif
