// SPDX-License-Identifier: GPL-2.0

/* Copyright (C) 2023-2024, Intel Corporation.
 * Copyright 2021-2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "gaudi2_en.h"

void gaudi2_en_dcbnl_get_pfc_cnts(struct hl_en_port *port, void *ptr)
{
#ifdef CONFIG_DCB
	struct hl_en_device *hdev = port->hdev;
	struct gaudi2_en_aux_ops *asic_aux_ops;
	struct hl_en_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;
	struct ieee_pfc *pfc = ptr;
	u64 indications, requests;
	u32 port_idx = port->idx;
	int pfc_prio;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	asic_aux_ops = aux_ops->asic_ops;

	for (pfc_prio = 0; pfc_prio < HL_EN_PFC_PRIO_NUM; pfc_prio++) {
		asic_aux_ops->get_pfc_cnts(aux_dev, port_idx, pfc_prio, &indications, &requests);

		pfc->indications[pfc_prio] = indications;
		pfc->requests[pfc_prio] = requests;
	}
#endif
}
