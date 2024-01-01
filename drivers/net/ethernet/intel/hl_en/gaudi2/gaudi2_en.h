/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2023-2024, Intel Corporation.
 * Copyright 2021-2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef GAUDI2_EN_H_
#define GAUDI2_EN_H_

#include <linux/net/intel/gaudi2.h>

#include "../common/habanalabs_en.h"

/**
 * struct gaudi2_en_device - Gaudi2 device structure.
 * @ports: array of Gaudi2 ports structures.
 * @aux_data: relevant data from the core device.
 * @aux_ops: pointer functions for core <-> en drivers communication.
 */
struct gaudi2_en_device {
	struct gaudi2_en_port *ports;
	struct gaudi2_en_aux_data *aux_data;
	struct gaudi2_en_aux_ops *aux_ops;
};

/**
 * struct gaudi2_en_port - Gaudi2 port structure.
 * @hdev: habanalabs device structure.
 * @rx_ring: raw skb ring.
 * @cq_ring: packets completion ring.
 * @wq_ring: work queue ring.
 * @tx_buf_info: Tx packets ring.
 * @idx: port index.
 * @tx_buf_info_pi: Tx producer index.
 * @tx_buf_info_ci: Tx consumer index.
 * @fifo_overrrun_err_cnt: error count of fifo overrun
 */
struct gaudi2_en_port {
	struct hl_en_device *hdev;
	struct hl_cn_ring *rx_ring;
	struct hl_cn_ring *cq_ring;
	struct hl_cn_ring *wq_ring;
	struct gaudi2_en_tx_buf *tx_buf_info;
	u32 idx;
	u32 tx_buf_info_pi;
	u32 tx_buf_info_ci;
	u32 fifo_overrun_err_cnt;
};

void gaudi2_en_dcbnl_get_pfc_cnts(struct hl_en_port *port, void *ptr);

#endif /* GAUDI2_EN_H_ */
