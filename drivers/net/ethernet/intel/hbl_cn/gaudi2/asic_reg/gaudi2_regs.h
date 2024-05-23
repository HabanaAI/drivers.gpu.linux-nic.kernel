/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 *
 */

#ifndef ASIC_REG_GAUDI2_REGS_H_
#define ASIC_REG_GAUDI2_REGS_H_

#include "arc_farm_kdma_ctx_axuser_masks.h"
#include "dcore0_sync_mngr_objs_regs.h"
#include "gaudi2_blocks_linux_driver.h"
#include "nic0_mac_ch0_mac_128_masks.h"
#include "nic0_mac_ch0_mac_128_regs.h"
#include "nic0_mac_ch0_mac_pcs_masks.h"
#include "nic0_mac_ch0_mac_pcs_regs.h"
#include "nic0_mac_ch1_mac_pcs_regs.h"
#include "nic0_mac_ch2_mac_pcs_regs.h"
#include "nic0_mac_ch3_mac_pcs_regs.h"
#include "nic0_mac_glob_stat_control_reg_masks.h"
#include "nic0_mac_glob_stat_control_reg_regs.h"
#include "nic0_mac_glob_stat_rx0_regs.h"
#include "nic0_mac_glob_stat_rx2_regs.h"
#include "nic0_mac_glob_stat_tx0_regs.h"
#include "nic0_mac_glob_stat_tx2_regs.h"
#include "nic0_mac_rs_fec_regs.h"
#include "nic0_phy_masks.h"
#include "nic0_phy_regs.h"
#include "nic0_qm0_axuser_nonsecured_regs.h"
#include "nic0_qpc0_axuser_cong_que_regs.h"
#include "nic0_qpc0_axuser_db_fifo_regs.h"
#include "nic0_qpc0_axuser_err_fifo_regs.h"
#include "nic0_qpc0_axuser_ev_que_lbw_intr_regs.h"
#include "nic0_qpc0_axuser_qpc_req_regs.h"
#include "nic0_qpc0_axuser_qpc_resp_regs.h"
#include "nic0_qpc0_axuser_rxwqe_regs.h"
#include "nic0_qpc0_axuser_txwqe_lbw_qman_bp_regs.h"
#include "nic0_qpc0_dbfifo0_ci_upd_addr_regs.h"
#include "nic0_qpc0_dbfifosecur_ci_upd_addr_regs.h"
#include "nic0_qpc0_masks.h"
#include "nic0_qpc0_regs.h"
#include "nic0_qpc1_regs.h"
#include "nic0_rxb_core_masks.h"
#include "nic0_rxb_core_regs.h"
#include "nic0_rxe0_axuser_axuser_cq0_regs.h"
#include "nic0_rxe0_axuser_axuser_cq1_regs.h"
#include "nic0_rxe0_masks.h"
#include "nic0_rxe0_regs.h"
#include "nic0_rxe0_wqe_aruser_regs.h"
#include "nic0_rxe1_regs.h"
#include "nic0_serdes0_masks.h"
#include "nic0_serdes0_regs.h"
#include "nic0_serdes1_regs.h"
#include "nic0_tmr_axuser_tmr_fifo_regs.h"
#include "nic0_tmr_axuser_tmr_free_list_regs.h"
#include "nic0_tmr_axuser_tmr_fsm_regs.h"
#include "nic0_tmr_masks.h"
#include "nic0_tmr_regs.h"
#include "nic0_txb_regs.h"
#include "nic0_txe0_masks.h"
#include "nic0_txe0_regs.h"
#include "nic0_txs0_masks.h"
#include "nic0_txs0_regs.h"
#include "nic0_umr0_0_completion_queue_ci_1_regs.h"
#include "nic0_umr0_0_unsecure_doorbell0_regs.h"
#include "nic0_umr0_0_unsecure_doorbell1_regs.h"
#include "prt0_mac_core_masks.h"
#include "prt0_mac_core_regs.h"

#define NIC_OFFSET	(NIC1_MSTR_IF_RR_SHRD_HBW_BASE - NIC0_MSTR_IF_RR_SHRD_HBW_BASE)

#define NIC_UMR_OFFSET \
	(NIC0_UMR0_1_UNSECURE_DOORBELL0_BASE - NIC0_UMR0_0_UNSECURE_DOORBELL0_BASE)

#endif /* ASIC_REG_GAUDI2_REGS_H_ */
