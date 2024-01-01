// SPDX-License-Identifier: GPL-2.0

/* Copyright (C) 2023-2024, Intel Corporation.
 * Copyright 2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "gaudi2_cn.h"

int gaudi2_cn_config_wqe_asid(struct hl_cn_port *cn_port, u32 asid, bool set_asid)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	u32 port = cn_port->port;
	int rc = 0;

	/* This is a privilege register that is modified on the go, hence we should disable
	 * assertion on simulator to allow us the modification. At the end of this section we
	 * enable security assertion back.
	 */

	/* change asid to secured asid */
	if (!hdev->cpucp_fw) {
		hl_cn_set_priv_assertions(hdev, false);

		/* set chicken bit before changing asid */
		NIC_WREG32(NIC0_TXE0_CHICKEN_BITS, set_asid ? 0x1 : 0);
		if (set_asid)
			NIC_WREG32(NIC0_TXE0_WQE_FETCH_AXI_USER_LO, asid);

		hl_cn_set_priv_assertions(hdev, true);
	} else {
		rc = hl_cn_send_cpucp_packet(hdev, port, set_asid ? CPUCP_PACKET_NIC_WQE_ASID_SET :
					    CPUCP_PACKET_NIC_WQE_ASID_UNSET, asid);
	}

	if (rc)
		dev_err(hdev->dev, "Failed to %s WQE ASID, port %d, rc %d\n",
			set_asid ? "set" : "unset", port, rc);

	return rc;
}

void gaudi2_cn_override_phy_readiness(struct hl_cn_port *cn_port, bool set_ready)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	u32 port, val, ready_val = 0;

	if (hdev->cpucp_fw)
		return;

	hl_cn_set_priv_assertions(hdev, false);

	port = cn_port->port;

	/* simulator doesn't get an indication elsewhere, therefore mark phy as ready explicitly */
	if (!hdev->phy_config_fw)
		ready_val = NIC0_PHY_PHY_RX_CFG_SW_PHY_READY_MASK |
			    NIC0_PHY_PHY_RX_CFG_SW_PHY_READY_OVERRIDE_MASK;

	val = set_ready ? ready_val : NIC0_PHY_PHY_RX_CFG_SW_PHY_READY_OVERRIDE_MASK;

	if (port & 1) {
		/* odd ports use lanes 2,3 */
		NIC_MACRO_WREG32(NIC0_PHY_PHY_RX_CFG_2, val);
		NIC_MACRO_WREG32(NIC0_PHY_PHY_RX_CFG_3, val);
	} else {
		/* even ports use lanes 0,1 */
		NIC_MACRO_WREG32(NIC0_PHY_PHY_RX_CFG_0, val);
		NIC_MACRO_WREG32(NIC0_PHY_PHY_RX_CFG_1, val);
	}

	hl_cn_set_priv_assertions(hdev, true);
}

int gaudi2_cn_disable_wqe_index_checker_fw(struct hl_cn_port *cn_port)
{
	struct hl_cn_device *hdev = cn_port->hdev;
	u32 port = cn_port->port;
	int rc = 0;

	/* This is a privilege register that is modified on the go, hence we should disable
	 * assertion on simulator to allow us the modification. At the end of this section we
	 * enable security assertion back. We enter this section only if FW security
	 * is not enabled.
	 */
	if (!hdev->cpucp_fw) {
		hl_cn_set_priv_assertions(hdev, false);
		/* Disable the WQE index checker on the RX side */
		NIC_RMWREG32(NIC0_RXE0_RXE_CHECKS, 0,
			     NIC0_RXE0_RXE_CHECKS_WQE_IDX_MISMATCH_EN_MASK);
		/* Disable the WQE index checker on the TX side */
		NIC_RMWREG32(NIC0_TXE0_WQE_CHECK_EN, 0,
			     NIC0_TXE0_WQE_CHECK_EN_WQE_INDEX_EN_MASK);
		hl_cn_set_priv_assertions(hdev, true);
	} else {
		rc = hl_cn_send_cpucp_packet(hdev, port, CPUCP_PACKET_NIC_SET_CHECKERS,
					     RX_WQE_IDX_MISMATCH);

		if (rc) {
			dev_err(hdev->dev,
				"Failed to disable Rx WQE idx mismatch checker, port %d, rc %d\n",
				port, rc);
			return rc;
		}

		rc = hl_cn_send_cpucp_packet(hdev, port, CPUCP_PACKET_NIC_SET_CHECKERS,
					     TX_WQE_IDX_MISMATCH);
		if (rc) {
			dev_err(hdev->dev,
				"Failed to disable Tx WQE idx mismatch checker, port %d, rc %d\n",
				port, rc);
			return rc;
		}
	}

	return rc;
}
