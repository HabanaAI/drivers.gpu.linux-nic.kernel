// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2020-2022 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#include "gaudi2_cn.h"
#include "../include/gaudi2/asic_reg/gaudi2_regs.h"
#include "../include/gaudi2/gaudi2_async_ids_map_extended.h"
#include "../include/hw_ip/nic/nic_general.h"

static bool gaudi2_cn_get_hw_cap(struct hl_device *hdev);

int gaudi2_cn_handle_sw_error_event(struct hl_device *hdev, u16 event_type, u8 macro_index,
					struct hl_eq_nic_intr_cause *nic_intr_cause)
{
	struct hbl_aux_dev *aux_dev = &hdev->cn.cn_aux_dev;
	struct gaudi2_device *gaudi2 = hdev->asic_specific;
	struct gaudi2_cn_aux_ops *aux_ops = &gaudi2->cn_aux_ops;
	u32 error_count = 0;

	if (aux_ops->sw_err_event_handler)
		error_count = aux_ops->sw_err_event_handler(aux_dev, event_type, macro_index,
								nic_intr_cause);

	return error_count;
}

int gaudi2_cn_handle_axi_error_response_event(struct hl_device *hdev, u16 event_type,
						u8 macro_index,
						struct hl_eq_nic_intr_cause *nic_intr_cause)
{
	struct hbl_aux_dev *aux_dev = &hdev->cn.cn_aux_dev;
	struct gaudi2_device *gaudi2 = hdev->asic_specific;
	struct gaudi2_cn_aux_ops *aux_ops = &gaudi2->cn_aux_ops;
	u32 error_count = 0;

	if (aux_ops->axi_error_response_event_handler)
		error_count = aux_ops->axi_error_response_event_handler(aux_dev, event_type,
									macro_index,
									nic_intr_cause);

	return error_count;
}

/**
 * gaudi2_cn_disable_interrupts() - Disable interrupts of all ports.
 * Gaudi2 CN interrupts are enabled by default, need to disable them ASAP
 * before ports init and after hard reset.
 *
 * @hdev: habanalabs device structure.
 */
void gaudi2_cn_disable_interrupts(struct hl_device *hdev)
{
	u32 port;

	if (!hdev->cn.ports_mask)
		return;

	/* we only need the port number for NIC_WREG32 */
	for (port = 0 ; port < NIC_NUMBER_OF_PORTS ; port++) {
		NIC_WREG32(mmNIC0_QPC0_EVENT_QUE_CFG, 0);
		NIC_WREG32(mmNIC0_QPC0_INTERRUPT_EN, 0);
		NIC_WREG32(mmNIC0_QPC0_INTERRUPT_MASK, 0xFFFFFFFF);

		/* This registers needs to be configured only in case of PLDM */
		if (hdev->pldm) {
			NIC_WREG32(mmNIC0_QPC0_INTERRUPT_RESP_ERR_MASK, 0xFFFFFFFF);
			NIC_WREG32(mmNIC0_TXE0_INTERRUPT_MASK, 0xFFFFFFFF);
			NIC_WREG32(mmNIC0_RXE0_SPI_INTR_MASK, 0xFFFFFFFF);
			NIC_WREG32(mmNIC0_RXE0_SEI_INTR_MASK, 0xFFFFFFFF);
			NIC_WREG32(mmNIC0_TXS0_INTERRUPT_MASK, 0xFFFFFFFF);
		}

		/* WA for H/W bug H6-3339 - mask the link UP interrupt */
		NIC_MACRO_WREG32(mmNIC0_PHY_PHY_LINK_STS_INTR, 0x1);
	}

	/* flush */
	port = 0;
	NIC_RREG32(mmNIC0_QPC0_EVENT_QUE_CFG);
}

/**
 * gaudi2_cn_quiescence() - make sure that NIC does not generate events nor
 *                           receives traffic.
 * Gaudi2 default values at power-up and after hard-reset are interrupts enabled
 * and Rx enabled, we need to disable them until driver configuration is
 * complete.
 *
 * @hdev: habanalabs device structure.
 */
void gaudi2_cn_quiescence(struct hl_device *hdev)
{
	/*
	 * Do not quiescence the ports during device release
	 * reset aka soft reset flow.
	 */
	if (gaudi2_cn_get_hw_cap(hdev))
		return;

	dev_dbg(hdev->dev, "Quiescence the NICs\n");

	gaudi2_cn_disable_interrupts(hdev);
}

static bool gaudi2_cn_get_hw_cap(struct hl_device *hdev)
{
	struct gaudi2_device *gaudi2 = hdev->asic_specific;

	return (gaudi2->hw_cap_initialized & HW_CAP_NIC_DRV);
}

static void gaudi2_cn_set_hw_cap(struct hl_device *hdev, bool enable)
{
	struct gaudi2_device *gaudi2 = hdev->asic_specific;

	if (enable)
		gaudi2->hw_cap_initialized |= HW_CAP_NIC_DRV;
	else
		gaudi2->hw_cap_initialized &= ~HW_CAP_NIC_DRV;
}

/**
 * gaudi2_cn_override_ports_ext_mask() - Set the external ports mask.
 * @hdev: Hl device whose external ports mask to return.
 * @ports_ext_mask: Out, the external ports mask.
 */
static void gaudi2_cn_override_ports_ext_mask(struct hl_device *hdev, uint64_t *ports_ext_mask)
{
	/* For asic type GAUDI2B, the external ports mask shouldn't be changed */
	if (hdev->asic_type == ASIC_GAUDI2B) {
		*ports_ext_mask = hdev->cn.ports_ext_mask;
		return;
	}

	/* If we are running on a PCI card, all the ports should be set as external */
	if (hdev->card_type == cpucp_card_type_pci) {
		*ports_ext_mask = hdev->cn.ports_mask;
		return;
	}

	/* For HLS2 setup type, the external ports mask shouldn't be changed */
	*ports_ext_mask = hdev->cn.ports_ext_mask;
}

static int gaudi2_cn_check_oui_prefix_validity(u8 *mac_addr)
{
	u8 mac[ETH_ALEN];
	int i;

	for (i = 0 ; i < 3 ; i++)
		mac[i] = HABANALABS_MAC_OUI_1 >> (8 * (2 - i));

	if (!strncmp(mac, mac_addr, 3))
		return 1;

	for (i = 0 ; i < 3 ; i++)
		mac[i] = HABANALABS_MAC_OUI_2 >> (8 * (2 - i));

	if (!strncmp(mac, mac_addr, 3))
		return 1;

	return 0;
}

int gaudi2_cn_set_info(struct hl_device *hdev, bool get_from_fw)
{
	struct hbl_cn_cpucp_info *cn_cpucp_info = &hdev->asic_prop.cn_props.cpucp_info;
	struct cpucp_info *cpucp_info = &hdev->asic_prop.cpucp_info;
	struct hbl_cn_cpucp_mac_addr *mac_arr = cn_cpucp_info->mac_addrs;
	struct hl_cn *cn = &hdev->cn;
	u32 serdes_type = MAX_NUM_SERDES_TYPE;
	u8 mac[ETH_ALEN], *mac_addr;
	int rc, i;

	/* copy the MAC OUI in reverse */
	for (i = 0 ; i < 3 ; i++)
		mac[i] = HABANALABS_MAC_OUI_1 >> (8 * (2 - i));

	if (get_from_fw) {
		rc = hl_cn_cpucp_info_get(hdev);
		if (rc)
			return rc;

		cn->ports_mask &= cn_cpucp_info->link_mask[0];
		cn->ports_ext_mask &= cn_cpucp_info->link_ext_mask[0];
		cn->auto_neg_mask &= cn_cpucp_info->auto_neg_mask[0];

		serdes_type = cn_cpucp_info->serdes_type;

		/* check for invalid MAC addresses from F/W (bad OUI) */
		for (i = 0 ; i < NIC_NUMBER_OF_PORTS ; i++) {
			if (!(cn->ports_mask & BIT(i)))
				continue;

			mac_addr = mac_arr[i].mac_addr;
			if (!gaudi2_cn_check_oui_prefix_validity(mac_addr))
				dev_warn(hdev->dev, "unrecognized MAC OUI %pM, port %d\n",
					mac_addr, i);
		}

		cn->card_location = le32_to_cpu(cpucp_info->card_location);
		cn->use_fw_serdes_info = true;
	} else {
		/* No F/W, hence need to set the MACs manually (randomize) */
		get_random_bytes(&mac[3], 2);

		for (i = 0 ; i < NIC_NUMBER_OF_PORTS ; i++) {
			if (!(cn->ports_mask & BIT(i)))
				continue;

			mac[ETH_ALEN - 1] = i;
			memcpy(mac_arr[i].mac_addr, mac, ETH_ALEN);
		}

		dev_warn(hdev->dev, "can't read card location as FW security is enabled\n");
	}

	switch (serdes_type) {
	case HLS2_SERDES_TYPE:
		hdev->asic_prop.server_type = HL_SERVER_GAUDI2_HLS2;
		break;
	case HLS2_TYPE_1_SERDES_TYPE:
		hdev->asic_prop.server_type = HL_SERVER_GAUDI2_TYPE1;
		break;
	default:
		hdev->asic_prop.server_type = HL_SERVER_TYPE_UNKNOWN;

		if (get_from_fw) {
			dev_err(hdev->dev, "bad SerDes type %d\n", serdes_type);
			return -EFAULT;
		}
		break;
	}

	/* If we are running on non HLS2 setup or a PCI card, all the ports should be set as
	 * external (the only exception is when the asic type is GADUI2B).
	 */
	if (hdev->card_type == cpucp_card_type_pci) {
		if (hdev->asic_type != ASIC_GAUDI2B)
			cn->ports_ext_mask = cn->ports_mask;

		cn->auto_neg_mask &= ~cn->ports_ext_mask;
	}

	gaudi2_cn_override_ports_ext_mask(hdev, &cn->ports_ext_mask);

	if (hdev->card_type == cpucp_card_type_pci)
		cn->auto_neg_mask &= ~cn->ports_ext_mask;

	/* Disable ANLT on NIC 0 ports (due to lane swapping) */
	cn->auto_neg_mask &= ~0x3;

	cn->lanes_per_port = 2;
	cn->load_fw = false;
	cn->eth_on_internal = false;

	return 0;
}

static int gaudi2_cn_pre_core_init(struct hl_device *hdev)
{
	return 0;
}

static char *gaudi2_cn_get_event_name(struct hbl_aux_dev *aux_dev, u16 event_type)
{
	return gaudi2_irq_map_table[event_type].valid ? gaudi2_irq_map_table[event_type].name :
			"N/A Event";
}

static int gaudi2_cn_poll_mem(struct hbl_aux_dev *aux_dev, u32 *addr, u32 *val,
				hbl_cn_poll_cond_func func)
{
	return hl_poll_timeout_memory(hdev, addr, *val, func(*val, NULL), 10,
					HL_DEVICE_TIMEOUT_USEC, true);
}

static void *gaudi2_cn_dma_alloc_coherent(struct hbl_aux_dev *aux_dev, size_t size,
					  dma_addr_t *dma_handle, gfp_t flag)
{
	return hl_cn_dma_alloc_coherent(aux_dev, size, dma_handle, flag);
}

static void gaudi2_cn_dma_free_coherent(struct hbl_aux_dev *aux_dev, size_t size, void *cpu_addr,
					dma_addr_t dma_handle)
{
	hl_cn_dma_free_coherent(aux_dev, size, cpu_addr, dma_handle);
}

static void *gaudi2_cn_dma_pool_zalloc(struct hbl_aux_dev *aux_dev, size_t size, gfp_t mem_flags,
				       dma_addr_t *dma_handle)
{
	return hl_cn_dma_pool_zalloc(aux_dev, size, mem_flags, dma_handle);
}

static void gaudi2_cn_dma_pool_free(struct hbl_aux_dev *aux_dev, void *vaddr, dma_addr_t dma_addr)
{
	hl_cn_dma_pool_free(aux_dev, vaddr, dma_addr);
}

static void gaudi2_cn_set_cn_data(struct hl_device *hdev)
{
	struct gaudi2_device *gaudi2 = hdev->asic_specific;
	struct gaudi2_cn_aux_data *gaudi2_aux_data;
	struct gaudi2_cn_aux_ops *gaudi2_aux_ops;
	struct hbl_cn_aux_data *aux_data;
	struct hbl_cn_aux_ops *aux_ops;
	struct hl_cn *cn = &hdev->cn;
	struct hbl_aux_dev *aux_dev;

	aux_dev = &cn->cn_aux_dev;
	aux_data = aux_dev->aux_data;
	gaudi2_aux_data = &gaudi2->cn_aux_data;
	aux_data->asic_specific = gaudi2_aux_data;
	aux_ops = aux_dev->aux_ops;
	gaudi2_aux_ops = &gaudi2->cn_aux_ops;
	aux_ops->asic_ops = gaudi2_aux_ops;

	gaudi2_aux_data->cfg_base = CFG_BASE;
	gaudi2_aux_data->fw_security_enabled = hdev->asic_prop.fw_security_enabled;
	gaudi2_aux_data->msix_enabled = !!(gaudi2->hw_cap_initialized & HW_CAP_MSIX);
	gaudi2_aux_data->irq_num_port_base = GAUDI2_IRQ_NUM_NIC_PORT_FIRST;
	gaudi2_aux_data->sob_id_base = GAUDI2_RESERVED_SOB_NIC_PORT_FIRST;
	gaudi2_aux_data->sob_inc_cfg_val = GAUDI2_SOB_INCREMENT_BY_ONE;
	gaudi2_aux_data->setup_type = GAUDI2_SETUP_TYPE_HLS2;

	/* cn2accel */
	gaudi2_aux_ops->get_event_name = gaudi2_cn_get_event_name;
	gaudi2_aux_ops->poll_mem = gaudi2_cn_poll_mem;
	gaudi2_aux_ops->dma_alloc_coherent = gaudi2_cn_dma_alloc_coherent;
	gaudi2_aux_ops->dma_free_coherent = gaudi2_cn_dma_free_coherent;
	gaudi2_aux_ops->dma_pool_zalloc = gaudi2_cn_dma_pool_zalloc;
	gaudi2_aux_ops->dma_pool_free = gaudi2_cn_dma_pool_free;
	gaudi2_aux_ops->spmu_get_stats_info = hl_cn_spmu_get_stats_info;
	gaudi2_aux_ops->spmu_config = hl_cn_spmu_config;
	gaudi2_aux_ops->spmu_sample = hl_cn_spmu_sample;
	gaudi2_aux_ops->poll_reg = hl_cn_poll_reg;
	gaudi2_aux_ops->send_cpu_message = hl_cn_send_cpu_message;
	gaudi2_aux_ops->post_send_status = hl_cn_post_send_status;
}

void gaudi2_cn_compute_reset_prepare(struct hl_device *hdev)
{
	struct gaudi2_device *gaudi2 = hdev->asic_specific;
	struct gaudi2_cn_aux_ops *gaudi2_aux_ops;
	struct hl_cn *cn = &hdev->cn;
	struct hbl_aux_dev *aux_dev;

	aux_dev = &cn->cn_aux_dev;
	gaudi2_aux_ops = &gaudi2->cn_aux_ops;

	if (gaudi2_aux_ops->reset_prepare)
		gaudi2_aux_ops->reset_prepare(aux_dev);
}

void gaudi2_cn_compute_reset_late_init(struct hl_device *hdev)
{
	struct gaudi2_device *gaudi2 = hdev->asic_specific;
	struct gaudi2_cn_aux_ops *gaudi2_aux_ops;
	struct hl_cn *cn = &hdev->cn;
	struct hbl_aux_dev *aux_dev;

	aux_dev = &cn->cn_aux_dev;
	gaudi2_aux_ops = &gaudi2->cn_aux_ops;

	if (gaudi2_aux_ops->reset_late_init)
		gaudi2_aux_ops->reset_late_init(aux_dev);
}

static void gaudi2_cn_post_send_status(struct hl_device *hdev, u32 port)
{
	hl_fw_unmask_irq(hdev, GAUDI2_EVENT_CPU0_STATUS_NIC0_ENG0 + port);
}

static void gaudi2_cn_ports_stop_prepare(struct hl_device *hdev, bool fw_reset, bool in_teardown)
{
	struct gaudi2_device *gaudi2 = hdev->asic_specific;
	struct gaudi2_cn_aux_ops *gaudi2_aux_ops;
	struct hl_cn *cn = &hdev->cn;
	struct hbl_aux_dev *aux_dev;

	aux_dev = &cn->cn_aux_dev;
	gaudi2_aux_ops = &gaudi2->cn_aux_ops;

	if (gaudi2_aux_ops->ports_stop_prepare)
		gaudi2_aux_ops->ports_stop_prepare(aux_dev, fw_reset, in_teardown);
}

static int gaudi2_cn_send_port_cpucp_status(struct hl_device *hdev, u32 port, u8 cmd, u8 period)
{
	struct gaudi2_device *gaudi2 = hdev->asic_specific;
	struct gaudi2_cn_aux_ops *gaudi2_aux_ops;
	struct hl_cn *cn = &hdev->cn;
	struct hbl_aux_dev *aux_dev;

	aux_dev = &cn->cn_aux_dev;
	gaudi2_aux_ops = &gaudi2->cn_aux_ops;

	if (gaudi2_aux_ops->send_port_cpucp_status)
		return gaudi2_aux_ops->send_port_cpucp_status(aux_dev, port, cmd, period);

	return -ENODEV;
}

static struct hl_cn_port_funcs gaudi2_cn_port_funcs = {
	.spmu_get_stats_info = gaudi2_cn_spmu_get_stats_info,
	.spmu_config = gaudi2_cn_spmu_config,
	.spmu_sample = gaudi2_cn_spmu_sample,
	.post_send_status = gaudi2_cn_post_send_status,
	.ports_stop_prepare = gaudi2_cn_ports_stop_prepare,
	.send_port_cpucp_status = gaudi2_cn_send_port_cpucp_status,
};

struct hl_cn_funcs gaudi2_cn_funcs = {
	.get_hw_cap = gaudi2_cn_get_hw_cap,
	.set_hw_cap = gaudi2_cn_set_hw_cap,
	.pre_core_init = gaudi2_cn_pre_core_init,
	.set_cn_data = gaudi2_cn_set_cn_data,
	.port_funcs = &gaudi2_cn_port_funcs,
};
