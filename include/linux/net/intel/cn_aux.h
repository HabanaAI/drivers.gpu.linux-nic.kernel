/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#ifndef HBL_CN_AUX_H_
#define HBL_CN_AUX_H_

#include <linux/irqreturn.h>
#include <linux/habanalabs/cpucp_if.h>
#include <linux/auxiliary_bus.h>
#include <linux/if_vlan.h>
#include <uapi/linux/ethtool.h>

#define HBL_EN_MAX_HEADERS_SZ	(ETH_HLEN + 2 * VLAN_HLEN + ETH_FCS_LEN)

/* driver specific value, should always be >= asic specific h/w resource */
#define NIC_DRV_MAX_CQS_NUM	32
#define NIC_DRV_MAX_CCQS_NUM	4
#define NIC_DRV_NUM_DB_FIFOS	32

/**
 * enum hbl_cn_asic_type - supported ASIC types.
 * @ASIC_GAUDI2: Gaudi2 device.
 */
enum hbl_cn_asic_type {
	HBL_ASIC_GAUDI2,
};

/**
 * enum hbl_cn_status_cmd - status cmd type.
 * @HBL_CN_STATUS_ONE_SHOT: one shot command.
 * @HBL_CN_STATUS_PERIODIC_START: start periodic status update.
 * @HBL_CN_STATUS_PERIODIC_STOP: stop periodic status update.
 */
enum hbl_cn_status_cmd {
	HBL_CN_STATUS_ONE_SHOT,
	HBL_CN_STATUS_PERIODIC_START,
	HBL_CN_STATUS_PERIODIC_STOP,
};

/**
 * enum hbl_aux_dev_type - auxiliary device type.
 * HBL_AUX_DEV_CN: Shared Network Interface.
 * HBL_AUX_DEV_ETH: Ethernet.
 * HBL_AUX_DEV_IB: InfiniBand.
 */
enum hbl_aux_dev_type {
	HBL_AUX_DEV_CN,
	HBL_AUX_DEV_ETH,
	HBL_AUX_DEV_IB,
};

/**
 * struct hbl_aux_dev - habanalabs auxiliary device structure.
 * @adev: auxiliary device.
 * @aux_ops: pointer functions for drivers communication.
 * @aux_data: essential data for operating the auxiliary device.
 * @priv: auxiliary device private data.
 * @type: type of the auxiliary device.
 */
struct hbl_aux_dev {
	struct auxiliary_device adev;
	void *aux_ops;
	void *aux_data;
	void *priv;
	enum hbl_aux_dev_type type;
};

/**
 * struct hbl_cn_stat - Holds ASIC specific statistics string and default register offset.
 * @str: String name of ethtool stat.
 * @lo_offset: Register offset of the stat.
 * @hi_offset: High register offset. May be unused for some stats.
 */
struct hbl_cn_stat {
	char str[ETH_GSTRING_LEN];
	int lo_offset;
	int hi_offset;
};

/*
 * struct hbl_cn_cpucp_mac_addr - port MAC address received from FW.
 * @mac_addr: port MAC address.
 */
struct hbl_cn_cpucp_mac_addr {
	u8 mac_addr[ETH_ALEN];
};

/*
 * struct hbl_cn_cpucp_info - info received from FW.
 * @mac_addrs: array of MAC address for all physical ports.
 * @link_mask: mask of available ports.
 * @pol_tx_mask: array of Tx polarity value for all ports.
 * @pol_rx_mask: array of Rx polarity value for all ports.
 * @link_ext_mask: mask of external ports.
 * @qsfp_eeprom: QSFP EEPROM info.
 * @auto_neg_mask: mask of ports which supports Autonegotiation.
 * @serdes_type: type of serdes.
 * @tx_swap_map: lane swapping map.
 */
struct hbl_cn_cpucp_info {
	struct hbl_cn_cpucp_mac_addr mac_addrs[CPUCP_MAX_NICS];
	u64 link_mask[CPUCP_NIC_MASK_ARR_LEN];
	u64 pol_tx_mask[CPUCP_NIC_POLARITY_ARR_LEN];
	u64 pol_rx_mask[CPUCP_NIC_POLARITY_ARR_LEN];
	u64 link_ext_mask[CPUCP_NIC_MASK_ARR_LEN];
	u8 qsfp_eeprom[CPUCP_NIC_QSFP_EEPROM_MAX_LEN];
	u64 auto_neg_mask[CPUCP_NIC_MASK_ARR_LEN];
	enum cpucp_serdes_type serdes_type;
	u16 tx_swap_map[CPUCP_MAX_NICS];
};

/**
 * struct hbl_cn_aux_data - habanalabs data for the cn driver.
 * @pdev: pointer to PCI device.
 * @dev: related kernel basic device structure.
 * @asic_specific: ASIC specific data.
 * @fw_ver: FW version.
 * @asic_type: ASIC specific type.
 * @ports_mask: mask of available ports.
 * @ext_ports_mask: mask of external ports (subset of ports_mask).
 * @auto_neg_mask: mask of ports with Autonegotiation enabled.
 * @dram_size: available DRAM size.
 * @nic_drv_addr: base address for NIC driver on DRAM.
 * @nic_drv_size: driver size reserved for NIC driver on DRAM.
 * @macro_cfg_size: the size of the macro configuration space.
 * @max_num_of_ports: max number of available ports.
 * @pending_reset_long_timeout: long timeout for pending hard reset to finish in seconds.
 * @kernel_asid: kernel ASID.
 * @card_location: the OAM number in the HLS (relevant for PMC card type).
 * @device_timeout: device access timeout in usec.
 * @fw_major_version: major version of current loaded preboot.
 * @fw_minor_version: minor version of current loaded preboot.
 * @fw_app_cpu_boot_dev_sts0: bitmap representation of application security
 *                            status reported by FW, bit description can be
 *                            found in CPU_BOOT_DEV_STS0
 * @fw_app_cpu_boot_dev_sts1: bitmap representation of application security
 *                            status reported by FW, bit description can be
 *                            found in CPU_BOOT_DEV_STS1
 * @id: device ID.
 * @cache_line_size: device cache line size.
 * @clk: clock frequency in MHz.
 * @pldm: is running on Palladium setup.
 * @skip_phy_init: avoid writing/reading PHY registers.
 * @load_phy_fw: load PHY F/W.
 * @cpucp_fw: is CPUCP FW enabled.
 * @supports_coresight: is CoreSight supported.
 * @use_fw_serdes_info: true if FW serdes values should be used, false if hard coded values should
 *                      be used.
 * @mmu_enable: is MMU enabled.
 * @lanes_per_port: number of physical lanes per port.
 * @cpucp_checkers_shift: CPUCP checkers flags shift.
 */
struct hbl_cn_aux_data {
	struct pci_dev *pdev;
	struct device *dev;
	void *asic_specific;
	char *fw_ver;
	enum hbl_cn_asic_type asic_type;
	u64 ports_mask;
	u64 ext_ports_mask;
	u64 auto_neg_mask;
	u64 dram_size;
	u64 nic_drv_addr;
	u64 nic_drv_size;
	u32 macro_cfg_size;
	u32 pending_reset_long_timeout;
	u32 kernel_asid;
	u32 card_location;
	u32 device_timeout;
	u32 fw_major_version;
	u32 fw_minor_version;
	u32 fw_app_cpu_boot_dev_sts0;
	u32 fw_app_cpu_boot_dev_sts1;
	u16 id;
	u16 cache_line_size;
	u16 clk;
	u8 pldm;
	u8 skip_phy_init;
	u8 load_phy_fw;
	u8 cpucp_fw;
	u8 supports_coresight;
	u8 use_fw_serdes_info;
	u8 mmu_enable;
	u8 lanes_per_port;
	u8 cpucp_checkers_shift;
};

/**
 * enum hbl_cn_mmu_mode - MMU modes the CN can work with.
 * @HBL_CN_MMU_MODE_EXTERNAL: using external MMU HW IP.
 * @HBL_CN_MMU_MODE_NETWORK_TLB: Using internal network TLB (but external page-table).
 */
enum hbl_cn_mmu_mode {
	HBL_CN_MMU_MODE_EXTERNAL,
	HBL_CN_MMU_MODE_NETWORK_TLB,
};

/**
 * struct hbl_cn_vm_info - VM related info for the cn driver.
 * @mmu_mode: the type (or mode) of MMU currently configured.
 * @ext_mmu.work_id: the unique work-ID assigned to this VM when in external MMU mode.
 * @net_tlb.pasid: the PCI process space address ID assigned to the device.
 * @net_tlb.page_tbl_addr: the address of the MMU page table of this VM.
 */
struct hbl_cn_vm_info {
	enum hbl_cn_mmu_mode mmu_mode;
	union {
		struct {
			u32 work_id;
		} ext_mmu;

		struct {
			u32 pasid;
			u64 page_tbl_addr;
		} net_tlb;
	};
};

typedef bool (*hbl_cn_poll_cond_func)(u32 val, void *arg);

enum hbl_cn_mem_type {
	HBL_CN_MEM_TYPE_HOST,
	HBL_CN_MEM_TYPE_DEVICE,
};

/**
 * struct hbl_cn_aux_ops - pointer functions for cn <-> compute drivers communication.
 * @device_operational: is device operational.
 * @hw_access_lock: prevent HW access.
 * @hw_access_unlock: allow HW access.
 * @device_reset: Perform device reset.
 * @vm_dev_mmu_map: map cpu/kernel address or device memory range to device address range in order
 *                  to provide device-memory access.
 * @vm_dev_mmu_unmap: unmap a previously mapped address range.
 * @vm_reserve_dva_block: Reserve a device virtual block of a given size.
 * @vm_unreserve_dva_block: Release a given device virtual block.
 * @dram_readl: Read long from DRAM.
 * @dram_writel: Write long to DRAM.
 * @rreg: Read register.
 * @wreg: Write register.
 * @get_reg_pcie_addr: Retrieve pci address.
 * @poll_reg: Poll on a register until a given condition is fulfilled or timeout.
 * @get_cpucp_info: fetch updated CPUCP info.
 * @register_cn_user_context: register a user context represented by user provided FD. If the
 *                            returned comp_handle and vm_handle are equal then this context doesn't
 *                            support data transfer.
 * @deregister_cn_user_context: de-register the user context represented by the vm_handle returned
 *                              from calling register_cn_user_context.
 * @vm_create: create a VM in registered context.
 * @vm_destroy: destroy a VM in registered context.
 * @get_vm_info: get information on a VM.
 * @ports_reopen: reopen the ports after hard reset.
 * @ports_stop_prepare: prepare the ports for a stop.
 * @ports_stop: stop traffic.
 * @synchronize_irqs: Synchronize IRQs.
 * @asic_ops: pointer for ASIC specific ops struct.
 */
struct hbl_cn_aux_ops {
	/* cn2compute */
	bool (*device_operational)(struct hbl_aux_dev *aux_dev);
	void (*hw_access_lock)(struct hbl_aux_dev *aux_dev);
	void (*hw_access_unlock)(struct hbl_aux_dev *aux_dev);
	void (*device_reset)(struct hbl_aux_dev *aux_dev);
	int (*vm_dev_mmu_map)(struct hbl_aux_dev *aux_dev, u64 vm_handle,
			      enum hbl_cn_mem_type mem_type, u64 addr, u64 dva, size_t size);
	void (*vm_dev_mmu_unmap)(struct hbl_aux_dev *aux_dev, u64 vm_handle, u64 dva, size_t size);
	int (*vm_reserve_dva_block)(struct hbl_aux_dev *aux_dev, u64 vm_handle, u64 size, u64 *dva);
	void (*vm_unreserve_dva_block)(struct hbl_aux_dev *aux_dev, u64 vm_handle, u64 dva,
				       u64 size);
	u32 (*dram_readl)(struct hbl_aux_dev *aux_dev, u64 addr);
	void (*dram_writel)(struct hbl_aux_dev *aux_dev, u32 val, u64 addr);
	u32 (*rreg)(struct hbl_aux_dev *aux_dev, u32 reg);
	void (*wreg)(struct hbl_aux_dev *aux_dev, u32 reg, u32 val);
	int (*get_reg_pcie_addr)(struct hbl_aux_dev *aux_dev, u32 reg, u64 *pci_addr);
	int (*poll_reg)(struct hbl_aux_dev *aux_dev, u32 reg, u64 timeout_us,
			hbl_cn_poll_cond_func func, void *arg);
	void (*get_cpucp_info)(struct hbl_aux_dev *aux_dev,
			       struct hbl_cn_cpucp_info *hbl_cn_cpucp_info);
	int (*register_cn_user_context)(struct hbl_aux_dev *aux_dev, int user_fd,
					const void *cn_ctx, u64 *comp_handle, u64 *vm_handle);
	void (*deregister_cn_user_context)(struct hbl_aux_dev *aux_dev, u64 vm_handle);
	int (*vm_create)(struct hbl_aux_dev *aux_dev, u64 comp_handle, u32 flags, u64 *vm_handle);
	void (*vm_destroy)(struct hbl_aux_dev *aux_dev, u64 vm_handle);
	int (*get_vm_info)(struct hbl_aux_dev *aux_dev, u64 vm_handle,
			   struct hbl_cn_vm_info *vm_info);

	/* compute2cn */
	int (*ports_reopen)(struct hbl_aux_dev *aux_dev);
	void (*ports_stop_prepare)(struct hbl_aux_dev *aux_dev, bool fw_reset, bool in_teardown);
	void (*ports_stop)(struct hbl_aux_dev *aux_dev);
	void (*synchronize_irqs)(struct hbl_aux_dev *aux_dev);
	void *asic_ops;
};

#endif /* HBL_CN_AUX_H_ */
