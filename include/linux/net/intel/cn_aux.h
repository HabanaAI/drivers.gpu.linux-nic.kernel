/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2023-2024, Intel Corporation.
 * Copyright 2021-2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef HL_CN_AUX_H_
#define HL_CN_AUX_H_

#include <linux/irqreturn.h>
#include <linux/habanalabs/cpucp_if.h>
#include <linux/auxiliary_bus.h>
#include <linux/if_vlan.h>
#include <uapi/linux/ethtool.h>

#define HL_CN_NAME		"habanalabs_cn"

#define HL_EN_MAX_HEADERS_SZ	(ETH_HLEN + 2 * VLAN_HLEN + ETH_FCS_LEN)

/* driver specific value, should always be >= asic specific h/w resource */
#define NIC_DRV_MAX_CQS_NUM	32
#define NIC_DRV_MAX_CCQS_NUM	4
#define NIC_DRV_NUM_DB_FIFOS	32

/**
 * enum hl_cn_asic_type - supported ASIC types.
 * @ASIC_GAUDI2: Gaudi2 device.
 */
enum hl_cn_asic_type {
	HL_ASIC_GAUDI2,
};

/**
 * enum hl_cn_status_cmd - status cmd type.
 * @HL_CN_STATUS_ONE_SHOT: one shot command.
 * @HL_CN_STATUS_PERIODIC_START: start periodic status update.
 * @HL_CN_STATUS_PERIODIC_STOP: stop periodic status update.
 */
enum hl_cn_status_cmd {
	HL_CN_STATUS_ONE_SHOT,
	HL_CN_STATUS_PERIODIC_START,
	HL_CN_STATUS_PERIODIC_STOP,
};

/**
 * enum hl_aux_dev_type - auxiliary device type.
 * HL_AUX_DEV_CN: Shared Network Interface.
 * HL_AUX_DEV_ETH: Ethernet.
 * HL_AUX_DEV_IB: InfiniBand.
 */
enum hl_aux_dev_type {
	HL_AUX_DEV_CN,
	HL_AUX_DEV_ETH,
	HL_AUX_DEV_IB,
};

/**
 * struct hl_aux_dev - habanalabs auxiliary device structure.
 * @adev: auxiliary device.
 * @aux_ops: pointer functions for drivers communication.
 * @aux_data: essential data for operating the auxiliary device.
 * @priv: auxiliary device private data.
 * @type: type of the auxiliary device.
 */
struct hl_aux_dev {
	struct auxiliary_device adev;
	void *aux_ops;
	void *aux_data;
	void *priv;
	enum hl_aux_dev_type type;
};

/**
 * struct hl_cn_stat - Holds ASIC specific statistics string and default register offset.
 * @str: String name of ethtool stat.
 * @lo_offset: Register offset of the stat.
 * @hi_offset: High register offset. May be unused for some stats.
 */
struct hl_cn_stat {
	char str[ETH_GSTRING_LEN];
	int lo_offset;
	int hi_offset;
};

/*
 * struct hl_cn_cpucp_mac_addr - port MAC address received from FW.
 * @mac_addr: port MAC address.
 */
struct hl_cn_cpucp_mac_addr {
	u8 mac_addr[ETH_ALEN];
};

/*
 * struct hl_cn_cpucp_info - info received from FW.
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
struct hl_cn_cpucp_info {
	struct hl_cn_cpucp_mac_addr mac_addrs[CPUCP_MAX_NICS];
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
 * struct hl_cn_aux_data - habanalabs data for the cn driver.
 * @pdev: pointer to PCI device.
 * @dev: related kernel basic device structure.
 * @asic_specific: ASIC specific data.
 * @fw_ver: FW version.
 * @asic_type: ASIC specific type.
 * @ports_mask: mask of available ports.
 * @ext_ports_mask: mask of external ports (subset of ports_mask).
 * @auto_neg_mask: mask of port with Autonegotiation enabled.
 * @dram_size: available DRAM size.
 * @mmap_type_flag: flag to indicate CN MMAP type.
 * @nic_drv_addr: base address for NIC driver on DRAM.
 * @nic_drv_size: driver size reserved for NIC driver on DRAM.
 * @macro_cfg_size: the size of the macro configuration space.
 * @vendor_id: PCI vendor ID.
 * @pci_id: device PCI Id.
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
 * @minor: minor id of the device.
 * @id: device ID.
 * @cache_line_size: device cache line size.
 * @clk: clock frequency in MHz.
 * @pldm: is running on Palladium setup.
 * @skip_phy_init: avoid writing/reading PHY registers, relevant for Gaudi2 or later.
 * @load_phy_fw: load PHY F/W.
 * @cpucp_fw: is CPUCP FW enabled.
 * @supports_coresight: is CoreSight supported.
 * @use_fw_serdes_info: true if FW serdes values should be used, false if hard coded values should
 *                      be used.
 * @mmu_enable: is MMU enabled.
 * @lanes_per_port: number of physical lanes per port.
 * @cpucp_checkers_shift: CPUCP checkers flags shift.
 */
struct hl_cn_aux_data {
	struct pci_dev *pdev;
	struct device *dev;
	void *asic_specific;
	char *fw_ver;
	enum hl_cn_asic_type asic_type;
	u64 ports_mask;
	u64 ext_ports_mask;
	u64 auto_neg_mask;
	u64 dram_size;
	u64 mmap_type_flag;
	u64 nic_drv_addr;
	u64 nic_drv_size;
	u32 macro_cfg_size;
	u32 vendor_id;
	u32 pci_id;
	u32 pending_reset_long_timeout;
	u32 kernel_asid;
	u32 card_location;
	u32 device_timeout;
	u32 fw_major_version;
	u32 fw_minor_version;
	u32 fw_app_cpu_boot_dev_sts0;
	u32 fw_app_cpu_boot_dev_sts1;
	u16 minor;
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
 * enum hl_cn_mmu_mode - MMU modes the CN can work with.
 * @HL_CN_MMU_MODE_EXTERNAL: using external MMU HW IP.
 * @HL_CN_MMU_MODE_NETWORK_TLB: Using internal network TLB (but external page-table).
 */
enum hl_cn_mmu_mode {
	HL_CN_MMU_MODE_EXTERNAL,
	HL_CN_MMU_MODE_NETWORK_TLB,
};

/**
 * struct hl_cn_vm_info - VM related info for the cn driver.
 * @mmu_mode: the type (or mode) of MMU currently configured.
 * @ext_mmu.work_id: the unique work-ID assigned to this VM when in external MMU mode.
 * @net_tlb.pasid: the PCI process space address ID assigned to the device.
 * @net_tlb.page_tbl_addr: the address of the MMU page table of this VM.
 */
struct hl_cn_vm_info {
	enum hl_cn_mmu_mode mmu_mode;
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

typedef bool (*hl_cn_poll_cond_func)(u32 val, void *arg);

/**
 * struct hl_cn_aux_ops - pointer functions for cn <-> accel drivers communication.
 * @device_operational: is device operational.
 * @hw_access_lock: prevent HW access.
 * @hw_access_unlock: allow HW access.
 * @spmu_get_stats_info: get SPMU statistics information.
 * @spmu_config: config the SPMU.
 * @spmu_sample: read SPMU counters.
 * @device_reset: Perform device reset.
 * @dma_alloc_coherent: Allocate coherent DMA memory.
 * @dma_free_coherent: Free coherent DMA memory.
 * @dma_pool_zalloc: Allocate small size DMA memory from the pool.
 * @dma_pool_free: Free small size DMA memory from the pool.
 * @map_vmalloc_range: Map memory allocated by vmalloc.
 * @unmap_vmalloc_range: Unmap memory allocated by vmalloc.
 * @vm_reserve_dva_block: Reserve a device virtual block of a given size.
 * @vm_unreserve_dva_block: Release a given device virtual block.
 * @get_hw_block_handle: Map block and return its handle.
 * @dma_mmap: Map DMA memory region.
 * @user_mmap: Map memory allocated by the driver.
 * @dram_readl: Read long from DRAM.
 * @dram_writel: Write long to DRAM.
 * @rreg: Read register.
 * @wreg: Write register.
 * @poll_reg: Poll on a register until a given condition is fulfilled or timeout.
 * @get_cpucp_info: fetch updated CPUCP info.
 * @send_cpu_message: send message to F/W. If the message is timedout, the driver will eventually
 *                    reset the device. The timeout is passed as an argument. If it is 0 the
 *                    timeout set is the default timeout for the specific ASIC.
 * @post_send_status: handler for post sending status packet to FW.
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
 * @send_port_cpucp_status: Send port status to FW.
 * @mmap: Map CN memory.
 * @asic_ops: pointer for ASIC specific ops struct.
 */
struct hl_cn_aux_ops {
	/* cn2accel */
	bool (*device_operational)(struct hl_aux_dev *aux_dev);
	void (*hw_access_lock)(struct hl_aux_dev *aux_dev);
	void (*hw_access_unlock)(struct hl_aux_dev *aux_dev);
	void (*spmu_get_stats_info)(struct hl_aux_dev *aux_dev, u32 port,
					struct hl_cn_stat **stats, u32 *n_stats);
	int (*spmu_config)(struct hl_aux_dev *aux_dev, u32 port, u32 num_event_types,
				u32 event_types[], bool enable);
	int (*spmu_sample)(struct hl_aux_dev *aux_dev, u32 port, u32 num_out_data, u64 out_data[]);
	void (*device_reset)(struct hl_aux_dev *aux_dev);
	void *(*dma_alloc_coherent)(struct hl_aux_dev *aux_dev, size_t size, dma_addr_t *dma_handle,
					gfp_t flag);
	void (*dma_free_coherent)(struct hl_aux_dev *aux_dev, size_t size, void *cpu_addr,
					dma_addr_t dma_handle);
	void *(*dma_pool_zalloc)(struct hl_aux_dev *aux_dev, size_t size, gfp_t mem_flags,
					dma_addr_t *dma_handle);
	void (*dma_pool_free)(struct hl_aux_dev *aux_dev, void *vaddr, dma_addr_t dma_addr);
	int (*map_vmalloc_range)(struct hl_aux_dev *aux_dev, u64 vmalloc_va, u64 device_va,
					u64 size);
	int (*unmap_vmalloc_range)(struct hl_aux_dev *aux_dev, u64 device_va);
	int (*vm_reserve_dva_block)(struct hl_aux_dev *aux_dev, u64 vm_handle, u64 size, u64 *dva);
	void (*vm_unreserve_dva_block)(struct hl_aux_dev *aux_dev, u64 vm_handle, u64 dva,
					u64 size);
	int (*get_hw_block_handle)(struct hl_aux_dev *aux_dev, u64 address, u64 *handle);
	int (*dma_mmap)(struct hl_aux_dev *aux_dev, struct vm_area_struct *vma, void *cpu_addr,
			dma_addr_t dma_addr, size_t size);
	int (*user_mmap)(struct hl_aux_dev *aux_dev, struct vm_area_struct *vma);
	u32 (*dram_readl)(struct hl_aux_dev *aux_dev, u64 addr);
	void (*dram_writel)(struct hl_aux_dev *aux_dev, u32 val, u64 addr);
	u32 (*rreg)(struct hl_aux_dev *aux_dev, u32 reg);
	void (*wreg)(struct hl_aux_dev *aux_dev, u32 reg, u32 val);
	int (*poll_reg)(struct hl_aux_dev *aux_dev, u32 reg, u64 timeout_us,
			hl_cn_poll_cond_func func, void *arg);
	void (*get_cpucp_info)(struct hl_aux_dev *aux_dev,
				struct hl_cn_cpucp_info *hl_cn_cpucp_info);
	int (*send_cpu_message)(struct hl_aux_dev *aux_dev, u32 *msg, u16 len, u32 timeout,
				u64 *result);
	void (*post_send_status)(struct hl_aux_dev *aux_dev, u32 port);
	int (*register_cn_user_context)(struct hl_aux_dev *aux_dev, int user_fd,
					const void *cn_ctx, u64 *comp_handle, u64 *vm_handle);
	void (*deregister_cn_user_context)(struct hl_aux_dev *aux_dev, u64 vm_handle);
	int (*vm_create)(struct hl_aux_dev *aux_dev, u64 comp_handle, u32 flags, u64 *vm_handle);
	void (*vm_destroy)(struct hl_aux_dev *aux_dev, u64 vm_handle);
	int (*get_vm_info)(struct hl_aux_dev *aux_dev, u64 vm_handle,
			   struct hl_cn_vm_info *vm_info);

	/* accel2cn */
	int (*ports_reopen)(struct hl_aux_dev *aux_dev);
	void (*ports_stop_prepare)(struct hl_aux_dev *aux_dev, bool fw_reset, bool in_teardown);
	void (*ports_stop)(struct hl_aux_dev *aux_dev);
	void (*synchronize_irqs)(struct hl_aux_dev *aux_dev);
	int (*send_port_cpucp_status)(struct hl_aux_dev *aux_dev, u32 port, u8 cmd, u8 period);
	int (*mmap)(struct hl_aux_dev *aux_dev, u32 asid, struct vm_area_struct *vma);
	void *asic_ops;
};

#endif /* HL_CN_AUX_H_ */
