// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#include <linux/module.h>
#include <linux/firmware.h>

#include "gaudi2_cn.h"

#define NIC_PHY_CFG_SIZE (NIC0_SERDES1_LANE0_REGISTER_0P00 - NIC0_SERDES0_LANE0_REGISTER_0P00)

#define NIC_PHY_CFG_BASE(port) \
		({ \
			u32 __port = (port); \
			((u64)(NIC_MACRO_CFG_BASE(__port) + \
			NIC_PHY_CFG_SIZE * (u64)((__port) & 1))); \
		})

#define LANE_LO_OFF (NIC0_SERDES0_LANE1_REGISTER_0P00 - NIC0_SERDES0_LANE0_REGISTER_0P00)

#define LANE_HI_OFF (NIC0_SERDES0_LANE1_REGISTER_AI00 - NIC0_SERDES0_LANE0_REGISTER_AI00)

#define LANE_OFF(reg, lane) \
		({ \
			u32 __lane = lane; \
			((reg) < NIC0_SERDES0_LANE0_REGISTER_AI00) ? \
			((__lane) * LANE_LO_OFF) : ((__lane) * LANE_HI_OFF); \
		})

#define PHY_PRINT(port, lane, op, val, reg) \
	({ \
		if (hdev->phy_regs_print) { \
			u32 __port = (port); \
			dev_info(hdev->dev, "[%s],Nic,%u,Port,%u,Lane,%d,%s,0x%08x,0x%08llx\n", \
				 __func__, __port >> 1, __port & 0x1, (lane), (op), (val), (reg)); \
			usleep_range(1000, 2000); \
		} \
	})

#define NIC_PHY_RREG32(reg) \
	({ \
		u32 _port = port; \
		u64 _reg = NIC_PHY_CFG_BASE(_port) + (reg); \
		u32 _val = RREG32(_reg); \
		PHY_PRINT(_port, -1, "read", _val, _reg); \
		_val; \
	})

#define NIC_PHY_WREG32(reg, val) \
	do { \
		u32 _port = port; \
		u64 _reg = NIC_PHY_CFG_BASE(_port) + (reg); \
		u32 _val = (val); \
		WREG32(_reg, _val); \
		PHY_PRINT(_port, -1, "write", _val, _reg); \
	} while (0)

#define NIC_PHY_RMWREG32(reg, val, mask) \
	do { \
		u32 _port = port; \
		u64 _reg = NIC_PHY_CFG_BASE(_port) + (reg); \
		u32 _val = (val); \
		u32 _mask = (mask); \
		u32 _tmp = RREG32(_reg); \
		PHY_PRINT(_port, -1, "read(rmw)", _tmp, _reg); \
		_tmp &= ~_mask; \
		_tmp |= (_val << __ffs(_mask)); \
		WREG32(_reg, _tmp); \
		PHY_PRINT(_port, -1, "write(rmw)", _tmp, _reg); \
	} while (0)

#define NIC_PHY_RREG32_LANE(reg) \
	({ \
		u32 _port = port; \
		u32 _lane = lane; \
		u64 _reg = (reg); \
		u64 __reg = NIC_PHY_CFG_BASE(_port) + _reg + LANE_OFF(_reg, _lane); \
		u32 _val = RREG32(__reg); \
		PHY_PRINT(_port, _lane, "read", _val, __reg); \
		_val; \
	})

#define NIC_PHY_WREG32_LANE(reg, val) \
	do { \
		u32 _port = port; \
		u32 _lane = lane; \
		u64 _reg = (reg); \
		u64 __reg = NIC_PHY_CFG_BASE(_port) + _reg + LANE_OFF(_reg, _lane); \
		u32 _val = (val); \
		WREG32(__reg, _val); \
		PHY_PRINT(_port, _lane, "write", _val, __reg); \
	} while (0)

#define NIC_PHY_RMWREG32_LANE(reg, val, mask) \
	do { \
		u32 _port = port; \
		u32 _lane = lane; \
		u64 _reg = (reg); \
		u64 __reg = NIC_PHY_CFG_BASE(_port) + _reg + LANE_OFF(_reg, _lane); \
		u32 _val = (val); \
		u32 _mask = (mask); \
		u32 _tmp = RREG32(__reg); \
		PHY_PRINT(_port, _lane, "read(rmw)", _tmp, __reg); \
		_tmp &= ~_mask; \
		_tmp |= (_val << __ffs(_mask)); \
		WREG32(__reg, _tmp); \
		PHY_PRINT(_port, _lane, "write(rmw)", _tmp, __reg); \
	} while (0)

#define NIC_PHY_READ_COUNTS_PER_MS		100000
#define NIC_PHY_FW_TIME_CONSTANT_RATIO		64
#define NIC_PHY_FW_TUNING_INTERVAL_MS		100
#define NIC_PHY_FW_TUNING_TIMEOUT_MS		(30 * MSEC_PER_SEC) /* 30 seconds */
#define NIC_PHY_PAM4_BER_FACTOR			53125000
#define NIC_PHY_NRZ_BER_FACTOR			25781250

#define NIC_PHY_TX_POL_MASK_HL225		0xF00000000430
#define NIC_PHY_RX_POL_MASK_HL225		0x0FFFFFFFFBCF
#define NIC_PHY_TX_POL_MASK_HLS2		0x0
#define NIC_PHY_RX_POL_MASK_HLS2		0x0

#define NIC_PHY_PCS_LINK_DOWN_TH_S		5
#define NIC_PHY_MAC_REMOTE_FAULT_TH_S		10

#define NIC_PHY_PCS_SETTLING_WAIT_MS		(5 * MSEC_PER_SEC)
#define NIC_PHY_PCS_STRESS_INT_MS		10
#define NIC_PHY_PCS_STEADY_STATE_INT_MS		(1 * MSEC_PER_SEC)

#define NIC_PHY_PCS_TESTING_WINDOW_S		20
#define NIC_PHY_PCS_TESTING_WINDOW_MS		(NIC_PHY_PCS_TESTING_WINDOW_S * MSEC_PER_SEC)
#define NIC_PHY_PCS_STRESS_WINDOW_MS \
		(NIC_PHY_PCS_TESTING_WINDOW_MS - NIC_PHY_PCS_SETTLING_WAIT_MS)

#define NIC_PHY_PCS_MAX_LINK_TOGGLES		5

enum tx_taps_sets {
	NIC_PHY_TX_TAPS_SET_1 = 0,
	NIC_PHY_TX_TAPS_SET_2,
	NIC_PHY_TX_TAPS_SET_3,
	NIC_PHY_TX_TAPS_SET_4,

	NIC_PHY_TX_TAPS_NUM_SETS
};

#define NIC_PHY_DEFAULT_TX_TAPS_DEFAULT		NIC_PHY_TX_TAPS_SET_1

struct hbl_cn_tx_taps tx_taps_set_array[NIC_PHY_TX_TAPS_NUM_SETS] = {
	{.pam4_taps = {2, -10, 23, 0, 0}, .nrz_taps = {0, -10, 26, 0, 0}},
	{.pam4_taps = {0, -6, 22, 0, 0}, .nrz_taps = {0, -10, 26, 0, 0}},
	{.pam4_taps = {3, -12, 21, 0, 0}, .nrz_taps = {0, -10, 26, 0, 0}},
	{.pam4_taps = {1, -7, 18, 0, 0}, .nrz_taps = {0, -10, 26, 0, 0}},
};

static enum tx_taps_sets tx_taps_cfg_array[][2] = {
	{NIC_PHY_TX_TAPS_SET_1, NIC_PHY_TX_TAPS_SET_1},
	{NIC_PHY_TX_TAPS_SET_1, NIC_PHY_TX_TAPS_SET_2},
	{NIC_PHY_TX_TAPS_SET_2, NIC_PHY_TX_TAPS_SET_1},
	{NIC_PHY_TX_TAPS_SET_2, NIC_PHY_TX_TAPS_SET_2},
	{NIC_PHY_TX_TAPS_SET_1, NIC_PHY_TX_TAPS_SET_3},
	{NIC_PHY_TX_TAPS_SET_3, NIC_PHY_TX_TAPS_SET_1},
	{NIC_PHY_TX_TAPS_SET_3, NIC_PHY_TX_TAPS_SET_3},
	{NIC_PHY_TX_TAPS_SET_1, NIC_PHY_TX_TAPS_SET_4},
	{NIC_PHY_TX_TAPS_SET_4, NIC_PHY_TX_TAPS_SET_1},
	{NIC_PHY_TX_TAPS_SET_4, NIC_PHY_TX_TAPS_SET_4}
};

static size_t tx_taps_num_cfgs = ARRAY_SIZE(tx_taps_cfg_array);

#define NIC_MAC_LANE_MAP(lane_0, lane_1, lane_2, lane_3) \
	(((lane_0) & \
	NIC0_PHY_PHY_ASYNC_LANE_SWAP_SERDES0_TX0_SWAP_ID_MASK) | \
	(((lane_1) & \
	NIC0_PHY_PHY_ASYNC_LANE_SWAP_SERDES0_TX0_SWAP_ID_MASK) << \
	NIC0_PHY_PHY_ASYNC_LANE_SWAP_SERDES0_TX1_SWAP_ID_SHIFT) | \
	(((lane_2) & \
	NIC0_PHY_PHY_ASYNC_LANE_SWAP_SERDES0_TX0_SWAP_ID_MASK) << \
	NIC0_PHY_PHY_ASYNC_LANE_SWAP_SERDES1_TX0_SWAP_ID_SHIFT) | \
	(((lane_3) & \
	NIC0_PHY_PHY_ASYNC_LANE_SWAP_SERDES0_TX0_SWAP_ID_MASK) << \
	NIC0_PHY_PHY_ASYNC_LANE_SWAP_SERDES1_TX1_SWAP_ID_SHIFT))

/* Lane map for HL-225 */
static u32 default_cn_mac_lane_remap[] = {
	/* MACRO 0 */
	NIC_MAC_LANE_MAP(NIC_MAC_LANE_3, NIC_MAC_LANE_1, NIC_MAC_LANE_0, NIC_MAC_LANE_2),
	/* MACRO 1-10. Use default HW power on reset mapping. */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* MACRO 11 */
	NIC_MAC_LANE_MAP(NIC_MAC_LANE_1, NIC_MAC_LANE_0, NIC_MAC_LANE_3, NIC_MAC_LANE_2),
};

/* Firmware lane mapping per macro are nibbles.
 * e.g. 0x3210 maps to lane 3/2/1/0
 */
#define FW_PARSE_LANE_MAP(macro, lane) \
	({ \
		u32 _lane = (lane); \
		((macro) & (0xf << (_lane * 4))) >> (_lane * 4); \
	})

enum lane_state {
	READY,
	NOT_READY,
	FAILURE
};

#define GAUDI2_PHY_FW_FILE	"habanalabs/gaudi2/gaudi2_cn_fw.bin"

MODULE_FIRMWARE(GAUDI2_PHY_FW_FILE);

const char *gaudi2_cn_phy_get_fw_name(void)
{
	return GAUDI2_PHY_FW_FILE;
}

static int get_tx_lane_in_macro(struct hbl_cn_device *hdev, u32 port, int lane)
{
	u32 lane_in_macro, lane_swap_val;
	int tx_lane;

	lane_in_macro = (port & 0x1) * 2 + lane;
	lane_swap_val = hdev->mac_lane_remap[port >> 1];

	if (!lane_swap_val)
		return lane_in_macro;

	for (tx_lane = 0; tx_lane < NIC_MAC_NUM_OF_LANES; tx_lane++) {
		if (((lane_swap_val >> (tx_lane * 2)) & 0x3) == lane_in_macro)
			break;
	}

	return tx_lane;
}

static void get_tx_port_and_lane(struct hbl_cn_device *hdev, u32 port, int lane, u32 *tx_port,
				 int *tx_lane)
{
	struct hbl_cn_port *cn_port = &hdev->cn_ports[port];
	u32 tx_lane_in_macro, abs_tx_lane_idx;

	if (!cn_port->auto_neg_enable) {
		*tx_port = port;
		*tx_lane = lane;
		return;
	}

	tx_lane_in_macro = get_tx_lane_in_macro(hdev, port, lane);
	abs_tx_lane_idx = (port >> 1) * NIC_MAC_NUM_OF_LANES + tx_lane_in_macro;

	*tx_port = abs_tx_lane_idx >> 1;
	*tx_lane = abs_tx_lane_idx & 0x1;
}

static bool is_lane_swapping(struct hbl_cn_device *hdev, u32 port, int lane)
{
	u32 tx_port;
	int tx_lane;

	get_tx_port_and_lane(hdev, port, lane, &tx_port, &tx_lane);

	return (tx_port != port) || (tx_lane != lane);
}

static void set_fw_lane_mapping(struct hbl_cn_device *hdev)
{
	struct hbl_cn_cpucp_info *cpucp_info = hdev->cpucp_info;
	u16 cpu_macro_tx_swap_map;
	int i;

	for (i = 0; i < NIC_NUMBER_OF_MACROS; i++) {
		cpu_macro_tx_swap_map = cpucp_info->tx_swap_map[i];
		hdev->mac_lane_remap[i] = NIC_MAC_LANE_MAP(FW_PARSE_LANE_MAP(cpu_macro_tx_swap_map,
									     0), /* lane 0 */
							   FW_PARSE_LANE_MAP(cpu_macro_tx_swap_map,
									     1), /* lane 1 */
							   FW_PARSE_LANE_MAP(cpu_macro_tx_swap_map,
									     2), /* lane 2 */
							   FW_PARSE_LANE_MAP(cpu_macro_tx_swap_map,
									     3)); /* lane 3 */
	}
}

static void mac_lane_remap(struct hbl_cn_device *hdev, u32 port)
{
	if (hdev->mac_lane_remap[port >> 1])
		NIC_MACRO_WREG32(NIC0_PHY_PHY_ASYNC_LANE_SWAP, hdev->mac_lane_remap[port >> 1]);
}

static void soft_reset(struct hbl_cn_device *hdev, u32 port)
{
	NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_980D, 0x888,
			 NIC0_SERDES0_REGISTER_980D_DOMAIN_RESET_MASK);
	NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_980D, 0x0,
			 NIC0_SERDES0_REGISTER_980D_DOMAIN_RESET_MASK);
}

static void logic_reset(struct hbl_cn_device *hdev, u32 port)
{
	NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_980D, 0x777,
			 NIC0_SERDES0_REGISTER_980D_DOMAIN_RESET_MASK);
	NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_980D, 0x0,
			 NIC0_SERDES0_REGISTER_980D_DOMAIN_RESET_MASK);
}

static void cpu_reset(struct hbl_cn_device *hdev, u32 port)
{
	NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_980D, 0xAAA,
			 NIC0_SERDES0_REGISTER_980D_DOMAIN_RESET_MASK);
	NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_980D, 0x0,
			 NIC0_SERDES0_REGISTER_980D_DOMAIN_RESET_MASK);
}

static int fw_cmd(struct hbl_cn_device *hdev, u32 port, u32 cmd, u32 *detail, u32 expected_res,
		  u32 *res_ptr)
{
	u32 res, val, checks = 0;

	if (detail)
		NIC_PHY_WREG32(NIC0_SERDES0_REGISTER_9816, *detail);

	NIC_PHY_WREG32(NIC0_SERDES0_REGISTER_9815, cmd);

	do {
		usleep_range(1000, 2000);
		res = NIC_PHY_RREG32(NIC0_SERDES0_REGISTER_9815);
		if (checks++ > NIC_PHY_READ_COUNTS_PER_MS) {
			dev_dbg(hdev->dev, "timeout for PHY cmd 0x%x port %u\n", cmd, port);
			return -ETIMEDOUT;
		}
	} while (res == cmd);

	val = (res >> 8) & 0xF;

	if (val != expected_res) {
		dev_dbg(hdev->dev, "cmd 0x%x returned error 0x%x port %u\n", cmd, val, port);
		return -EFAULT;
	}

	*res_ptr = res;

	return 0;
}

static void clock_init(struct hbl_cn_device *hdev, u32 port, int lane)
{
	u32 first_val, second_val;

	if (port & 0x1) { /* raven 1 */
		if (lane == 0) {
			first_val = 0xA9E0;
			second_val = 0x9B9E;
		} else { /* lane 1 */
			first_val = 0xA9E0;
			second_val = 0x9B9E;
		}
	} else { /* raven 0 */
		if (lane == 0) {
			first_val = 0x59E0;
			second_val = 0x9B5E;
		} else { /* lane 1 */
			first_val = 0xA9E0;
			second_val = 0x9B9E;
		}
	}

	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PCC, first_val);
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0NF3, second_val);
}

static u32 int_to_twos(s32 val, u8 bitwidth)
{
	return val < 0 ? (1 << bitwidth) + val : val;
}

static int twos_to_int(unsigned int val, u8 bitwidth)
{
	u32 mask = 1 << (bitwidth - 1);

	return -(val & mask) + (val & ~mask);
}

static void set_tx_taps(struct hbl_cn_device *hdev, u32 port, int lane, s32 tx_pre2, s32 tx_pre1,
			s32 tx_main, s32 tx_post1, s32 tx_post2, bool pam4)
{
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA5, int_to_twos(tx_pre2, 8),
			      NIC0_SERDES0_LANE0_REGISTER_0PA5_TX_PRE_2_MASK);
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA7, int_to_twos(tx_pre1, 8),
			      NIC0_SERDES0_LANE0_REGISTER_0PA7_TX_PRE_1_MASK);
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA9, int_to_twos(tx_main, 8),
			      NIC0_SERDES0_LANE0_REGISTER_0PA9_TX_MAIN_MASK);
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PAB, int_to_twos(tx_post1, 8),
			      NIC0_SERDES0_LANE0_REGISTER_0PAB_TX_POST_1_MASK);
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PAD, int_to_twos(tx_post2, 8),
			      NIC0_SERDES0_LANE0_REGISTER_0PAD_TX_POST_2_MASK);

	dev_dbg(hdev->dev, "Card %u Port %u lane %d: set %s tx taps [%d,%d,%d,%d,%d]\n",
		hdev->card_location, port, lane, pam4 ? "PAM4" : "NRZ", tx_pre2, tx_pre1, tx_main,
		tx_post1, tx_post2);
}

static void set_tx_taps_cfg(struct hbl_cn_device *hdev, u32 port, int lane, u8 cfg, bool pam4,
			    bool reset_taps)
{
	enum tx_taps_sets set_id;
	u32 abs_lane_idx;
	s32 *taps;

	set_id = tx_taps_cfg_array[cfg][lane];
	abs_lane_idx = (port << 1) + lane;

	if (pam4) {
		taps = hdev->phy_tx_taps[abs_lane_idx].pam4_taps;
		memcpy(taps, tx_taps_set_array[set_id].pam4_taps,
		       sizeof(hdev->phy_tx_taps[abs_lane_idx].pam4_taps));
	} else {
		taps = hdev->phy_tx_taps[abs_lane_idx].nrz_taps;
		memcpy(taps, tx_taps_set_array[set_id].nrz_taps,
		       sizeof(hdev->phy_tx_taps[abs_lane_idx].nrz_taps));
	}

	if (reset_taps) {
		/* Here we first reset the Tx taps (setting all to zero) in order to force link
		 * down on the remote port, so it will have a "fresh start" when setting the next
		 * Tx taps set.
		 */
		set_tx_taps(hdev, port, lane, 0, 0, 0, 0, 0, pam4);
		msleep(100);
	}

	set_tx_taps(hdev, port, lane, taps[0], taps[1], taps[2], taps[3], taps[4], pam4);
}

static u8 get_curr_tx_taps_cfg(struct hbl_cn_device *hdev, u32 port)
{
	struct gaudi2_cn_port *gaudi2_port = hdev->cn_ports[port].cn_specific;

	return gaudi2_port->tx_taps_cfg;
}

static void init_pam4_tx(struct hbl_cn_device *hdev, u32 port, int lane)
{
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA1, 0x0);
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA2, 0x0);
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA3, 0x0);
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA4, 0x0);
	/* data quite */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, 0x6320);
	/* auto symmetric, scale */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PAF, 0xFAC9);
	/* data, prbs */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PB0, 0x4000);
	/* cursor -2 */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA5, 0x100);
	/* cursor -1 */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA7, 0xF900);
	/* cursor -main */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA9, 0x1700);
	/* cursor +1 */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PAB, 0x0);
	/* cursor +2 */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PAD, 0x0);
}

static void init_pam4_rx(struct hbl_cn_device *hdev, u32 port, int lane)
{
	/* ac-couple always */
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PF8, 0x1,
			      NIC0_SERDES0_LANE0_REGISTER_0PF8_AC_COUPLE_EN_MASK);
}

static void set_lane_mode_tx(struct hbl_cn_device *hdev, u32 port, int lane, bool pam4)
{
	if (pam4) {
		/* Disable NRZ mode */
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PB0, 0x0,
				      NIC0_SERDES0_LANE0_REGISTER_0PB0_TX_NRZ_MODE_MASK);
		/* Disable NRZ PRBS Generator */
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PB0, 0x0,
				      NIC0_SERDES0_LANE0_REGISTER_0PB0_TX_NRZ_PRBS_GEN_EN_MASK);
		/* Enable PAM4 PRBS Generator */
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, 0x1,
				      NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_PRBS_CLK_EN_MASK);
	} else {
		/* Disable PAM4 PRBS Generator */
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, 0x0,
				      NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_PRBS_CLK_EN_MASK);
		/* Enable NRZ mode */
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PB0, 0x1,
				      NIC0_SERDES0_LANE0_REGISTER_0PB0_TX_NRZ_MODE_MASK);
		/* Enable NRZ PRBS Generator */
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PB0, 0x1,
				      NIC0_SERDES0_LANE0_REGISTER_0PB0_TX_NRZ_PRBS_GEN_EN_MASK);
	}
}

static void set_lane_mode_rx(struct hbl_cn_device *hdev, u32 port, int lane, bool pam4)
{
	if (pam4)
		/* Enable PAM4 mode */
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P41, 0x1,
				      NIC0_SERDES0_LANE0_REGISTER_0P41_PAM4_EN_MASK);
	else
		/* Disable PAM4 mode */
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P41, 0x0,
				      NIC0_SERDES0_LANE0_REGISTER_0P41_PAM4_EN_MASK);
}

static void prbs_mode_select_tx(struct hbl_cn_device *hdev, u32 port, int lane, bool pam4,
				char *mode)
{
	u32 val;

	if (!mode || strncmp(mode, "PRBS", strlen("PRBS")))
		return;

	if (pam4) {
		if (!strncmp(mode, "PRBS9", strlen("PRBS9")))
			val = 0;
		else if (!strncmp(mode, "PRBS13", strlen("PRBS13")))
			val = 1;
		else if (!strncmp(mode, "PRBS15", strlen("PRBS15")))
			val = 2;
		else /* PRBS31 */
			val = 3;

		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, val,
				      NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_PRBS_MODE_MASK);
	} else {
		if (!strncmp(mode, "PRBS9", strlen("PRBS9")))
			val = 0;
		else if (!strncmp(mode, "PRBS15", strlen("PRBS15")))
			val = 1;
		else if (!strncmp(mode, "PRBS23", strlen("PRBS23")))
			val = 2;
		else /* PRBS31 */
			val = 3;

		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, val,
				      NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_PRBS_MODE_MASK);
	}

	val = pam4 ? 0 : 1;

	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PB0, val,
			      NIC0_SERDES0_LANE0_REGISTER_0PB0_TX_NRZ_PRBS_CLK_EN_MASK);
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PB0, val,
			      NIC0_SERDES0_LANE0_REGISTER_0PB0_TX_NRZ_PRBS_GEN_EN_MASK);
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PB0, val,
			      NIC0_SERDES0_LANE0_REGISTER_0PB0_TX_NRZ_MODE_MASK);

	if (pam4)
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PB0, 0x0,
				      NIC0_SERDES0_LANE0_REGISTER_0PB0_TX_HALF_RATE_EN_MASK);

	val = pam4 ? 1 : 0;

	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, 0x1,
			      NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_TEST_DATA_SRC_MASK);
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, val,
			      NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_PRBS_CLK_EN_MASK);
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, 0x1,
			      NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_PAM4_TEST_EN_MASK);
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, val,
			      NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_PRBS_GEN_EN_MASK);
}

static void prbs_mode_select_rx(struct hbl_cn_device *hdev, u32 port, int lane, bool pam4,
				char *mode)
{
	u32 val;

	if (!mode || strncmp(mode, "PRBS", strlen("PRBS")))
		return;

	if (pam4) {
		if (!strncmp(mode, "PRBS9", strlen("PRBS9")))
			val = 0;
		else if (!strncmp(mode, "PRBS13", strlen("PRBS13")))
			val = 1;
		else if (!strncmp(mode, "PRBS15", strlen("PRBS15")))
			val = 2;
		else /* PRBS31 */
			val = 3;

		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P43, val,
				      NIC0_SERDES0_LANE0_REGISTER_0P43_PRBS_MODE_SEL_MASK);
	} else {
		if (!strncmp(mode, "PRBS9", strlen("PRBS9")))
			val = 0;
		else if (!strncmp(mode, "PRBS15", strlen("PRBS15")))
			val = 1;
		else if (!strncmp(mode, "PRBS23", strlen("PRBS23")))
			val = 2;
		else /* PRBS31 */
			val = 3;

		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0N61, val,
				      NIC0_SERDES0_LANE0_REGISTER_0N61_NRZ_PRBS_MODE_SEL_MASK);
	}

	if (pam4) {
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P43, 0x1,
				      NIC0_SERDES0_LANE0_REGISTER_0P43_PU_PRBS_CHKR_MASK);
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P43, 0x1,
				      NIC0_SERDES0_LANE0_REGISTER_0P43_PU_PRBS_SYNC_CHKR_MASK);
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P43, 0x1,
				      NIC0_SERDES0_LANE0_REGISTER_0P43_RX_PRBS_AUTO_SYNC_EN_MASK);
	} else {
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0N61, 0x1,
				      NIC0_SERDES0_LANE0_REGISTER_0N61_PRBS_CHKR_EN_MASK);
	}
}

static void set_default_polarity_values(struct hbl_cn_device *hdev)
{
	struct gaudi2_cn_device *gaudi2 = hdev->asic_specific;
	enum gaudi2_setup_type setup_type;
	u64 pol_tx, pol_rx;

	setup_type = gaudi2->setup_type;

	if (hdev->skip_phy_pol_cfg)
		return;

	switch (setup_type) {
	case GAUDI2_SETUP_TYPE_HLS2:
		pol_tx = NIC_PHY_TX_POL_MASK_HL225 ^ NIC_PHY_TX_POL_MASK_HLS2;
		pol_rx = NIC_PHY_RX_POL_MASK_HL225 ^ NIC_PHY_RX_POL_MASK_HLS2;
		break;
	default:
		dev_err(hdev->dev, "Wrong setup type %d\n", setup_type);
		return;
	}

	hdev->pol_tx_mask = pol_tx;
	hdev->pol_rx_mask = pol_rx;
}

static void set_default_mac_lane_remap(struct hbl_cn_device *hdev)
{
	memcpy(hdev->mac_lane_remap, default_cn_mac_lane_remap,
	       sizeof(default_cn_mac_lane_remap));
}

static s32 get_pam4_tap_pre2(struct hbl_cn_device *hdev, u32 card_location, u32 abs_lane_idx)
{
	struct gaudi2_cn_device *gaudi2 = hdev->asic_specific;
	enum gaudi2_setup_type setup_type;

	setup_type = gaudi2->setup_type;

	switch (setup_type) {
	case GAUDI2_SETUP_TYPE_HLS2:
		return tx_taps_set_array[NIC_PHY_DEFAULT_TX_TAPS_DEFAULT].pam4_taps[0];
	default:
		dev_err(hdev->dev, "Wrong setup type %d\n", setup_type);
	}

	return 2;
}

static s32 get_pam4_tap_pre1(struct hbl_cn_device *hdev, u32 card_location, u32 abs_lane_idx)
{
	struct gaudi2_cn_device *gaudi2 = hdev->asic_specific;
	enum gaudi2_setup_type setup_type;

	setup_type = gaudi2->setup_type;

	switch (setup_type) {
	case GAUDI2_SETUP_TYPE_HLS2:
		return tx_taps_set_array[NIC_PHY_DEFAULT_TX_TAPS_DEFAULT].pam4_taps[1];
	default:
		dev_err(hdev->dev, "Wrong setup type %d\n", setup_type);
	}

	return -12;
}

static s32 get_pam4_tap_main(struct hbl_cn_device *hdev, u32 card_location, u32 abs_lane_idx)
{
	struct gaudi2_cn_device *gaudi2 = hdev->asic_specific;
	enum gaudi2_setup_type setup_type;

	setup_type = gaudi2->setup_type;

	switch (setup_type) {
	case GAUDI2_SETUP_TYPE_HLS2:
		return tx_taps_set_array[NIC_PHY_DEFAULT_TX_TAPS_DEFAULT].pam4_taps[2];
	default:
		dev_err(hdev->dev, "Wrong setup type %d\n", setup_type);
	}

	return 22;
}

static s32 get_pam4_tap_post1(struct hbl_cn_device *hdev, u32 card_location, u32 abs_lane_idx)
{
	return tx_taps_set_array[NIC_PHY_DEFAULT_TX_TAPS_DEFAULT].pam4_taps[3];
}

static s32 get_pam4_tap_post2(struct hbl_cn_device *hdev, u32 card_location, u32 abs_lane_idx)
{
	return tx_taps_set_array[NIC_PHY_DEFAULT_TX_TAPS_DEFAULT].pam4_taps[4];
}

static void set_default_tx_taps_values(struct hbl_cn_device *hdev)
{
	struct hbl_cn_properties *cn_props = &hdev->cn_props;
	u32 card_location;
	int abs_lane_idx;
	s32 *taps;

	card_location = hdev->card_location;

	for (abs_lane_idx = 0; abs_lane_idx < cn_props->max_num_of_lanes; abs_lane_idx++) {
		/* PAM4 */
		taps = hdev->phy_tx_taps[abs_lane_idx].pam4_taps;
		taps[0] = get_pam4_tap_pre2(hdev, card_location, abs_lane_idx);
		taps[1] = get_pam4_tap_pre1(hdev, card_location, abs_lane_idx);
		taps[2] = get_pam4_tap_main(hdev, card_location, abs_lane_idx);
		taps[3] = get_pam4_tap_post1(hdev, card_location, abs_lane_idx);
		taps[4] = get_pam4_tap_post2(hdev, card_location, abs_lane_idx);

		/* NRZ */
		taps = hdev->phy_tx_taps[abs_lane_idx].nrz_taps;
		taps[0] = tx_taps_set_array[NIC_PHY_DEFAULT_TX_TAPS_DEFAULT].nrz_taps[0];
		taps[1] = tx_taps_set_array[NIC_PHY_DEFAULT_TX_TAPS_DEFAULT].nrz_taps[1];
		taps[2] = tx_taps_set_array[NIC_PHY_DEFAULT_TX_TAPS_DEFAULT].nrz_taps[2];
		taps[3] = tx_taps_set_array[NIC_PHY_DEFAULT_TX_TAPS_DEFAULT].nrz_taps[3];
		taps[4] = tx_taps_set_array[NIC_PHY_DEFAULT_TX_TAPS_DEFAULT].nrz_taps[4];
	}
}

static void set_pol_tx(struct hbl_cn_device *hdev, u32 port, int lane, u32 tx_pol)
{
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, tx_pol,
			      NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_ANA_OUT_FLIP_MASK);
}

static void set_pol_rx(struct hbl_cn_device *hdev, u32 port, int lane, u32 rx_pol)
{
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P43, rx_pol,
			      NIC0_SERDES0_LANE0_REGISTER_0P43_RX_DATA_FLIP_MASK);
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0N61, rx_pol,
			      NIC0_SERDES0_LANE0_REGISTER_0N61_PRBS_CHECK_FLIP_MASK);
}

static void set_gc_tx(struct hbl_cn_device *hdev, u32 port, int lane, u32 tx_gc)
{
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PAF, tx_gc,
			      NIC0_SERDES0_LANE0_REGISTER_0PAF_TX_GRAYCODE_EN_MASK);
}

static void set_gc_rx(struct hbl_cn_device *hdev, u32 port, int lane, u32 rx_gc)
{
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P42, rx_gc,
			      NIC0_SERDES0_LANE0_REGISTER_0P42_RX_GRAYCODE_EN_MASK);
}

static void set_pc_tx(struct hbl_cn_device *hdev, u32 port, int lane, u32 tx_pc)
{
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PAF, tx_pc,
			      NIC0_SERDES0_LANE0_REGISTER_0PAF_TX_PRECODE_EN_MASK);
}

static void set_pc_rx(struct hbl_cn_device *hdev, u32 port, int lane, u32 rx_pc)
{
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P42, rx_pc,
			      NIC0_SERDES0_LANE0_REGISTER_0P42_RX_PRECODE_EN_MASK);
}

static void set_msblsb_tx(struct hbl_cn_device *hdev, u32 port, int lane, u32 tx_msblsb)
{
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PAF, tx_msblsb,
			      NIC0_SERDES0_LANE0_REGISTER_0PAF_TX_SWAP_MSB_LSB_MASK);
}

static void set_msblsb_rx(struct hbl_cn_device *hdev, u32 port, int lane, u32 rx_msblsb)
{
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P43, rx_msblsb,
			      NIC0_SERDES0_LANE0_REGISTER_0P43_RX_SWAP_MSB_LSB_MASK);
}

static void init_lane_for_fw_tx(struct hbl_cn_device *hdev, u32 port, int lane, bool pam4,
				bool do_lt)
{
	u32 abs_lane_idx, tx_pol, tx_gc, tx_msblsb;

	abs_lane_idx = (port << 1) + lane;
	tx_pol = (hdev->pol_tx_mask >> abs_lane_idx) & 1;

	tx_gc = (pam4 && !do_lt) ? 1 : 0;
	tx_msblsb = do_lt ? 1 : 0;

	set_lane_mode_tx(hdev, port, lane, pam4);
	set_gc_tx(hdev, port, lane, tx_gc);
	set_pc_tx(hdev, port, lane, 0);
	set_msblsb_tx(hdev, port, lane, tx_msblsb);
	set_pol_tx(hdev, port, lane, tx_pol);
}

static void init_lane_for_fw_rx(struct hbl_cn_device *hdev, u32 port, int lane, bool pam4,
				bool do_lt)
{
	u32 abs_lane_idx, rx_pol, rx_gc, rx_msblsb;

	abs_lane_idx = (port << 1) + lane;
	rx_pol = (hdev->pol_rx_mask >> abs_lane_idx) & 1;

	rx_gc = (pam4 && !do_lt) ? 1 : 0;
	rx_msblsb = do_lt ? 1 : 0;

	set_lane_mode_rx(hdev, port, lane, pam4);
	set_gc_rx(hdev, port, lane, rx_gc);
	set_pc_rx(hdev, port, lane, 0);
	set_msblsb_rx(hdev, port, lane, rx_msblsb);
	set_pol_rx(hdev, port, lane, rx_pol);
}

static void set_functional_mode_lane(struct hbl_cn_device *hdev, u32 port, int lane, bool do_lt)
{
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, 0,
			      NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_PRBS_CLK_EN_MASK);
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, 0,
			      NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_PAM4_TEST_EN_MASK);
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, 0,
			      NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_PRBS_GEN_EN_MASK);

	if (do_lt)
		NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_AN10, 0x5);
	else
		NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_AN10, 0);
}

static void set_functional_mode(struct hbl_cn_device *hdev, u32 port)
{
	struct hbl_cn_port *cn_port = &hdev->cn_ports[port];
	int lane, tx_lane;
	u32 tx_port;
	bool do_lt;

	do_lt = cn_port->auto_neg_enable;

	for (lane = 0; lane < 2; lane++) {
		get_tx_port_and_lane(hdev, port, lane, &tx_port, &tx_lane);
		set_functional_mode_lane(hdev, tx_port, tx_lane, do_lt);
	}

	cn_port->phy_func_mode_en = true;
}

static u32 get_fw_reg(struct hbl_cn_device *hdev, u32 port, u32 fw_addr)
{
	u32 ignore;

	fw_cmd(hdev, port, 0xE010, &fw_addr, 0xE, &ignore);

	return NIC_PHY_RREG32(NIC0_SERDES0_REGISTER_9812);
}

static int set_fw_reg(struct hbl_cn_device *hdev, u32 port, u32 fw_addr, u32 val)
{
	u32 ignore;

	NIC_PHY_WREG32(NIC0_SERDES0_REGISTER_9812, val);

	return fw_cmd(hdev, port, 0xE020, &fw_addr, 0xE, &ignore);
}

static void enable_lane_swapping(struct hbl_cn_device *hdev, u32 port, int lane, bool do_an,
				 bool do_lt)
{
	if (do_an || do_lt)
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_AJ40, 0x1,
				      NIC0_SERDES0_LANE0_REGISTER_AJ40_ANLT_LANE_SWAPPING_EN_MASK);

	if (do_an)
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_AJ40, 0x0, 0x40);
}

static void disable_lane_swapping(struct hbl_cn_device *hdev, u32 port, int lane, bool do_an,
				  bool do_lt)
{
	if (do_an)
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_AJ40, 0x0,
				      NIC0_SERDES0_LANE0_REGISTER_AJ40_ANLT_LANE_SWAPPING_EN_MASK);
}

static void lane_swapping_config(struct hbl_cn_device *hdev, u32 port, int lane, bool do_an,
				 bool do_lt)
{
	u32 tx_port, lt_option;
	int tx_lane;

	get_tx_port_and_lane(hdev, port, lane, &tx_port, &tx_lane);

	lt_option = get_fw_reg(hdev, port, 366);

	if (is_lane_swapping(hdev, port, lane)) {
		enable_lane_swapping(hdev, tx_port, tx_lane, do_an, do_lt);
		enable_lane_swapping(hdev, port, lane, do_an, do_lt);

		lt_option |= (1 << (3 + 8 * (1 - lane)));
	} else {
		disable_lane_swapping(hdev, tx_port, tx_lane, do_an, do_lt);
		disable_lane_swapping(hdev, port, lane, do_an, do_lt);

		lt_option &= ~(1 << (3 + 8 * (1 - lane)));
	}

	set_fw_reg(hdev, port, 366, lt_option);
}

static int fw_start(struct hbl_cn_device *hdev, u32 port, int lane, bool pam4, bool do_lt)
{
	u32 cmd, speed, ignore;

	cmd = pam4 ? (0x80D0 | lane) : (0x80C0 | lane);
	speed = pam4 ? 0x9 : 0x3;

	if (do_lt)
		speed |= 0x100;

	return fw_cmd(hdev, port, cmd, &speed, 0x8, &ignore);
}

static int fw_start_tx(struct hbl_cn_device *hdev, u32 port, int lane, bool pam4, bool do_lt)
{
	u32 speed, cmd, ignore;
	int rc;

	speed = pam4 ? 0x9 : 0x3;

	if (pam4)
		cmd = do_lt ? (0x7030 | lane) : (0x7010 | lane);
	else
		cmd = do_lt ? (0x7020 | lane) : (0x7000 | lane);

	rc = fw_cmd(hdev, port, cmd, &speed, 0x7, &ignore);
	if (rc)
		return rc;

	if (do_lt)
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, 0x1,
				      NIC0_SERDES0_LANE0_REGISTER_0PA0_RSVD_0PA0_04_MASK);

	return 0;
}

static int fw_config_vcocap(struct hbl_cn_device *hdev, u32 port, int lane, u32 mode,
			    u32 counter_value)
{
	u32 ignore;

	return fw_cmd(hdev, port, 0x6000 | (mode << 4) | lane, &counter_value, 14, &ignore);
}

static int set_pll_tx(struct hbl_cn_device *hdev, u32 port, int lane, u32 data_rate)
{
	u32 card_location, msbc, lsbc;
	int rc;

	card_location = hdev->card_location;

	if (lane == 0)
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_9825, 0x0,
				 NIC0_SERDES0_REGISTER_9825_PLL_0_LOCK_32T_CLK_SEL_MASK);
	else
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_982E, 0x0,
				 NIC0_SERDES0_REGISTER_982E_PLL_1_LOCK_32T_CLK_SEL_MASK);

	switch (data_rate) {
	case NIC_DR_50:
		/* toggle FRACN LSB for better phase noise */
		NIC_PHY_RMWREG32_LANE(0x54587D4, 0x0, 0x1);
		msbc = 0x5;
		lsbc = 0x4FFA;
		break;
	case NIC_DR_26:
		/* toggle FRACN LSB for better phase noise */
		NIC_PHY_RMWREG32_LANE(0x54587D4, 0x0, 0x1);
		NIC_PHY_RMWREG32_LANE(0x5458320, 0x0, 0x1);
		msbc = 0x5;
		lsbc = 0x4FFA;
		break;
	case NIC_DR_25:
		msbc = 0x5;
		lsbc = 0x27FA;
		break;
	case NIC_DR_10:
		msbc = 0x2;
		lsbc = 0xFFD;
		break;
	default:
		dev_err(hdev->dev, "Card %u Port %u lane %d: unsupported data rate\n",
			card_location, port, lane);
		return -EFAULT;
	}

	rc = fw_config_vcocap(hdev, port, lane, 1, msbc);
	if (rc)
		return rc;

	rc = fw_config_vcocap(hdev, port, lane, 2, lsbc);
	if (rc)
		return rc;

	rc = fw_config_vcocap(hdev, port, lane, 3, 0x40);
	if (rc)
		return rc;

	rc = fw_config_vcocap(hdev, port, lane, 4, 0x0);
	if (rc)
		return rc;

	usleep_range(500, 1000);

	if (lane == 0) {
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_9825, 0x1,
				 NIC0_SERDES0_REGISTER_9825_PLL_LOCK_SRC_SEL_MASK);
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_9825, 0x0,
				 NIC0_SERDES0_REGISTER_9825_PLL_0_LOCK_EN_MASK);
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_9825, 0x1,
				 NIC0_SERDES0_REGISTER_9825_PLL_0_LOCK_EN_MASK);
	} else {
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_9825, 0x2,
				 NIC0_SERDES0_REGISTER_9825_PLL_LOCK_SRC_SEL_MASK);
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_982E, 0x0,
				 NIC0_SERDES0_REGISTER_982E_PLL_1_LOCK_EN_MASK);
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_982E, 0x1,
				 NIC0_SERDES0_REGISTER_982E_PLL_1_LOCK_EN_MASK);
	}

	usleep_range(500, 1000);

	return 0;
}

static int set_pll_rx(struct hbl_cn_device *hdev, u32 port, int lane, u32 data_rate)
{
	u32 card_location, msbc, lsbc, third_val;
	int rc;

	card_location = hdev->card_location;

	if (lane == 0)
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_9825, 0x1,
				 NIC0_SERDES0_REGISTER_9825_PLL_0_LOCK_32T_CLK_SEL_MASK);
	else
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_982E, 0x1,
				 NIC0_SERDES0_REGISTER_982E_PLL_1_LOCK_32T_CLK_SEL_MASK);

	switch (data_rate) {
	case NIC_DR_50:
	case NIC_DR_26:
		msbc = 0x5;
		lsbc = 0x4FFA;
		third_val = 0x30;
		break;
	case NIC_DR_25:
		msbc = 0x5;
		lsbc = 0x27FA;
		third_val = 0x30;
		break;
	case NIC_DR_10:
		msbc = 0x2;
		lsbc = 0xFFD;
		third_val = 0x40;
		break;
	default:
		dev_err(hdev->dev, "Card %u Port %u lane %d: unsupported data rate\n",
			card_location, port, lane);
		return -EFAULT;
	}

	rc = fw_config_vcocap(hdev, port, lane, 1, msbc);
	if (rc)
		return rc;

	rc = fw_config_vcocap(hdev, port, lane, 2, lsbc);
	if (rc)
		return rc;

	rc = fw_config_vcocap(hdev, port, lane, 3, third_val);
	if (rc)
		return rc;

	rc = fw_config_vcocap(hdev, port, lane, 4, 0x1);
	if (rc)
		return rc;

	usleep_range(500, 1000);

	if (lane == 0) {
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_9825, 0x1,
				 NIC0_SERDES0_REGISTER_9825_PLL_LOCK_SRC_SEL_MASK);
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_9825, 0x0,
				 NIC0_SERDES0_REGISTER_9825_PLL_0_LOCK_EN_MASK);
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_9825, 0x1,
				 NIC0_SERDES0_REGISTER_9825_PLL_0_LOCK_EN_MASK);
	} else {
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_9825, 0x2,
				 NIC0_SERDES0_REGISTER_9825_PLL_LOCK_SRC_SEL_MASK);
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_982E, 0x0,
				 NIC0_SERDES0_REGISTER_982E_PLL_1_LOCK_EN_MASK);
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_982E, 0x1,
				 NIC0_SERDES0_REGISTER_982E_PLL_1_LOCK_EN_MASK);
	}

	usleep_range(500, 1000);

	return 0;
}

static int set_pll(struct hbl_cn_device *hdev, u32 port, int lane, u32 data_rate)
{
	u32 card_location, tx_port;
	int tx_lane, rc;

	card_location = hdev->card_location;

	get_tx_port_and_lane(hdev, port, lane, &tx_port, &tx_lane);

	rc = set_pll_tx(hdev, tx_port, tx_lane, data_rate);
	if (rc) {
		dev_err(hdev->dev, "Card %u Port %u lane %d: set Tx PLL failed, rc %d\n",
			card_location, tx_port, tx_lane, rc);
		return rc;
	}

	rc = set_pll_rx(hdev, port, lane, data_rate);
	if (rc) {
		dev_err(hdev->dev, "Card %u Port %u lane %d: set Rx PLL failed, rc %d\n",
			card_location, port, lane, rc);
		return rc;
	}

	return 0;
}

static void set_tx_taps_scale(struct hbl_cn_device *hdev, u32 port, int lane)
{
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PAF, 0x4, 0x3E);
}

static int fw_config_speed_pam4(struct hbl_cn_device *hdev, u32 port, int lane, bool do_lt)
{
	u32 tx_port, card_location, val;
	u8 curr_tx_taps_cfg;
	int tx_lane, rc;

	card_location = hdev->card_location;

	get_tx_port_and_lane(hdev, port, lane, &tx_port, &tx_lane);

	init_pam4_tx(hdev, tx_port, tx_lane);
	init_pam4_rx(hdev, port, lane);

	/* Disable AN/LT lane swapping */
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_AJ40, 0x0,
			      NIC0_SERDES0_LANE0_REGISTER_AJ40_ANLT_LANE_SWAPPING_EN_MASK);

	lane_swapping_config(hdev, port, lane, false, do_lt);

	init_lane_for_fw_tx(hdev, tx_port, tx_lane, true, do_lt);
	init_lane_for_fw_rx(hdev, port, lane, true, do_lt);

	prbs_mode_select_tx(hdev, tx_port, tx_lane, true, "PRBS31");
	prbs_mode_select_rx(hdev, port, lane, true, "PRBS31");

	rc = fw_start(hdev, port, lane, true, do_lt);
	if (rc) {
		dev_err(hdev->dev,
			"Card %u Port %u lane %d: F/W config speed PAM4 failed (LT %s), rc %d\n",
			card_location, port, lane, do_lt ? "enabled" : "disable", rc);
		return rc;
	}

	if (is_lane_swapping(hdev, port, lane)) {
		rc = fw_start_tx(hdev, tx_port, tx_lane, true, do_lt);
		if (rc) {
			dev_err(hdev->dev,
				"Card %u Port %u lane %d: F/W config speed PAM4 failed (LT %s), rc %d\n",
				card_location, tx_port, tx_lane, do_lt ? "enabled" : "disable",
				rc);
			return rc;
		}

		if (do_lt)
			NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, 0x1,
					      NIC0_SERDES0_LANE0_REGISTER_0PA0_RSVD_0PA0_04_MASK);
	}

	if (do_lt) {
		if (!hdev->phy_calc_ber) {
			/* tell the F/W to do LT with PCS data instead of PRBS */
			val = get_fw_reg(hdev, port, 366);
			val &= 0xFEFE;
			set_fw_reg(hdev, port, 366, val);
		}

		set_tx_taps_scale(hdev, tx_port, tx_lane);
		set_gc_tx(hdev, tx_port, tx_lane, 0);
		set_pc_tx(hdev, tx_port, tx_lane, 0);
		set_gc_rx(hdev, port, lane, 0);
		set_pc_rx(hdev, port, lane, 0);
	} else {
		curr_tx_taps_cfg = get_curr_tx_taps_cfg(hdev, port);
		set_tx_taps_cfg(hdev, tx_port, tx_lane, curr_tx_taps_cfg, true, false);
	}

	return 0;
}

static void init_nrz_tx(struct hbl_cn_device *hdev, u32 port, int lane)
{
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA1, 0x0);
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA2, 0x0);
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA3, 0x0);
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA4, 0x0);
	/* data quiet */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, 0x6320);
	/* auto symmetric, scale */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PAF, 0xF8C9);
	/* data, prbs */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PB0, 0x4820);
	/* cursor -2 */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA5, 0x0);
	/* cursor -1 */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA7, 0xFC00);
	/* cursor -main */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA9, 0x1800);
	/* cursor +1 */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PAB, 0x0);
	/* cursor +2 */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PAD, 0x0);
}

static void init_nrz_rx(struct hbl_cn_device *hdev, u32 port, int lane)
{
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PF8, 0xEC06);
}

static int fw_config_speed_nrz(struct hbl_cn_device *hdev, u32 port, int lane)
{
	u32 tx_port, card_location;
	u8 curr_tx_taps_cfg;
	int tx_lane, rc;

	card_location = hdev->card_location;

	get_tx_port_and_lane(hdev, port, lane, &tx_port, &tx_lane);

	lane_swapping_config(hdev, port, lane, false, false);

	init_nrz_tx(hdev, tx_port, tx_lane);
	init_nrz_rx(hdev, port, lane);

	init_lane_for_fw_tx(hdev, tx_port, tx_lane, false, false);
	init_lane_for_fw_rx(hdev, port, lane, false, false);

	prbs_mode_select_tx(hdev, tx_port, tx_lane, false, "PRBS31");
	prbs_mode_select_rx(hdev, port, lane, false, "PRBS31");

	rc = fw_start(hdev, port, lane, false, false);
	if (rc) {
		dev_err(hdev->dev,
			"Card %u Port %u lane %d: F/W config speed NRZ failed, rc %d\n",
			card_location, port, lane, rc);
		return rc;
	}

	if (is_lane_swapping(hdev, port, lane)) {
		rc = fw_start_tx(hdev, tx_port, tx_lane, false, false);
		if (rc) {
			dev_err(hdev->dev,
				"Card %u Port %u lane %d: F/W config speed NRZ failed, rc %d\n",
				card_location, tx_port, tx_lane, rc);
			return rc;
		}
	}

	curr_tx_taps_cfg = get_curr_tx_taps_cfg(hdev, port);
	set_tx_taps_cfg(hdev, tx_port, tx_lane, curr_tx_taps_cfg, false, false);

	return 0;
}

static void reset_mac_tx(struct hbl_cn_device *hdev, u32 port)
{
	struct gaudi2_cn_device *gaudi2 = hdev->asic_specific;
	u32 tx_ch_mask;

	/* For F/W version 37.1.0 and above, the reset will be done by the F/W */
	if ((hdev->fw_major_version == 37 && hdev->fw_minor_version > 1) ||
	    hdev->fw_major_version > 37) {
		struct gaudi2_cn_aux_ops *gaudi2_aux_ops;
		struct hbl_cn_aux_ops *aux_ops;
		struct hbl_aux_dev *aux_dev;
		struct cpucp_packet pkt;
		int rc;

		aux_dev = hdev->cn_aux_dev;
		aux_ops = aux_dev->aux_ops;
		gaudi2_aux_ops = aux_ops->asic_ops;

		memset(&pkt, 0, sizeof(pkt));
		pkt.ctl = cpu_to_le32(CPUCP_PACKET_NIC_MAC_TX_RESET << CPUCP_PKT_CTL_OPCODE_SHIFT);
		pkt.port_index = cpu_to_le32(port);

		rc = gaudi2_aux_ops->send_cpu_message(aux_dev, (u32 *)&pkt, sizeof(pkt), 0, NULL);
		if (rc)
			dev_warn(hdev->dev, "Card %u Port %u: Failed to reset MAC Tx, rc %d\n",
				 hdev->card_location, port, rc);

		return;
	}

	if (gaudi2->fw_security_enabled) {
		dev_warn(hdev->dev, "Card %u Port %u: Failed to reset MAC Tx, security is enabled.\n",
			 hdev->card_location, port);
		return;
	}

	tx_ch_mask = 1 << PRT0_MAC_CORE_MAC_RST_CFG_SD_TX_SW_RST_N_SHIFT;
	tx_ch_mask <<= (port & 0x1) ? 2 : 0;

	NIC_MACRO_RMWREG32(PRT0_MAC_CORE_MAC_RST_CFG, 0, tx_ch_mask);
	msleep(100);
	NIC_MACRO_RMWREG32(PRT0_MAC_CORE_MAC_RST_CFG, 1, tx_ch_mask);
}

static int fw_config(struct hbl_cn_device *hdev, u32 port, u32 data_rate, bool do_lt)
{
	u32 card_location;
	int lane, rc;
	bool pam4;

	card_location = hdev->card_location;
	pam4 = (data_rate == NIC_DR_50);

	/* clear go bit */
	if (pam4) {
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_980F, 0x1, 0x800);
		NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_980F, 0x1, 0x100);
	}

	NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_980F, 0x0, 0x8000);

	for (lane = 0; lane < 2; lane++) {
		if (pam4) {
			rc = fw_config_speed_pam4(hdev, port, lane, do_lt);
			if (rc) {
				dev_err(hdev->dev,
					"Card %u Port %u lane %d: F/W PAM4 config failed, rc %d\n",
					card_location, port, lane, rc);
				return rc;
			}

			NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PEA, 0x60,
					      NIC0_SERDES0_LANE0_REGISTER_0PEA_VDACCLKPHASE0_MASK);
		} else {
			rc = fw_config_speed_nrz(hdev, port, lane);
			if (rc) {
				dev_err(hdev->dev,
					"Card %u Port %u lane %d: F/W NRZ config failed, rc %d\n",
					card_location, port, lane, rc);
				return rc;
			}
		}
	}

	for (lane = 0; lane < 2; lane++) {
		rc = set_pll(hdev, port, lane, data_rate);
		if (rc)
			return rc;
	}

	msleep(100);

	reset_mac_tx(hdev, port);

	if (!hdev->phy_calc_ber)
		set_functional_mode(hdev, port);

	/* set go bit */
	NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_980F, 0x1, 0x8000);

	return 0;
}

static void phy_port_reset(struct hbl_cn_device *hdev, u32 port)
{
	int lane;

	soft_reset(hdev, port);
	usleep_range(500, 1000);

	for (lane = 0; lane < 2; lane++)
		clock_init(hdev, port, lane);

	cpu_reset(hdev, port);
	logic_reset(hdev, port);

	usleep_range(500, 1000);
}

static void prbs_reset(struct hbl_cn_port *cn_port, int lane, bool pam4)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	u32 port = cn_port->port;

	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P43, 1,
			      NIC0_SERDES0_LANE0_REGISTER_0P43_RX_PRBS_AUTO_SYNC_EN_MASK);

	if (pam4) {
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P43, 1,
				      NIC0_SERDES0_LANE0_REGISTER_0P43_PRBS_SYNC_CNTR_RESET_MASK);
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P43, 0,
				      NIC0_SERDES0_LANE0_REGISTER_0P43_PRBS_SYNC_CNTR_RESET_MASK);
	} else {
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0N61, 1,
				      NIC0_SERDES0_LANE0_REGISTER_0N61_PRBS_CNTR_RESET_MASK);
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0N61, 0,
				      NIC0_SERDES0_LANE0_REGISTER_0N61_PRBS_CNTR_RESET_MASK);
	}

	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P43, 0,
			      NIC0_SERDES0_LANE0_REGISTER_0P43_RX_PRBS_AUTO_SYNC_EN_MASK);
}

static u64 _get_prbs_cnt(struct hbl_cn_port *cn_port, int lane, bool pam4)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	u32 port = cn_port->port;
	u64 cnt;

	if (pam4)
		cnt = (((u64)NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P50)) << 16) +
		      NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P51);
	else
		cnt = (((u64)NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0N66)) << 16) +
		      NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0N67);

	return cnt;
}

static enum lane_state get_prbs_cnt(struct hbl_cn_port *cn_port, int lane, bool pam4,
				    u64 prbs_prev_cnt, u64 *prbs_new_cnt)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	u32 port = cn_port->port, phy_ready;
	u64 cnt;

	if (pam4) {
		phy_ready = (NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P6A) &
			     NIC0_SERDES0_LANE0_REGISTER_0P6A_RX_READ_PHY_READY_MASK) >>
			    NIC0_SERDES0_LANE0_REGISTER_0P6A_RX_READ_PHY_READY_SHIFT;
	} else {
		phy_ready = (NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0N2E) &
			     NIC0_SERDES0_LANE0_REGISTER_0N2E_NRZ_READ_PHY_READY_MASK) >>
			    NIC0_SERDES0_LANE0_REGISTER_0N2E_NRZ_READ_PHY_READY_SHIFT;
	}

	if (!phy_ready)
		return NOT_READY;

	cnt = _get_prbs_cnt(cn_port, lane, pam4);

	/* check PRBS counter wrapped around */
	if (cnt < prbs_prev_cnt) {
		if ((prbs_prev_cnt - cnt) < 0x10000)
			return FAILURE;

		cnt = _get_prbs_cnt(cn_port, lane, pam4);
	}

	*prbs_new_cnt = cnt;

	return READY;
}

static void _calc_ber_lane(struct hbl_cn_port *cn_port, int lane, u64 total_cnt, u64 error_cnt,
			   struct hbl_cn_ber_info *ber_info)
{
	u64 total_high_digits, error_high_digits, integer, frac;
	u8 total_num_digits, error_num_digits, exp;
	int i;

	total_num_digits = hbl_cn_get_num_of_digits(total_cnt);
	error_num_digits = hbl_cn_get_num_of_digits(error_cnt);

	if (total_num_digits > 2) {
		total_high_digits = total_cnt;

		for (i = 0; i < total_num_digits - 2; i++)
			total_high_digits = total_high_digits / 10;
	} else {
		total_high_digits = total_cnt;
	}

	if (!total_high_digits)
		return;

	if (error_num_digits > 2) {
		error_high_digits = error_cnt;

		for (i = 0; i < error_num_digits - 2; i++)
			error_high_digits = error_high_digits / 10;
	} else {
		error_high_digits = error_cnt;
	}

	exp = total_num_digits - error_num_digits;

	if (error_high_digits < total_high_digits) {
		error_high_digits *= 10;
		exp++;
	}

	integer = div_u64(error_high_digits, total_high_digits);
	frac = div_u64(((error_high_digits - (integer * total_high_digits)) * 10),
		       total_high_digits);

	ber_info->integer = integer;
	ber_info->frac = frac;
	ber_info->exp = exp;
	ber_info->valid = true;
}

static void calc_ber_lane(struct hbl_cn_port *cn_port, int lane, bool pam4)
{
	u64 prbs_err_cnt_pre, prbs_prev_cnt, prbs_err_cnt_post, prbs_err_cnt,
	    prbs_reset_time_jiffies, prbs_accum_time_jiffies, prbs_accum_time_ms,
	    factor, error_cnt, total_cnt;
	struct hbl_cn_device *hdev = cn_port->hdev;
	u32 card_location, port, abs_lane_idx;
	struct hbl_cn_ber_info *ber_info;
	enum lane_state state;

	card_location = hdev->card_location;
	port = cn_port->port;
	abs_lane_idx = (port << 1) + lane;

	ber_info = &hdev->phy_ber_info[abs_lane_idx];
	memset(ber_info, 0, sizeof(*ber_info));

	prbs_reset(cn_port, lane, pam4);
	prbs_reset_time_jiffies = jiffies;
	prbs_err_cnt_pre = _get_prbs_cnt(cn_port, lane, pam4);
	prbs_err_cnt_post = 0;

	prbs_prev_cnt = prbs_err_cnt_pre;

	while (true) {
		msleep(500);

		state = get_prbs_cnt(cn_port, lane, pam4, prbs_prev_cnt, &prbs_err_cnt_post);
		prbs_accum_time_jiffies = jiffies - prbs_reset_time_jiffies;
		prbs_accum_time_ms = jiffies_to_msecs(prbs_accum_time_jiffies);
		prbs_err_cnt = prbs_err_cnt_post - prbs_err_cnt_pre;

		if (state != READY) {
			dev_dbg(hdev->dev, "Card %u Port %u lane %d: No BER (state = %s)\n",
				card_location, port, lane,
				(state == NOT_READY) ? "NOT_READY" : "FAILURE");
			return;
		}

		if (prbs_accum_time_ms >= 5000 || prbs_err_cnt >= 10000000)
			break;

		prbs_prev_cnt = prbs_err_cnt_post;
	}

	factor = pam4 ? NIC_PHY_PAM4_BER_FACTOR : NIC_PHY_NRZ_BER_FACTOR;

	error_cnt = prbs_err_cnt;
	total_cnt = prbs_accum_time_ms * factor;

	_calc_ber_lane(cn_port, lane, total_cnt, error_cnt, ber_info);

	dev_dbg(hdev->dev,
		"Card %u Port %u lane %d: total_cnt %llu error_cnt %llu (%llu ms) - BER %llu.%llue-%u\n",
		card_location, port, lane, total_cnt, error_cnt, prbs_accum_time_ms,
		ber_info->integer, ber_info->frac, ber_info->exp);
}

static void calc_ber(struct hbl_cn_port *cn_port)
{
	int lane;

	for (lane = 0; lane < 2; lane++)
		calc_ber_lane(cn_port, lane, cn_port->data_rate == NIC_DR_50);
}

static void get_tx_port_lane(u32 port, int lane, u32 *_port, int *_lane)
{
	if (port != 0 && port != 1) {
		*_port = port;
		*_lane = lane;
		return;
	}

	if (port == 0 && lane == 0) {
		*_port = 1;
		*_lane = 1;
	} else if (port == 0 && lane == 1) {
		*_port = 0;
		*_lane = 1;
	} else if (port == 1 && lane == 0) {
		*_port = 0;
		*_lane = 0;
	} else if (port == 1 && lane == 1) {
		*_port = 1;
		*_lane = 0;
	}
}

static void modify_tx_taps(struct hbl_cn_port *cn_port)
{
	struct gaudi2_cn_port *gaudi2_port = cn_port->cn_specific;
	struct hbl_cn_device *hdev = cn_port->hdev;
	u8 curr_cfg, next_cfg;
	u32 port, _port;
	int lane, _lane;
	bool pam4;

	port = cn_port->port;
	curr_cfg = get_curr_tx_taps_cfg(hdev, port);
	next_cfg = (curr_cfg + 1) % tx_taps_num_cfgs;
	pam4 = cn_port->data_rate == NIC_DR_50;
	_port = 0;
	_lane = 0;

	gaudi2_port->tx_taps_cfg = next_cfg;

	/* If the next cfg equals the initial cfg, it means that we went through all the taps cfgs.
	 * In that case, PHY reconfigure should be triggered.
	 */
	if (next_cfg == gaudi2_port->initial_tx_taps_cfg) {
		dev_dbg(hdev->dev,
			"Card %u Port %u: all tx taps cfgs were failed - reconfiguring PHY\n",
			hdev->card_location, port);

		return hbl_cn_phy_port_reconfig(cn_port);
	}

	dev_dbg(hdev->dev, "Card %u Port %u: modify %s tx taps (%u,%u)->(%u,%u)\n",
		hdev->card_location, port, pam4 ? "PAM4" : "NRZ",
		tx_taps_cfg_array[curr_cfg][0] + 1, tx_taps_cfg_array[curr_cfg][1] + 1,
		tx_taps_cfg_array[next_cfg][0] + 1, tx_taps_cfg_array[next_cfg][1] + 1);

	for (lane = 0; lane < 2; lane++) {
		get_tx_port_lane(port, lane, &_port, &_lane);
		set_tx_taps_cfg(hdev, _port, _lane, next_cfg, pam4, true);
	}

	gaudi2_port->tx_taps_modified = true;
}

static void print_final_tx_taps(struct hbl_cn_port *cn_port)
{
	char tx_taps_str0[25] = {0}, tx_taps_str1[25] = {0};
	struct hbl_cn_device *hdev = cn_port->hdev;
	u32 port, abs_lane0_idx, abs_lane1_idx;
	s32 *taps;
	bool pam4;

	pam4 = cn_port->data_rate == NIC_DR_50;
	port = cn_port->port;
	abs_lane0_idx = port << 1;
	abs_lane1_idx = abs_lane0_idx + 1;

	taps = pam4 ? hdev->phy_tx_taps[abs_lane0_idx].pam4_taps :
			hdev->phy_tx_taps[abs_lane0_idx].nrz_taps;
	sprintf(tx_taps_str0, "%d,%d,%d,%d,%d", taps[0], taps[1], taps[2], taps[3], taps[4]);

	taps = pam4 ? hdev->phy_tx_taps[abs_lane1_idx].pam4_taps :
			hdev->phy_tx_taps[abs_lane1_idx].nrz_taps;
	sprintf(tx_taps_str1, "%d,%d,%d,%d,%d", taps[0], taps[1], taps[2], taps[3], taps[4]);

	dev_dbg(hdev->dev, "Card %u Port %u: Final Tx taps - lane0: [%s], lane1: [%s]\n",
		hdev->card_location, port, tx_taps_str0, tx_taps_str1);
}

static void change_pcs_link_state(struct gaudi2_cn_port *gaudi2_port,
				  enum gaudi2_cn_pcs_link_state pcs_link_state)
{
	struct hbl_cn_port *cn_port = gaudi2_port->cn_port;

	gaudi2_port->pcs_link_state = pcs_link_state;

	/* The retry count is being incremented in a different frequency in every state.
	 * Therefore, in order to have a logical value in each state, it needs to be reset when
	 * moving to a new state.
	 */
	cn_port->retry_cnt = 0;
}

static void check_pcs_link(struct hbl_cn_port *cn_port)
{
	u32 card_location, port, mac_gnrl_sts, pcs_link_samples_per_sec, link_down_cnt_th,
	    remote_fault_cnt_th, link_toggles;
	enum gaudi2_cn_pcs_link_state pcs_link_state;
	struct gaudi2_cn_port *gaudi2_port;
	struct hbl_cn_device *hdev;

	hdev = cn_port->hdev;
	gaudi2_port = cn_port->cn_specific;
	card_location = hdev->card_location;
	port = cn_port->port;
	pcs_link_state = gaudi2_port->pcs_link_state;

	if (pcs_link_state == PCS_LINK_STATE_SETTLING) {
		if (cn_port->eth_enable) {
			change_pcs_link_state(gaudi2_port, PCS_LINK_STATE_STEADY);
		} else {
			change_pcs_link_state(gaudi2_port, PCS_LINK_STATE_STRESS);
			gaudi2_port->pcs_link_stady_state_ts =
				ktime_add_ms(ktime_get(), NIC_PHY_PCS_STRESS_WINDOW_MS);
		}

		return;
	}

	mac_gnrl_sts = (port & 0x1) ? NIC_MACRO_RREG32(PRT0_MAC_CORE_MAC_GNRL_STS_2) :
			NIC_MACRO_RREG32(PRT0_MAC_CORE_MAC_GNRL_STS_0);

	if (FIELD_GET(PRT0_MAC_CORE_MAC_GNRL_STS_LOC_FAULT_MASK, mac_gnrl_sts))
		cn_port->pcs_local_fault_cnt++;

	if (FIELD_GET(PRT0_MAC_CORE_MAC_GNRL_STS_REM_FAULT_MASK, mac_gnrl_sts)) {
		cn_port->pcs_remote_fault_cnt++;
		cn_port->pcs_remote_fault_seq_cnt++;
	} else {
		cn_port->pcs_remote_fault_seq_cnt = 0;
	}

	pcs_link_samples_per_sec = gaudi2_port->pcs_link_samples_per_sec;
	remote_fault_cnt_th = NIC_PHY_MAC_REMOTE_FAULT_TH_S * pcs_link_samples_per_sec;

	if (pcs_link_state == PCS_LINK_STATE_STRESS) {
		if (ktime_after(ktime_get(), gaudi2_port->pcs_link_stady_state_ts)) {
			change_pcs_link_state(gaudi2_port, PCS_LINK_STATE_STEADY);
			goto check_link;
		}

		if (cn_port->pcs_remote_fault_seq_cnt) {
			dev_dbg(hdev->dev, "Card %u Port %u: got MAC remote fault during stress window\n",
				card_location, port);

			modify_tx_taps(cn_port);
			change_pcs_link_state(gaudi2_port, PCS_LINK_STATE_SETTLING);
			cn_port->pcs_remote_fault_seq_cnt = 0;
		}
	} else { /* PCS_LINK_STATE_STEADY */
		if (gaudi2_port->tx_taps_modified) {
			print_final_tx_taps(cn_port);
			gaudi2_port->tx_taps_modified = false;
		}

		if (cn_port->pcs_remote_fault_seq_cnt == remote_fault_cnt_th) {
			dev_dbg(hdev->dev,
				"Card %u Port %u: %u sequential seconds of MAC remote faults\n",
				card_location, port, NIC_PHY_MAC_REMOTE_FAULT_TH_S);

			/* Modify tx taps - external ports are excluded */
			if (!cn_port->eth_enable) {
				modify_tx_taps(cn_port);
				change_pcs_link_state(gaudi2_port, PCS_LINK_STATE_SETTLING);
			}

			cn_port->pcs_remote_fault_seq_cnt = 0;
		}
	}

check_link:
	link_toggles = cn_port->port_toggle_cnt - cn_port->port_toggle_cnt_prev;
	cn_port->port_toggle_cnt_prev = cn_port->port_toggle_cnt;

	/* The condition to reset the retry_cnt is that the link is UP, and if in steady state,
	 * only if the link toggling threshold is not exceeded.
	 */
	if (cn_port->pcs_link && !(pcs_link_state == PCS_LINK_STATE_STEADY &&
				   link_toggles > NIC_PHY_PCS_MAX_LINK_TOGGLES)) {
		cn_port->retry_cnt = 0;
		return;
	}

	cn_port->retry_cnt++;
	link_down_cnt_th = NIC_PHY_PCS_LINK_DOWN_TH_S * pcs_link_samples_per_sec;

	if (cn_port->retry_cnt == link_down_cnt_th) {
		dev_dbg(hdev->dev,
			"Card %u Port %u: %u sequential seconds of PCS link down - reconfiguring PHY\n",
			card_location, port, NIC_PHY_PCS_LINK_DOWN_TH_S);

		hbl_cn_phy_port_reconfig(cn_port);
	}
}

static u32 rv_debug(struct hbl_cn_device *hdev, u32 port, int lane, u32 mode, u32 index)
{
	u32 cmd, res;

	cmd = 0xB000 + ((mode & 0xF) << 4) + lane;

	fw_cmd(hdev, port, cmd, &index, 0xB, &res);

	return NIC_PHY_RREG32(NIC0_SERDES0_REGISTER_9816);
}

static int fw_tuning(struct hbl_cn_device *hdev, u32 port, int lane, bool pam4)
{
	u32 state, mode;

	mode = pam4 ? 2 : 1;
	state = rv_debug(hdev, port, lane, mode, 0);

	if (pam4) {
		if (((u16)state) != 0x8F00 && ((u16)state) != 0x8F80)
			return -EAGAIN;
	} else {
		if (((u16)state) != 0x9A00)
			return -EAGAIN;
	}

	return 0;
}

static void do_fw_tuning(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	u32 card_location, port;
	int lane, rc;
	bool pam4;

	card_location = hdev->card_location;
	port = cn_port->port;
	pam4 = (cn_port->data_rate == NIC_DR_50);

	for (lane = 0; lane < 2; lane++) {
		rc = fw_tuning(hdev, port, lane, pam4);
		if (rc) {
			if (ktime_after(ktime_get(), cn_port->fw_tuning_limit_ts)) {
				dev_dbg(hdev->dev,
					"Card %u Port %u lane %d: F/W tuning limit - reconfiguring PHY\n",
					card_location, port, lane);

				hbl_cn_phy_port_reconfig(cn_port);
				return;
			}

			break;
		}
	}

	if (!rc) {
		/* The control lock needs to be taken here in order to protect against a parallel
		 * status set from the link event handler.
		 * This lock also protects port close flow that destroys this thread synchronically,
		 * so a potential deadlock could happen here.
		 * In order to avoid this deadlock, we need to check if this lock was taken.
		 * If it was taken and the port is marked as closed (i.e., we are now during port
		 * close flow), we can return immediately.
		 * Otherwise, we need to keep trying to take this lock before we enter the critial
		 * section.
		 */
		while (!mutex_trylock(&cn_port->control_lock))
			if (!hbl_cn_is_port_open(cn_port))
				return;

		cn_port->phy_fw_tuned = true;

		/* If we got link up event, set it now when PHY is ready */
		if (cn_port->eq_pcs_link) {
			cn_port->pcs_link = true;
			hbl_cn_phy_set_port_status(cn_port, true);
		}

		mutex_unlock(&cn_port->control_lock);

		cn_port->retry_cnt = 0;
	}
}

static int fw_tuning_an(struct hbl_cn_device *hdev, u32 port, int lane)
{
	u32 state = rv_debug(hdev, port, lane, 1, 0);

	if (((u16)state) != 0xA01F && ((u16)state) != 0xA020 && ((u16)state) != 0xAF00) {
		u32 error_status = rv_debug(hdev, port, lane, 0, 3);

		dev_dbg_ratelimited(hdev->dev,
				    "Card %u Port %u lane %d: auto neg fw is not ready, state 0x%x error 0x%x\n",
				    hdev->card_location, port, lane, state, error_status);
		return -EAGAIN;
	}

	return 0;
}

static void tx_quite(struct hbl_cn_device *hdev, u32 port, int lane)
{
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA1, 0x0);
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA2, 0x0);
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA3, 0x0);
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA4, 0x0);
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, 0x0,
			      NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_TEST_DATA_SRC_MASK);
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, 0x0,
			      NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_PAM4_TEST_EN_MASK);
}

static int do_anlt(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	u32 port = cn_port->port, tx_port;
	int tx_lane, rc;

	/* fw_tuning_an needs to be done only on lane 0 */
	rc = fw_tuning_an(hdev, port, 0);
	if (rc)
		return rc;

	get_tx_port_and_lane(hdev, port, 0, &tx_port, &tx_lane);
	tx_quite(hdev, tx_port, tx_lane);

	rc = fw_config(hdev, port, NIC_DR_50, true);
	if (rc) {
		dev_dbg(hdev->dev,
			"Card %u Port %u: PHY link training failed, rc %d - reconfiguring PHY\n",
			hdev->card_location, port, rc);

		hbl_cn_phy_port_reconfig(cn_port);

		return rc;
	}

	cn_port->auto_neg_resolved = true;

	return 0;
}

static void do_fw_tuning_auto_neg(struct hbl_cn_port *cn_port)
{
	u32 fw_tuning_timeout_ms;

	if (cn_port->auto_neg_enable) {
		if (do_anlt(cn_port))
			return;
	} else {
		cn_port->auto_neg_skipped = true;
	}

	if (cn_port->eth_enable)
		fw_tuning_timeout_ms = NIC_PHY_FW_TUNING_TIMEOUT_MS;
	else
		fw_tuning_timeout_ms = tx_taps_num_cfgs * NIC_PHY_PCS_SETTLING_WAIT_MS;

	cn_port->fw_tuning_limit_ts = ktime_add_ms(ktime_get(), fw_tuning_timeout_ms);
	do_fw_tuning(cn_port);
}

static u32 get_timeout_ms(struct hbl_cn_port *cn_port)
{
	u32 card_location, port, timeout_ms;
	struct gaudi2_cn_port *gaudi2_port;
	struct hbl_cn_device *hdev;

	hdev = cn_port->hdev;
	gaudi2_port = cn_port->cn_specific;
	card_location = hdev->card_location;
	port = cn_port->port;
	timeout_ms = MSEC_PER_SEC;

	if (!cn_port->phy_fw_tuned) {
		timeout_ms = NIC_PHY_FW_TUNING_INTERVAL_MS;
	} else if (!cn_port->phy_func_mode_en) {
		u16 timeout_sec = hdev->phy_calc_ber_wait_sec;

		dev_info(hdev->dev, "Card %u Port %u: Waiting %u seconds before calculating BER\n",
			 card_location, port, timeout_sec);
		timeout_ms = timeout_sec * MSEC_PER_SEC;
	} else {
		enum gaudi2_cn_pcs_link_state pcs_link_state = gaudi2_port->pcs_link_state;

		switch (pcs_link_state) {
		case PCS_LINK_STATE_SETTLING:
			timeout_ms = NIC_PHY_PCS_SETTLING_WAIT_MS;
			dev_dbg(hdev->dev, "Card %u Port %u: waiting %lu seconds for settling\n",
				card_location, port, timeout_ms / MSEC_PER_SEC);
			break;
		case PCS_LINK_STATE_STRESS:
			timeout_ms = NIC_PHY_PCS_STRESS_INT_MS;
			gaudi2_port->pcs_link_samples_per_sec = MSEC_PER_SEC / timeout_ms;
			break;
		case PCS_LINK_STATE_STEADY:
			timeout_ms = NIC_PHY_PCS_STEADY_STATE_INT_MS;
			gaudi2_port->pcs_link_samples_per_sec = MSEC_PER_SEC / timeout_ms;
			break;
		default:
			dev_err(hdev->dev, "Card %u Port %u: invalid pcs_link_state %u\n",
				card_location, port, pcs_link_state);
		}
	}

	return timeout_ms;
}

void gaudi2_cn_phy_link_status_work(struct work_struct *work)
{
	u32 card_location, port, timeout_ms;
	struct gaudi2_cn_device *gaudi2;
	struct hbl_cn_port *cn_port;
	struct hbl_cn_device *hdev;

	cn_port = container_of(work, struct hbl_cn_port, link_status_work.work);
	hdev = cn_port->hdev;
	gaudi2 = hdev->asic_specific;
	card_location = hdev->card_location;
	port = cn_port->port;

	/* Reschedule this work if the device is under compute reset */
	if (gaudi2->in_compute_reset) {
		timeout_ms = MSEC_PER_SEC;
		goto reschedule;
	}

	if (cn_port->phy_fw_tuned) {
		if (!cn_port->phy_func_mode_en) {
			calc_ber(cn_port);
			dev_info(hdev->dev, "Card %u Port %u: BER calculation is done\n",
				 card_location, port);
			return;
		}

		check_pcs_link(cn_port);
	} else {
		if (cn_port->auto_neg_resolved || cn_port->auto_neg_skipped)
			do_fw_tuning(cn_port);
		else
			do_fw_tuning_auto_neg(cn_port);
	}

	timeout_ms = get_timeout_ms(cn_port);

reschedule:
	queue_delayed_work(cn_port->wq, &cn_port->link_status_work, msecs_to_jiffies(timeout_ms));
}

static void set_tx(struct hbl_cn_device *hdev, u32 port, int lane, bool enable)
{
	u32 val = enable ? 0x1 : 0x0;

	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0NF8, val,
			      NIC0_SERDES0_LANE0_REGISTER_0NF8_PU_VDRV_MASK);
}

void gaudi2_cn_phy_port_start_stop(struct hbl_cn_port *cn_port, bool is_start)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	u32 port = cn_port->port, tx_port;
	int lane, tx_lane;

	for (lane = 0; lane < 2; lane++) {
		get_tx_port_and_lane(hdev, port, lane, &tx_port, &tx_lane);

		if (is_start) {
			/* Enable TX driver in SerDes */
			set_tx(hdev, tx_port, tx_lane, true);
			/* Enable F/W Rx tuning is done during power up flow */
		} else {
			/* Disable TX driver in SerDes */
			set_tx(hdev, tx_port, tx_lane, false);
			/* Silence F/W Rx tuning */
			NIC_PHY_WREG32(NIC0_SERDES0_REGISTER_9815, 0x9000 | lane);
		}
	}
}

static int fw_start_an(struct hbl_cn_device *hdev, u32 port, int lane)
{
	u32 detail = 0, ignore;

	return fw_cmd(hdev, port, 0x80A0 | lane, &detail, 0x8, &ignore);
}

static int fw_start_an_tx(struct hbl_cn_device *hdev, u32 port, int lane)
{
	u32 detail = 0, ignore;
	int rc;

	rc = fw_cmd(hdev, port, 0x7040 | lane, &detail, 0x7, &ignore);
	if (rc)
		return rc;

	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0, 0x0,
			      NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_PAM4_TEST_EN_MASK);

	return 0;
}

static int fw_config_auto_neg(struct hbl_cn_device *hdev, u32 port, int lane)
{
	struct hbl_cn_port *cn_port = &hdev->cn_ports[port];
	u64 basepage = 0x800000001ull;
	u32 tx_port, pflags;
	u32 card_location;
	int tx_lane, rc;

	card_location = hdev->card_location;
	pflags = hbl_cn_get_pflags(cn_port);

	get_tx_port_and_lane(hdev, port, lane, &tx_port, &tx_lane);

	/* clear go bit */
	NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_980F, 0x0, 0x8000);

	init_nrz_tx(hdev, tx_port, tx_lane);
	init_nrz_rx(hdev, port, lane);

	init_lane_for_fw_tx(hdev, tx_port, tx_lane, false, true);
	init_lane_for_fw_rx(hdev, port, lane, false, true);

	prbs_mode_select_tx(hdev, tx_port, tx_lane, false, "PRBS31");
	prbs_mode_select_rx(hdev, port, lane, false, "PRBS31");

	lane_swapping_config(hdev, port, lane, true, true);

	/* set FW to start AN */

	rc = fw_start_an(hdev, port, lane);
	if (rc) {
		dev_err(hdev->dev, "Card %u Port %u lane %d: start auto neg failed, rc %d\n",
			card_location, tx_port, tx_lane, rc);
		return rc;
	}

	if (is_lane_swapping(hdev, port, lane)) {
		rc = fw_start_an_tx(hdev, tx_port, tx_lane);
		if (rc) {
			dev_err(hdev->dev,
				"Card %u Port %u lane %d: start auto neg failed, rc %d\n",
				card_location, tx_port, tx_lane, rc);
			return rc;
		}
	}

	/* AN reset */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_AK00, 0xE000);

	/* AN mode */
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_AI10, basepage & 0xFFFF);
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_AI11, (basepage >> 16) & 0xFFFF);
	NIC_PHY_WREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_AI12, (basepage >> 32) & 0xFFFF);

	/* IEEE */
	NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_AK00, 0x1,
			      NIC0_SERDES0_LANE0_REGISTER_AK00_ARG_ANEG_IEEE_MODE_S_MASK);

	if (pflags & PFLAGS_PHY_AUTO_NEG_LPBK)
		NIC_PHY_RMWREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_AK00, 0x1,
				      NIC0_SERDES0_LANE0_REGISTER_AK00_ARG_DIS_NONCE_MATCH_S_MASK);

	rc = set_pll(hdev, port, lane, NIC_DR_25);
	if (rc)
		return rc;

	/* set go bit */
	NIC_PHY_RMWREG32(NIC0_SERDES0_REGISTER_980F, 0x1, 0x8000);

	return 0;
}

static int port_9_reinit(struct hbl_cn_device *hdev)
{
	struct hbl_cn_port *cn_port_9 = &hdev->cn_ports[9];

	if (!hbl_cn_is_port_open(cn_port_9))
		return 0;

	dev_dbg(hdev->dev,
		"Card %u Port 9: Performing port 9 PHY reinit following port 8 PHY init\n",
		hdev->card_location);

	hbl_cn_phy_fini(cn_port_9);

	return hbl_cn_phy_init(cn_port_9);
}

int gaudi2_cn_phy_port_power_up(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	struct gaudi2_cn_port *gaudi2_port;
	u32 data_rate = cn_port->data_rate;
	u32 card_location, port;
	int rc;

	gaudi2_port = cn_port->cn_specific;
	card_location = hdev->card_location;
	port = cn_port->port;

	phy_port_reset(hdev, port);

	if (hdev->phy_force_first_tx_taps_cfg)
		gaudi2_port->tx_taps_cfg = 0;

	cn_port->phy_func_mode_en = false;
	gaudi2_port->pcs_link_state = PCS_LINK_STATE_SETTLING;
	gaudi2_port->initial_tx_taps_cfg = gaudi2_port->tx_taps_cfg;

	if (cn_port->auto_neg_enable) {
		/* AN config should be done only on lane 0 */
		rc = fw_config_auto_neg(hdev, port, 0);
		if (rc) {
			dev_err(hdev->dev, "Card %u Port %u: F/W config auto_neg failed, rc %d\n",
				card_location, port, rc);
			return rc;
		}
	} else {
		rc = fw_config(hdev, port, data_rate, false);
		if (rc) {
			dev_err(hdev->dev, "Card %u Port %u: F/W config failed, rc %d\n",
				card_location, port, rc);
			return rc;
		}
	}

	/* Port 8 is an external port which will usually be brought UP after all the internal ports
	 * are UP. Due to macro clock nest dependency, when PHY reset is called for port 8,
	 * port 9 (which is internal) is being toggled and might lost stabilization.
	 * A W/A to overcome this issue is to reinit port 9 right after.
	 */
	if (port == 8)
		port_9_reinit(hdev);

	return 0;
}

void gaudi2_cn_phy_port_reconfig(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	u32 card_location, port;
	int rc;

	if (!hdev->phy_config_fw)
		return;

	card_location = hdev->card_location;
	port = cn_port->port;

	rc = gaudi2_cn_phy_port_power_up(cn_port);
	if (rc)
		dev_err(hdev->dev, "Card %u Port %u: PHY reconfig failed\n", card_location, port);
}

int gaudi2_cn_phy_port_init(struct hbl_cn_port *cn_port)
{
	struct hbl_cn_device *hdev = cn_port->hdev;
	u32 port = cn_port->port;
	int rc;

	mac_lane_remap(hdev, port);

	rc = hbl_cn_phy_init(cn_port);
	if (rc)
		dev_err(hdev->dev, "Port %u: failed to init PHY, rc %d\n", port, rc);

	return rc;
}

void gaudi2_cn_phy_port_fini(struct hbl_cn_port *cn_port)
{
	hbl_cn_phy_fini(cn_port);
}

int gaudi2_cn_phy_reset_macro(struct hbl_cn_macro *cn_macro)
{
	struct hbl_cn_device *hdev = cn_macro->hdev;
	u32 port;

	/* Reset the two ports under the given cn_macro */
	port = cn_macro->idx << 1;

	/* Enable PHY refclk */
	NIC_MACRO_WREG32(NIC0_PHY_PHY_IDDQ_0, 0);
	NIC_MACRO_WREG32(NIC0_PHY_PHY_IDDQ_1, 0);

	phy_port_reset(hdev, port);
	phy_port_reset(hdev, port + 1);

	return 0;
}

void gaudi2_cn_phy_flush_link_status_work(struct hbl_cn_device *hdev)
{
	struct hbl_cn_port *cn_port;
	int i;

	for (i = 0; i < hdev->cn_props.max_num_of_ports; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		cn_port = &hdev->cn_ports[i];

		flush_delayed_work(&cn_port->link_status_work);
	}
}

static int find_first_enabled_port(struct hbl_cn_device *hdev, u32 *port)
{
	int i;

	for (i = 0; i < NIC_NUMBER_OF_PORTS; i++) {
		if (!(hdev->ports_mask & BIT(i)))
			continue;

		*port = i;
		return 0;
	}

	return -EINVAL;
}

static void fw_write_all(struct hbl_cn_device *hdev, u32 addr, u32 data)
{
	int port;

	for (port = 0; port < NIC_NUMBER_OF_PORTS; port++) {
		if (!(hdev->ports_mask & BIT(port)))
			continue;

		NIC_PHY_WREG32(addr, data);
	}
}

static void fw_write_all_lanes(struct hbl_cn_device *hdev, u32 addr, u32 data)
{
	int port, lane;

	for (port = 0; port < NIC_NUMBER_OF_PORTS; port++) {
		if (!(hdev->ports_mask & BIT(port)))
			continue;

		for (lane = 0; lane < 2; lane++)
			NIC_PHY_WREG32_LANE(addr, data);
	}
}

static void fw_unload_all(struct hbl_cn_device *hdev)
{
	u32 port;

	fw_write_all(hdev, NIC0_SERDES0_REGISTER_9814, 0xFFF0);

	for (port = 0; port < NIC_NUMBER_OF_PORTS; port++) {
		if (!(hdev->ports_mask & BIT(port)))
			continue;

		cpu_reset(hdev, port);
	}

	msleep(100);

	fw_write_all(hdev, NIC0_SERDES0_REGISTER_9814, 0x0);

	/* PAM4 */
	fw_write_all_lanes(hdev, NIC0_SERDES0_LANE0_REGISTER_0P11, 0);
	usleep_range(1000, 2000);
	fw_write_all_lanes(hdev, NIC0_SERDES0_LANE0_REGISTER_0P11, 0x2000);

	/* NRZ */
	fw_write_all_lanes(hdev, NIC0_SERDES0_LANE0_REGISTER_0N0B, 0);
	fw_write_all_lanes(hdev, NIC0_SERDES0_LANE0_REGISTER_0N0C, 0);
	usleep_range(1000, 2000);
	fw_write_all_lanes(hdev, NIC0_SERDES0_LANE0_REGISTER_0N0C, 0x8000);
}

static u32 fw_crc(struct hbl_cn_device *hdev, u32 port)
{
	u32 checksum_code, ignore;

	fw_cmd(hdev, port, 0xF001, NULL, 0xF, &ignore);
	checksum_code = NIC_PHY_RREG32(NIC0_SERDES0_REGISTER_9816);

	return checksum_code;
}

static u32 fw_hash(struct hbl_cn_device *hdev, u32 port)
{
	u32 low_word, hash_code, res;

	fw_cmd(hdev, port, 0xF000, NULL, 0xF, &res);
	low_word = NIC_PHY_RREG32(NIC0_SERDES0_REGISTER_9816);
	hash_code = ((res & 0xFF) << 16) | low_word;

	return hash_code;
}

static int mcu_cal_enable_all(struct hbl_cn_device *hdev)
{
	u32 port;
	int rc;

	for (port = 0; port < NIC_NUMBER_OF_PORTS; port++) {
		if (!(hdev->ports_mask & BIT(port)))
			continue;

		rc = set_fw_reg(hdev, port, 357, NIC_PHY_FW_TIME_CONSTANT_RATIO);
		if (rc) {
			dev_dbg(hdev->dev, "Port %u: MCU calibration failed\n", port);
			return rc;
		}
	}

	return 0;
}

int gaudi2_cn_phy_fw_load_all(struct hbl_cn_device *hdev)
{
	u32 entry_point, length, ram_addr, sections, status, checks, checksum;
	int rc, i, j, data_ptr = 0;
	const struct firmware *fw;
	const void *fw_data;
	const char *fw_name;
	u16 mdio_data;
	u32 port; /* For regs read */

	rc = find_first_enabled_port(hdev, &port);
	if (rc)
		return rc;

	fw_name = gaudi2_cn_phy_get_fw_name();

	fw_unload_all(hdev);

	rc = request_firmware(&fw, fw_name, hdev->dev);
	if (rc) {
		dev_err(hdev->dev, "Firmware file %s is not found\n", fw_name);
		return rc;
	}

	fw_data = (const void *)fw->data;
	fw_data += 0x1000;

	/* skip hash, crc and date */
	entry_point = get_unaligned_be32(fw_data + 8);
	length = get_unaligned_be32(fw_data + 12);
	ram_addr = get_unaligned_be32(fw_data + 16);

	dev_dbg(hdev->dev, "entry_point: 0x%x\n", entry_point);
	dev_dbg(hdev->dev, "length: 0x%x\n", length);

	fw_data += 20;

	sections = DIV_ROUND_UP(length, 24);

	dev_dbg(hdev->dev, "sections: %d\n", sections);

	fw_write_all(hdev, NIC0_SERDES0_REGISTER_9814, 0xFFF0); /* FW2 */
	fw_write_all(hdev, NIC0_SERDES0_REGISTER_980D, 0x0AAA); /* FW1 */
	fw_write_all(hdev, NIC0_SERDES0_REGISTER_980D, 0x0); /* FW1 */

	checks = 0;

	do {
		usleep_range(10000, 20000);
		status = NIC_PHY_RREG32(NIC0_SERDES0_REGISTER_9814); /* FW2 */
		dev_dbg(hdev->dev, "port %d, status: 0x%x\n", port, status);
		if (checks++ > NIC_PHY_READ_COUNTS_PER_MS) {
			dev_err(hdev->dev, "failed to load F/W, fw2 timeout 0x%x\n", status);
			rc = -ETIMEDOUT;
			goto release_fw;
		}
	} while (status);

	fw_write_all(hdev, NIC0_SERDES0_REGISTER_9814, 0x0);

	for (i = 0; i <= sections; i++) {
		checksum = 0x800C;

		fw_write_all(hdev, NIC0_SERDES0_REGISTER_9F0C, ram_addr >> 16); /* FW0 + 12 */
		fw_write_all(hdev, NIC0_SERDES0_REGISTER_9F0D, ram_addr & 0xFFFF); /* FW0 + 13 */
		checksum += (ram_addr >> 16) + (ram_addr & 0xFFFF);

		for (j = 0; j < 12; j++) {
			if (data_ptr >= length)
				mdio_data = 0;
			else
				mdio_data = get_unaligned_be16(fw_data + data_ptr);

			fw_write_all(hdev, NIC0_SERDES0_REGISTER_9F00 + 4 * j, mdio_data);

			checksum += mdio_data;
			data_ptr += 2;
			ram_addr += 2;
		}

		/* FW0 + 14 */
		fw_write_all(hdev, NIC0_SERDES0_REGISTER_9F0E, (~checksum + 1) & 0xFFFF);
		fw_write_all(hdev, NIC0_SERDES0_REGISTER_9F0F, 0x800C); /* FW0 + 15 */

		checks = 0;

		do {
			usleep_range(1000, 2000);
			status = NIC_PHY_RREG32(NIC0_SERDES0_REGISTER_9F0F); /* FW0 + 15 */
			if (checks++ > NIC_PHY_READ_COUNTS_PER_MS) {
				dev_err(hdev->dev, "failed to load F/W, fw0 timeout 0x%x\n",
					status);
				rc = -ETIMEDOUT;
				goto release_fw;
			}
		} while (status == 0x800C);
	}

	fw_write_all(hdev, NIC0_SERDES0_REGISTER_9F0C, entry_point >> 16); /* FW0 + 12 */
	fw_write_all(hdev, NIC0_SERDES0_REGISTER_9F0D, entry_point & 0xFFFF); /* FW0 + 13 */
	checksum = (entry_point >> 16) + (entry_point & 0xFFFF) + 0x4000;
	fw_write_all(hdev, NIC0_SERDES0_REGISTER_9F0E, (~checksum + 1) & 0xFFFF); /* FW0 + 14 */
	fw_write_all(hdev, NIC0_SERDES0_REGISTER_9F0F, 0x4000); /* FW0 + 15 */

	msleep(500);

	dev_dbg(hdev->dev, "F/W CRC = 0x%x\n", fw_crc(hdev, port));
	dev_dbg(hdev->dev, "F/W hash = 0x%x\n", fw_hash(hdev, port));

	rc = mcu_cal_enable_all(hdev);

release_fw:
	release_firmware(fw);
	return rc;
}

u16 gaudi2_cn_phy_get_crc(struct hbl_cn_device *hdev)
{
	u32 port;
	int rc;

	rc = find_first_enabled_port(hdev, &port);
	if (rc)
		return rc;

	return fw_crc(hdev, port);
}

static bool is_old_phy_fw_loaded(struct hbl_cn_device *hdev)
{
	return gaudi2_cn_phy_get_crc(hdev) == 0x1723;
}

static bool is_phy_fw_with_anlt_support(struct hbl_cn_device *hdev)
{
	return gaudi2_cn_phy_get_crc(hdev) == 0x185E;
}

int gaudi2_cn_phy_init(struct hbl_cn_device *hdev)
{
	if (!hdev->phy_config_fw)
		return 0;

	/* Fail the initialization in case of an old PHY F/W, as the current PHY init flow won't
	 * work with it.
	 */
	if (is_old_phy_fw_loaded(hdev)) {
		dev_err(hdev->dev, "PHY F/W is very old - failing the initialization\n");
		return -EINVAL;
	}

	/* In case LKD override the existing PHY F/W with an unofficial one and this F/W has ANLT
	 * support, ANLT will be enabled according to the mask.
	 * Otherwise, ANLT will be disabled on all ports.
	 */
	if (hdev->load_phy_fw && is_phy_fw_with_anlt_support(hdev))
		hdev->auto_neg_mask = hdev->phys_auto_neg_mask;
	else
		hdev->auto_neg_mask = 0;

	/* In case we didn't get serdes info from FW, set to default values */
	if (hdev->use_fw_serdes_info) {
		set_fw_lane_mapping(hdev);
		hbl_cn_phy_set_fw_polarity(hdev);
	} else {
		set_default_mac_lane_remap(hdev);
		set_default_polarity_values(hdev);
	}

	/* Set the tx taps to their default values only once */
	if (!hdev->skip_phy_default_tx_taps_cfg) {
		set_default_tx_taps_values(hdev);
		hdev->skip_phy_default_tx_taps_cfg = true;
	}

	return 0;
}

static int fw_read_s16(struct hbl_cn_device *hdev, u32 port, u32 offset)
{
	u32 t = NIC_PHY_RREG32(NIC0_SERDES0_REGISTER_9F00 + 4 * offset);

	return (t & 0x8000) ? t - 0x10000 : t;
}

static void get_channel_estimation_params(struct hbl_cn_device *hdev, u32 port, int lane, u32 *of,
					  u32 *hf)
{
	struct hbl_cn_port *cn_port = &hdev->cn_ports[port];

	if (cn_port->auto_neg_enable) {
		*of = rv_debug(hdev, port, lane, 5, 22);
		*hf = rv_debug(hdev, port, lane, 5, 23);
	} else {
		*of = rv_debug(hdev, port, lane, 2, 4);
		*hf = rv_debug(hdev, port, lane, 2, 5);
	}
}

static void get_tx_taps(struct hbl_cn_device *hdev, u32 port, int lane, int *tx_taps)
{
	u32 tx_pre2, tx_pre1, tx_main, tx_post1, tx_post2;

	tx_pre2 = (NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA5) &
		   NIC0_SERDES0_LANE0_REGISTER_0PA5_TX_PRE_2_MASK) >>
		  NIC0_SERDES0_LANE0_REGISTER_0PA5_TX_PRE_2_SHIFT;
	tx_pre1 = (NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA7) &
		   NIC0_SERDES0_LANE0_REGISTER_0PA7_TX_PRE_1_MASK) >>
		  NIC0_SERDES0_LANE0_REGISTER_0PA7_TX_PRE_1_SHIFT;
	tx_main = (NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA9) &
		   NIC0_SERDES0_LANE0_REGISTER_0PA9_TX_MAIN_MASK) >>
		  NIC0_SERDES0_LANE0_REGISTER_0PA9_TX_MAIN_SHIFT;
	tx_post1 = (NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PAB) &
		    NIC0_SERDES0_LANE0_REGISTER_0PAB_TX_POST_1_MASK) >>
		   NIC0_SERDES0_LANE0_REGISTER_0PAB_TX_POST_1_SHIFT;
	tx_post2 = (NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PAD) &
		    NIC0_SERDES0_LANE0_REGISTER_0PAD_TX_POST_2_MASK) >>
		   NIC0_SERDES0_LANE0_REGISTER_0PAD_TX_POST_2_SHIFT;

	tx_taps[0] = twos_to_int(tx_pre2, 8);
	tx_taps[1] = twos_to_int(tx_pre1, 8);
	tx_taps[2] = twos_to_int(tx_main, 8);
	tx_taps[3] = twos_to_int(tx_post1, 8);
	tx_taps[4] = twos_to_int(tx_post2, 8);
}

static void copy_info(char *buf, char *name, int *data, u8 count, ssize_t size)
{
	int i;

	__snprintf(buf, size, "%s:", name);

	for (i = 0; i < count; i++)
		__snprintf(buf, size, " %d", data[i]);

	__snprintf(buf, size, "\n");
}

static void dump_ber_info(struct hbl_cn_device *hdev, u32 port, int lane, char *buf, ssize_t size)
{
	struct hbl_cn_ber_info *ber_info;
	u32 abs_lane_idx;

	abs_lane_idx = (port << 1) + lane;
	ber_info = &hdev->phy_ber_info[abs_lane_idx];

	if (ber_info->valid)
		__snprintf(buf, size, "BER: %llu.%llue-%u\n",
			   ber_info->integer, ber_info->frac, ber_info->exp);
	else
		__snprintf(buf, size, "No BER information\n");
}

void gaudi2_cn_phy_dump_serdes_params(struct hbl_cn_device *hdev, char *buf, size_t size)
{
	u32 port, card_location, sd, phy_ready, ch_est_of, ch_est_hf, ppm_twos, adapt_state;
	int lane, i, ppm, eye[3], isi[18], tx_taps[5];
	u8 tx_pol, rx_pol;
	bool pam4;

	port = hdev->phy_port_to_dump;
	card_location = hdev->card_location;
	pam4 = hdev->cn_ports[port].data_rate == NIC_DR_50;

	__snprintf(buf, size, "\nmode: %s\n\n", pam4 ? "PAM4" : "NRZ");

	for (lane = 0; lane < 2; lane++) {
		sd = (NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P6A) &
		      NIC0_SERDES0_LANE0_REGISTER_0P6A_READ_SIG_DET_MASK) >>
		     NIC0_SERDES0_LANE0_REGISTER_0P6A_READ_SIG_DET_SHIFT;

		phy_ready = (NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P6A) &
			     NIC0_SERDES0_LANE0_REGISTER_0P6A_RX_READ_PHY_READY_MASK) >>
			    NIC0_SERDES0_LANE0_REGISTER_0P6A_RX_READ_PHY_READY_SHIFT;
		ppm_twos = (NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P73) &
			    NIC0_SERDES0_LANE0_REGISTER_0P73_READ_FREQ_ACC_MASK) >>
			   NIC0_SERDES0_LANE0_REGISTER_0P73_READ_FREQ_ACC_SHIFT;
		ppm = twos_to_int(ppm_twos, 11);
		adapt_state = rv_debug(hdev, port, lane, 2, 0);

		tx_pol = (NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0PA0) &
			  NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_ANA_OUT_FLIP_MASK) >>
			  NIC0_SERDES0_LANE0_REGISTER_0PA0_TX_ANA_OUT_FLIP_SHIFT;

		rx_pol = pam4 ? (NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0P43) &
				 NIC0_SERDES0_LANE0_REGISTER_0P43_RX_DATA_FLIP_MASK) >>
				 NIC0_SERDES0_LANE0_REGISTER_0P43_RX_DATA_FLIP_SHIFT :
				(NIC_PHY_RREG32_LANE(NIC0_SERDES0_LANE0_REGISTER_0N61) &
				 NIC0_SERDES0_LANE0_REGISTER_0N61_PRBS_CHECK_FLIP_MASK) >>
				 NIC0_SERDES0_LANE0_REGISTER_0N61_PRBS_CHECK_FLIP_SHIFT;

		get_channel_estimation_params(hdev, port, lane, &ch_est_of, &ch_est_hf);

		rv_debug(hdev, port, lane, 0xA, 5);
		for (i = 0; i < 3; i++)
			eye[i] = fw_read_s16(hdev, port, i);

		rv_debug(hdev, port, lane, 0xA, 0);
		for (i = 0; i < 16; i++)
			isi[i] = fw_read_s16(hdev, port, i);

		rv_debug(hdev, port, lane, 0xA, 8);
		for (i = 0; i < 2; i++)
			isi[16 + i] = fw_read_s16(hdev, port, i);

		get_tx_taps(hdev, port, lane, tx_taps);

		__snprintf(buf, size, "Card %u Port %u lane %d:\n", card_location, port, lane);
		__snprintf(buf, size,
			   "sd: %u\nphy_ready: %u\nppm: %d\nch_est_of: %u\nch_est_hf: %u\n"
			   "adaptation state: 0x%x\ntx_pol: %u\nrx_pol: %u\n", sd, phy_ready, ppm,
			   ch_est_of, ch_est_hf, adapt_state, tx_pol, rx_pol);
		copy_info(buf, "eyes", eye, 3, size);
		copy_info(buf, "isi", isi, 18, size);
		copy_info(buf, "tx_taps", tx_taps, 5, size);

		dump_ber_info(hdev, port, lane, buf, size);

		__snprintf(buf, size, "\n");
	}
}
