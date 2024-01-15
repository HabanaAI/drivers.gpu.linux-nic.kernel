/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2023-2024, Intel Corporation.
 * Copyright 2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef HL_CNI_H_
#define HL_CNI_H_

#include <linux/if_ether.h>

/* Memory flags */
#define HL_CNI_MEM_CONTIGUOUS	0x1
#define HL_CNI_MEM_SHARED	0x2
#define HL_CNI_MEM_USERPTR	0x4
#define HL_CNI_MEM_FORCE_HINT	0x8
#define HL_CNI_MEM_ODP		0x20
#define HL_CNI_MEM_PREFETCH	0x40

/**
 * structure hl_cni_mem_in - structure that handle input args for memory request.
 * @union arg: union of structures to be used based on the input operation
 * @op: specify the requested memory operation (one of the HL_MEM_OP_* definitions).
 * @flags: flags for the memory operation (one of the HL_MEM_* definitions).
 *         For the HL_MEM_OP_EXPORT_DMABUF_FD opcode, this field holds the DMA-BUF file/FD flags.
 * @ctx_id: context ID - currently not in use.
 * @num_of_elements: number of timestamp elements used only with HL_MEM_OP_TS_ALLOC opcode.
 */
struct hl_cni_mem_in {
	union {
		/**
		 * structure for device memory allocation (used with the HL_MEM_OP_ALLOC op)
		 * @mem_size: memory size to allocate
		 * @page_size: page size to use on allocation. when the value is 0 the default page
		 *             size will be taken.
		 */
		struct {
			u64 mem_size;
			u64 page_size;
		} alloc;

		/**
		 * structure for free-ing device memory (used with the HL_MEM_OP_FREE op)
		 * @handle: handle returned from HL_MEM_OP_ALLOC
		 */
		struct {
			u64 handle;
		} free;

		/**
		 * structure for mapping device memory (used with the HL_MEM_OP_MAP op)
		 * @hint_addr: requested virtual address of mapped memory.
		 *             the driver will try to map the requested region to this hint
		 *             address, as long as the address is valid and not already mapped.
		 *             the user should check the returned address to make sure he got the
		 *             hint address.
		 *             passing 0 here means that the driver will choose the address itself.
		 * @handle: handle returned from HL_MEM_OP_ALLOC.
		 */
		struct {
			u64 hint_addr;
			u64 handle;
		} map_device;

		/**
		 * structure for mapping host memory (used with the HL_MEM_OP_MAP op)
		 * @host_virt_addr: address of allocated host memory.
		 * @hint_addr: requested virtual address of mapped memory.
		 *             the driver will try to map the requested region to this hint
		 *             address, as long as the address is valid and not already mapped.
		 *             the user should check the returned addres to make sure he got the
		 *             hint address.
		 *             passing 0 here means that the driver will choose the address itself.
		 * @size: size of allocated host memory.
		 */
		struct {
			u64 host_virt_addr;
			u64 hint_addr;
			u64 mem_size;
		} map_host;

		/**
		 * structure for mapping hw block (used with the HL_MEM_OP_MAP_BLOCK op)
		 * @block_addr:HW block address to map, a handle and size will be returned
		 *             to the user and will be used to mmap the relevant block.
		 *             only addresses from configuration space are allowed.
		 */
		struct {
			u64 block_addr;
		} map_block;

		/**
		 * structure for unmapping host memory (used with the HL_MEM_OP_UNMAP op)
		 * @device_virt_addr: virtual address returned from HL_MEM_OP_MAP or
		 *                    from HL_MEM_OP_REG_DMABUF_FD
		 */
		struct {
			u64 device_virt_addr;
		} unmap;

		/**
		 * structure for exporting DMABUF object (used with
		 * the HL_MEM_OP_EXPORT_DMABUF_FD op)
		 * @addr: for all other ASICs, the driver expects a device
		 *        virtual address that represents the start address of
		 *        a mapped DRAM memory area inside the device.
		 *        the address must be the same as was received from the
		 *        driver during a previous HL_MEM_OP_MAP operation.
		 * @mem_size: size of memory to export.
		 * @offset: For all other ASICs, the driver expects an offset
		 *          inside of the memory area described by addr.
		 *          The offset represents the start address of that the
		 *          exported dma-buf object describes.
		 */
		struct {
			u64 addr;
			u64 mem_size;
			u64 offset;
		} export_dmabuf_fd;

		/**
		 * structure for registering DMABUF object (used with
		 * the HL_MEM_OP_REG_DMABUF_FD op)
		 * @fd: handle of DMA-BUF object to register.
		 * @length: total length of device memory area that the dmabuf object represents
		 */
		struct {
			u64 fd;
			u64 length;
		} reg_dmabuf_fd;
	};

	u32 op;
	u32 flags;
	u32 ctx_id;
	u32 num_of_elements;
};

#define HL_CNI_STAT_STR_LEN	32

/* Requester */
#define HL_CNI_CQE_TYPE_REQ	0
/* Responder */
#define HL_CNI_CQE_TYPE_RES	1

/* Number of backpressure offsets */
#define HL_CNI_USER_BP_OFFS_MAX	16

/* Number of FnA addresses for SRAM/DCCM completion */
#define HL_CNI_FNA_CMPL_ADDR_NUM 2

/**
 * struct hl_cni_cqe: NIC CQ entry. This structure is shared between the driver and the user
 *                    application. It represents each entry of the NIC CQ buffer.
 * @requester.wqe_index: work queue index - for requester only.
 * @responder.msg_id: message ID to notify which receive action was completed - for responder only.
 * @qp_err.syndrome: error syndrome of the QP error - for QP error only.
 * @port: NIC port index of the related CQ.
 * @qp_number: QP number - for requester or QP error only.
 * @type: type of the CQE - requester or responder.
 * @is_err: true for QP error entry, false otherwise.
 */
struct hl_cni_cqe {
	union {
		struct {
			u32 wqe_index;
		} requester;

		struct {
			u32 msg_id;
		} responder;

		struct {
			u32 syndrome;
		} qp_err;
	};

	u32 port;
	u32 qp_number;
	u8 type;
	u8 is_err;
};

/**
 * struct hl_cni_alloc_conn_in - NIC opcode HL_CNI_OP_ALLOC_CONN in param
 * @port: NIC port ID
 * @hint: this may be used as the connection-number hint for the driver as a recommendation of user
 */
struct hl_cni_alloc_conn_in {
	u32 port;
	u32 hint;
};

/**
 * struct hl_cni_alloc_conn_out - NIC opcode HL_CNI_OP_ALLOC_CONN out param
 * @conn_id: Connection ID
 */
struct hl_cni_alloc_conn_out {
	u32 conn_id;
};

/**
 * struct hl_cni_req_conn_ctx_in - NIC opcode HL_CNI_OP_SET_REQ_CONN_CTX in param
 * @dst_ip_addr: Destination IP address in native endianness
 * @dst_conn_id: Destination connection ID
 * @last_index: Index of last entry [2..(2^22)-1]
 * @port: NIC port ID
 * @conn_id: Connection ID
 * @dst_mac_addr: Destination MAC address
 * @priority: Connection priority [0..3]
 * @timer_granularity: Timer granularity [0..127]
 * @swq_granularity: SWQ granularity [0 for 32B or 1 for 64B]
 * @wq_type: Work queue type [1..3]
 * @cq_number: Completion queue number
 * @wq_remote_log_size: Remote Work queue log size [2^QPC] Rendezvous
 * @congestion_en: Enable/disable Congestion-Control
 * @congestion_wnd: Congestion-Window size
 * @mtu: Max Transmit Unit
 * @encap_en: used as boolean; indicates if this QP has encapsulation support
 * @encap_id: Encapsulation-id; valid only if 'encap_en' is set
 * @wq_size: Max number of elements in the work queue
 * @loopback: used as boolean; indicates if this QP used for loopback mode.
 * @compression_en: Enable compression
 * @remote_key: Remote-key to be used to generate on outgoing packets
 */
struct hl_cni_req_conn_ctx_in {
	u32 reserved;
	u32 dst_ip_addr;
	u32 dst_conn_id;
	u32 deprecated1;
	u32 last_index;
	u32 port;
	u32 conn_id;
	u8 dst_mac_addr[ETH_ALEN];
	u8 deprecated2;
	u8 priority;
	u8 deprecated3;
	u8 timer_granularity;
	u8 swq_granularity;
	u8 wq_type;
	u8 deprecated4;
	u8 cq_number;
	u8 wq_remote_log_size;
	u8 congestion_en;
	u32 congestion_wnd;
	u16 mtu;
	u8 encap_en;
	u8 encap_id;
	u32 wq_size;
	u8 loopback;
	u8 compression_en;
	u32 remote_key;
};

/**
 * struct hl_cni_req_conn_ctx_out - NIC opcode HL_CNI_OP_SET_REQ_CONN_CTX out param
 * @swq_mem_handle: Handle for send WQ memory.
 * @rwq_mem_handle: Handle for receive WQ memory.
 */
struct hl_cni_req_conn_ctx_out {
	u64 swq_mem_handle;
	u64 rwq_mem_handle;
};

/**
 * struct hl_cni_res_conn_ctx_in - NIC opcode HL_CNI_OP_SET_RES_CONN_CTX in param
 * @dst_ip_addr: Destination IP address in native endianness
 * @dst_conn_id: Destination connection ID
 * @port: NIC port ID
 * @conn_id: Connection ID
 * @dst_mac_addr: Destination MAC address
 * @priority: Connection priority [0..3]
 * @wq_peer_granularity: Work queue granularity
 * @cq_number: Completion queue number
 * @conn_peer: Connection peer
 * @rdv: used as boolean; indicates if this QP is RDV (WRITE or READ)
 * @loopback: used as boolean; indicates if this QP used for loopback mode.
 * @encap_en: used as boolean; indicates if this QP has encapsulation support
 * @encap_id: Encapsulation-id; valid only if 'encap_en' is set
 * @wq_peer_size: size of the peer Work queue
 * @local_key: Local-key to be used to validate against incoming packets
 */
struct hl_cni_res_conn_ctx_in {
	u32 reserved;
	u32 dst_ip_addr;
	u32 dst_conn_id;
	u32 port;
	u32 conn_id;
	u8 dst_mac_addr[ETH_ALEN];
	u8 priority;
	u8 deprecated1;
	u8 deprecated2;
	u8 wq_peer_granularity;
	u8 cq_number;
	u8 deprecated3;
	u32 conn_peer;
	u8 rdv;
	u8 loopback;
	u8 encap_en;
	u8 encap_id;
	u32 wq_peer_size;
	u32 local_key;
};

/**
 * struct hl_cni_destroy_conn_in - NIC opcode HL_CNI_OP_DESTROY_CONN in param
 * @port: NIC port ID
 * @conn_id: Connection ID
 */
struct hl_cni_destroy_conn_in {
	u32 port;
	u32 conn_id;
};

/**
 * enum hl_nic_mem_type - NIC WQ memory allocation type
 * @HL_CNI_USER_WQ_SEND: Allocate memory for the user send WQ array
 * @HL_CNI_USER_WQ_RECV: Allocate memory for the user receive WQ array
 * @HL_CNI_USER_WQ_TYPE_MAX: number of values in enum
 */
enum hl_nic_mem_type {
	HL_CNI_USER_WQ_SEND,
	HL_CNI_USER_WQ_RECV,
	HL_CNI_USER_WQ_TYPE_MAX
};

/**
 * enum hl_nic_mem_id - memory allocation methods
 * @HL_CNI_MEM_HOST: memory allocated on the host memory
 * @HL_CNI_MEM_DEVICE: memory allocated on the device memory
 */
enum hl_nic_mem_id {
	HL_CNI_MEM_HOST = 1,
	HL_CNI_MEM_DEVICE
};

/**
 * enum hl_nic_swq_granularity - send WQE granularity
 * @HL_CNI_SWQE_GRAN_32B: 32 byte WQE for linear write
 * @HL_CNI_SWQE_GRAN_64B: 64 byte WQE for multi-stride write
 */
enum hl_nic_swq_granularity {
	HL_CNI_SWQE_GRAN_32B,
	HL_CNI_SWQE_GRAN_64B
};

/**
 * struct hl_cni_user_wq_arr_set_in - NIC opcode HL_CNI_OP_USER_WQ_SET in param
 * @addr: Deprecated
 * @port: NIC port ID
 * @num_of_wqs: Number of user WQs
 * @num_of_wq_entries: Number of entries per user WQ
 * @type: Type of user WQ array
 * @mem_id: Specify host/device memory allocation
 * @swq_granularity: Specify the granularity of send WQ, 0: 32 bytes, 1: 64 bytes
 */
struct hl_cni_user_wq_arr_set_in {
	u64 addr;
	u32 port;
	u32 num_of_wqs;
	u32 num_of_wq_entries;
	u32 type;
	u32 mem_id;
	u8 swq_granularity;
};

/**
 * struct hl_cni_user_wq_arr_set_out - NIC opcode HL_CNI_OP_USER_WQ_SET out param
 * @mem_handle: Handle of WQ array memory buffer
 */
struct hl_cni_user_wq_arr_set_out {
	u64 mem_handle;
};

/**
 * struct hl_cni_user_wq_arr_unset_in - NIC opcode HL_CNI_OP_USER_WQ_UNSET in param
 * @port: NIC port ID
 * @type: Type of user WQ array
 */
struct hl_cni_user_wq_arr_unset_in {
	u32 port;
	u32 type;
};

/**
 * struct hl_cni_alloc_user_cq_id_in - NIC opcode HL_CNI_OP_ALLOC_USER_CQ_ID in param.
 * @port: NIC port ID.
 */
struct hl_cni_alloc_user_cq_id_in {
	u32 port;
};

/**
 * struct hl_cni_alloc_user_cq_id_out - NIC opcode HL_CNI_OP_ALLOC_USER_CQ_ID out param.
 * @id: CQ ID.
 */
struct hl_cni_alloc_user_cq_id_out {
	u32 id;
};

/**
 * struct hl_cni_user_cq_id_set_in - NIC opcode HL_CNI_OP_USER_CQ_SET in param.
 * @port: NIC port ID.
 * @num_of_cqes: Number of CQ entries in the buffer.
 * @id: CQ ID.
 */
struct hl_cni_user_cq_id_set_in {
	u32 port;
	u32 num_of_cqes;
	u32 id;
};

/**
 * struct hl_cni_user_cq_id_set_out - NIC opcode HL_CNI_OP_USER_CQ_ID_SET out param.
 * @mem_handle: Handle of CQ memory buffer.
 * @pi_handle: Handle of CQ producer-inder memory buffer.
 * @regs_handle: Handle of CQ Registers base-address.
 * @regs_offset: CQ Registers sub-offset.
 */
struct hl_cni_user_cq_id_set_out {
	u64 mem_handle;
	u64 pi_handle;
	u64 regs_handle;
	u32 regs_offset;
};

/**
 * struct hl_cni_user_cq_id_unset_in - NIC opcode HL_CNI_OP_USER_CQ_ID_UNSET in param.
 * @port: NIC port ID.
 * @id: NIC CQ ID.
 */
struct hl_cni_user_cq_id_unset_in {
	u32 port;
	u32 id;
};

/**
 * struct hl_cni_dump_qp_in - NIC opcode HL_CNI_OP_DUMP_QP in param.
 * @user_buf_address: Pre-allocated user buffer address to hold the dump output.
 * @user_buf_size: Size of the user buffer.
 * @port: NIC port ID.
 * @qpn: NIC QP ID.
 * @req: is requester (otherwise responder).
 */
struct hl_cni_dump_qp_in {
	u64 user_buf;
	u32 user_buf_size;
	u32 port;
	u32 qpn;
	u8 req;
};

/**
 * struct hl_cni_set_user_app_params_in - NIC opcode HL_CNI_OP_SET_USER_APP_PARAMS in param.
 *                                        allow the user application to set general parameters
 *                                        regarding the RDMA nic operation. These parameters stay
 *                                        in effect until the application releases the device
 * @port: NIC port ID
 * @bp_offs: Offsets in NIC memory to signal a back pressure. Note that the advanced flag
 *              must be enabled in case it's being set.
 * @advanced: A boolean that indicates whether this WQ should support advanced operations, such as
 *            RDV, QMan, WTD, etc.
 * @fna_mask_size: Completion address value mask.
 * @fna_fifo_offs: SRAM/DCCM addresses provided to the HW by the user when FnA completion is
 *		configured in the SRAM/DDCM.
 */
struct hl_cni_set_user_app_params_in {
	u32 port;
	u32 bp_offs[HL_CNI_USER_BP_OFFS_MAX];
	u8 advanced;
	u8 fna_mask_size;
	u32 fna_fifo_offs[HL_CNI_FNA_CMPL_ADDR_NUM];
};

/**
 * struct hl_cni_get_user_app_params_in - NIC opcode HL_CNI_OP_GET_USER_APP_PARAMS in param
 * @port: NIC port ID
 */
struct hl_cni_get_user_app_params_in {
	u32 port;
};

/**
 * struct hl_cni_get_user_app_params_out - NIC opcode HL_CNI_OP_GET_USER_APP_PARAMS out param
 * @max_num_of_qps: Number of QPs that are supported by the driver. User must allocate enough room
 *                  for his work-queues according to this number.
 * @num_allocated_qps: Number of QPs that were already allocated (in use)
 * @max_allocated_qp_idx: The highest index of the allocated QPs (i.e. this is where the
 *                        driver may allocate its next QP).
 * @max_cq_size: Maximum size of a CQ buffer.
 * @advanced: true if advanced features are supported.
 * @max_num_of_cqs: Maximum number of CQs.
 * @max_num_of_db_fifos: Maximum number of DB-FIFOs.
 * @max_num_of_encaps: Maximum number of encapsulations.
 * @speed: port speed in Mbps.
 * @nic_macro_idx: macro index of this specific port.
 * @nic_phys_port_idx: physical port index (AKA lane) of this specific port.
 */
struct hl_cni_get_user_app_params_out {
	u32 max_num_of_qps;
	u32 num_allocated_qps;
	u32 max_allocated_qp_idx;
	u32 max_cq_size;
	u8 advanced;
	u8 max_num_of_cqs;
	u8 max_num_of_db_fifos;
	u8 max_num_of_encaps;
	u32 speed;
	u8 nic_macro_idx;
	u8 nic_phys_port_idx;
};

/**
 * struct hl_cni_alloc_user_db_fifo_in - NIC opcode HL_CNI_OP_ALLOC_USER_DB_FIFO in param
 * @port: NIC port ID
 * @id_hint: Hint to allocate a specific HW resource
 */
struct hl_cni_alloc_user_db_fifo_in {
	u32 port;
	u32 id_hint;
};

/**
 * struct hl_cni_alloc_user_db_fifo_out - NIC opcode HL_CNI_OP_ALLOC_USER_DB_FIFO out param
 * @id: DB-FIFO ID
 */
struct hl_cni_alloc_user_db_fifo_out {
	u32 id;
};

/**
 * enum hl_nic_db_fifo_type - NIC users FIFO modes of operation.
 * @HL_CNI_DB_FIFO_TYPE_DB: mode for direct user door-bell submit.
 * @HL_CNI_DB_FIFO_TYPE_CC: mode for congestion control.
 */
enum hl_nic_db_fifo_type {
	HL_CNI_DB_FIFO_TYPE_DB = 0,
	HL_CNI_DB_FIFO_TYPE_CC,
};

/**
 * struct hl_cni_user_db_fifo_set_in - NIC opcode HL_CNI_OP_USER_DB_FIFO_SET in param
 * @port: NIC port ID
 * @id: NIC DB-FIFO ID
 * @mode: represents desired mode of operation for provided FIFO, according to hl_nic_db_fifo_type
 */
struct hl_cni_user_db_fifo_set_in {
	u32 port;
	u32 id;
	u8 mode;
};

/**
 * struct hl_cni_user_db_fifo_set_out - NIC opcode HL_CNI_OP_USER_DB_FIFO_SET out param
 * @ci_handle: Handle of DB-FIFO consumer-inder memory buffer
 * @regs_handle: Handle of DB-FIFO Registers base-address
 * @regs_offset: Offset to the DB-FIFO Registers
 * @fifo_size: fifo size that was allocated
 * @fifo_bp_thresh: fifo threshold that was set by the driver
 */
struct hl_cni_user_db_fifo_set_out {
	u64 ci_handle;
	u64 regs_handle;
	u32 regs_offset;
	u32 fifo_size;
	u32 fifo_bp_thresh;
};

/**
 * struct hl_cni_user_db_fifo_unset_in - NIC opcode HL_CNI_OP_USER_DB_FIFO_UNSET in param
 * @port: NIC port ID
 * @id: NIC DB-FIFO ID
 */
struct hl_cni_user_db_fifo_unset_in {
	u32 port;
	u32 id;
};

/* The operation completed successfully and an event was read */
#define HL_CNI_EQ_POLL_STATUS_SUCCESS			0
/* The operation completed successfully, no event was found */
#define HL_CNI_EQ_POLL_STATUS_EQ_EMPTY			1
/* The operation failed since it is not supported by the device/driver */
#define HL_CNI_EQ_POLL_STATUS_ERR_UNSUPPORTED_OP	2
/* The operation failed, port was not found */
#define HL_CNI_EQ_POLL_STATUS_ERR_NO_SUCH_PORT		3
/* The operation failed, port is disabled */
#define HL_CNI_EQ_POLL_STATUS_ERR_PORT_DISABLED		4
/* The operation failed, an event-queue associated with the app was not found */
#define HL_CNI_EQ_POLL_STATUS_ERR_NO_SUCH_EQ		5
/* The operation failed with an undefined error */
#define HL_CNI_EQ_POLL_STATUS_ERR_UNDEF			6

/* completion-queue events */
#define HL_CNI_EQ_EVENT_TYPE_CQ_ERR 0
/* Queue-pair events */
#define HL_CNI_EQ_EVENT_TYPE_QP_ERR 1
/* Doorbell events */
#define HL_CNI_EQ_EVENT_TYPE_DB_FIFO_ERR 2
/* congestion completion-queue events */
#define HL_CNI_EQ_EVENT_TYPE_CCQ 3
/* Direct WQE security error. */
#define HL_CNI_EQ_EVENT_TYPE_WTD_SECURITY_ERR 4
/* Numerical error */
#define HL_CNI_EQ_EVENT_TYPE_NUMERICAL_ERR 5
/* Link status. */
#define HL_CNI_EQ_EVENT_TYPE_LINK_STATUS 6
/* Queue-pair counters aligned */
#define HL_CNI_EQ_EVENT_TYPE_QP_ALIGN_COUNTERS 7

/**
 * struct hl_cni_eq_poll_in - NIC opcode HL_CNI_OP_EQ_POLL in param
 * @port: NIC port ID
 */
struct hl_cni_eq_poll_in {
	u32 port;
};

/**
 * struct hl_cni_eq_poll_out - NIC opcode HL_CNI_OP_EQ_POLL out param
 * @status: HL_CNI_EQ_POLL_STATUS_*
 * @idx: Connection/CQ/DB-fifo index, depends on event type
 * @ev_data: Event-specific data
 * @ev_type: Event type
 * @rest_occurred: Was the error due to reset
 * @is_req: For QP events marks if corresponding QP is requestor
 */
struct hl_cni_eq_poll_out {
	u32 status;
	u32 idx;
	u32 ev_data;
	u8 ev_type;
	u8 rest_occurred;
	u8 is_req;
};

/**
 * enum hl_nic_encap_type - Supported encapsulation types
 * @HL_CNI_ENCAP_NONE: No Tunneling.
 * @HL_CNI_ENCAP_OVER_IPV4: Tunnel RDMA packets through L3 layer
 * @HL_CNI_ENCAP_OVER_UDP: Tunnel RDMA packets through L4 layer
 */
enum hl_nic_encap_type {
	HL_CNI_ENCAP_NONE,
	HL_CNI_ENCAP_OVER_IPV4,
	HL_CNI_ENCAP_OVER_UDP,
};

/**
 * struct hl_cni_user_encap_alloc_in - NIC opcode HL_CNI_OP_USER_ENCAP_ALLOC in param
 * @port: NIC port ID
 */
struct hl_cni_user_encap_alloc_in {
	u32 port;
};

/**
 * struct hl_cni_user_encap_alloc_out - NIC opcode HL_CNI_OP_USER_ENCAP_ALLOC out param
 * @id: Encapsulation ID
 */
struct hl_cni_user_encap_alloc_out {
	u32 id;
};

/**
 * struct hl_cni_user_encap_set_in - NIC opcode HL_CNI_OP_USER_ENCAP_SET in param
 * @tnl_hdr_ptr: Pointer to the tunnel encapsulation header. i.e. specific tunnel header data to be
 *               used in the encapsulation by the HW.
 * @tnl_hdr_size: Tunnel encapsulation header size.
 * @port: NIC port ID
 * @id: Encapsulation ID
 * @ipv4_addr: Source IP address, set regardless of encapsulation type.
 * @udp_dst_port: The UDP destination-port. Valid for L4 tunnel.
 * @ip_proto: IP protocol to use. Valid for L3 tunnel.
 * @encap_type: Encapsulation type. May be either no-encapsulation or encapsulation over L3 or L4.
 */
struct hl_cni_user_encap_set_in {
	u64 tnl_hdr_ptr;
	u32 tnl_hdr_size;
	u32 port;
	u32 id;
	u32 ipv4_addr;
	union {
		u16 udp_dst_port;
		u16 ip_proto;
	};
	u8 encap_type;
};

/**
 * struct hl_cni_user_encap_unset_in - NIC opcode HL_CNI_OP_USER_ENCAP_UNSET in param
 * @port: NIC port ID
 * @id: Encapsulation ID
 */
struct hl_cni_user_encap_unset_in {
	u32 port;
	u32 id;
};

/**
 * struct hl_cni_user_ccq_set_in - NIC opcode HL_CNI_OP_USER_CCQ_SET in param
 * @port: NIC port ID
 * @num_of_entries: Number of CCQ entries in the buffer
 */
struct hl_cni_user_ccq_set_in {
	u32 port;
	u32 num_of_entries;
};

/**
 * struct hl_cni_user_ccq_set_out - NIC opcode HL_CNI_OP_USER_CCQ_SET out param
 * @mem_handle: Handle of CCQ memory buffer
 * @pi_handle: Handle of CCQ producer-index memory buffer
 * @id: CQ ID.
 */
struct hl_cni_user_ccq_set_out {
	u64 mem_handle;
	u64 pi_handle;
	u32 id;
};

/**
 * struct hl_cni_user_ccq_unset_in - NIC opcode HL_CNI_OP_USER_CCQ_UNSET in param
 * @port: NIC port ID
 */
struct hl_cni_user_ccq_unset_in {
	u32 port;
};

/* Opcode to allocate connection ID */
#define HL_CNI_OP_ALLOC_CONN			0
/* Opcode to set up a requester connection context */
#define HL_CNI_OP_SET_REQ_CONN_CTX		1
/* Opcode to set up a responder connection context */
#define HL_CNI_OP_SET_RES_CONN_CTX		2
/* Opcode to destroy a connection */
#define HL_CNI_OP_DESTROY_CONN			3
/* Reserved opcode */
#define HL_CNI_OP_RESERVED4			4
/* Reserved opcode */
#define HL_CNI_OP_RESERVED5			5
/* Reserved opcode */
#define HL_CNI_OP_RESERVED6			6
/* Reserved opcode */
#define HL_CNI_OP_RESERVED7			7
/* Reserved opcode */
#define HL_CNI_OP_RESERVED8			8
/* Opcode to set a user WQ array */
#define HL_CNI_OP_USER_WQ_SET			9
/* Opcode to unset a user WQ array */
#define HL_CNI_OP_USER_WQ_UNSET			10
/* Reserved opcode */
#define HL_CNI_OP_RESERVED11			11
/* Reserved opcode */
#define HL_CNI_OP_RESERVED12			12
/* Reserved opcode */
#define HL_CNI_OP_RESERVED13			13
/* Opcode to allocate a CQ */
#define HL_CNI_OP_ALLOC_USER_CQ_ID		14
/* Opcode to set specific user-application parameters */
#define HL_CNI_OP_SET_USER_APP_PARAMS		15
/* Opcode to get specific user-application parameters */
#define HL_CNI_OP_GET_USER_APP_PARAMS		16
/* Opcode to allocate a DB-FIFO */
#define HL_CNI_OP_ALLOC_USER_DB_FIFO		17
/* Opcode to create a DB-FIFO */
#define HL_CNI_OP_USER_DB_FIFO_SET		18
/* Opcode to destroy a DB-FIFO */
#define HL_CNI_OP_USER_DB_FIFO_UNSET		19
/* Opcode to poll on EQ */
#define HL_CNI_OP_EQ_POLL			20
/* Opcode to allocate encapsulation ID */
#define HL_CNI_OP_USER_ENCAP_ALLOC		21
/* Opcode to create an encapsulation */
#define HL_CNI_OP_USER_ENCAP_SET		22
/* Opcode to destroy an encapsulation */
#define HL_CNI_OP_USER_ENCAP_UNSET		23
/* Opcode to create a CCQ */
#define HL_CNI_OP_USER_CCQ_SET			24
/* Opcode to destroy a CCQ */
#define HL_CNI_OP_USER_CCQ_UNSET		25
/* Opcode to set user CQ by ID */
#define HL_CNI_OP_USER_CQ_ID_SET		26
/* Opcode to unset user CQ by ID */
#define HL_CNI_OP_USER_CQ_ID_UNSET		27
/* Reserved opcode */
#define HL_CNI_OP_RESERVED28			28
/* Opcode to dump the context of a QP */
#define HL_CNI_OP_DUMP_QP			29

#endif /* HL_CNI_H_ */
