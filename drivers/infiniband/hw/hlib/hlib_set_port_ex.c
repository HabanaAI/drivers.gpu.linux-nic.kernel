// SPDX-License-Identifier: GPL-2.0

/* Copyright 2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlib.h"
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_addr.h>
#include <rdma/uverbs_ioctl.h>
#include <linux/net/intel/cni.h>

#include <rdma/uverbs_ioctl.h>
#include <uapi/rdma/hlib_user_ioctl_cmds.h>
#include <uapi/rdma/hlib_user_ioctl_verbs.h>

#define UVERBS_MODULE_NAME hlib
#include <rdma/uverbs_named_ioctl.h>

static int UVERBS_HANDLER(HL_IB_METHOD_SET_PORT_EX)(struct uverbs_attr_bundle *attrs)
{
	struct hl_ib_port_init_params port_init_params = {};
	struct hlib_uapi_set_port_ex_in in = {};
	struct hl_ib_ucontext *hctx;
	struct hl_ib_device *hdev;
	struct ib_device *ibdev;
	u32 hl_port;
	int rc, i;

	hctx = to_hl_ib_ucontext(ib_uverbs_get_ucontext(attrs));
	if (IS_ERR(hctx))
		return PTR_ERR(hctx);

	hdev = to_hl_ib_dev(hctx->ibucontext.device);
	ibdev = &hdev->ibdev;

	rc = uverbs_copy_from(&in, attrs, HL_IB_ATTR_SET_PORT_EX_IN);
	if (rc)
		return rc;

	rc = ib_to_hl_port_num(hdev, in.port_num, &hl_port);
	if (rc) {
		hl_ibdev_dbg(ibdev, "invalid IB port %u\n", in.port_num);
		return rc;
	}

	if (!(hctx->ports_mask & BIT(hl_port))) {
		hl_ibdev_dbg(ibdev, "port %d is not part of the context's ports mask 0x%llx\n",
					hl_port, hctx->ports_mask);
		return -EINVAL;
	}

	if ((!in.qp_wq_bp_offs && in.qp_wq_bp_offs_cnt > 0) ||
		(!in.atomic_fna_fifo_offs && in.atomic_fna_fifo_offs_cnt > 0))
		return -EINVAL;

	port_init_params.hl_port_num = hl_port;

	for (i = 0; i < HL_IB_WQ_ARRAY_TYPE_MAX; i++) {
		port_init_params.wq_arr_attr[i].max_num_of_wqs =
						in.wq_arr_attr[i].max_num_of_wqs;
		port_init_params.wq_arr_attr[i].max_num_of_wqes_in_wq =
						in.wq_arr_attr[i].max_num_of_wqes_in_wq;
		port_init_params.wq_arr_attr[i].mem_id = in.wq_arr_attr[i].mem_id;
		port_init_params.wq_arr_attr[i].swq_granularity =
						in.wq_arr_attr[i].swq_granularity;
	}

	if (copy_from_user(port_init_params.qp_wq_bp_offs, u64_to_user_ptr(in.qp_wq_bp_offs),
			   sizeof(port_init_params.qp_wq_bp_offs[0]) *
			   min((uint32_t) HL_IB_MAX_BP_OFFS, in.qp_wq_bp_offs_cnt)))
		return -EFAULT;

	if (copy_from_user(port_init_params.atomic_fna_fifo_offs,
			   u64_to_user_ptr(in.atomic_fna_fifo_offs),
			   sizeof(port_init_params.atomic_fna_fifo_offs[0]) *
			   min((uint32_t) HL_IB_FNA_CMPL_ADDR_NUM, in.atomic_fna_fifo_offs_cnt)))
		return -EFAULT;

	port_init_params.atomic_fna_mask_size = in.atomic_fna_mask_size;
	port_init_params.advanced = in.advanced;

	rc = hl_ib_port_init(hctx, &port_init_params);
	if (rc)
		hl_ibdev_dbg(ibdev, "failed(%d) to set port %u extended params\n", rc, hl_port);

	return rc;
}

DECLARE_UVERBS_NAMED_METHOD(
	HL_IB_METHOD_SET_PORT_EX,
	UVERBS_ATTR_PTR_IN(HL_IB_ATTR_SET_PORT_EX_IN,
			   UVERBS_ATTR_STRUCT(struct hlib_uapi_set_port_ex_in, advanced),
			   UA_MANDATORY));

DECLARE_UVERBS_GLOBAL_METHODS(HL_IB_OBJECT_SET_PORT_EX,
			      &UVERBS_METHOD(HL_IB_METHOD_SET_PORT_EX));

const struct uapi_definition hlib_set_port_ex_defs[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(HL_IB_OBJECT_SET_PORT_EX),
	{},
};
