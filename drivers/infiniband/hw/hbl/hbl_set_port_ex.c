// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2022-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#include "hbl.h"
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_addr.h>
#include <rdma/uverbs_ioctl.h>
#include <linux/net/intel/cni.h>

#include <rdma/uverbs_ioctl.h>
#include <uapi/rdma/hbl_user_ioctl_cmds.h>
#include <uapi/rdma/hbl_user_ioctl_verbs.h>

#define UVERBS_MODULE_NAME hbl
#include <rdma/uverbs_named_ioctl.h>

static int UVERBS_HANDLER(HBL_IB_METHOD_SET_PORT_EX)(struct uverbs_attr_bundle *attrs)
{
	struct hbl_ib_port_init_params port_init_params = {};
	struct hbl_uapi_set_port_ex_in in = {};
	struct hbl_ib_ucontext *hctx;
	struct hbl_ib_device *hdev;
	struct ib_device *ibdev;
	u32 hbl_port;
	int rc, i;

	hctx = to_hbl_ib_ucontext(ib_uverbs_get_ucontext(attrs));
	if (IS_ERR(hctx))
		return PTR_ERR(hctx);

	hdev = to_hbl_ib_dev(hctx->ibucontext.device);
	ibdev = &hdev->ibdev;

	rc = uverbs_copy_from(&in, attrs, HBL_IB_ATTR_SET_PORT_EX_IN);
	if (rc)
		return rc;

	rc = ib_to_hbl_port_num(hdev, in.port_num, &hbl_port);
	if (rc) {
		hbl_ibdev_dbg(ibdev, "invalid IB port %u\n", in.port_num);
		return rc;
	}

	if (!(hctx->ports_mask & BIT(hbl_port))) {
		hbl_ibdev_dbg(ibdev, "port %d is not part of the context's ports mask 0x%llx\n",
			      hbl_port, hctx->ports_mask);
		return -EINVAL;
	}

	if (!in.qp_wq_bp_offs && in.qp_wq_bp_offs_cnt > 0)
		return -EINVAL;

	port_init_params.hbl_port_num = hbl_port;

	for (i = 0; i < HBL_IB_WQ_ARRAY_TYPE_MAX; i++) {
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
			   min((u32)HBL_IB_MAX_BP_OFFS, in.qp_wq_bp_offs_cnt)))
		return -EFAULT;

	port_init_params.advanced = in.advanced;
	port_init_params.adaptive_timeout_en = in.adaptive_timeout_en;

	rc = hbl_ib_port_init(hctx, &port_init_params);
	if (rc)
		hbl_ibdev_dbg(ibdev, "failed(%d) to set port %u extended params\n", rc, hbl_port);

	return rc;
}

DECLARE_UVERBS_NAMED_METHOD(
	HBL_IB_METHOD_SET_PORT_EX,
	UVERBS_ATTR_PTR_IN(HBL_IB_ATTR_SET_PORT_EX_IN,
			   UVERBS_ATTR_STRUCT(struct hbl_uapi_set_port_ex_in, reserved3),
			   UA_MANDATORY));

DECLARE_UVERBS_GLOBAL_METHODS(HBL_IB_OBJECT_SET_PORT_EX,
			      &UVERBS_METHOD(HBL_IB_METHOD_SET_PORT_EX));

const struct uapi_definition hbl_set_port_ex_defs[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(HBL_IB_OBJECT_SET_PORT_EX),
	{},
};
