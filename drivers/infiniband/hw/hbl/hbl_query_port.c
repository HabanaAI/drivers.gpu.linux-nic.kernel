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

static int UVERBS_HANDLER(HBL_IB_METHOD_QUERY_PORT)(struct uverbs_attr_bundle *attrs)
{
	struct hbl_cni_get_user_app_params_out app_params_out = {};
	struct hbl_cni_get_user_app_params_in app_params_in = {};
	struct hbl_uapi_query_port_out out = {};
	struct hbl_uapi_query_port_in in = {};
	struct hbl_ib_aux_ops *aux_ops;
	struct hbl_ib_ucontext *hctx;
	struct hbl_aux_dev *aux_dev;
	struct hbl_ib_device *hdev;
	struct ib_device *ibdev;
	int rc;

	hctx = to_hbl_ib_ucontext(ib_uverbs_get_ucontext(attrs));
	if (IS_ERR(hctx))
		return PTR_ERR(hctx);

	hdev = to_hbl_ib_dev(hctx->ibucontext.device);
	ibdev = &hdev->ibdev;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	rc = uverbs_copy_from(&in, attrs, HBL_IB_ATTR_QUERY_PORT_IN);
	if (rc)
		return rc;

	rc = ib_to_hbl_port_num(hdev, in.port_num, &app_params_in.port);
	if (rc) {
		hbl_ibdev_dbg(ibdev, "invalid IB port %u\n", in.port_num);
		return rc;
	}

	if (!(hctx->ports_mask & BIT(app_params_in.port))) {
		hbl_ibdev_dbg(ibdev, "port %d is not part of the context's ports mask 0x%llx\n",
			      app_params_in.port, hctx->ports_mask);
		return -EINVAL;
	}

	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HBL_CNI_OP_GET_USER_APP_PARAMS,
			       &app_params_in, &app_params_out);
	if (rc) {
		hbl_ibdev_dbg(ibdev, "failed to get user params for port %d\n", app_params_in.port);
		return rc;
	}

	out.max_num_of_qps = app_params_out.max_num_of_qps;
	out.num_allocated_qps = app_params_out.num_allocated_qps;
	out.max_allocated_qp_num = app_params_out.max_allocated_qp_idx;
	out.max_cq_size = app_params_out.max_cq_size;
	out.advanced = app_params_out.advanced;
	out.max_num_of_cqs = app_params_out.max_num_of_cqs;
	out.max_num_of_usr_fifos = app_params_out.max_num_of_db_fifos;
	out.max_num_of_encaps = app_params_out.max_num_of_encaps;
	out.nic_macro_idx = app_params_out.nic_macro_idx;
	out.nic_phys_port_idx = app_params_out.nic_phys_port_idx;

	rc = uverbs_copy_to_struct_or_zero(attrs, HBL_IB_ATTR_QUERY_PORT_OUT, &out, sizeof(out));

	return rc;
}

DECLARE_UVERBS_NAMED_METHOD(
	HBL_IB_METHOD_QUERY_PORT,
	UVERBS_ATTR_PTR_IN(HBL_IB_ATTR_QUERY_PORT_IN,
			   UVERBS_ATTR_STRUCT(struct hbl_uapi_query_port_in, reserved),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HBL_IB_ATTR_QUERY_PORT_OUT,
			    UVERBS_ATTR_STRUCT(struct hbl_uapi_query_port_out, reserved),
			    UA_MANDATORY));

DECLARE_UVERBS_GLOBAL_METHODS(HBL_IB_OBJECT_QUERY_PORT, &UVERBS_METHOD(HBL_IB_METHOD_QUERY_PORT));

const struct uapi_definition hbl_query_port_defs[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(HBL_IB_OBJECT_QUERY_PORT),
	{},
};
