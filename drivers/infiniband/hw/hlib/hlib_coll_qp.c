// SPDX-License-Identifier: GPL-2.0

/* Copyright 2022 HabanaLabs, Ltd.
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

static int UVERBS_HANDLER(HL_IB_METHOD_RESERVE_COLL_QP)(struct uverbs_attr_bundle *attrs)
{
	struct hl_cni_alloc_coll_conn_out alloc_coll_conn_out = {};
	struct hl_cni_alloc_coll_conn_in alloc_coll_conn_in = {};
	struct hlib_uapi_reserve_coll_conn_out out = {};
	struct hlib_uapi_reserve_coll_conn_in in = {};
	struct hl_ib_aux_ops *aux_ops;
	struct hl_ib_ucontext *hctx;
	struct hl_aux_dev *aux_dev;
	struct hl_ib_device *hdev;
	struct ib_device *ibdev;
	int rc;

	hctx = to_hl_ib_ucontext(ib_uverbs_get_ucontext(attrs));
	if (IS_ERR(hctx))
		return PTR_ERR(hctx);

	hdev = to_hl_ib_dev(hctx->ibucontext.device);
	ibdev = &hdev->ibdev;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	rc = uverbs_copy_from(&in, attrs, HL_IB_ATTR_RESERVE_COLL_QP_IN);
	if (rc)
		return rc;

	alloc_coll_conn_in.is_scale_out = in.is_scale_out;

	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_ALLOC_COLL_CONN,
			       &alloc_coll_conn_in, &alloc_coll_conn_out);
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed(%d) to allocate collective qp\n", rc);
		return rc;
	}

	atomic_inc(&hdev->dev_stats.coll_qp);

	out.qp_num = alloc_coll_conn_out.conn_id;

#ifdef _HAS_UVERBS_COPY_TO_STRUCT_OR_ZERO
	rc = uverbs_copy_to_struct_or_zero(attrs, HL_IB_ATTR_RESERVE_COLL_QP_OUT, &out,
					   sizeof(out));
#else
	rc = uverbs_copy_to(attrs, HL_IB_ATTR_RESERVE_COLL_QP_OUT, &out, sizeof(out));
#endif

	return rc;
}

DECLARE_UVERBS_NAMED_METHOD(
	HL_IB_METHOD_RESERVE_COLL_QP,
	UVERBS_ATTR_PTR_IN(HL_IB_ATTR_RESERVE_COLL_QP_IN,
			   UVERBS_ATTR_STRUCT(struct hlib_uapi_reserve_coll_conn_in, reserved),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HL_IB_ATTR_RESERVE_COLL_QP_OUT,
			    UVERBS_ATTR_STRUCT(struct hlib_uapi_reserve_coll_conn_out, reserved),
			    UA_MANDATORY));

DECLARE_UVERBS_GLOBAL_METHODS(HL_IB_OBJECT_COLLECTIVE_QP,
				&UVERBS_METHOD(HL_IB_METHOD_RESERVE_COLL_QP));

const struct uapi_definition hlib_collective_qp_defs[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(HL_IB_OBJECT_COLLECTIVE_QP),
	{},
};
