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

struct hlib_usr_fifo {
	u32 port;
	u32 id;
};

static int UVERBS_HANDLER(HL_IB_METHOD_USR_FIFO_OBJ_CREATE)(struct uverbs_attr_bundle *attrs)
{
	struct hl_cni_alloc_user_db_fifo_out alloc_db_fifo_out = {};
	struct hl_cni_alloc_user_db_fifo_in alloc_db_fifo_in = {};
	struct hl_cni_user_db_fifo_unset_in db_fifo_unset_in = {};
	struct hl_cni_user_db_fifo_set_out db_fifo_set_out = {};
	struct hl_cni_user_db_fifo_set_in db_fifo_set_in = {};
	struct hlib_uapi_usr_fifo_create_out out = {};
	struct hlib_uapi_usr_fifo_create_in in = {};
	u32 port, id, base_sob_addr, num_sobs;
	struct hlib_usr_fifo *usr_fifo_pdata;
	struct hl_ib_aux_ops *aux_ops;
	struct hl_ib_ucontext *hctx;
	struct hl_aux_dev *aux_dev;
	struct hl_ib_device *hdev;
	struct ib_device *ibdev;
	struct ib_uobject *uobj;
	u8 mode, dir_dup_mask;
	int rc;

	hctx = to_hl_ib_ucontext(ib_uverbs_get_ucontext(attrs));
	if (IS_ERR(hctx))
		return PTR_ERR(hctx);

	uobj = uverbs_attr_get_uobject(attrs, HL_IB_ATTR_USR_FIFO_CREATE_HANDLE);
	hdev = to_hl_ib_dev(hctx->ibucontext.device);
	ibdev = &hdev->ibdev;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	rc = uverbs_copy_from(&in, attrs, HL_IB_ATTR_USR_FIFO_CREATE_IN);
	if (rc)
		return rc;

	rc = ib_to_hl_port_num(hdev, in.port_num, &port);
	if (rc) {
		hl_ibdev_dbg(ibdev, "invalid IB port %u\n", in.port_num);
		return rc;
	}

	if (!(hctx->ports_mask & BIT(port))) {
		hl_ibdev_dbg(ibdev, "port %d is not part of the context's ports mask 0x%llx\n",
					port, hctx->ports_mask);
		return -EINVAL;
	}

	usr_fifo_pdata = kzalloc(sizeof(*usr_fifo_pdata), GFP_KERNEL);
	if (!usr_fifo_pdata)
		return -ENOMEM;

	base_sob_addr = in.base_sob_addr;
	num_sobs = in.num_sobs;
	mode = in.mode;
	dir_dup_mask = in.dir_dup_mask;

	alloc_db_fifo_in.port = port;
	alloc_db_fifo_in.id_hint = in.usr_fifo_num_hint;

	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_ALLOC_USER_DB_FIFO,
			       &alloc_db_fifo_in, &alloc_db_fifo_out);
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed to alloc db fifo, port %d\n", port);
		goto err_free_pdata;
	}

	id = alloc_db_fifo_out.id;

	usr_fifo_pdata->port = port;
	usr_fifo_pdata->id = id;

	db_fifo_set_in.port = port;
	db_fifo_set_in.id = id;
	db_fifo_set_in.mode = mode;
	db_fifo_set_in.dir_dup_ports_mask = dir_dup_mask;
	db_fifo_set_in.base_sob_addr = base_sob_addr;
	db_fifo_set_in.num_sobs = num_sobs;

	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_USER_DB_FIFO_SET, &db_fifo_set_in,
			       &db_fifo_set_out);
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed to set db fifo %d, port %d\n", id, port);
		goto err_usr_fifo_unset;
	}

	out.usr_fifo_num = id;
	out.ci_handle = db_fifo_set_out.ci_handle;
	out.regs_handle = db_fifo_set_out.regs_handle;
	out.regs_offset = db_fifo_set_out.regs_offset;
	out.size = db_fifo_set_out.fifo_size;
	out.bp_thresh = db_fifo_set_out.fifo_bp_thresh;

	uobj->object = usr_fifo_pdata;

#ifdef _HAS_UVERBS_COPY_TO_STRUCT_OR_ZERO
	rc = uverbs_copy_to_struct_or_zero(attrs, HL_IB_ATTR_USR_FIFO_CREATE_OUT, &out,
					   sizeof(out));
#else
	rc = uverbs_copy_to(attrs, HL_IB_ATTR_USR_FIFO_CREATE_OUT, &out, sizeof(out));
#endif
	if (rc)
		goto err_usr_fifo_unset;

	return 0;

err_usr_fifo_unset:
	db_fifo_unset_in.port = port;
	db_fifo_unset_in.id = id;

	if (aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_USER_DB_FIFO_UNSET,
			      &db_fifo_unset_in, NULL))
		hl_ibdev_dbg(ibdev, "failed to unset db fifo %d, port %d\n", id, port);

err_free_pdata:
	kfree(usr_fifo_pdata);

	return rc;
}

static int hlib_free_usr_fifo(struct ib_uobject *uobject,
			      enum rdma_remove_reason why,
			      struct uverbs_attr_bundle *attrs)
{
	struct hl_cni_user_db_fifo_unset_in db_fifo_unset_in = {};
	struct hlib_usr_fifo *usr_fifo_pdata;
	struct hl_ib_aux_ops *aux_ops;
	struct hl_ib_ucontext *hctx;
	struct hl_aux_dev *aux_dev;
	struct hl_ib_device *hdev;
	struct ib_device *ibdev;
	int rc;

	hctx = to_hl_ib_ucontext(ib_uverbs_get_ucontext(attrs));
	if (IS_ERR(hctx))
		return PTR_ERR(hctx);

	usr_fifo_pdata = uobject->object;
	hdev = to_hl_ib_dev(hctx->ibucontext.device);
	ibdev = &hdev->ibdev;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	db_fifo_unset_in.port = usr_fifo_pdata->port;
	db_fifo_unset_in.id = usr_fifo_pdata->id;

	if (aux_ops->device_operational(aux_dev)) {
		rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_USER_DB_FIFO_UNSET,
				       &db_fifo_unset_in, NULL);
		if (rc) {
			hl_ibdev_dbg(ibdev, "failed to unset db fifo %d, port %d\n",
				usr_fifo_pdata->id, usr_fifo_pdata->port);
			return rc;
		}
	}

	kfree(usr_fifo_pdata);

	return 0;
}

DECLARE_UVERBS_NAMED_METHOD(
	HL_IB_METHOD_USR_FIFO_OBJ_CREATE,
	UVERBS_ATTR_IDR(HL_IB_ATTR_USR_FIFO_CREATE_HANDLE,
			HL_IB_OBJECT_USR_FIFO,
			UVERBS_ACCESS_NEW,
			UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(HL_IB_ATTR_USR_FIFO_CREATE_IN,
			   UVERBS_ATTR_STRUCT(struct hlib_uapi_usr_fifo_create_in, reserved),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HL_IB_ATTR_USR_FIFO_CREATE_OUT,
			    UVERBS_ATTR_STRUCT(struct hlib_uapi_usr_fifo_create_out, bp_thresh),
			    UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD_DESTROY(
	HL_IB_METHOD_USR_FIFO_OBJ_DESTROY,
	UVERBS_ATTR_IDR(HL_IB_ATTR_USR_FIFO_DESTROY_HANDLE,
			HL_IB_OBJECT_USR_FIFO,
			UVERBS_ACCESS_DESTROY,
			UA_MANDATORY));

DECLARE_UVERBS_NAMED_OBJECT(HL_IB_OBJECT_USR_FIFO,
			    UVERBS_TYPE_ALLOC_IDR(hlib_free_usr_fifo),
			    &UVERBS_METHOD(HL_IB_METHOD_USR_FIFO_OBJ_CREATE),
			    &UVERBS_METHOD(HL_IB_METHOD_USR_FIFO_OBJ_DESTROY));

const struct uapi_definition hlib_usr_fifo_defs[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(HL_IB_OBJECT_USR_FIFO),
	{},
};
