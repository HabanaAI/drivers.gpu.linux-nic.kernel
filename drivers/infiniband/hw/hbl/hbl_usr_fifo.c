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

/**
 * struct hbl_usr_fifo - This structure will be stored inside the uobject.
 * @ci_entry: The rdma_user_mmap_entry for the mapped ci.
 * @regs_entry: The rdma_user_mmap_entry for the mapped registers.
 * @port: The port of this fifo.
 * @id: The id of this fifo.
 */
struct hbl_usr_fifo {
	struct rdma_user_mmap_entry *ci_entry;
	struct rdma_user_mmap_entry *regs_entry;
	u32 port;
	u32 id;
};

static void user_fifo_mmap_entry_remove(struct hbl_usr_fifo *usr_fifo)
{
	rdma_user_mmap_entry_remove(usr_fifo->regs_entry);
	if (usr_fifo->ci_entry)
		rdma_user_mmap_entry_remove(usr_fifo->ci_entry);
}

static int user_fifo_mmap_entry_setup(struct hbl_ib_device *dev, struct hbl_ib_ucontext *hctx,
				      struct hbl_usr_fifo *usr_fifo,
				      struct hbl_uapi_usr_fifo_create_out *out)
{
	if (out->ci_handle) {
		usr_fifo->ci_entry = hbl_ib_user_mmap_entry_insert(&hctx->ibucontext,
								   out->ci_handle,
								   PAGE_SIZE, &out->ci_handle);
		if (IS_ERR(usr_fifo->ci_entry))
			return PTR_ERR(usr_fifo->ci_entry);
	}

	usr_fifo->regs_entry = hbl_ib_user_mmap_entry_insert(&hctx->ibucontext, out->regs_handle,
							     PAGE_SIZE, &out->regs_handle);
	if (IS_ERR(usr_fifo->regs_entry))
		goto err_free_ci;

	return 0;

err_free_ci:
	if (usr_fifo->ci_entry)
		rdma_user_mmap_entry_remove(usr_fifo->ci_entry);

	return PTR_ERR(usr_fifo->regs_entry);
}

static int UVERBS_HANDLER(HBL_IB_METHOD_USR_FIFO_OBJ_CREATE)(struct uverbs_attr_bundle *attrs)
{
	struct hbl_cni_alloc_user_db_fifo_out alloc_db_fifo_out = {};
	struct hbl_cni_alloc_user_db_fifo_in alloc_db_fifo_in = {};
	struct hbl_cni_user_db_fifo_unset_in db_fifo_unset_in = {};
	struct hbl_cni_user_db_fifo_set_out db_fifo_set_out = {};
	struct hbl_cni_user_db_fifo_set_in db_fifo_set_in = {};
	struct hbl_uapi_usr_fifo_create_out out = {};
	struct hbl_uapi_usr_fifo_create_in in = {};
	struct hbl_usr_fifo *usr_fifo_pdata;
	struct hbl_ib_aux_ops *aux_ops;
	struct hbl_ib_ucontext *hctx;
	struct hbl_aux_dev *aux_dev;
	struct hbl_ib_device *hdev;
	struct ib_device *ibdev;
	struct ib_uobject *uobj;
	u32 port, id;
	u8 mode;
	int rc;

	hctx = to_hbl_ib_ucontext(ib_uverbs_get_ucontext(attrs));
	if (IS_ERR(hctx))
		return PTR_ERR(hctx);

	uobj = uverbs_attr_get_uobject(attrs, HBL_IB_ATTR_USR_FIFO_CREATE_HANDLE);
	hdev = to_hbl_ib_dev(hctx->ibucontext.device);
	ibdev = &hdev->ibdev;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	rc = uverbs_copy_from(&in, attrs, HBL_IB_ATTR_USR_FIFO_CREATE_IN);
	if (rc)
		return rc;

	rc = ib_to_hbl_port_num(hdev, in.port_num, &port);
	if (rc) {
		hbl_ibdev_dbg(ibdev, "invalid IB port %u\n", in.port_num);
		return rc;
	}

	if (!(hctx->ports_mask & BIT(port))) {
		hbl_ibdev_dbg(ibdev, "port %d is not part of the context's ports mask 0x%llx\n",
			      port, hctx->ports_mask);
		return -EINVAL;
	}

	usr_fifo_pdata = kzalloc(sizeof(*usr_fifo_pdata), GFP_KERNEL);
	if (!usr_fifo_pdata)
		return -ENOMEM;

	mode = in.mode;

	alloc_db_fifo_in.port = port;
	alloc_db_fifo_in.id_hint = in.usr_fifo_num_hint;

	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HBL_CNI_OP_ALLOC_USER_DB_FIFO,
			       &alloc_db_fifo_in, &alloc_db_fifo_out);
	if (rc) {
		hbl_ibdev_dbg(ibdev, "failed to alloc db fifo, port %d\n", port);
		goto err_free_pdata;
	}

	id = alloc_db_fifo_out.id;

	usr_fifo_pdata->port = port;
	usr_fifo_pdata->id = id;

	db_fifo_set_in.port = port;
	db_fifo_set_in.id = id;
	db_fifo_set_in.mode = mode;

	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HBL_CNI_OP_USER_DB_FIFO_SET, &db_fifo_set_in,
			       &db_fifo_set_out);
	if (rc) {
		hbl_ibdev_dbg(ibdev, "failed to set db fifo %d, port %d\n", id, port);
		goto err_usr_fifo_unset;
	}

	out.usr_fifo_num = id;
	out.ci_handle = db_fifo_set_out.ci_handle;
	out.regs_handle = db_fifo_set_out.regs_handle;
	out.regs_offset = db_fifo_set_out.regs_offset;
	out.size = db_fifo_set_out.fifo_size;
	out.bp_thresh = db_fifo_set_out.fifo_bp_thresh;

	rc = user_fifo_mmap_entry_setup(hdev, hctx, usr_fifo_pdata, &out);
	if (rc)
		goto err_usr_fifo_unset;

	uobj->object = usr_fifo_pdata;

	rc = uverbs_copy_to_struct_or_zero(attrs, HBL_IB_ATTR_USR_FIFO_CREATE_OUT, &out,
					   sizeof(out));
	if (rc)
		goto err_remove_mmap_entries;

	return 0;

err_remove_mmap_entries:
	user_fifo_mmap_entry_remove(usr_fifo_pdata);

err_usr_fifo_unset:
	db_fifo_unset_in.port = port;
	db_fifo_unset_in.id = id;

	if (aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HBL_CNI_OP_USER_DB_FIFO_UNSET,
			      &db_fifo_unset_in, NULL))
		hbl_ibdev_dbg(ibdev, "failed to unset db fifo %d, port %d\n", id, port);

err_free_pdata:
	kfree(usr_fifo_pdata);
	return rc;
}

static int hbl_free_usr_fifo(struct ib_uobject *uobject, enum rdma_remove_reason why,
			     struct uverbs_attr_bundle *attrs)
{
	struct hbl_cni_user_db_fifo_unset_in db_fifo_unset_in = {};
	struct hbl_usr_fifo *usr_fifo_pdata;
	struct hbl_ib_aux_ops *aux_ops;
	struct hbl_ib_ucontext *hctx;
	struct hbl_aux_dev *aux_dev;
	struct hbl_ib_device *hdev;
	struct ib_device *ibdev;
	int rc;

	hctx = to_hbl_ib_ucontext(ib_uverbs_get_ucontext(attrs));
	if (IS_ERR(hctx))
		return PTR_ERR(hctx);

	usr_fifo_pdata = uobject->object;
	hdev = to_hbl_ib_dev(hctx->ibucontext.device);
	ibdev = &hdev->ibdev;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	db_fifo_unset_in.port = usr_fifo_pdata->port;
	db_fifo_unset_in.id = usr_fifo_pdata->id;

	user_fifo_mmap_entry_remove(usr_fifo_pdata);

	if (aux_ops->device_operational(aux_dev)) {
		rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HBL_CNI_OP_USER_DB_FIFO_UNSET,
				       &db_fifo_unset_in, NULL);
		if (rc) {
			hbl_ibdev_dbg(ibdev, "failed to unset db fifo %d, port %d\n",
				      usr_fifo_pdata->id, usr_fifo_pdata->port);
			return rc;
		}
	}

	kfree(usr_fifo_pdata);

	return 0;
}

DECLARE_UVERBS_NAMED_METHOD(
	HBL_IB_METHOD_USR_FIFO_OBJ_CREATE,
	UVERBS_ATTR_IDR(HBL_IB_ATTR_USR_FIFO_CREATE_HANDLE,
			HBL_IB_OBJECT_USR_FIFO,
			UVERBS_ACCESS_NEW,
			UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(HBL_IB_ATTR_USR_FIFO_CREATE_IN,
			   UVERBS_ATTR_STRUCT(struct hbl_uapi_usr_fifo_create_in, reserved3),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HBL_IB_ATTR_USR_FIFO_CREATE_OUT,
			    UVERBS_ATTR_STRUCT(struct hbl_uapi_usr_fifo_create_out, bp_thresh),
			    UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD_DESTROY(
	HBL_IB_METHOD_USR_FIFO_OBJ_DESTROY,
	UVERBS_ATTR_IDR(HBL_IB_ATTR_USR_FIFO_DESTROY_HANDLE,
			HBL_IB_OBJECT_USR_FIFO,
			UVERBS_ACCESS_DESTROY,
			UA_MANDATORY));

DECLARE_UVERBS_NAMED_OBJECT(HBL_IB_OBJECT_USR_FIFO,
			    UVERBS_TYPE_ALLOC_IDR(hbl_free_usr_fifo),
			    &UVERBS_METHOD(HBL_IB_METHOD_USR_FIFO_OBJ_CREATE),
			    &UVERBS_METHOD(HBL_IB_METHOD_USR_FIFO_OBJ_DESTROY));

const struct uapi_definition hbl_usr_fifo_defs[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(HBL_IB_OBJECT_USR_FIFO),
	{},
};
