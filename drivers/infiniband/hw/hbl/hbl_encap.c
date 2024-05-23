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

#define UVERBS_MODULE_NAME hbl
#include <rdma/uverbs_named_ioctl.h>

struct hbl_encap {
	u32 port_num;
	u32 encap_num;
};

static int UVERBS_HANDLER(HBL_IB_METHOD_ENCAP_CREATE)(struct uverbs_attr_bundle *attrs)
{
	struct hbl_cni_user_encap_alloc_out alloc_encap_out = {};
	struct hbl_cni_user_encap_alloc_in alloc_encap_in = {};
	struct hbl_cni_user_encap_unset_in unset_encap_in = {};
	struct hbl_cni_user_encap_set_in set_encap_in = {};
	struct hbl_uapi_encap_create_out out = {};
	struct hbl_uapi_encap_create_in in = {};
	u32 port, tnl_hdr_size, encap_num;
	struct hbl_ib_aux_ops *aux_ops;
	struct hbl_encap *encap_pdata;
	struct hbl_ib_ucontext *hctx;
	struct hbl_aux_dev *aux_dev;
	struct hbl_ib_device *hdev;
	struct ib_device *ibdev;
	struct ib_uobject *uobj;
	u64 tnl_hdr_ptr;
	u8 encap_type;
	int rc;

	hctx = to_hbl_ib_ucontext(ib_uverbs_get_ucontext(attrs));
	if (IS_ERR(hctx))
		return PTR_ERR(hctx);

	uobj = uverbs_attr_get_uobject(attrs, HBL_IB_ATTR_ENCAP_CREATE_HANDLE);
	hdev = to_hbl_ib_dev(hctx->ibucontext.device);
	ibdev = &hdev->ibdev;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	rc = uverbs_copy_from(&in, attrs, HBL_IB_ATTR_ENCAP_CREATE_IN);
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

	encap_pdata = kzalloc(sizeof(*encap_pdata), GFP_KERNEL);
	if (!encap_pdata)
		return -ENOMEM;

	encap_type = in.encap_type;

	alloc_encap_in.port = port;
	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HBL_CNI_OP_USER_ENCAP_ALLOC, &alloc_encap_in,
			       &alloc_encap_out);
	if (rc) {
		hbl_ibdev_dbg(ibdev, "failed to alloc encap for port %d\n", port);
		goto err_free_pdata;
	}

	encap_num = alloc_encap_out.id;

	if (encap_type != HBL_CNI_ENCAP_NONE) {
		tnl_hdr_ptr = in.tnl_hdr_ptr;
		tnl_hdr_size = in.tnl_hdr_size;
	} else {
		tnl_hdr_ptr = 0;
		tnl_hdr_size = 0;
	}

	encap_pdata->port_num = port;
	encap_pdata->encap_num = encap_num;

	set_encap_in.tnl_hdr_ptr = tnl_hdr_ptr;
	set_encap_in.tnl_hdr_size = tnl_hdr_size;
	set_encap_in.port = port;
	set_encap_in.id = encap_num;
	set_encap_in.encap_type = encap_type;

	switch (encap_type) {
	case HBL_CNI_ENCAP_NONE:
		set_encap_in.ipv4_addr = in.ipv4_addr;
		break;
	case HBL_CNI_ENCAP_OVER_UDP:
		set_encap_in.udp_dst_port = in.udp_dst_port;
		break;
	case HBL_CNI_ENCAP_OVER_IPV4:
		set_encap_in.ip_proto = in.ip_proto;
		break;
	default:
		break;
	}

	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HBL_CNI_OP_USER_ENCAP_SET, &set_encap_in,
			       NULL);
	if (rc) {
		hbl_ibdev_dbg(ibdev, "failed to set encap for port %d\n", port);
		goto err_encap_unset;
	}

	out.encap_num = encap_num;
	uobj->object = encap_pdata;

	rc = uverbs_copy_to_struct_or_zero(attrs, HBL_IB_ATTR_ENCAP_CREATE_OUT, &out, sizeof(out));
	if (rc)
		goto err_encap_unset;

	return 0;

err_encap_unset:
	unset_encap_in.port = port;
	unset_encap_in.id = encap_num;

	if (aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HBL_CNI_OP_USER_ENCAP_UNSET, &unset_encap_in,
			      NULL))
		hbl_ibdev_dbg(ibdev, "failed to unset encap for port %d, encap_num %d\n", port,
			      encap_num);

err_free_pdata:
	kfree(encap_pdata);

	return rc;
}

static int hbl_free_encap(struct ib_uobject *uobject, enum rdma_remove_reason why,
			  struct uverbs_attr_bundle *attrs)
{
	struct hbl_cni_user_encap_unset_in unset_encap_in = {};
	struct hbl_ib_aux_ops *aux_ops;
	struct hbl_encap *encap_pdata;
	struct hbl_ib_ucontext *hctx;
	struct hbl_aux_dev *aux_dev;
	struct hbl_ib_device *hdev;
	struct ib_device *ibdev;
	int rc;

	hctx = to_hbl_ib_ucontext(ib_uverbs_get_ucontext(attrs));
	if (IS_ERR(hctx))
		return PTR_ERR(hctx);

	encap_pdata = uobject->object;
	hdev = to_hbl_ib_dev(hctx->ibucontext.device);
	ibdev = &hdev->ibdev;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	unset_encap_in.port = encap_pdata->port_num;
	unset_encap_in.id = encap_pdata->encap_num;
	if (aux_ops->device_operational(aux_dev)) {
		rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HBL_CNI_OP_USER_ENCAP_UNSET,
				       &unset_encap_in, NULL);
		if (rc) {
			hbl_ibdev_dbg(ibdev, "failed to unset encap for port %d, id %d\n",
				      unset_encap_in.port, unset_encap_in.id);
			return rc;
		}
	}

	kfree(encap_pdata);

	return 0;
}

DECLARE_UVERBS_NAMED_METHOD(
	HBL_IB_METHOD_ENCAP_CREATE,
	UVERBS_ATTR_IDR(HBL_IB_ATTR_ENCAP_CREATE_HANDLE,
			HBL_IB_OBJECT_ENCAP,
			UVERBS_ACCESS_NEW,
			UA_MANDATORY),
	UVERBS_ATTR_PTR_IN(HBL_IB_ATTR_ENCAP_CREATE_IN,
			   UVERBS_ATTR_STRUCT(struct hbl_uapi_encap_create_in, reserved),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HBL_IB_ATTR_ENCAP_CREATE_OUT,
			    UVERBS_ATTR_STRUCT(struct hbl_uapi_encap_create_out, reserved),
			    UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD_DESTROY(
	HBL_IB_METHOD_ENCAP_DESTROY,
	UVERBS_ATTR_IDR(HBL_IB_ATTR_ENCAP_DESTROY_HANDLE,
			HBL_IB_OBJECT_ENCAP,
			UVERBS_ACCESS_DESTROY,
			UA_MANDATORY));

DECLARE_UVERBS_NAMED_OBJECT(HBL_IB_OBJECT_ENCAP,
			    UVERBS_TYPE_ALLOC_IDR(hbl_free_encap),
			    &UVERBS_METHOD(HBL_IB_METHOD_ENCAP_CREATE),
			    &UVERBS_METHOD(HBL_IB_METHOD_ENCAP_DESTROY));

const struct uapi_definition hbl_encap_defs[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(HBL_IB_OBJECT_ENCAP),
	{},
};
