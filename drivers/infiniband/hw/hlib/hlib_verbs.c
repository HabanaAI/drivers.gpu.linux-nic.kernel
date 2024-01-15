// SPDX-License-Identifier: GPL-2.0

/* Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include <rdma/ib_addr.h>
#include <rdma/uverbs_ioctl.h>
#include <linux/net/intel/cni.h>
#include <linux/bitfield.h>
#include <linux/ctype.h>

#include "hlib.h"
#include <uapi/rdma/hlib_user_ioctl_cmds.h>
#include <uapi/rdma/hlib_user_ioctl_verbs.h>

#define HL_IB_MAX_QP				BIT(10)
#define HL_IB_MAX_CQE				BIT(13)
#define HL_IB_MAX_MSG_SIZE			SZ_1G
#define HL_IB_DEFAULT_MAX_NUM_OF_QPS		128
#define HL_IB_DEFAULT_MAX_NUM_WQES_IN_WQ	256
#define HL_IB_DEFAULT_WQ_MEM_ID			HL_CNI_MEM_HOST
#define HL_IB_DUMP_QP_SZ			SZ_1K

static int verify_qp_xarray(struct hl_ib_qp *hlqp);

enum hl_ib_device_stats_type {
	COLL_QP,
};

#ifdef _HAS_STRUCT_RDMA_STAT_DESC
static const struct rdma_stat_desc hl_ib_device_stats[] = {
	{ .name = "coll_qp",},
};
#else
static const char *const hl_ib_device_stats[] = {
	"coll_qp",
};
#endif

static inline struct hl_ib_pd *to_hl_ib_pd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct hl_ib_pd, ibpd);
}

static inline struct hl_ib_qp *to_hl_ib_qp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct hl_ib_qp, ibqp);
}

static inline struct hl_ib_cq *to_hl_ib_cq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct hl_ib_cq, ibcq);
}

static inline u64 to_hl_port_mask(struct hl_ib_device *hdev, u64 ib_port_mask)
{
	u32 hl_port_num, ib_port_num;
	u64 hl_port_mask = 0x0;

	for (hl_port_num = 0; hl_port_num < hdev->max_num_of_ports; hl_port_num++) {
		ib_port_num = hdev->hl_to_ib_port_map[hl_port_num];
		if (!ib_port_num)
			continue;

		if (ib_port_mask & BIT_ULL(ib_port_num))
			hl_port_mask |= BIT_ULL(hl_port_num);
	}

	return hl_port_mask;
}

static inline u64 to_ib_port_mask(u64 hl_port_mask)
{
	/* The IB mask should be 1-based so we do shift left on the core mask.
	 * In order to fully align with IB, we also enables bit 0 which usually belongs to the PF.
	 */
	return (hl_port_mask << 1) | 0x1;
}

static int to_hl_wq_arr_types(struct ib_device *ibdev, enum hl_ib_wq_array_type ib_wq_arr_type,
			      enum hl_nic_mem_type *swq_type, enum hl_nic_mem_type *rwq_type)
{
	switch (ib_wq_arr_type) {
	case HL_IB_WQ_ARRAY_TYPE_GENERIC:
		*swq_type = HL_CNI_USER_WQ_SEND;
		*rwq_type = HL_CNI_USER_WQ_RECV;
		break;
	case HL_IB_WQ_ARRAY_TYPE_COLLECTIVE:
		*swq_type = HL_CNI_USER_COLL_WQ_SEND;
		*rwq_type = HL_CNI_USER_COLL_WQ_RECV;
		break;
	case HL_IB_WQ_ARRAY_TYPE_SCALE_OUT_COLLECTIVE:
		*swq_type = HL_CNI_USER_COLL_SCALE_OUT_WQ_SEND;
		*rwq_type = HL_CNI_USER_COLL_SCALE_OUT_WQ_RECV;
		break;
	default:
		hl_ibdev_err(ibdev, "Invalid WQ array type %d\n", ib_wq_arr_type);
		return -EINVAL;
	}

	return 0;
}

static int hl_ib_wqs_init(struct hl_ib_port *ib_port, enum hl_ib_wq_array_type ib_wq_arr_type)
{
	struct hl_cni_user_wq_arr_unset_in wq_arr_unset_in = {};
	struct hl_cni_user_wq_arr_set_out wq_arr_set_out = {};
	struct hl_cni_user_wq_arr_set_in wq_arr_set_in = {};
	enum hl_nic_mem_type swq_type, rwq_type;
	struct hlib_wq_array_attr *wq_arr_attr;
	struct hl_ib_aux_ops *aux_ops;
	struct hl_ib_ucontext *hctx;
	struct hl_aux_dev *aux_dev;
	struct hl_ib_device *hdev;
	struct ib_device *ibdev;
	u32 port;
	int rc;

	hdev = ib_port->hdev;
	port = ib_port->port;
	ibdev = &hdev->ibdev;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	hctx = ib_port->hctx;

	rc = to_hl_wq_arr_types(ibdev, ib_wq_arr_type, &swq_type, &rwq_type);
	if (rc)
		return rc;

	wq_arr_attr = &ib_port->init_params.wq_arr_attr[ib_wq_arr_type];

	if (!wq_arr_attr->max_num_of_wqs || !wq_arr_attr->max_num_of_wqes_in_wq)
		return 0;

	wq_arr_set_in.port = port;
	wq_arr_set_in.num_of_wqs = wq_arr_attr->max_num_of_wqs;
	wq_arr_set_in.num_of_wq_entries = wq_arr_attr->max_num_of_wqes_in_wq;
	wq_arr_set_in.mem_id = wq_arr_attr->mem_id;
	wq_arr_set_in.swq_granularity = wq_arr_attr->swq_granularity;

	wq_arr_set_in.type = swq_type;
	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_USER_WQ_SET,  &wq_arr_set_in,
			       &wq_arr_set_out);
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed to set send WQ, port %d\n", port);
		return rc;
	}

	ib_port->swqs_enabled[ib_wq_arr_type] = true;

	wq_arr_set_in.type = rwq_type;
	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_USER_WQ_SET, &wq_arr_set_in,
			       &wq_arr_set_out);
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed to set recv WQ, port %d\n", port);
		goto clear_send_wq;
	}

	ib_port->rwqs_enabled[ib_wq_arr_type] = true;

	return 0;

clear_send_wq:
	wq_arr_unset_in.port = port;
	wq_arr_unset_in.type = swq_type;
	aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_USER_WQ_UNSET, &wq_arr_unset_in, NULL);
	ib_port->swqs_enabled[ib_wq_arr_type] = false;

	return rc;
}

static void hl_ib_wqs_fini(struct hl_ib_port *ib_port, enum hl_ib_wq_array_type ib_wq_arr_type)
{
	struct hl_cni_user_wq_arr_unset_in wq_arr_unset_in = {};
	enum hl_nic_mem_type swq_type, rwq_type;
	struct hl_ib_aux_ops *aux_ops;
	struct hl_ib_ucontext *hctx;
	struct hl_aux_dev *aux_dev;
	struct hl_ib_device *hdev;
	struct ib_device *ibdev;
	u32 port;
	int rc;

	hdev = ib_port->hdev;
	port = ib_port->port;
	ibdev = &hdev->ibdev;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	hctx = ib_port->hctx;

	rc = to_hl_wq_arr_types(ibdev, ib_wq_arr_type, &swq_type, &rwq_type);
	if (rc)
		return;

	wq_arr_unset_in.port = port;

	if (ib_port->rwqs_enabled[ib_wq_arr_type]) {
		wq_arr_unset_in.type = rwq_type;
		rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_USER_WQ_UNSET,
				       &wq_arr_unset_in, NULL);
		if (rc)
			hl_ibdev_dbg(ibdev, "failed to unset recv WQ, port %d\n", port);

		ib_port->rwqs_enabled[ib_wq_arr_type] = false;
	}

	if (ib_port->swqs_enabled[ib_wq_arr_type]) {
		wq_arr_unset_in.type = swq_type;
		rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_USER_WQ_UNSET,
				       &wq_arr_unset_in, NULL);
		if (rc)
			hl_ibdev_dbg(ibdev, "failed to unset send WQ, port %d\n", port);

		ib_port->swqs_enabled[ib_wq_arr_type] = false;
	}
}

static void hl_ib_port_clear(struct hl_ib_ucontext *hctx, int port)
{
	struct hl_ib_device *hdev = to_hl_ib_dev(hctx->ibucontext.device);
	struct hl_ib_port *ib_port = &hdev->ib_port[port];

	/* Clean IB port struct from previous CTX allocations */
	memset(ib_port, 0, sizeof(*ib_port));
}

static int hl_ib_eq_func(void *param)
{
	unsigned long timeout = msecs_to_jiffies(60 * MSEC_PER_SEC);
	struct hl_ib_port *ib_port = param;
	int rc;

	while (!kthread_should_stop()) {
		/* Use timeout to avoid warnings for sleeping too long */
		rc = wait_for_completion_interruptible_timeout(&ib_port->eq_comp, timeout);

		/* No need to iterate on the devices when timed out or signaled, but only when
		 * completed.
		 */
		if (rc > 0)
			hl_ib_eqe_handler(ib_port);
	}

	return 0;
}

static int hl_ib_eq_init(struct hl_ib_port *ib_port)
{
	struct ib_device *ibdev = &ib_port->hdev->ibdev;
	char eq_th_name[32] = {0};
	u32 port = ib_port->port;
	int rc;

	init_completion(&ib_port->eq_comp);
	atomic_set(&ib_port->eq_lock, 0);

	snprintf(eq_th_name, sizeof(eq_th_name) - 1, "hlib_eq%d", port);
	ib_port->eq_thread = kthread_run(hl_ib_eq_func, ib_port, eq_th_name);
	if (IS_ERR(ib_port->eq_thread)) {
		rc = PTR_ERR(ib_port->eq_thread);
		hl_ibdev_dbg(ibdev, "failed to create an EQ thread, port %d, err %d\n", port, rc);
		return rc;
	}

	return 0;
}

static void hl_ib_eqe_fini(struct hl_ib_port *ib_port)
{
	while (atomic_cmpxchg(&ib_port->eq_lock, 0, 1))
		usleep_range(50, 200);

	complete_all(&ib_port->eq_comp);
	kthread_stop(ib_port->eq_thread);
}

int hl_ib_port_init(struct hl_ib_ucontext *hctx, struct hl_ib_port_init_params *in)
{
	struct hl_cni_set_user_app_params_in set_app_params_in = {};
	struct hl_ib_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;
	struct hl_ib_port *ib_port;
	struct hl_ib_device *hdev;
	struct ib_device *ibdev;
	u32 port;
	int rc;

	hdev = to_hl_ib_dev(hctx->ibucontext.device);
	ibdev = &hdev->ibdev;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	port = in->hl_port_num;

	ib_port = &hdev->ib_port[port];

	ib_port->hdev = hdev;
	ib_port->port = port;
	ib_port->hctx = hctx;
	memcpy(&ib_port->init_params, in, sizeof(ib_port->init_params));

	set_app_params_in.port = port;
	set_app_params_in.advanced = in->advanced;
	set_app_params_in.fna_mask_size = in->atomic_fna_mask_size;
	memcpy(set_app_params_in.bp_offs, in->qp_wq_bp_offs, sizeof(set_app_params_in.bp_offs));
	memcpy(set_app_params_in.fna_fifo_offs, in->atomic_fna_fifo_offs,
	       sizeof(set_app_params_in.fna_fifo_offs));

	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_SET_USER_APP_PARAMS,
			       &set_app_params_in, NULL);
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed to set app params, port %d\n", port);
		return rc;
	}

	/* Create pointer table to hold pointer to allocated ib_cq structs.
	 * We need them to post dispatch IB events.
	 */
	xa_init(&ib_port->hl_ibcq_tbl);

	rc = hl_ib_wqs_init(ib_port, HL_IB_WQ_ARRAY_TYPE_GENERIC);
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed to init WQs, port %d\n", port);
		goto destroy_xa;
	}

	rc = hl_ib_wqs_init(ib_port, HL_IB_WQ_ARRAY_TYPE_COLLECTIVE);
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed to init collective WQs, port %d\n", port);
		goto clean_wqs;
	}

	rc = hl_ib_wqs_init(ib_port, HL_IB_WQ_ARRAY_TYPE_SCALE_OUT_COLLECTIVE);
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed to init scale-out collective WQs, port %d\n", port);
		goto clean_coll_wqs;
	}

	rc = hl_ib_eq_init(ib_port);
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed to init EQ completion object, port %d\n", port);
		goto clean_scale_out_coll_wqs;
	}

	ib_port->open = true;

	return 0;

clean_scale_out_coll_wqs:
	hl_ib_wqs_fini(ib_port, HL_IB_WQ_ARRAY_TYPE_SCALE_OUT_COLLECTIVE);
clean_coll_wqs:
	hl_ib_wqs_fini(ib_port, HL_IB_WQ_ARRAY_TYPE_COLLECTIVE);
clean_wqs:
	hl_ib_wqs_fini(ib_port, HL_IB_WQ_ARRAY_TYPE_GENERIC);
destroy_xa:
	xa_destroy(&ib_port->hl_ibcq_tbl);
	return rc;
}

static void hl_ib_port_fini(struct hl_ib_ucontext *hctx, u32 port)
{
	struct hl_ib_port *ib_port;
	struct hl_ib_device *hdev;

	hdev = to_hl_ib_dev(hctx->ibucontext.device);
	ib_port = &hdev->ib_port[port];

	if (!ib_port->open)
		return;

	hl_ib_eqe_fini(ib_port);

	hl_ib_wqs_fini(ib_port, HL_IB_WQ_ARRAY_TYPE_SCALE_OUT_COLLECTIVE);
	hl_ib_wqs_fini(ib_port, HL_IB_WQ_ARRAY_TYPE_COLLECTIVE);
	hl_ib_wqs_fini(ib_port, HL_IB_WQ_ARRAY_TYPE_GENERIC);
	xa_destroy(&ib_port->hl_ibcq_tbl);
}

static int hl_ib_alloc_ucontext(struct ib_ucontext *ibucontext, struct ib_udata *udata)
{
	struct hl_ib_device *hdev = to_hl_ib_dev(ibucontext->device);
	struct hl_ib_ucontext *hctx = to_hl_ib_ucontext(ibucontext);
	struct hl_ib_port_init_params port_init_params = {};
	struct hlib_ibv_alloc_ucontext_resp resp = {};
	struct ib_device *ibdev = ibucontext->device;
	struct hlib_ibv_alloc_ucontext_req req = {};
	struct hl_aux_dev *aux_dev = hdev->aux_dev;
	struct hl_ib_aux_ops *aux_ops;
	u64 user_ports_mask;
	int rc, i;

	aux_ops = aux_dev->aux_ops;

	rc = ib_copy_from_udata(&req, udata, min(sizeof(req), udata->inlen));
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed to copy in udata for alloc_ucontext\n");
		return rc;
	}

	user_ports_mask = req.ports_mask;

	/* If the user didn't provide mask, we should use the core mask, which is 0-based.
	 * Otherwise, the user provides 1-based mask, so we need to convert it to core mask.
	 */
	if (!user_ports_mask)
		user_ports_mask = hdev->ports_mask;
	else
		user_ports_mask = to_hl_port_mask(hdev, user_ports_mask);

	if (user_ports_mask & ~hdev->ports_mask) {
		hl_ibdev_dbg(ibdev, "user ports mask (0x%llx) contains a disabled port\n",
			  user_ports_mask);
		return -EINVAL;
	}

	if (atomic_cmpxchg(&hdev->ctx_open, 0, 1)) {
		hl_ibdev_dbg(ibdev, "ucontext is already allocated\n");
		return -EBUSY;
	}

	rc = aux_ops->alloc_ucontext(aux_dev, req.core_fd, &hctx->cn_ctx);
	if (rc) {
		hl_ibdev_dbg(ibdev, "alloc context failed\n");
		goto exit;
	}

	/* Clear all the Ports */
	for (i = 0; i < hdev->max_num_of_ports; i++)
		hl_ib_port_clear(hctx, i);

	xa_init_flags(&hctx->qp_xarray, XA_FLAGS_ALLOC);

	/* If alloc context called from non-DV flow, need to initialize the ports here */
	if (!req.use_dvs) {
		struct hlib_wq_array_attr *gen_wq_arr_attr =
				&port_init_params.wq_arr_attr[HL_IB_WQ_ARRAY_TYPE_GENERIC];

		gen_wq_arr_attr->max_num_of_wqs = HL_IB_DEFAULT_MAX_NUM_OF_QPS;
		gen_wq_arr_attr->max_num_of_wqes_in_wq = HL_IB_DEFAULT_MAX_NUM_WQES_IN_WQ;
		gen_wq_arr_attr->mem_id = HL_IB_DEFAULT_WQ_MEM_ID;

		for (i = 0; i < hdev->max_num_of_ports; i++) {
			if (!(user_ports_mask & BIT(i)))
				continue;

			port_init_params.hl_port_num = i;
			rc = hl_ib_port_init(hctx, &port_init_params);
			if (rc)
				goto uninit_ports;
		}
	}

	hctx->ports_mask = user_ports_mask;

	/* Here we should return ib mask, which is 1-based */
	resp.ports_mask = to_ib_port_mask(user_ports_mask);

	if (hdev->umr_support)
		resp.cap_mask = HLIB_UCONTEXT_CAP_MMAP_UMR;

	rc = ib_copy_to_udata(udata, &resp, min(sizeof(resp), udata->outlen));
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed to copy out udata for alloc ucontext\n");
		goto uninit_ports;
	}

	aux_ops->eqe_work_schd = hl_ib_eqe_work_schd;

	hl_ibdev_dbg(ibdev, "IB context was allocated\n");

	return 0;

uninit_ports:
	for (--i; i >= 0; i--) {
		if (!(user_ports_mask & BIT(i)))
			continue;

		hl_ib_port_fini(hctx, i);
	}
	xa_destroy(&hctx->qp_xarray);
	aux_ops->dealloc_ucontext(aux_dev, hctx->cn_ctx);
exit:
	atomic_set(&hdev->ctx_open, 0);

	return rc;
}

static void hl_ib_dealloc_ucontext(struct ib_ucontext *ibucontext)
{
	struct hl_ib_device *hdev = to_hl_ib_dev(ibucontext->device);
	struct hl_ib_ucontext *hctx = to_hl_ib_ucontext(ibucontext);
	struct hl_aux_dev *aux_dev = hdev->aux_dev;
	struct hl_ib_aux_ops *aux_ops;
	int i;

	aux_ops = aux_dev->aux_ops;
	/* User context is dealocated, prevent from future EQE call the handler */
	aux_ops->eqe_work_schd = hl_ib_eqe_null_work;

	for (i = 0; i < hdev->max_num_of_ports; i++) {
		if (!(hctx->ports_mask & BIT(i)))
			continue;

		hl_ib_port_fini(hctx, i);
	}

	/* Core uverbs enforces that all ucontext sub-resources (e.g. QPs) are already released by
	 * the time we reach here. Hence, no need to check for active xarray IDs.
	 */
	xa_destroy(&hctx->qp_xarray);

	aux_ops->dealloc_ucontext(aux_dev, hctx->cn_ctx);

	atomic_set(&hdev->ctx_open, 0);

	hl_ibdev_dbg(&hdev->ibdev, "IB context was deallocated\n");
}

static void hl_ib_get_dev_fw_str(struct ib_device *device, char *str)
{
	struct hl_ib_device *hdev = to_hl_ib_dev(device);
	struct hl_aux_dev *aux_dev = hdev->aux_dev;
	struct hl_ib_device_attr dev_attr = {};
	struct hl_ib_aux_ops *aux_ops;

	aux_ops = aux_dev->aux_ops;
	aux_ops->query_device(aux_dev, &dev_attr);

	snprintf(str, IB_FW_VERSION_NAME_MAX, "%d.%u.%u", (u32)(dev_attr.fw_ver >> 32),
		 (u16)FIELD_GET((0xffff << 16), dev_attr.fw_ver), (u16)(dev_attr.fw_ver & 0xffff));
}

#ifdef _HAS_EX_RDMA_PORTS
static enum rdma_link_layer hl_ib_port_link_layer(struct ib_device *ibdev, u32 port_num)
#else
static enum rdma_link_layer hl_ib_port_link_layer(struct ib_device *ibdev, u8 port_num)
#endif
{
	return IB_LINK_LAYER_ETHERNET;
}

#ifdef _HAS_EX_RDMA_PORTS
static int hl_ib_get_port_immutable(struct ib_device *ibdev, u32 port_num,
				    struct ib_port_immutable *immutable)
#else
static int hl_ib_get_port_immutable(struct ib_device *ibdev, u8 port_num,
				    struct ib_port_immutable *immutable)
#endif
{
	struct hl_ib_device *hdev = to_hl_ib_dev(ibdev);
	struct ib_port_attr attr;
	u32 hport = 0;
	int rc;

	rc = ib_to_hl_port_num(hdev, port_num, &hport);
	if (rc) {
		hl_ibdev_dbg(ibdev, "invalid IB port %u\n", port_num);
		return rc;
	}

	rc = ib_query_port(ibdev, port_num, &attr);
	if (rc) {
		hl_ibdev_dbg(ibdev, "Couldn't query port %d, rc %d\n", port_num, rc);
		return rc;
	}

	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;

	if (hdev->ext_ports_mask & BIT(hport))
		/* RoCEv1 is used for MAC based address resoultion on L2 networks.
		 * while RoCEv2 is used for IP based address resolution on L3 networks.
		 */
		immutable->core_cap_flags = RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP |
					    RDMA_CORE_CAP_PROT_ROCE;
	else
		/* Since the internal ports are not advertised to netdev, we need to advertise them
		 * as plain IB to the IB core.
		 */
		immutable->core_cap_flags = RDMA_CORE_CAP_PROT_IB;

	return 0;
}

static int hl_ib_query_device(struct ib_device *ibdev, struct ib_device_attr *props,
			      struct ib_udata *udata)
{
	struct hl_ib_device *hdev = to_hl_ib_dev(ibdev);
	struct hl_aux_dev *aux_dev = hdev->aux_dev;
	struct hl_ib_device_attr dev_attr = {};
	struct hl_ib_aux_ops *aux_ops;

	aux_ops = aux_dev->aux_ops;

	if (udata && udata->inlen && !ib_is_udata_cleared(udata, 0, udata->inlen)) {
		hl_ibdev_dbg(ibdev, "Incompatible ABI params, udata not cleared\n");
		return -EINVAL;
	}

	memset(props, 0, sizeof(*props));

	aux_ops->query_device(aux_dev, &dev_attr);

	props->fw_ver = dev_attr.fw_ver;
	props->max_mr = 1;
	props->max_mr_size = dev_attr.max_mr_size;
	props->page_size_cap = dev_attr.page_size_cap;

	props->vendor_id = dev_attr.vendor_id;
	props->vendor_part_id = dev_attr.vendor_part_id;
	props->hw_ver = dev_attr.hw_ver;

	/* TODO: SW-87402: handle QPs per port */
	props->max_qp = dev_attr.max_qp;
	props->max_qp_wr = dev_attr.max_qp_wr;

	props->device_cap_flags = IB_DEVICE_RAW_MULTI |
				  IB_DEVICE_CHANGE_PHY_PORT |
				  IB_DEVICE_CURR_QP_STATE_MOD |
				  IB_DEVICE_SHUTDOWN_PORT |
				  IB_DEVICE_PORT_ACTIVE_EVENT |
				  IB_DEVICE_RC_RNR_NAK_GEN |
				  IB_DEVICE_N_NOTIFY_CQ;

	/* RR is unsupported but we need at least 2 max sge to pass pyverbs test */
	props->max_send_sge = HL_IB_MAX_SEND_SGE;
	props->max_recv_sge = HL_IB_MAX_RECV_SGE;

	/* RD is unsupported */
	props->max_sge_rd = 0;
	props->max_cq = 1;
	props->max_cqe = dev_attr.max_cqe;

	props->max_pd = 1;
	props->atomic_cap = IB_ATOMIC_NONE;
	props->max_raw_ipv6_qp = 1;
	props->max_raw_ethy_qp = 1;
	props->max_pkeys = 1;

	if (udata && udata->outlen)
		hl_ibdev_dbg(ibdev, "Failed to copy udata for query_device\n");

	return 0;
}

static u32 conv_lane_to_ib_width(u32 num_lanes)
{
	switch (num_lanes) {
	case 1:
		return IB_WIDTH_1X;
	case 2:
		return IB_WIDTH_2X;
	case 4:
		return IB_WIDTH_4X;
	default:
		return IB_WIDTH_4X;
	}
}

static u32 conv_speed_to_ib_speed(u32 port_speed, u8 lanes)
{
	u32 speed_per_lane = port_speed / lanes;

	switch (speed_per_lane) {
	case SPEED_25000:
		return IB_SPEED_EDR;
	case SPEED_50000:
		return IB_SPEED_HDR;
	case SPEED_100000:
		return IB_SPEED_NDR;
	default:
		return IB_SPEED_HDR;
	}
}

#ifdef _HAS_EX_RDMA_PORTS
static int hl_ib_query_port(struct ib_device *ibdev, u32 port, struct ib_port_attr *props)
#else
static int hl_ib_query_port(struct ib_device *ibdev, u8 port, struct ib_port_attr *props)
#endif
{
	struct hl_ib_device *hdev = to_hl_ib_dev(ibdev);
	struct hl_aux_dev *aux_dev = hdev->aux_dev;
	struct hl_ib_port_attr port_attr = {};
	struct hl_ib_aux_ops *aux_ops;
	u32 hport;
	int rc;

	rc = ib_to_hl_port_num(hdev, port, &hport);
	if (rc) {
		hl_ibdev_dbg(ibdev, "invalid IB port %u\n", port);
		return rc;
	}

	aux_ops = aux_dev->aux_ops;
	aux_ops->query_port(aux_dev, hport, &port_attr);

	props->state = (port_attr.open && port_attr.link_up) ? IB_PORT_ACTIVE : IB_PORT_DOWN;
	props->max_mtu = ib_mtu_int_to_enum(port_attr.max_mtu);

	/* external ports: Use value initialized in hl_ib_port.
	 * Internal ports: Hard code 4KB for now
	 */
	props->active_mtu = ib_mtu_int_to_enum(hdev->ib_port[hport].mtu);
	if (hdev->ext_ports_mask & BIT(hport))
		props->gid_tbl_len = HL_IB_MAX_PORT_GIDS;
	else
		props->gid_tbl_len = HL_IB_MAX_PORT_GIDS_INTERNAL;

	props->max_msg_sz = port_attr.max_msg_sz;
	props->pkey_tbl_len = 1;

	props->active_speed = conv_speed_to_ib_speed(port_attr.speed, port_attr.num_lanes);
	props->active_width = conv_lane_to_ib_width(port_attr.num_lanes);

	props->phys_state = port_attr.link_up ? IB_PORT_PHYS_STATE_LINK_UP :
			    IB_PORT_PHYS_STATE_DISABLED;

	return 0;
}

static int hl_ib_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct hl_ib_ucontext *hctx = rdma_udata_to_drv_context(udata, struct hl_ib_ucontext,
								ibucontext);
	struct hl_ib_pd *pd = to_hl_ib_pd(ibpd);
	struct hlib_ibv_alloc_pd_resp resp = {};
	struct ib_device *ibdev = ibpd->device;
	int rc;

	if (udata->inlen && !ib_is_udata_cleared(udata, 0, udata->inlen)) {
		hl_ibdev_dbg(ibdev, "Incompatible ABI params, udata not cleared\n");
		return -EINVAL;
	}

	/* currently only a single PD is supoprted */
	if (atomic_cmpxchg(&hctx->pd_allocated, 0, 1)) {
		hl_ibdev_dbg(ibdev, "no available PD\n");
		return -ESRCH;
	}

	pd->pdn = 1;
	resp.pdn = pd->pdn;

	if (udata->outlen) {
		rc = ib_copy_to_udata(udata, &resp, min(sizeof(resp), udata->outlen));
		if (rc) {
			hl_ibdev_dbg(ibdev, "Failed to copy udata for alloc_pd\n");
			goto err;
		}
	}

	hl_ibdev_dbg(ibdev, "allocated PD %d\n", pd->pdn);

	return 0;

err:
	atomic_set(&hctx->pd_allocated, 0);

	return rc;
}

static int __create_cq(struct hl_ib_cq *hlcq, struct hl_ib_device *hdev,
			const struct ib_cq_init_attr *attr, struct ib_udata *udata,
			u32 hl_port_num)
{
	struct hl_cni_alloc_user_cq_id_out alloc_cq_out = {};
	struct hl_cni_alloc_user_cq_id_in alloc_cq_in = {};
	struct hl_cni_user_cq_id_unset_in cq_unset_in = {};
	struct hl_cni_user_cq_id_set_out cq_set_out = {};
	struct hl_cni_user_cq_id_set_in cq_set_in = {};
	struct hlib_ibv_create_cq_resp resp = {};
	struct hl_ib_device_attr dev_attr = {};
	struct hl_ib_aux_ops *aux_ops;
	struct hl_ib_ucontext *hctx;
	struct hl_ib_port *ib_port;
	struct hl_aux_dev *aux_dev;
	struct ib_device *ibdev;
	int cqes, rc;
	u32 cq_num;

	ibdev = &hdev->ibdev;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	cqes = attr->cqe;
	ib_port = &hdev->ib_port[hl_port_num];
	hctx = ib_port->hctx;

	/* Step 1: Alloc cq */
	alloc_cq_in.port = hl_port_num;

	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_ALLOC_USER_CQ_ID, &alloc_cq_in,
			       &alloc_cq_out);
	if (rc) {
		hl_ibdev_dbg(ibdev, "Allocation of cq_id failed, port: %d\n", hl_port_num);
		return rc;
	}

	cq_num = alloc_cq_out.id;

	aux_ops->query_device(aux_dev, &dev_attr);

	/* If the number of cqes requested by the IB user is less than the minimum required by the
	 * HW, ceil it to min required cq entries. This is needed to pass the test_cq pyverbs test
	 * TODO: SW-112274.
	 */
	if (cqes < dev_attr.min_cq_entries) {
		cqes = dev_attr.min_cq_entries;
		hl_ibdev_dbg(ibdev, "Requested cqe: %d is less than minimum required cqe: %d. Hence ceiling it to min required CQE\n",
				cqes, dev_attr.min_cq_entries);
	}

	/* Step 2: USER_CQ Set */
	cq_set_in.port = hl_port_num;
	cq_set_in.id = cq_num;
	cq_set_in.num_of_cqes = cqes;

	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_USER_CQ_ID_SET, &cq_set_in,
			       &cq_set_out);
	if (rc) {
		hl_ibdev_dbg(ibdev, "CQ_ID Set failed, port: %d\n", hl_port_num);
		goto unset_cq;
	}

	resp.cq_num = cq_num;
	resp.mem_handle = cq_set_out.mem_handle;
	resp.pi_handle = cq_set_out.pi_handle;
	resp.regs_handle = cq_set_out.regs_handle;
	resp.regs_offset = cq_set_out.regs_offset;
	resp.cq_size = PAGE_ALIGN(dev_attr.cqe_size * cqes);

	if (udata->outlen) {
		rc = ib_copy_to_udata(udata, &resp, min(sizeof(resp), udata->outlen));
		if (rc) {
			hl_ibdev_dbg(ibdev, "Failed to copy udata to userspace\n");
			goto unset_cq;
		}
	}

	/* Number of cqes that are allocated. Also store the relevant data needed for destroying the
	 * cq.
	 */
	hlcq->ibcq.cqe = cqes;
	hlcq->hl_port_num = hl_port_num;
	hlcq->cq_num = cq_num;
	hlcq->cq_type = HLIB_CQ_TYPE_QP;

	xa_store(&ib_port->hl_ibcq_tbl, cq_num, &hlcq->ibcq, GFP_KERNEL);

	return 0;

unset_cq:
	cq_unset_in.port = hl_port_num;
	cq_unset_in.id = cq_num;

	if (aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_USER_CQ_ID_UNSET, &cq_unset_in,
			      NULL))
		hl_ibdev_dbg(ibdev, "Failed to destroy cq, port: %d, cq_num: %d\n",
					hl_port_num, cq_num);

	return rc;
}

static int __create_cc_cq(struct hl_ib_cq *hlcq, struct hl_ib_device *hdev,
			const struct ib_cq_init_attr *attr, struct ib_udata *udata,
			u32 hl_port_num)
{
	struct hl_cni_user_ccq_unset_in cc_cq_unset_in = {};
	struct hl_cni_user_ccq_set_out cc_cq_set_out = {};
	struct hl_cni_user_ccq_set_in cc_cq_set_in = {};
	struct hlib_ibv_create_cq_resp resp = {};
	struct hl_ib_device_attr dev_attr = {};
	struct hl_ib_aux_ops *aux_ops;
	struct hl_ib_ucontext *hctx;
	struct hl_ib_port *ib_port;
	struct hl_aux_dev *aux_dev;
	struct ib_device *ibdev;
	int rc;

	ibdev = &hdev->ibdev;
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	ib_port = &hdev->ib_port[hl_port_num];
	hctx = ib_port->hctx;

	cc_cq_set_in.port = hl_port_num;
	cc_cq_set_in.num_of_entries = attr->cqe;

	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_USER_CCQ_SET, &cc_cq_set_in,
			       &cc_cq_set_out);
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed to set CC CQ, port %d\n", hl_port_num);
		return rc;
	}

	aux_ops->query_device(aux_dev, &dev_attr);

	resp.cq_num = cc_cq_set_out.id;
	resp.mem_handle = cc_cq_set_out.mem_handle;
	resp.pi_handle = cc_cq_set_out.pi_handle;
	resp.cq_size = PAGE_ALIGN(dev_attr.cqe_size * attr->cqe);

	if (udata->outlen) {
		rc = ib_copy_to_udata(udata, &resp, min(sizeof(resp), udata->outlen));
		if (rc) {
			hl_ibdev_dbg(ibdev, "Failed to copy udata to userspace\n");
			goto err_cc_cq_unset;
		}
	}

	/* Number of cqes that are allocated. Also store the relevant data needed for destroying the
	 * cq.
	 */
	hlcq->ibcq.cqe = attr->cqe;
	hlcq->hl_port_num = hl_port_num;
	hlcq->cq_num = cc_cq_set_out.id;
	hlcq->cq_type = HLIB_CQ_TYPE_CC;

	return 0;

err_cc_cq_unset:
	cc_cq_unset_in.port = hl_port_num;

	if (aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_USER_CCQ_UNSET, &cc_cq_unset_in,
			      NULL))
		hl_ibdev_dbg(ibdev, "failed to unset CC CQ, port %d\n", hl_port_num);

	return rc;
}

static int create_cq(struct hl_ib_cq *hlcq, struct hl_ib_device *hdev,
			const struct ib_cq_init_attr *attr, struct ib_udata *udata)
{
	struct hlib_ibv_create_cq_req cmd = {};
	struct hl_ib_ucontext *hctx;
	struct ib_device *ibdev;
	u32 hl_port_num;
	int rc;

	hctx = rdma_udata_to_drv_context(udata, struct hl_ib_ucontext, ibucontext);
	ibdev = &hdev->ibdev;

	if (attr->flags) {
		hl_ibdev_dbg(ibdev, "attr->flags: %d but should be 0\n", attr->flags);
		return -EOPNOTSUPP;
	}

	rc = ib_copy_from_udata(&cmd, udata, min(sizeof(cmd), udata->inlen));
	if (rc) {
		hl_ibdev_dbg(ibdev, "Failed to copy udata from user space\n");
		return rc;
	}

	rc = ib_to_hl_port_num(hdev, cmd.port_num, &hl_port_num);
	if (rc) {
		hl_ibdev_dbg(ibdev, "invalid IB port %u\n", cmd.port_num);
		return rc;
	}

	if (!(hctx->ports_mask & BIT(hl_port_num))) {
		hl_ibdev_dbg(ibdev, "port %d is not part of the context's ports mask 0x%llx\n",
					hl_port_num, hctx->ports_mask);
		return -EINVAL;
	}

	switch (cmd.cq_type) {
	case HLIB_CQ_TYPE_QP:
		rc = __create_cq(hlcq, hdev, attr, udata, hl_port_num);
		break;
	case HLIB_CQ_TYPE_CC:
		rc = __create_cc_cq(hlcq, hdev, attr, udata, hl_port_num);
		break;
	default:
		hl_ibdev_dbg(ibdev, "Invalid CQ resource requested %u\n", cmd.cq_type);
		rc = -EINVAL;
	}

	return rc;
}

#ifdef _HAS_INT_CREATE_CQ
static int hl_ib_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr,
			   struct ib_udata *udata)
{
	struct hl_ib_cq *hlcq = to_hl_ib_cq(ibcq);
	struct hl_ib_device *hdev = to_hl_ib_dev(ibcq->device);
	int rc;

	rc = create_cq(hlcq, hdev, attr, udata);
	if (rc) {
		hl_ibdev_dbg(&hdev->ibdev, "Failed to create a CQ\n");
		return rc;
	}

	return 0;
}
#else
static struct ib_cq *hl_ib_create_cq(struct ib_device *ibdev, const struct ib_cq_init_attr *attr,
				     struct ib_udata *udata)
{
	struct hl_ib_device *hdev = to_hl_ib_dev(ibdev);
	struct hl_ib_cq *hlcq;
	int rc;

	hlcq = kzalloc(sizeof(*hlcq), GFP_KERNEL);
	if (!hlcq)
		return ERR_PTR(-ENOMEM);

	rc = create_cq(hlcq, hdev, attr, udata);
	if (rc) {
		hl_ibdev_dbg(ibdev, "Failed to create CQ\n");
		goto err;
	}

	return &hlcq->ibcq;

err:
	kfree(hlcq);
	return ERR_PTR(rc);
}
#endif

static int create_qp(struct hl_ib_qp *hlqp, struct ib_qp_init_attr *qp_init_attr,
		     struct ib_udata *udata)
{
	struct hl_ib_ucontext *hctx = rdma_udata_to_drv_context(udata, struct hl_ib_ucontext,
								ibucontext);
	struct ib_device *ibdev = hlqp->ibqp.device;
	u32 qp_num;
	int rc;

	/* Allocate an IB QP handle. Note,
	 * - It doesn't map to HW QPC index.
	 * - No HW or HL core QP resources are allocated yet.
	 */
	rc = xa_alloc(&hctx->qp_xarray, &qp_num, hlqp, xa_limit_32b, GFP_KERNEL);
	if (rc) {
		hl_ibdev_dbg(ibdev, "Failed to allocate IB QP handle\n");
		return rc;
	}

	hlqp->ibqp.qp_num = qp_num;
	hlqp->qp_state = IB_QPS_RESET;
	hlqp->hctx = hctx;

	/* Cache the required QP params */
	hlqp->max_send_wr = qp_init_attr->cap.max_send_wr;
	hlqp->max_recv_wr = qp_init_attr->cap.max_recv_wr;

	return 0;
}

#ifdef _HAS_INT_CREATE_QP
static int hl_ib_create_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *qp_init_attr,
			   struct ib_udata *udata)
{
	struct hl_ib_qp *hlqp = to_hl_ib_qp(ibqp);

	return create_qp(hlqp, qp_init_attr, udata);
}
#else
static struct ib_qp *hl_ib_create_qp(struct ib_pd *pd, struct ib_qp_init_attr *qp_init_attr,
				     struct ib_udata *udata)
{
	struct hl_ib_qp *hlqp;
	struct ib_qp *ibqp;
	int rc;

	hlqp = kzalloc(sizeof(*hlqp), GFP_KERNEL);
	if (!hlqp)
		return ERR_PTR(-ENOMEM);

	/* Init IB QP for HL usage. Rest of the init is done by IB core later. */
	ibqp = &hlqp->ibqp;
	ibqp->device = pd->device;
	ibqp->pd = pd;

	rc = create_qp(hlqp, qp_init_attr, udata);
	if (rc)
		goto err_free_qp;

	return ibqp;

err_free_qp:
	kfree(hlqp);

	return ERR_PTR(rc);
}
#endif

static int __hl_ib_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct hl_ib_ucontext *hctx = rdma_udata_to_drv_context(udata, struct hl_ib_ucontext,
								ibucontext);
	struct hl_ib_pd *pd = to_hl_ib_pd(ibpd);
	struct ib_device *ibdev = ibpd->device;

	hl_ibdev_dbg(ibdev, "deallocated PD %d\n", pd->pdn);

	atomic_set(&hctx->pd_allocated, 0);

	return 0;
}

#ifdef _HAS_INT_DEALLOC_PD
static int hl_ib_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	return __hl_ib_dealloc_pd(ibpd, udata);
}
#else
static void hl_ib_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	__hl_ib_dealloc_pd(ibpd, udata);
}
#endif

static int hl_ib_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
{
	return -EOPNOTSUPP;
}

static int destroy_cq(struct ib_cq *ibcq)
{
	struct hl_cni_user_ccq_unset_in cc_cq_unset_in = {};
	struct hl_cni_user_cq_id_unset_in cq_unset_in = {};
	struct hl_ib_aux_ops *aux_ops;
	struct hl_ib_ucontext *hctx;
	struct hl_aux_dev *aux_dev;
	struct hl_ib_port *ib_port;
	struct hl_ib_device *hdev;
	struct ib_device *ibdev;
	struct hl_ib_cq *hlcq;
	int rc;

	hlcq = to_hl_ib_cq(ibcq);
	ibdev = ibcq->device;
	hdev = to_hl_ib_dev(ibdev);
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	ib_port = &hdev->ib_port[hlcq->hl_port_num];
	hctx = ib_port->hctx;

	if (hlcq->cq_type == HLIB_CQ_TYPE_QP) {
		xa_erase(&ib_port->hl_ibcq_tbl, hlcq->cq_num);
		cq_unset_in.port = hlcq->hl_port_num;
		cq_unset_in.id = hlcq->cq_num;

		if (aux_ops->device_operational(aux_dev)) {
			rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_USER_CQ_ID_UNSET,
					       &cq_unset_in, NULL);
			if (rc) {
				hl_ibdev_dbg(ibdev, "Failed to destroy cq, port: %d, cq_num: %d\n",
								hlcq->hl_port_num, hlcq->cq_num);
				return rc;
			}
		}
	} else {
		cc_cq_unset_in.port = hlcq->hl_port_num;

		if (aux_ops->device_operational(aux_dev)) {
			rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_USER_CCQ_UNSET,
					       &cc_cq_unset_in, NULL);
			if (rc) {
				hl_ibdev_dbg(ibdev, "failed to unset CC CQ, port %d\n",
						hlcq->hl_port_num);
				return rc;
			}
		}
	}


	/* Destroy the internal CQ struct we allocated during create CQ */
#ifndef _HAS_INT_CREATE_CQ
	kfree(hlcq);
#endif
	return 0;
}

#ifdef _HAS_INT_DESTROY_CQ
static int hl_ib_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata)
{
	int rc;

	rc = destroy_cq(ibcq);
	if (rc)
		return rc;

	return 0;
}
#else
static void hl_ib_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata)
{
	destroy_cq(ibcq);
}
#endif

static int __destroy_qp(struct hl_ib_qp *hlqp)
{
	struct hl_cni_destroy_conn_in destroy_conn_in = {};
	struct hl_ib_aux_ops *aux_ops;
	struct hl_ib_ucontext *hctx;
	struct hl_aux_dev *aux_dev;
	struct hl_ib_device *hdev;
	struct ib_device *ibdev;
	struct ib_qp *ibqp;
	u32 hl_port;
	int rc;

	ibqp = &hlqp->ibqp;
	ibdev = ibqp->device;
	hdev = to_hl_ib_dev(ibdev);
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	hctx = hlqp->hctx;

	rc = ib_to_hl_port_num(hdev, ibqp->port, &hl_port);
	if (rc) {
		hl_ibdev_dbg(ibdev, "invalid IB port %u, IB QP %u\n", ibqp->port, ibqp->qp_num);
		return rc;
	}

	destroy_conn_in.port = hl_port;
	destroy_conn_in.conn_id = hlqp->qp_id;

	if (aux_ops->device_operational(aux_dev)) {
		rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_DESTROY_CONN,
				       &destroy_conn_in, NULL);
		if (rc) {
			hl_ibdev_dbg(ibdev, "Failed to destroy QP id %d, port %d\n",
					hlqp->qp_id, hl_port);
			return rc;
		}
	}
	return 0;
}

static int destroy_qp(struct hl_ib_qp *hlqp)
{
	struct hl_ib_ucontext *hctx;
	struct ib_qp *ibqp;
	int rc;

	rc = verify_qp_xarray(hlqp);
	if (rc)
		return rc;

	ibqp = &hlqp->ibqp;
	hctx = hlqp->hctx;

	if (hlqp->qp_state >= IB_QPS_INIT) {
		rc = __destroy_qp(hlqp);
		if (rc)
			return rc;
	}

	xa_erase(&hctx->qp_xarray, ibqp->qp_num);

	return 0;
}

static int hl_ib_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata)
{
	struct hl_ib_qp *hlqp = to_hl_ib_qp(ibqp);
	int rc;

	rc = destroy_qp(hlqp);
	if (rc)
		return rc;

#ifndef _HAS_INT_CREATE_QP
	kfree(hlqp);
#endif

	return 0;
}

static struct rdma_hw_stats *__hl_ib_alloc_hw_stats(struct ib_device *ibdev, u32 port_num)
{
#ifdef _HAS_STRUCT_RDMA_STAT_DESC
	struct rdma_stat_desc *hl_ib_port_stats;
#else
	const char **hl_ib_port_stats;
#endif
	struct hl_ib_port_stats *port_stats;
	struct hl_ib_device *hdev;
	u32 port;
	int rc;

	if (!port_num)
		return rdma_alloc_hw_stats_struct(hl_ib_device_stats,
						  ARRAY_SIZE(hl_ib_device_stats),
						  RDMA_HW_STATS_DEFAULT_LIFESPAN);

	hdev = to_hl_ib_dev(ibdev);

	rc = ib_to_hl_port_num(hdev, port_num, &port);
	if (rc) {
		hl_ibdev_dbg(ibdev, "invalid IB port %u\n", port_num);
		return NULL;
	}

	port_stats = &hdev->port_stats[port];

#ifdef _HAS_STRUCT_RDMA_STAT_DESC
	hl_ib_port_stats = port_stats->stat_desc;
#else
	hl_ib_port_stats = (const char **)port_stats->names;
#endif

	return rdma_alloc_hw_stats_struct(hl_ib_port_stats, port_stats->num,
					  RDMA_HW_STATS_DEFAULT_LIFESPAN);
}

#ifdef _HAS_IB_DEVICE_STATS
static struct rdma_hw_stats *hl_ib_alloc_hw_port_stats(struct ib_device *ibdev, u32 port_num)
{
	return __hl_ib_alloc_hw_stats(ibdev, port_num);
}

static struct rdma_hw_stats *hl_ib_alloc_hw_device_stats(struct ib_device *ibdev)
{
	return __hl_ib_alloc_hw_stats(ibdev, 0);
}
#else
#ifdef _HAS_EX_RDMA_PORTS
static struct rdma_hw_stats *hl_ib_alloc_hw_stats(struct ib_device *ibdev, u32 port_num)
#else
static struct rdma_hw_stats *hl_ib_alloc_hw_stats(struct ib_device *ibdev, u8 port_num)
#endif
{
	return __hl_ib_alloc_hw_stats(ibdev, port_num);
}
#endif

#ifdef _HAS_EX_RDMA_PORTS
static int hl_ib_get_hw_stats(struct ib_device *ibdev, struct rdma_hw_stats *stats, u32 port_num,
			      int index)
#else
static int hl_ib_get_hw_stats(struct ib_device *ibdev, struct rdma_hw_stats *stats, u8 port_num,
			      int index)
#endif
{
	struct hl_ib_device *hdev = to_hl_ib_dev(ibdev);
	struct hl_ib_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;
	u32 port;
	int rc;

	if (!port_num) {
		stats->value[COLL_QP] = atomic_read(&hdev->dev_stats.coll_qp);

		return ARRAY_SIZE(hl_ib_device_stats);
	}

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	rc = ib_to_hl_port_num(hdev, port_num, &port);
	if (rc) {
		hl_ibdev_dbg(ibdev, "invalid IB port %u\n", port_num);
		return rc;
	}

	aux_ops->get_cnts_values(aux_dev, port, stats->value);

	return stats->num_counters;
}

static int hl_ib_mmap(struct ib_ucontext *ibucontext, struct vm_area_struct *vma)
{
	struct hl_ib_aux_ops *aux_ops;
	struct hl_ib_ucontext *hctx;
	struct hl_aux_dev *aux_dev;
	struct hl_ib_device *hdev;
	struct ib_device *ibdev;
	int rc;

	ibdev = ibucontext->device;
	hdev = to_hl_ib_dev(ibdev);
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	hctx = to_hl_ib_ucontext(ibucontext);

	rc = aux_ops->mmap(aux_dev, hctx->cn_ctx, vma);
	if (rc) {
		hl_ibdev_dbg(ibdev, "Mmap failed, %d\n", rc);
		return rc;
	}

	return 0;
}

#ifdef _HAS_MMAP_FREE
static void hl_ib_mmap_free(struct rdma_user_mmap_entry *rdma_entry)
{
	/* NoOps */
}
#endif

static int verify_qp_xarray(struct hl_ib_qp *hlqp)
{
	struct ib_device *ibdev;
	struct ib_qp *ibqp;

	ibqp = &hlqp->ibqp;
	ibdev = ibqp->device;

	hlqp = xa_load(&hlqp->hctx->qp_xarray, ibqp->qp_num);
	if (!hlqp) {
		hl_ibdev_dbg(ibdev, "Invalid IB QP %d modified\n", ibqp->qp_num);
		return -EINVAL;
	}

	return 0;
}

static int verify_modify_qp(struct hl_ib_qp *hlqp, struct ib_qp_attr *qp_attr, int qp_attr_mask)
{
	struct ib_device *ibdev;
	struct ib_qp *ibqp;
	int rc;

	ibqp = &hlqp->ibqp;
	ibdev = ibqp->device;

	rc = verify_qp_xarray(hlqp);
	if (rc)
		return rc;

	/* Verify state change and corresponding QP attribute mask. */
	if (!ib_modify_qp_is_ok(hlqp->qp_state, qp_attr->qp_state, IB_QPT_RC, qp_attr_mask)) {
		hl_ibdev_dbg(ibdev, "Invalid IB QP %d params\n", ibqp->qp_num);
		return -EINVAL;
	}

	return 0;
}

static int get_qp_wq_type(struct hl_ib_device *hdev, enum qpc_req_wq_type *to, u8 from)
{
	if (from & HLIB_WQ_READ_RDV_ENDP) {
		if (hweight_long(from) != 1)
			return -EINVAL;

		*to = QPC_REQ_WQ_TYPE_RDV_READ;

		return 0;
	}

	if (from & HLIB_WQ_SEND_RDV) {
		if (hweight_long(from) != 1)
			return -EINVAL;

		*to = QPC_REQ_WQ_TYPE_RDV_WRITE;

		return 0;
	}

	if (from & (HLIB_WQ_WRITE | HLIB_WQ_RECV_RDV | HLIB_WQ_READ_RDV)) {
		if (hdev->mixed_qp_wq_types) {
			if ((from & HLIB_WQ_RECV_RDV) && (from & HLIB_WQ_READ_RDV))
				return -EINVAL;
		} else {
			if (hweight_long(from) != 1)
				return -EINVAL;
		}

		*to = QPC_REQ_WQ_TYPE_WRITE;

		return 0;
	}

	return -EINVAL;
}

static int alloc_qp(struct hl_ib_qp *hlqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
			struct hlib_ibv_modify_qp_req *modify_qp_req,
			struct hlib_ibv_modify_qp_resp *modify_qp_resp)
{
	struct hl_cni_alloc_conn_out alloc_conn_out = {};
	struct hl_cni_alloc_conn_in alloc_conn_in = {};
	enum qpc_req_wq_type hl_wq_type;
	struct hl_ib_aux_ops *aux_ops;
	struct hl_ib_ucontext *hctx;
	struct hl_aux_dev *aux_dev;
	struct hl_ib_device *hdev;
	struct ib_device *ibdev;
	struct ib_qp *ibqp;
	u8 ib_wq_type;
	u32 hl_port;
	int rc;

	ibqp = &hlqp->ibqp;
	ibdev = ibqp->device;
	hdev = to_hl_ib_dev(ibdev);
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	hctx = hlqp->hctx;

	rc = ib_to_hl_port_num(hdev, qp_attr->port_num, &hl_port);
	if (rc) {
		hl_ibdev_dbg(ibdev, "invalid IB port %u\n", qp_attr->port_num);
		return rc;
	}

	ib_wq_type = modify_qp_req->wq_type;
	rc = get_qp_wq_type(hdev, &hl_wq_type, ib_wq_type);
	if (rc) {
		hl_ibdev_dbg(ibdev, "invalid WQ type mask %d, port %u\n", ib_wq_type, hl_port);
		return rc;
	}

	alloc_conn_in.port = hl_port;

	if (modify_qp_req->is_coll) {
		/* For collective QPs, alloc request to core is once as driver allocates QPs
		 * for all ports in a single call. But IB driver still needs to alloc QPs per
		 * request to manage QP states. So its expected that user will first allocate a
		 * collective QP id and then allocate standard QPs for all ports within the group
		 * by providing the collective QP id as a hint. IB driver will just verify that
		 * the qp id is indeed valid.
		 */
		rc = aux_ops->verify_qp_id(aux_dev, modify_qp_req->qp_num_hint, hl_port, true);
		if (!rc)
			alloc_conn_out.conn_id = modify_qp_req->qp_num_hint;
	} else {
		rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_ALLOC_CONN, &alloc_conn_in,
				       &alloc_conn_out);
	}

	if (rc) {
		hl_ibdev_dbg(ibdev, "Failed to allocate QP, port %d\n", hl_port);
		return rc;
	}

	hlqp->qp_id = alloc_conn_out.conn_id;
	hlqp->qp_state = IB_QPS_INIT;
	hlqp->wq_type = hl_wq_type;
	hlqp->wq_granularity = modify_qp_req->wq_granularity;

	modify_qp_resp->qp_num = hlqp->qp_id;

	return 0;
}

static u8 get_req_cq_number(struct hl_ib_qp *hlqp)
{
	struct ib_cq *ibcq;
	struct hl_ib_cq *hlcq;

	ibcq = hlqp->ibqp.send_cq;
	hlcq = to_hl_ib_cq(ibcq);

	return hlcq->cq_num;
}

static u8 get_res_cq_number(struct hl_ib_qp *hlqp)
{
	struct ib_cq *ibcq;
	struct hl_ib_cq *hlcq;

	ibcq = hlqp->ibqp.recv_cq;
	hlcq = to_hl_ib_cq(ibcq);

	return hlcq->cq_num;
}

static void copy_mac_reverse(u8 *dst, u8 *src)
{
	int i;

	for (i = 0; i < ETH_ALEN; i++)
		dst[i] = src[(ETH_ALEN - 1) - i];
}

static inline bool is_l2_gid(struct in6_addr *addr)
{
	return (addr->s6_addr32[0] == htonl(0xfe800000)) && (addr->s6_addr32[1] == 0);
}

static int set_res_qp_ctx(struct hl_ib_qp *hlqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
			  struct hlib_ibv_modify_qp_req *modify_qp_req)
{
	struct hl_cni_res_conn_ctx_in res_conn_ctx_in = {};
	struct hl_ib_aux_ops *aux_ops;
	struct hl_ib_ucontext *hctx;
	struct hl_aux_dev *aux_dev;
	struct hl_ib_device *hdev;
	struct ib_device *ibdev;
	union ib_gid *dgid;
	struct ib_qp *ibqp;
	u32 hl_port;
	int rc;

	ibqp = &hlqp->ibqp;
	ibdev = ibqp->device;
	hdev = to_hl_ib_dev(ibdev);
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	dgid = &qp_attr->ah_attr.grh.dgid;
	hctx = hlqp->hctx;

	rc = ib_to_hl_port_num(hdev, ibqp->port, &hl_port);
	if (rc) {
		hl_ibdev_dbg(ibdev, "invalid IB port %u\n, IB QP %u", ibqp->port, ibqp->qp_num);
		return rc;
	}

	/* If the ports are internal, anyway we don't use the dst_mac_addr when configuring the QPC.
	 * Instead we use the broadcast MAC for dest MAC. Refer the ASIC specific set_res_qp_ctx
	 */
	if (hdev->ext_ports_mask & BIT(hl_port)) {
		copy_mac_reverse(hlqp->dst_mac_addr, qp_attr->ah_attr.roce.dmac);
		memcpy(res_conn_ctx_in.dst_mac_addr, hlqp->dst_mac_addr, ETH_ALEN);
	}

	if ((hdev->ext_ports_mask & BIT(hl_port)) && !is_l2_gid((struct in6_addr *)dgid->raw)) {
		hlqp->dst_ip_addr = htonl(((struct in6_addr *)dgid->raw)->s6_addr32[3]);
		res_conn_ctx_in.dst_ip_addr = hlqp->dst_ip_addr;
	}

	res_conn_ctx_in.dst_conn_id = qp_attr->dest_qp_num;
	res_conn_ctx_in.port = hl_port;
	res_conn_ctx_in.conn_id = hlqp->qp_id;
	res_conn_ctx_in.cq_number = get_res_cq_number(hlqp);
	res_conn_ctx_in.local_key = modify_qp_req->local_key;
	res_conn_ctx_in.priority = modify_qp_req->priority;
	res_conn_ctx_in.loopback = modify_qp_req->loopback;
	res_conn_ctx_in.wq_peer_size = hlqp->max_send_wr;
	res_conn_ctx_in.rdv = hlqp->wq_type == QPC_REQ_WQ_TYPE_RDV_READ ||
			      hlqp->wq_type == QPC_REQ_WQ_TYPE_RDV_WRITE;
	res_conn_ctx_in.conn_peer = hlqp->qp_id;
	res_conn_ctx_in.sack_en = modify_qp_req->sack_en;
	res_conn_ctx_in.wq_peer_granularity = hlqp->wq_granularity;
	res_conn_ctx_in.encap_en = modify_qp_req->encap_en;
	res_conn_ctx_in.encap_id = modify_qp_req->encap_num;

	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_SET_RES_CONN_CTX, &res_conn_ctx_in,
			       NULL);
	if (rc) {
		hl_ibdev_dbg(ibdev, "Failed to config RTR, QP %d, port %d\n",
			  hlqp->qp_id, hl_port);
		return rc;
	}

	hlqp->qp_state = IB_QPS_RTR;
	hlqp->dest_qp_num = qp_attr->dest_qp_num;

	if (qp_attr->path_mtu == HL_IB_MTU_8192)
		hlqp->mtu = 8192;
	else
		hlqp->mtu = ib_mtu_enum_to_int(qp_attr->path_mtu);

	return 0;
}

static int set_req_qp_ctx(struct hl_ib_qp *hlqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
			  struct hlib_ibv_modify_qp_req *modify_qp_req,
			  struct hlib_ibv_modify_qp_resp *modify_qp_resp)
{
	struct hl_cni_req_conn_ctx_out req_conn_ctx_out = {};
	struct hl_cni_req_conn_ctx_in req_conn_ctx_in = {};
	struct hl_ib_port_attr port_attr = {};
	struct hl_ib_aux_ops *aux_ops;
	struct hl_ib_ucontext *hctx;
	struct hl_aux_dev *aux_dev;
	struct hl_ib_device *hdev;
	struct ib_device *ibdev;
	struct ib_qp *ibqp;
	u32 hl_port;
	int rc;

	ibqp = &hlqp->ibqp;
	ibdev = ibqp->device;
	hdev = to_hl_ib_dev(ibdev);
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	hctx = hlqp->hctx;

	rc = ib_to_hl_port_num(hdev, ibqp->port, &hl_port);
	if (rc) {
		hl_ibdev_dbg(ibdev, "invalid IB port %u, IB QP %u\n", ibqp->port, ibqp->qp_num);
		return rc;
	}

	req_conn_ctx_in.port = hl_port;
	req_conn_ctx_in.conn_id = hlqp->qp_id;
	req_conn_ctx_in.dst_conn_id = hlqp->dest_qp_num;
	req_conn_ctx_in.wq_type = hlqp->wq_type;
	req_conn_ctx_in.wq_size = hlqp->max_send_wr;
	req_conn_ctx_in.cq_number = get_req_cq_number(hlqp);
	req_conn_ctx_in.remote_key = modify_qp_req->remote_key;
	req_conn_ctx_in.priority = modify_qp_req->priority;
	req_conn_ctx_in.timer_granularity = qp_attr->timeout;

	if (modify_qp_req->dest_wq_size) {
		if (!is_power_of_2(modify_qp_req->dest_wq_size)) {
			hl_ibdev_dbg(ibdev, "dest_wq_size :%d is not power of 2, QP %d, port %d\n",
				  modify_qp_req->dest_wq_size, hlqp->qp_id, hl_port);
			return -EINVAL;
		}
		req_conn_ctx_in.wq_remote_log_size = ilog2(modify_qp_req->dest_wq_size);
	}

	req_conn_ctx_in.congestion_en = modify_qp_req->congestion_en;
	req_conn_ctx_in.congestion_wnd = modify_qp_req->congestion_wnd;
	req_conn_ctx_in.loopback = modify_qp_req->loopback;
	req_conn_ctx_in.coll_lag_idx = modify_qp_req->coll_lag_idx;
	req_conn_ctx_in.coll_last_in_lag = modify_qp_req->coll_last_in_lag;
	req_conn_ctx_in.compression_en = modify_qp_req->compression_en;
	req_conn_ctx_in.sack_en = modify_qp_req->sack_en;
	req_conn_ctx_in.encap_en = modify_qp_req->encap_en;
	req_conn_ctx_in.encap_id = modify_qp_req->encap_num;
	req_conn_ctx_in.swq_granularity = hlqp->wq_granularity;
	req_conn_ctx_in.mtu = hlqp->mtu;

	/* If the ports are internal, anyway we don't use the dst_mac_addr when configuring the QPC.
	 * Instead we use the broadcast MAC for dest MAC. Refer the ASIC specific set_req_qp_ctx
	 */
	if (hdev->ext_ports_mask & BIT(hl_port)) {
		memcpy(req_conn_ctx_in.dst_mac_addr, hlqp->dst_mac_addr, ETH_ALEN);
		req_conn_ctx_in.dst_ip_addr = hlqp->dst_ip_addr;
	}

	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_SET_REQ_CONN_CTX, &req_conn_ctx_in,
			       &req_conn_ctx_out);
	if (rc) {
		hl_ibdev_dbg(ibdev, "Failed to config RTS, QP %d, port %d\n",
			  hlqp->qp_id, hl_port);
		return rc;
	}

	aux_ops->query_port(aux_dev, hl_port, &port_attr);

	modify_qp_resp->swq_mem_handle = req_conn_ctx_out.swq_mem_handle;

	modify_qp_resp->swq_mem_size = PAGE_ALIGN(req_conn_ctx_in.wq_size * port_attr.swqe_size);
	modify_qp_resp->rwq_mem_handle = req_conn_ctx_out.rwq_mem_handle;
	modify_qp_resp->rwq_mem_size = PAGE_ALIGN(req_conn_ctx_in.wq_size * port_attr.rwqe_size);

	hlqp->qp_state = IB_QPS_RTS;

	return 0;
}

static int reset_qp(struct hl_ib_qp *hlqp)
{
	struct ib_device *ibdev;
	struct ib_qp *ibqp;
	int rc;

	ibqp = &hlqp->ibqp;
	ibdev = ibqp->device;

	rc = __destroy_qp(hlqp);
	if (rc) {
		hl_ibdev_dbg(ibdev, "Failed to reset QP %d, port %d\n", hlqp->qp_id, ibqp->port);
		return rc;
	}

	hlqp->qp_state = IB_QPS_RESET;

	return 0;
}

static int hl_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
			   struct ib_udata *udata)
{
	struct hlib_ibv_modify_qp_resp modify_qp_resp = {};
	struct hlib_ibv_modify_qp_req modify_qp_req = {};
	struct hl_ib_ucontext *hctx;
	struct hl_ib_device *hdev;
	struct ib_device *ibdev;
	struct hl_ib_qp *hlqp;
	u32 ib_port, hl_port;
	int rc;

	ibdev = ibqp->device;
	hdev = to_hl_ib_dev(ibdev);
	hlqp = to_hl_ib_qp(ibqp);
	hctx = hlqp->hctx;

	rc = verify_modify_qp(hlqp, qp_attr, qp_attr_mask);
	if (rc)
		return rc;

	ib_port = (qp_attr_mask & IB_QP_PORT) ? qp_attr->port_num : hlqp->ibqp.port;

	rc = ib_to_hl_port_num(hdev, ib_port, &hl_port);
	if (rc) {
		hl_ibdev_dbg(ibdev, "invalid IB port %u\n", ib_port);
		return rc;
	}

	if (!(hctx->ports_mask & BIT(hl_port))) {
		hl_ibdev_dbg(ibdev, "port %d is not part of the context's ports mask 0x%llx\n",
					hl_port, hctx->ports_mask);
		return -EINVAL;
	}

	rc = ib_copy_from_udata(&modify_qp_req, udata, min(sizeof(modify_qp_req), udata->inlen));
	if (rc) {
		hl_ibdev_dbg(ibdev, "Failed to copy from modify QP udata\n");
		return rc;
	}

	if ((qp_attr_mask & IB_QP_STATE) && (qp_attr->qp_state == IB_QPS_RESET)) {
		/* QP state transition IB_QPS_RESET ==> IB_QPS_RESET is NoOps */
		if (hlqp->qp_state != IB_QPS_RESET) {
			rc = reset_qp(hlqp);
			if (rc)
				return rc;
		}
	}

	if ((qp_attr_mask & IB_QP_STATE) && (qp_attr->qp_state == IB_QPS_INIT)) {
		/* QP state transition IB_QPS_INIT ==> IB_QPS_INIT. Destroy old QP. */
		if (hlqp->qp_state == IB_QPS_INIT) {
			rc = reset_qp(hlqp);
			if (rc)
				return rc;
		}

		rc = alloc_qp(hlqp, qp_attr, qp_attr_mask, &modify_qp_req, &modify_qp_resp);
		if (rc)
			return rc;
	}

	if ((qp_attr_mask & IB_QP_STATE) && (qp_attr->qp_state == IB_QPS_RTR)) {
		rc = set_res_qp_ctx(hlqp, qp_attr, qp_attr_mask, &modify_qp_req);
		if (rc)
			goto err_reset_qp;
	}

	if ((qp_attr_mask & IB_QP_STATE) && (qp_attr->qp_state == IB_QPS_RTS)) {
		rc = set_req_qp_ctx(hlqp, qp_attr, qp_attr_mask, &modify_qp_req, &modify_qp_resp);
		if (rc)
			goto err_reset_qp;
	}

	rc = ib_copy_to_udata(udata, &modify_qp_resp, min(sizeof(modify_qp_resp), udata->outlen));
	if (rc) {
		hl_ibdev_dbg(ibdev, "Failed to copy to QP modify udata\n");
		goto err_reset_qp;
	}

	return 0;

err_reset_qp:
	reset_qp(hlqp);

	return rc;
}

#ifdef _HAS_EX_RDMA_PORTS
static int hl_ib_query_gid(struct ib_device *ibdev, u32 port, int index, union ib_gid *gid)
#else
static int hl_ib_query_gid(struct ib_device *ibdev, u8 port, int index, union ib_gid *gid)
#endif
{
	/* The IB core would query the GID for non-ROCE ports i.e. internal ports. Ultimately this
	 * GID would be listed in the sysfs entry of each port. This is populated as 0xFF for now
	 * and will be replaced with the actual port's MAC address in subsequent patch.
	 */
	memset(gid->raw, 0xFF, sizeof(gid->raw));

	return 0;
}

#ifdef _HAS_EX_RDMA_PORTS
static int hl_ib_query_pkey(struct ib_device *ibdev, u32 port, u16 index, u16 *pkey)
#else
static int hl_ib_query_pkey(struct ib_device *ibdev, u8 port, u16 index, u16 *pkey)
#endif
{
	if (index > 0)
		return -EINVAL;

	*pkey = 0xffff;

	return 0;
}

static int hl_ib_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
			  struct ib_qp_init_attr *qp_init_attr)
{
	struct hl_ib_qp *hlqp;

	hlqp = to_hl_ib_qp(ibqp);

	memset(qp_attr, 0, sizeof(*qp_attr));
	memset(qp_init_attr, 0, sizeof(*qp_init_attr));

	qp_attr->qp_state = hlqp->qp_state;
	qp_attr->dest_qp_num = hlqp->dest_qp_num;
	qp_attr->port_num = ibqp->port;

	qp_init_attr->cap.max_send_wr = hlqp->max_send_wr;
	qp_init_attr->cap.max_recv_wr = hlqp->max_recv_wr;

	/* We need to populate these 2 params to pass query_qp pyverbs test */
	qp_init_attr->cap.max_send_sge = HL_IB_MAX_SEND_SGE;
	qp_init_attr->cap.max_recv_sge = HL_IB_MAX_RECV_SGE;

	/* TODO: SW-151494 - both xrcd and qp_access_flags are not used by our flows, so we may
	 * override them in order to pass extra data for EQ events.
	 */
	qp_attr->qp_access_flags = (int)(uintptr_t)ibqp->xrcd;

	return 0;
}

#ifdef _HAS_REG_MR_ATTR
static struct ib_mr *hl_ib_reg_mr(struct ib_pd *ibpd, struct ib_mr_init_attr *attr,
				  struct ib_udata *udata)
{
	return ERR_PTR(-EOPNOTSUPP);
}
#else
static struct ib_mr *hl_ib_reg_mr(struct ib_pd *ibpd, u64 start, u64 length, u64 virt_addr,
				  int access_flags, struct ib_udata *udata)
{
	return ERR_PTR(-EOPNOTSUPP);
}
#endif

#ifdef _HAS_REG_USER_MR_DMABUF
static struct ib_mr *hl_ib_reg_user_mr_dmabuf(struct ib_pd *ibpd, u64 start, u64 length,
					      u64 virt_addr, int fd, int access_flags,
					      struct ib_udata *udata)
{
	return ERR_PTR(-EOPNOTSUPP);
}
#endif

/* The GID table is created and maintained by the kernel rdma cache module based on the gid_tbl_len
 * provided. add_gid callback would be called whenever a new GID entry is added to the GID table. We
 * get the gid details as part of the attr param. We can store that for our reference.
 */
static int hl_ib_add_gid(const struct ib_gid_attr *attr, void **context)
{
	struct hl_ib_device *hdev = to_hl_ib_dev(attr->device);
	struct hl_aux_dev *aux_dev = hdev->aux_dev;
	struct hl_ib_aux_ops *aux_ops;
	struct hl_ib_port *ib_port;
	union hl_ib_sockaddr {
		struct sockaddr_in saddr_in;
		struct sockaddr_in6 saddr_in6;
	} sa;
	u32 port, ip_addr;
	int rc;

	rc = ib_to_hl_port_num(hdev, attr->port_num, &port);
	if (rc) {
		hl_ibdev_dbg(&hdev->ibdev, "invalid IB port %u\n", attr->port_num);
		return rc;
	}

	ib_port = &hdev->ib_port[port];
	aux_ops = aux_dev->aux_ops;

	memcpy(ib_port->gids[attr->index].gid.raw, attr->gid.raw, sizeof(attr->gid));
	ib_port->gids[attr->index].gid_type = attr->gid_type;

	if (ipv6_addr_v4mapped((struct in6_addr *)&attr->gid)) {
		rdma_gid2ip((struct sockaddr *)&sa, &ib_port->gids[attr->index].gid);
		ip_addr = be32_to_cpu(sa.saddr_in.sin_addr.s_addr);
		aux_ops->set_ip_addr_encap(aux_dev, ip_addr, port);
	}

	return 0;
}

static int hl_ib_del_gid(const struct ib_gid_attr *attr, void **context)
{
	struct hl_ib_device *hdev = to_hl_ib_dev(attr->device);
	struct hl_ib_port *ib_port;

	if (attr->port_num > hdev->max_num_of_ports) {
		hl_ibdev_dbg(&hdev->ibdev, "%s, port num: %d out of bounds\n",
				__func__, attr->port_num);
		return -EINVAL;
	}

	ib_port = &hdev->ib_port[attr->port_num - 1];

	/* validate the params */
	if (attr->index >= HL_IB_MAX_PORT_GIDS) {
		hl_ibdev_dbg(&hdev->ibdev, "%s, GID index: %d out of bounds\n",
				__func__, attr->index);
		return -EINVAL;
	}

	memset(ib_port->gids[attr->index].gid.raw, 0, sizeof(attr->gid));
	ib_port->gids[attr->index].gid_type = 0;

	return 0;
}

static int hl_ib_fill_data(struct sk_buff *msg, struct ib_qp *ibqp, bool req)
{
	char *data_buf, *str_buf, *ptr, *ptr2, *full_name, *name, *val, *prefix;
	struct hl_ib_dump_qp_attr attr = {};
	struct hl_ib_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;
	struct hl_ib_device *hdev;
	struct ib_device *ibdev;
	struct hl_ib_qp *hlqp;
	int rc = 0, len, i;
	u32 hl_port;

	ibdev = ibqp->device;
	hlqp = to_hl_ib_qp(ibqp);
	hdev = to_hl_ib_dev(ibdev);
	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;

	rc = ib_to_hl_port_num(hdev, ibqp->port, &hl_port);
	if (rc) {
		hl_ibdev_dbg(ibdev, "invalid IB port %u\n", ibqp->port);
		return rc;
	}

	data_buf = kzalloc(HL_IB_DUMP_QP_SZ, GFP_KERNEL);
	if (!data_buf)
		return -ENOMEM;

	str_buf = kcalloc(2, NAME_MAX, GFP_KERNEL);
	if (!str_buf) {
		rc = -ENOMEM;
		goto free_data_buf;
	}

	prefix = req ? "req_" : "res_";

	full_name = str_buf;
	memcpy(full_name, prefix, strlen(prefix));
	name = full_name + strlen(prefix);

	val = full_name + NAME_MAX;

	attr.port = hl_port;
	attr.qpn = hlqp->qp_id;
	attr.req = req;
	attr.full = true;
	attr.force = true;
	attr.exts = true;

	rc = aux_ops->dump_qp(aux_dev, &attr, data_buf, HL_IB_DUMP_QP_SZ);
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed to dump QP %d, port %d\n", attr.qpn, attr.port);
		rc = -ENODATA;
		goto free_str_buf;
	}

	/* skip first line */
	ptr = strchr(data_buf, '\n');
	ptr++;

	while (1) {
		ptr2 = strchr(ptr, ':');
		if (!ptr2)
			break;

		/* extract attribute name */
		len = ptr2 - ptr;
		memcpy(name, ptr, len);
		name[len] = '\0';

		/* to lowercase and no spaces */
		for (i = 0; i < len; i++)
			if (isspace(name[i]))
				name[i] = '_';
			else
				name[i] = tolower(name[i]);

		/* skip ':' and the following space */
		ptr = ptr2 + 2;

		ptr2 = strchr(ptr, '\n');

		/* extract attribute value */
		len = ptr2 - ptr;
		memcpy(val, ptr, len);
		val[len] = '\0';

		if (rdma_nl_put_driver_string(msg, full_name, val)) {
			rc = -EMSGSIZE;
			goto free_str_buf;
		}

		/* move to next line */
		ptr = ptr2 + 1;
	}

free_str_buf:
	kfree(str_buf);
free_data_buf:
	kfree(data_buf);

	return rc;
}

static int hl_ib_fill_res_qp_entry(struct sk_buff *msg, struct ib_qp *ibqp)
{
	struct ib_device *ibdev = ibqp->device;
	struct nlattr *table_attr;
	int rc;

	table_attr = nla_nest_start(msg, RDMA_NLDEV_ATTR_DRIVER);
	if (!table_attr)
		return -EMSGSIZE;

	rc = hl_ib_fill_data(msg, ibqp, true);
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed get REQ QP %d data, port %d\n", ibqp->qp_num,
			     ibqp->port);
		rc = -ENODATA;
		goto free_table;
	}

	rc = hl_ib_fill_data(msg, ibqp, false);
	if (rc) {
		hl_ibdev_dbg(ibdev, "failed get RES QP %d data, port %d\n", ibqp->qp_num,
			     ibqp->port);
		rc = -ENODATA;
		goto free_table;
	}

	nla_nest_end(msg, table_attr);

	return 0;

free_table:
	nla_nest_cancel(msg, table_attr);
	return rc;
}

#ifndef _HAS_RES_QP_ENTRY
static int hl_ib_fill_res_entry(struct sk_buff *msg, struct rdma_restrack_entry *res)
{
	if (res->type == RDMA_RESTRACK_QP) {
		struct ib_qp *ibqp = container_of(res, struct ib_qp, res);

		return hl_ib_fill_res_qp_entry(msg, ibqp);
	}

	return 0;
}
#endif

void hl_ib_eqe_null_work(struct hl_aux_dev *aux_dev, u32 port)
{

}

void hl_ib_eqe_work_schd(struct hl_aux_dev *aux_dev, u32 port)
{
	struct hl_ib_device *hdev = aux_dev->priv;
	struct hl_ib_port *ib_port = &hdev->ib_port[port];

	if (!ib_port->open)
		return;

	/* Use this atomic to prevent a race - a thread handling received EQE in hl core enters here
	 * to wake up the EQ thread while another thread is executing hl_ib_port_fini which releases
	 * it. In such case the first thread might access a released resource.
	 */
	if (atomic_cmpxchg(&ib_port->eq_lock, 0, 1))
		return;

	complete(&ib_port->eq_comp);

	atomic_set(&ib_port->eq_lock, 0);
}

static bool hl_ib_dispatch_event_qp(struct hl_ib_device *hdev, struct hl_ib_ucontext *hctx,
				    u32 port, u32 qpn, enum ib_event_type event_type,
				    u64 extra_data)
{
	struct ib_event ibev = {};
	struct hl_ib_qp *hlqp;
	bool found_qp = false;
	unsigned long id = 0;
	struct ib_qp *ibqp;
	u32 qp_port;
	int rc;

	xa_lock(&hctx->qp_xarray);
	xa_for_each(&hctx->qp_xarray, id, hlqp) {
		ibqp = &hlqp->ibqp;

		rc = ib_to_hl_port_num(hdev, ibqp->port, &qp_port);
		if (rc) {
			hl_ibdev_dbg(&hdev->ibdev, "invalid IB port %u, IB QP %u\n",
					ibqp->port, ibqp->qp_num);
			continue;
		}

		/* We need to iterate over all QPs that are allocated
		 * under this CTX as we need to perform backward mapping
		 * of QP ID we have in HL to the corresponding IB QP struct
		 */
		if (hlqp->qp_id == qpn && qp_port == port) {
			/* TODO: SW-151494 - xrcd is not used by our flows, so we may override it
			 * in order to pass extra data for EQ events. This is not part of the event,
			 * but rather part of the qp structure. Meaning an additional QP event
			 * will override the value stored in xrcd. Since this is an error case, the
			 * QP should not receive anymore events.
			 */
			ibqp->xrcd = (void *)extra_data;
			ibev.event = event_type;
			ibev.element.qp = ibqp;

			ibqp->event_handler(&ibev, ibqp->qp_context);

			/* We should mark the QP as in error state */
			hlqp->qp_state = IB_QPS_ERR;

			found_qp = true;
			break;
		}
	}

	xa_unlock(&hctx->qp_xarray);

	return found_qp;
}

void hl_ib_eqe_handler(struct hl_ib_port *ib_port)
{
	struct hl_ib_ucontext *hctx = ib_port->hctx;
	struct hl_cni_eq_poll_out eq_poll_out = {};
	struct hl_ib_device *hdev = ib_port->hdev;
	struct hl_cni_eq_poll_in eq_poll_in = {};
	enum ib_event_type event_type;
	struct hl_ib_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;
	struct ib_event ibev = {};
	u32 port = ib_port->port;
	bool found_qp = false;
	struct ib_cq *ibcq;
	int rc;

	aux_dev = hdev->aux_dev;
	aux_ops = aux_dev->aux_ops;
	eq_poll_in.port = port;

	rc = aux_ops->cmd_ctrl(aux_dev, hctx->cn_ctx, HL_CNI_OP_EQ_POLL, &eq_poll_in, &eq_poll_out);
	if (rc) {
		hl_ibdev_err(&hdev->ibdev, "port %d - EQ poll failed %d\n", port, rc);
		return;
	}

	switch (eq_poll_out.status) {
	case HL_CNI_EQ_POLL_STATUS_SUCCESS:

		ibev.device = &hdev->ibdev;

		switch (eq_poll_out.ev_type) {
		case HL_CNI_EQ_EVENT_TYPE_CQ_ERR:
			hl_ibdev_dbg(&hdev->ibdev, "port %d cq %d - received CQ ERR event\n", port,
				     eq_poll_out.idx);

			xa_lock(&ib_port->hl_ibcq_tbl);
			ibcq = xa_load(&ib_port->hl_ibcq_tbl, eq_poll_out.idx);

			if (ibcq) {
				ibev.element.cq = ibcq;
				ibev.event = IB_EVENT_CQ_ERR;

				ibcq->event_handler(&ibev, ibcq->cq_context);
			} else {
				hl_ibdev_err(&hdev->ibdev,
					     "port %d cq %d - received CQ ERR event, but CQ is not allocated\n",
					     port, eq_poll_out.idx);
			}

			xa_unlock(&ib_port->hl_ibcq_tbl);
			break;
		case HL_CNI_EQ_EVENT_TYPE_QP_ERR:
			/* In IBv we can't pass the syndrome value to user space via IB events
			 * mechanism, and hence we will print it instead.
			 */
			hl_ibdev_err(&hdev->ibdev, "port %d qp %d - received QP ERR syndrome: %s\n",
				     port, eq_poll_out.idx,
				     aux_ops->qp_syndrome_to_str(aux_dev, eq_poll_out.ev_data));

			/* TODO: SW-151494 - is QP fatal an adequate event for QP RES? */
			event_type = eq_poll_out.is_req ? IB_EVENT_QP_REQ_ERR : IB_EVENT_QP_FATAL;

			found_qp = hl_ib_dispatch_event_qp(hdev, hctx, port, eq_poll_out.idx,
							   event_type, eq_poll_out.ev_data);

			if (!found_qp)
				hl_ibdev_err(&hdev->ibdev,
					     "port %d qp %d - received QP ERR event, but QP is not allocated\n",
					     port, eq_poll_out.idx);

			break;
		case HL_CNI_EQ_EVENT_TYPE_DB_FIFO_ERR:
			hl_ibdev_err(&hdev->ibdev, "port %d user fifo %d error\n", port,
				     eq_poll_out.idx);
			/* TODO: SW-151494 - change to vendor specific IB event */
			ibev.event = IB_EVENT_DEVICE_FATAL;
			/* TODO: SW-151494 - remove additional DB FIFO ID info from port_num */
			ibev.element.port_num = (port & HL_IB_EQ_PORT_FIELD_MASK) |
						(eq_poll_out.idx << HL_IB_EQ_PORT_FIELD_SIZE);
			ib_dispatch_event(&ibev);
			break;
		case HL_CNI_EQ_EVENT_TYPE_CCQ:
			hl_ibdev_dbg(&hdev->ibdev, "Port %u: got completion on congestion CQ %u\n",
				     port, eq_poll_out.idx);
			/* TODO: SW-151494 - change to vendor specific IB event */
			ibev.event = IB_EVENT_SM_CHANGE;
			ibev.element.port_num = (port & HL_IB_EQ_PORT_FIELD_MASK) |
						(eq_poll_out.idx << HL_IB_EQ_PORT_FIELD_SIZE);
			ib_dispatch_event(&ibev);
			break;
		case HL_CNI_EQ_EVENT_TYPE_WTD_SECURITY_ERR:
			hl_ibdev_dbg(&hdev->ibdev, "Port %u: got WTD security error on QP %u\n",
				     port, eq_poll_out.idx);

			/* TODO: SW-151494 - change to vendor specific IB event */
			found_qp = hl_ib_dispatch_event_qp(hdev, hctx, port, eq_poll_out.idx,
							   IB_EVENT_PATH_MIG, 0);

			if (!found_qp)
				hl_ibdev_err(&hdev->ibdev,
					     "port %d qp %d - received WTD security event, but QP is not allocated\n",
					     port, eq_poll_out.idx);
			break;
		case HL_CNI_EQ_EVENT_TYPE_NUMERICAL_ERR:
			hl_ibdev_dbg(&hdev->ibdev, "Port %u: got numerical error on QP %u\n",
				     port, eq_poll_out.idx);

			/* TODO: SW-151494 - change to vendor specific IB event */
			found_qp = hl_ib_dispatch_event_qp(hdev, hctx, port, eq_poll_out.idx,
							   IB_EVENT_PATH_MIG_ERR, 0);

			if (!found_qp)
				hl_ibdev_err(&hdev->ibdev,
					     "port %d qp %d - received numerical error event, but QP is not allocated\n",
					     port, eq_poll_out.idx);
			break;
		case HL_CNI_EQ_EVENT_TYPE_LINK_STATUS:
			hl_ibdev_dbg(&hdev->ibdev, "port %d link %s\n", port,
				     eq_poll_out.ev_data ? "up" : "down");

			ibev.event = eq_poll_out.ev_data ?
				     IB_EVENT_PORT_ACTIVE : IB_EVENT_PORT_ERR;
			ibev.element.port_num = port;
			ib_dispatch_event(&ibev);
			break;
		case HL_CNI_EQ_EVENT_TYPE_QP_ALIGN_COUNTERS:
			hl_ibdev_dbg(&hdev->ibdev, "port %d qp %d - Align QP counters on QP timeout\n",
					port, eq_poll_out.idx);

			/* TODO: SW-151494 - change to vendor specific IB event */
			found_qp = hl_ib_dispatch_event_qp(hdev, hctx, port, eq_poll_out.idx,
							   IB_EVENT_QP_LAST_WQE_REACHED, 0);

			if (!found_qp)
				hl_ibdev_err(&hdev->ibdev,
					     "port %d qp %d - received Align QP counters event, but QP is not allocated\n",
					     port, eq_poll_out.idx);
			break;
		default:
			hl_ibdev_dbg(&hdev->ibdev, "port %d EQ poll success, event %d\n", port,
				     eq_poll_out.ev_type);
			break;
		}
		break;
	default:
		break;
	}
}

const struct ib_device_ops hl_ib_dev_ops = {
#ifdef _HAS_DEVICE_OPS_INFO
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_HLIB,
	.uverbs_abi_ver = HL_IB_UVERBS_ABI_VERSION,
#endif

	.add_gid = hl_ib_add_gid,
	.del_gid = hl_ib_del_gid,
#ifdef _HAS_IB_DEVICE_STATS
	.alloc_hw_port_stats = hl_ib_alloc_hw_port_stats,
	.alloc_hw_device_stats = hl_ib_alloc_hw_device_stats,
#else
	.alloc_hw_stats = hl_ib_alloc_hw_stats,
#endif
	.alloc_pd = hl_ib_alloc_pd,
	.alloc_ucontext = hl_ib_alloc_ucontext,
	.create_cq = hl_ib_create_cq,
	.create_qp = hl_ib_create_qp,
	.dealloc_pd = hl_ib_dealloc_pd,
	.dealloc_ucontext = hl_ib_dealloc_ucontext,
	.dereg_mr = hl_ib_dereg_mr,
	.destroy_cq = hl_ib_destroy_cq,
	.destroy_qp = hl_ib_destroy_qp,
#ifdef _HAS_RES_QP_ENTRY
	.fill_res_qp_entry = hl_ib_fill_res_qp_entry,
#else
	.fill_res_entry = hl_ib_fill_res_entry,
#endif
	.get_hw_stats = hl_ib_get_hw_stats,
	.get_dev_fw_str = hl_ib_get_dev_fw_str,
	.get_link_layer = hl_ib_port_link_layer,
	.get_port_immutable = hl_ib_get_port_immutable,
	.mmap = hl_ib_mmap,
#ifdef _HAS_MMAP_FREE
	.mmap_free = hl_ib_mmap_free,
#endif
	.modify_qp = hl_ib_modify_qp,
	.query_device = hl_ib_query_device,
	.query_gid = hl_ib_query_gid,
	.query_pkey = hl_ib_query_pkey,
	.query_port = hl_ib_query_port,
	.query_qp = hl_ib_query_qp,
	.reg_user_mr = hl_ib_reg_mr,
#ifdef _HAS_REG_USER_MR_DMABUF
	.reg_user_mr_dmabuf = hl_ib_reg_user_mr_dmabuf,
#endif

#ifdef _HAS_IB_CQ_SIZE
	INIT_RDMA_OBJ_SIZE(ib_cq, hl_ib_cq, ibcq),
#endif
	INIT_RDMA_OBJ_SIZE(ib_pd, hl_ib_pd, ibpd),
#ifdef _HAS_IB_QP_SIZE
	INIT_RDMA_OBJ_SIZE(ib_qp, hl_ib_qp, ibqp),
#endif
	INIT_RDMA_OBJ_SIZE(ib_ucontext, hl_ib_ucontext, ibucontext),
};
