// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#include <linux/vmalloc.h>
#include "hbl_cn.h"
#include <trace/events/habanalabs_cn.h>

static int hbl_cn_map_vmalloc_range(struct hbl_cn_ctx *ctx, u64 vmalloc_va, u64 device_va,
				    u64 size)
{
	struct hbl_cn_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;

	aux_dev = ctx->hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	return aux_ops->vm_dev_mmu_map(aux_dev, ctx->driver_vm_info.vm_handle, HBL_CN_MEM_TYPE_HOST,
				       vmalloc_va, device_va, size);
}

static void hbl_cn_unmap_vmalloc_range(struct hbl_cn_ctx *ctx, u64 device_va, u64 size)
{
	struct hbl_cn_aux_ops *aux_ops;
	struct hbl_aux_dev *aux_dev;

	aux_dev = ctx->hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	aux_ops->vm_dev_mmu_unmap(aux_dev, ctx->driver_vm_info.vm_handle, device_va, size);
}

static int alloc_mem(struct hbl_cn_mem_buf *buf, gfp_t gfp, struct hbl_cn_mem_data *mem_data)
{
	u64 device_addr, size = mem_data->size;
	struct hbl_cn_ctx *ctx = buf->ctx;
	u32 mem_id = mem_data->mem_id;
	struct hbl_cn_device *hdev;
	void *p = NULL;

	hdev = ctx->hdev;

	switch (mem_id) {
	case HBL_CN_DRV_MEM_HOST_DMA_COHERENT:
		if (get_order(size) > MAX_PAGE_ORDER) {
			dev_err(hdev->dev, "memory size 0x%llx must be less than 0x%lx\n", size,
				1UL << (PAGE_SHIFT + MAX_PAGE_ORDER));
			return -ENOMEM;
		}

		p = hbl_cn_dma_alloc_coherent(hdev, size, &buf->bus_address, GFP_USER | __GFP_ZERO);
		if (!p) {
			dev_err(hdev->dev,
				"failed to allocate 0x%llx of dma memory for the NIC\n", size);
			return -ENOMEM;
		}

		break;
	case HBL_CN_DRV_MEM_HOST_VIRTUAL:
		p = vmalloc_user(size);
		if (!p) {
			dev_err(hdev->dev, "failed to allocate vmalloc memory, size 0x%llx\n",
				size);
			return -ENOMEM;
		}

		break;
	case HBL_CN_DRV_MEM_HOST_MAP_ONLY:
		p = mem_data->in.host_map_data.kernel_address;
		buf->bus_address = mem_data->in.host_map_data.bus_address;
		break;
	case HBL_CN_DRV_MEM_DEVICE:
		if (!hdev->wq_arrays_pool_enable) {
			dev_err(hdev->dev, "No WQ arrays pool support for device memory\n");
			return -EOPNOTSUPP;
		}

		device_addr = (u64)gen_pool_alloc(hdev->wq_arrays_pool, size);
		if (!device_addr) {
			dev_err(hdev->dev, "Failed to allocate device memory, size 0x%llx\n", size);
			return -ENOMEM;
		}

		buf->device_addr = device_addr;
		break;
	default:
		dev_err(hdev->dev, "Invalid mem_id %d\n", mem_id);
		return -EINVAL;
	}

	buf->kernel_address = p;
	buf->mappable_size = size;

	return 0;
}

static int map_mem(struct hbl_cn_mem_buf *buf, struct hbl_cn_mem_data *mem_data)
{
	struct hbl_cn_ctx *ctx = buf->ctx;
	struct hbl_cn_device *hdev;
	int rc;

	hdev = ctx->hdev;

	if (mem_data->mem_id == HBL_CN_DRV_MEM_HOST_DMA_COHERENT) {
		dev_err(hdev->dev, "Mapping DMA coherent host memory is not yet supported\n");
		return -EPERM;
	}

	rc = hbl_cn_map_vmalloc_range(ctx, (u64)buf->kernel_address, mem_data->device_va,
				      buf->mappable_size);
	if (rc)
		return rc;

	buf->device_va = mem_data->device_va;

	return 0;
}

static void mem_do_release(struct hbl_cn_device *hdev, struct hbl_cn_mem_buf *buf)
{
	struct hbl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	if (buf->mem_id == HBL_CN_DRV_MEM_HOST_DMA_COHERENT)
		asic_funcs->dma_free_coherent(hdev, buf->mappable_size, buf->kernel_address,
					      buf->bus_address);
	else if (buf->mem_id == HBL_CN_DRV_MEM_HOST_VIRTUAL)
		vfree(buf->kernel_address);
	else if (buf->mem_id == HBL_CN_DRV_MEM_DEVICE)
		gen_pool_free(hdev->wq_arrays_pool, buf->device_addr, buf->mappable_size);
}

static int __cn_mem_buf_alloc(struct hbl_cn_mem_buf *buf, gfp_t gfp,
			      struct hbl_cn_mem_data *mem_data)
{
	struct hbl_cn_ctx *ctx = buf->ctx;
	struct hbl_cn_device *hdev;
	int rc;

	hdev = ctx->hdev;

	if (mem_data->mem_id != HBL_CN_DRV_MEM_DEVICE)
		mem_data->size = PAGE_ALIGN(mem_data->size);

	rc = alloc_mem(buf, gfp, mem_data);
	if (rc)
		return rc;

	if (mem_data->device_va) {
		mem_data->device_va = PAGE_ALIGN(mem_data->device_va);
		rc = map_mem(buf, mem_data);
		if (rc)
			goto release_mem;
	}

	return 0;

release_mem:
	mem_do_release(hdev, buf);
	return rc;
}

static struct hbl_cn_mem_buf *cn_mem_buf_alloc(struct hbl_cn_ctx *ctx, gfp_t gfp,
					       struct hbl_cn_mem_data *mem_data)
{
	struct xa_limit id_limit = XA_LIMIT(1, INT_MAX);
	struct hbl_cn_device *hdev = ctx->hdev;
	struct hbl_cn_mem_buf *buf;
	int rc;
	u32 id;

	buf = kzalloc(sizeof(*buf), gfp);
	if (!buf)
		return NULL;

	rc = xa_alloc(&hdev->mem_ids, &id, buf, id_limit, GFP_ATOMIC);
	if (rc) {
		dev_err(hdev->dev, "Failed to allocate xarray for a new buffer, rc=%d\n", rc);
		goto free_buf;
	}

	buf->ctx = ctx;
	buf->mem_id = mem_data->mem_id;

	buf->handle = (((u64)id | hdev->mmap_type_flag) << PAGE_SHIFT);
	kref_init(&buf->refcount);

	rc = __cn_mem_buf_alloc(buf, gfp, mem_data);
	if (rc)
		goto remove_xa;

	return buf;

remove_xa:
	xa_erase(&hdev->mem_ids, lower_32_bits(buf->handle >> PAGE_SHIFT));
free_buf:
	kfree(buf);
	return NULL;
}

static int cn_mem_alloc(struct hbl_cn_ctx *ctx, struct hbl_cn_mem_data *mem_data)
{
	struct hbl_cn_device *hdev = ctx->hdev;
	struct hbl_cn_mem_buf *buf;

	buf = cn_mem_buf_alloc(ctx, GFP_KERNEL, mem_data);
	if (!buf)
		return -ENOMEM;

	trace_habanalabs_cn_mem_alloc(hdev->dev, buf->mem_id, buf->handle, (u64)buf->kernel_address,
				      buf->bus_address, buf->device_va, buf->mappable_size);

	mem_data->handle = buf->handle;

	if (mem_data->mem_id == HBL_CN_DRV_MEM_HOST_DMA_COHERENT)
		mem_data->addr = (u64)buf->bus_address;
	else if (mem_data->mem_id == HBL_CN_DRV_MEM_HOST_VIRTUAL)
		mem_data->addr = (u64)buf->kernel_address;
	else if (mem_data->mem_id == HBL_CN_DRV_MEM_DEVICE)
		mem_data->addr = (u64)buf->device_addr;

	return 0;
}

int hbl_cn_mem_alloc(struct hbl_cn_ctx *ctx, struct hbl_cn_mem_data *mem_data)
{
	struct hbl_cn_device *hdev = ctx->hdev;
	int rc;

	switch (mem_data->mem_id) {
	case HBL_CN_DRV_MEM_HOST_DMA_COHERENT:
	case HBL_CN_DRV_MEM_HOST_VIRTUAL:
	case HBL_CN_DRV_MEM_HOST_MAP_ONLY:
	case HBL_CN_DRV_MEM_DEVICE:
		rc = cn_mem_alloc(ctx, mem_data);
		break;
	default:
		dev_dbg(hdev->dev, "Invalid mem_id %d\n", mem_data->mem_id);
		rc = -EINVAL;
		break;
	}

	return rc;
}

static void cn_mem_buf_destroy(struct hbl_cn_mem_buf *buf)
{
	trace_habanalabs_cn_mem_destroy(buf->ctx->hdev->dev, buf->mem_id, buf->handle,
					(u64)buf->kernel_address, buf->bus_address, buf->device_va,
					buf->mappable_size);

	if (buf->device_va)
		hbl_cn_unmap_vmalloc_range(buf->ctx, buf->device_va, buf->mappable_size);

	mem_do_release(buf->ctx->hdev, buf);

	kfree(buf);
}

int hbl_cn_mem_destroy(struct hbl_cn_device *hdev, u64 handle)
{
	struct hbl_cn_mem_buf *buf;
	int rc;

	buf = hbl_cn_mem_buf_get(hdev, handle);
	if (!buf) {
		dev_dbg(hdev->dev, "Memory destroy failed, no match for handle 0x%llx\n", handle);
		return -EINVAL;
	}

	rc = atomic_cmpxchg(&buf->is_destroyed, 0, 1);
	hbl_cn_mem_buf_put(buf);
	if (rc) {
		dev_dbg(hdev->dev, "Memory destroy failed, handle 0x%llx was already destroyed\n",
			handle);
		return -EINVAL;
	}

	rc = hbl_cn_mem_buf_put_handle(hdev, handle);
	if (rc < 0)
		return rc;

	if (rc == 0)
		dev_dbg(hdev->dev, "Handle 0x%llx is destroyed while still in use\n", handle);

	return 0;
}

static void cn_mem_buf_release(struct kref *kref)
{
	struct hbl_cn_mem_buf *buf = container_of(kref, struct hbl_cn_mem_buf, refcount);
	struct hbl_cn_device *hdev = buf->ctx->hdev;

	xa_erase(&hdev->mem_ids, lower_32_bits(buf->handle >> PAGE_SHIFT));

	cn_mem_buf_destroy(buf);
}

struct hbl_cn_mem_buf *hbl_cn_mem_buf_get(struct hbl_cn_device *hdev, u64 handle)
{
	struct hbl_cn_mem_buf *buf;

	xa_lock(&hdev->mem_ids);
	buf = xa_load(&hdev->mem_ids, lower_32_bits(handle >> PAGE_SHIFT));
	if (!buf) {
		xa_unlock(&hdev->mem_ids);
		dev_dbg(hdev->dev, "Buff get failed, no match to handle %#llx\n", handle);
		return NULL;
	}

	kref_get(&buf->refcount);
	xa_unlock(&hdev->mem_ids);

	return buf;
}

int hbl_cn_mem_buf_put(struct hbl_cn_mem_buf *buf)
{
	return kref_put(&buf->refcount, cn_mem_buf_release);
}

static void cn_mem_buf_remove_xa_locked(struct kref *kref)
{
	struct hbl_cn_mem_buf *buf = container_of(kref, struct hbl_cn_mem_buf, refcount);

	__xa_erase(&buf->ctx->hdev->mem_ids, lower_32_bits(buf->handle >> PAGE_SHIFT));
}

int hbl_cn_mem_buf_put_handle(struct hbl_cn_device *hdev, u64 handle)
{
	struct hbl_cn_mem_buf *buf;

	xa_lock(&hdev->mem_ids);
	buf = xa_load(&hdev->mem_ids, lower_32_bits(handle >> PAGE_SHIFT));
	if (!buf) {
		xa_unlock(&hdev->mem_ids);
		dev_dbg(hdev->dev, "Buff put failed, no match to handle %#llx\n", handle);
		return -EINVAL;
	}

	if (kref_put(&buf->refcount, cn_mem_buf_remove_xa_locked)) {
		xa_unlock(&hdev->mem_ids);
		cn_mem_buf_destroy(buf);
		return 1;
	}

	xa_unlock(&hdev->mem_ids);
	return 0;
}

void hbl_cn_mem_init(struct hbl_cn_device *hdev)
{
	xa_init_flags(&hdev->mem_ids, XA_FLAGS_ALLOC);
}

void hbl_cn_mem_fini(struct hbl_cn_device *hdev)
{
	struct xarray *mem_ids;

	mem_ids = &hdev->mem_ids;

	if (!xa_empty(mem_ids))
		dev_crit(hdev->dev, "memory manager is destroyed while not empty!\n");

	xa_destroy(mem_ids);
}
