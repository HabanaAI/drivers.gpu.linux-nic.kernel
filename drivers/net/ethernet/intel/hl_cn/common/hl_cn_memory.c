// SPDX-License-Identifier: GPL-2.0

/* Copyright 2021 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include <linux/vmalloc.h>
#include <linux/genalloc.h>
#include "habanalabs_cn.h"
#include <trace/events/habanalabs_cn.h>

static int hl_cn_map_vmalloc_range(struct hl_cn_device *hdev, u64 vmalloc_va, u64 device_va,
				   u64 size)
{
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	return aux_ops->map_vmalloc_range(aux_dev, vmalloc_va, device_va, size);
}

static int hl_cn_unmap_vmalloc_range(struct hl_cn_device *hdev, u64 device_va)
{
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	return aux_ops->unmap_vmalloc_range(aux_dev, device_va);
}

static int alloc_mem(struct hl_cn_mem_buf *buf, gfp_t gfp, struct hl_cn_device *hdev,
		     struct hl_cn_mem_data *mem_data)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;
	u64 device_addr, size = mem_data->size;
	u32 mem_id = mem_data->mem_id;
	void *p = NULL;

	switch (mem_id) {
	case HL_CN_DRV_MEM_HOST_DMA_COHERENT:
		if (get_order(size) > MAX_ORDER) {
			dev_err(hdev->dev, "memory size 0x%llx must be less than 0x%lx\n", size,
				1UL << (PAGE_SHIFT + MAX_ORDER - 1));
			return -ENOMEM;
		}

		p = asic_funcs->dma_alloc_coherent(hdev, size, &buf->bus_address,
						   GFP_USER | __GFP_ZERO);
		if (!p) {
			dev_err(hdev->dev,
				"failed to allocate 0x%llx of dma memory for the NIC\n", size);
			return -ENOMEM;
		}

		break;
	case HL_CN_DRV_MEM_HOST_VIRTUAL:
		p = vmalloc_user(size);
		if (!p) {
			dev_err(hdev->dev,
				"failed to allocate vmalloc memory, size 0x%llx\n", size);
			return -ENOMEM;
		}

		break;
	case HL_CN_DRV_MEM_HOST_MAP_ONLY:
		p = mem_data->in.host_map_data.kernel_address;
		buf->bus_address = mem_data->in.host_map_data.bus_address;
		break;
	case HL_CN_DRV_MEM_DEVICE:
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

static int map_mem(struct hl_cn_device *hdev, struct hl_cn_mem_buf *buf,
		   struct hl_cn_mem_data *mem_data)
{
	int rc;

	if (mem_data->mem_id == HL_CN_DRV_MEM_HOST_DMA_COHERENT) {
		dev_err(hdev->dev, "Mapping DMA coherent host memory is not yet supported\n");
		return -EPERM;
	}

	rc = hl_cn_map_vmalloc_range(hdev, (u64)buf->kernel_address, mem_data->device_va,
				     buf->mappable_size);
	if (rc)
		return rc;

	buf->device_va = mem_data->device_va;

	return 0;
}

static void mem_do_release(struct hl_cn_device *hdev, struct hl_cn_mem_buf *buf)
{
	struct hl_cn_asic_funcs *asic_funcs = hdev->asic_funcs;

	if (buf->mem_id == HL_CN_DRV_MEM_HOST_DMA_COHERENT)
		asic_funcs->dma_free_coherent(hdev, buf->mappable_size, buf->kernel_address,
					      buf->bus_address);
	else if (buf->mem_id == HL_CN_DRV_MEM_HOST_VIRTUAL)
		vfree(buf->kernel_address);
	else if (buf->mem_id == HL_CN_DRV_MEM_DEVICE)
		gen_pool_free(hdev->wq_arrays_pool, buf->device_addr, buf->mappable_size);
}

static int __cn_mem_buf_alloc(struct hl_cn_mem_buf *buf, gfp_t gfp,
			      struct hl_cn_mem_data *mem_data)
{
	struct hl_cn_device *hdev = buf->hdev;
	int rc;

	if (mem_data->mem_id != HL_CN_DRV_MEM_DEVICE)
		mem_data->size = PAGE_ALIGN(mem_data->size);

	rc = alloc_mem(buf, gfp, hdev, mem_data);
	if (rc)
		return rc;

	if (mem_data->device_va) {
		mem_data->device_va = PAGE_ALIGN(mem_data->device_va);
		rc = map_mem(hdev, buf, mem_data);
		if (rc)
			goto release_mem;
	}

	return 0;

release_mem:
	mem_do_release(hdev, buf);
	return rc;
}

static struct hl_cn_mem_buf *cn_mem_buf_alloc(struct hl_cn_device *hdev, gfp_t gfp,
					      struct hl_cn_mem_data *mem_data)
{
	struct xa_limit id_limit = XA_LIMIT(1, INT_MAX);
	struct hl_cn_mem_buf *buf;
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

	buf->hdev = hdev;
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

static int cn_mem_alloc(struct hl_cn_device *hdev, struct hl_cn_mem_data *mem_data)
{
	struct hl_cn_mem_buf *buf;

	buf = cn_mem_buf_alloc(hdev, GFP_KERNEL, mem_data);
	if (!buf)
		return -ENOMEM;

	trace_habanalabs_cn_mem_alloc(buf->hdev->dev, buf->mem_id, buf->handle,
				      (u64)buf->kernel_address, buf->bus_address, buf->device_va,
				      buf->mappable_size);

	mem_data->handle = buf->handle;

	if (mem_data->mem_id == HL_CN_DRV_MEM_HOST_DMA_COHERENT)
		mem_data->addr = (u64)buf->bus_address;
	else if (mem_data->mem_id == HL_CN_DRV_MEM_HOST_VIRTUAL)
		mem_data->addr = (u64)buf->kernel_address;
	else if (mem_data->mem_id == HL_CN_DRV_MEM_DEVICE)
		mem_data->addr = (u64)buf->device_addr;

	return 0;
}

int hl_cn_mem_alloc(struct hl_cn_device *hdev, struct hl_cn_mem_data *mem_data)
{
	int rc;

	switch (mem_data->mem_id) {
	case HL_CN_DRV_MEM_HOST_DMA_COHERENT:
	case HL_CN_DRV_MEM_HOST_VIRTUAL:
	case HL_CN_DRV_MEM_HOST_MAP_ONLY:
	case HL_CN_DRV_MEM_DEVICE:
		rc = cn_mem_alloc(hdev, mem_data);
		break;
	default:
		dev_dbg(hdev->dev, "Invalid mem_id %d\n", mem_data->mem_id);
		rc = -EINVAL;
		break;
	}

	return rc;
}

static void cn_mem_buf_destroy(struct hl_cn_mem_buf *buf)
{
	trace_habanalabs_cn_mem_destroy(buf->hdev->dev, buf->mem_id, buf->handle,
					(u64)buf->kernel_address, buf->bus_address, buf->device_va,
					buf->mappable_size);

	if (buf->device_va)
		hl_cn_unmap_vmalloc_range(buf->hdev, buf->device_va);

	mem_do_release(buf->hdev, buf);

	kfree(buf);
}

int hl_cn_mem_destroy(struct hl_cn_device *hdev, u64 handle)
{
	struct hl_cn_mem_buf *buf;
	int rc;

	buf = hl_cn_mem_buf_get(hdev, handle);
	if (!buf) {
		dev_dbg(hdev->dev, "Memory destroy failed, no match for handle 0x%llx\n", handle);
		return -EINVAL;
	}

	rc = atomic_cmpxchg(&buf->is_destroyed, 0, 1);
	hl_cn_mem_buf_put(buf);
	if (rc) {
		dev_dbg(hdev->dev, "Memory destroy failed, handle 0x%llx was already destroyed\n",
			handle);
		return -EINVAL;
	}

	rc = hl_cn_mem_buf_put_handle(hdev, handle);
	if (rc < 0)
		return rc;

	if (rc == 0)
		dev_dbg(hdev->dev, "Handle 0x%llx is destroyed while still in use\n", handle);

	return 0;
}

static int cn_mem_buf_mmap(struct hl_cn_mem_buf *buf, struct vm_area_struct *vma)
{
	struct hl_cn_device *hdev = buf->hdev;
	struct hl_cn_aux_ops *aux_ops;
	struct hl_aux_dev *aux_dev;
	int rc = -EINVAL;

	aux_dev = hdev->cn_aux_dev;
	aux_ops = aux_dev->aux_ops;

	if (buf->mem_id == HL_CN_DRV_MEM_HOST_DMA_COHERENT ||
	    buf->mem_id == HL_CN_DRV_MEM_HOST_MAP_ONLY) {
		rc = aux_ops->dma_mmap(aux_dev, vma, buf->kernel_address, buf->bus_address,
				       buf->mappable_size);
	} else if (buf->mem_id == HL_CN_DRV_MEM_HOST_VIRTUAL) {
		vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP | VM_DONTCOPY | VM_NORESERVE);

		rc = remap_vmalloc_range(vma, buf->kernel_address, 0);
	}

	return rc;
}

static void cn_mem_buf_vm_close(struct vm_area_struct *vma)
{
	struct hl_cn_mem_buf *buf = (struct hl_cn_mem_buf *)vma->vm_private_data;
	long new_mmap_size;

	new_mmap_size = buf->real_mapped_size - (vma->vm_end - vma->vm_start);

	if (new_mmap_size > 0) {
		buf->real_mapped_size = new_mmap_size;
		return;
	}

	atomic_set(&buf->mmap, 0);
	hl_cn_mem_buf_put(buf);
	vma->vm_private_data = NULL;
}

static const struct vm_operations_struct cn_mem_buf_vm_ops = {
	.close = cn_mem_buf_vm_close
};

int hl_cn_mem_mmap(struct hl_cn_device *hdev, struct vm_area_struct *vma)
{
	struct hl_cn_mem_buf *buf;
	u64 user_mem_size;
	u64 handle;
	int rc;

	/* We use the page offset to hold the xarray and thus we need to clear it before doing the
	 * mmap itself
	 */
	handle = vma->vm_pgoff << PAGE_SHIFT;
	vma->vm_pgoff = 0;

	/* Reference was taken here */
	buf = hl_cn_mem_buf_get(hdev, handle);
	if (!buf) {
		dev_err(hdev->dev,
			"NIC: Memory mmap failed, no match to handle %#llx\n", handle);
		return -EINVAL;
	}

	/* Validation check */
	user_mem_size = vma->vm_end - vma->vm_start;
	if (user_mem_size != ALIGN(buf->mappable_size, PAGE_SIZE)) {
		dev_err(hdev->dev,
			"NIC: Memory mmap failed, mmap VM size 0x%llx != 0x%llx allocated physical mem size\n",
			user_mem_size, buf->mappable_size);
		rc = -EINVAL;
		goto put_mem;
	}

	if (!access_ok((void __user *)(uintptr_t)vma->vm_start, user_mem_size)) {
		dev_err(hdev->dev, "NIC: User pointer is invalid - 0x%lx\n", vma->vm_start);

		rc = -EINVAL;
		goto put_mem;
	}

	if (atomic_cmpxchg(&buf->mmap, 0, 1)) {
		dev_err(hdev->dev, "NIC: Memory mmap failed, already mapped to user\n");
		rc = -EINVAL;
		goto put_mem;
	}

	vma->vm_ops = &cn_mem_buf_vm_ops;

	/* Note: We're transferring the memory reference to vma->vm_private_data here. */

	vma->vm_private_data = buf;

	rc = cn_mem_buf_mmap(buf, vma);
	if (rc) {
		atomic_set(&buf->mmap, 0);
		goto put_mem;
	}

	buf->real_mapped_size = buf->mappable_size;
	vma->vm_pgoff = handle >> PAGE_SHIFT;

	return 0;

put_mem:
	hl_cn_mem_buf_put(buf);
	return rc;
}

static void cn_mem_buf_release(struct kref *kref)
{
	struct hl_cn_mem_buf *buf = container_of(kref, struct hl_cn_mem_buf, refcount);
	struct hl_cn_device *hdev = buf->hdev;

	xa_erase(&hdev->mem_ids, lower_32_bits(buf->handle >> PAGE_SHIFT));

	cn_mem_buf_destroy(buf);
}

struct hl_cn_mem_buf *hl_cn_mem_buf_get(struct hl_cn_device *hdev, u64 handle)
{
	struct hl_cn_mem_buf *buf;

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

int hl_cn_mem_buf_put(struct hl_cn_mem_buf *buf)
{
	return kref_put(&buf->refcount, cn_mem_buf_release);
}

static void cn_mem_buf_remove_xa_locked(struct kref *kref)
{
	struct hl_cn_mem_buf *buf = container_of(kref, struct hl_cn_mem_buf, refcount);

	__xa_erase(&buf->hdev->mem_ids, lower_32_bits(buf->handle >> PAGE_SHIFT));
}

int hl_cn_mem_buf_put_handle(struct hl_cn_device *hdev, u64 handle)
{
	struct hl_cn_mem_buf *buf;

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

void hl_cn_mem_init(struct hl_cn_device *hdev)
{
	xa_init_flags(&hdev->mem_ids, XA_FLAGS_ALLOC);
}

void hl_cn_mem_fini(struct hl_cn_device *hdev)
{
	struct xarray *mem_ids;

	mem_ids = &hdev->mem_ids;

	if (!xa_empty(mem_ids))
		dev_crit(hdev->dev, "memory manager is destroyed while not empty!\n");

	xa_destroy(mem_ids);
}
