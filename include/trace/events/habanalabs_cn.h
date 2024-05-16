/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright 2023 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 *
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM habanalabs_cn

#if !defined(_TRACE_HABANALABS_CN_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HABANALABS_CN_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(habanalabs_cn_mem_template,
	TP_PROTO(struct device *dev, u32 mem_id, u64 handle, u64 kernel_addr, u64 bus_addr,
		 u64 device_va, size_t size),

	TP_ARGS(dev, mem_id, handle, kernel_addr, bus_addr, device_va, size),

	TP_STRUCT__entry(
		__string(dname, dev_name(dev))
		__field(u32, mem_id)
		__field(u64, handle)
		__field(u64, kernel_addr)
		__field(u64, bus_addr)
		__field(u64, device_va)
		__field(u32, size)
	),

	TP_fast_assign(
		__assign_str(dname);
		__entry->mem_id = mem_id;
		__entry->handle = handle;
		__entry->kernel_addr = kernel_addr;
		__entry->bus_addr = bus_addr;
		__entry->device_va = device_va;
		__entry->size = size;
	),

	TP_printk("%s: mem_id: %#x, handle: %#llx, kernel_addr: %#llx, bus_addr: %#llx, device_va: %#llx, size: %#x",
		  __get_str(dname),
		  __entry->mem_id,
		  __entry->handle,
		  __entry->kernel_addr,
		  __entry->bus_addr,
		  __entry->device_va,
		  __entry->size)
);

DEFINE_EVENT(habanalabs_cn_mem_template, habanalabs_cn_mem_alloc,
	TP_PROTO(struct device *dev, u32 mem_id, u64 handle, u64 kernel_addr, u64 bus_addr,
		 u64 device_va, size_t size),
	TP_ARGS(dev, mem_id, handle, kernel_addr, bus_addr, device_va, size));

DEFINE_EVENT(habanalabs_cn_mem_template, habanalabs_cn_mem_destroy,
	TP_PROTO(struct device *dev, u32 mem_id, u64 handle, u64 kernel_addr, u64 bus_addr,
		 u64 device_va, size_t size),
	TP_ARGS(dev, mem_id, handle, kernel_addr, bus_addr, device_va, size));

DECLARE_EVENT_CLASS(habanalabs_cn_dma_alloc_template,
	TP_PROTO(struct device *dev, u64 cpu_addr, u64 dma_addr, size_t size, const char *caller),

	TP_ARGS(dev, cpu_addr, dma_addr, size, caller),

	TP_STRUCT__entry(
		__string(dname, dev_name(dev))
		__field(u64, cpu_addr)
		__field(u64, dma_addr)
		__field(u32, size)
		__field(const char *, caller)
	),

	TP_fast_assign(
		__assign_str(dname);
		__entry->cpu_addr = cpu_addr;
		__entry->dma_addr = dma_addr;
		__entry->size = size;
		__entry->caller = caller;
	),

	TP_printk("%s: cpu_addr: %#llx, dma_addr: %#llx, size: %#x, caller: %s",
		  __get_str(dname),
		  __entry->cpu_addr,
		  __entry->dma_addr,
		  __entry->size,
		  __entry->caller
	)
);

DEFINE_EVENT(habanalabs_cn_dma_alloc_template, habanalabs_cn_dma_alloc_coherent,
	     TP_PROTO(struct device *dev, u64 cpu_addr, u64 dma_addr, size_t size,
		      const char *caller),
	     TP_ARGS(dev, cpu_addr, dma_addr, size, caller));

DEFINE_EVENT(habanalabs_cn_dma_alloc_template, habanalabs_cn_dma_free_coherent,
	     TP_PROTO(struct device *dev, u64 cpu_addr, u64 dma_addr, size_t size,
		      const char *caller),
	     TP_ARGS(dev, cpu_addr, dma_addr, size, caller));

DEFINE_EVENT(habanalabs_cn_dma_alloc_template, habanalabs_cn_dma_pool_zalloc,
	     TP_PROTO(struct device *dev, u64 cpu_addr, u64 dma_addr, size_t size,
		      const char *caller),
	     TP_ARGS(dev, cpu_addr, dma_addr, size, caller));

DEFINE_EVENT(habanalabs_cn_dma_alloc_template, habanalabs_cn_dma_pool_free,
	     TP_PROTO(struct device *dev, u64 cpu_addr, u64 dma_addr, size_t size,
		      const char *caller),
	     TP_ARGS(dev, cpu_addr, dma_addr, size, caller));

#endif /* if !defined(_TRACE_HABANALABS_CN_H) || defined(TRACE_HEADER_MULTI_READ) */

/* This part must be outside protection */
#include <trace/define_trace.h>
