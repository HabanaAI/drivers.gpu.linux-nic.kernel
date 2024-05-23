// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#include "hbl_cn.h"

int hbl_cn_mem_alloc(struct hbl_cn_ctx *ctx, struct hbl_cn_mem_data *mem_data)
{
	return 0;
}

int hbl_cn_mem_destroy(struct hbl_cn_device *hdev, u64 handle)
{
	return 0;
}

struct hbl_cn_mem_buf *hbl_cn_mem_buf_get(struct hbl_cn_device *hdev, u64 handle)
{
	return NULL;
}

int hbl_cn_mem_buf_put(struct hbl_cn_mem_buf *buf)
{
	return 0;
}

int hbl_cn_mem_buf_put_handle(struct hbl_cn_device *hdev, u64 handle)
{
	return 0;
}

void hbl_cn_mem_init(struct hbl_cn_device *hdev)
{
}

void hbl_cn_mem_fini(struct hbl_cn_device *hdev)
{
}
