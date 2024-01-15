// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2016-2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlib.h"

static ssize_t ports_mask_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct hl_ib_device *hdev = container_of(dev, struct hl_ib_device, ibdev.dev);

	return sprintf(buf, "%llx\n", hdev->ports_mask);
}

static ssize_t ext_ports_mask_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct hl_ib_device *hdev = container_of(dev, struct hl_ib_device, ibdev.dev);

	return sprintf(buf, "%llx\n", hdev->ext_ports_mask);
}

static DEVICE_ATTR_RO(ports_mask);
static DEVICE_ATTR_RO(ext_ports_mask);

static struct attribute *hl_ib_attrs[] = {
	&dev_attr_ports_mask.attr,
	&dev_attr_ext_ports_mask.attr,
	NULL,
};

const struct attribute_group hl_ib_attr_group = {
	.attrs = hl_ib_attrs,
};

static const struct attribute_group *hl_ib_attr_groups[] = {
	&hl_ib_attr_group,
	NULL,
};

int hl_ib_sysfs_init(struct hl_ib_device *hdev)
{
	return device_add_groups(&hdev->ibdev.dev, hl_ib_attr_groups);
}

void hl_ib_sysfs_fini(struct hl_ib_device *hdev)
{
	device_remove_groups(&hdev->ibdev.dev, hl_ib_attr_groups);
}
