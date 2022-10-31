/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef DRM_ACCEL_H_
#define DRM_ACCEL_H_

#include <drm/drm_file.h>

#define ACCEL_MAJOR		261
#define ACCEL_MAX_MINORS	256

#if IS_ENABLED(CONFIG_ACCEL)

void accel_core_exit(void);
int accel_core_init(void);
void accel_minor_remove(int index);
int accel_minor_alloc(void);
int accel_minor_replace(struct drm_minor *minor, int index);
void accel_set_device_instance_params(struct device *kdev, int index);
int accel_open(struct inode *inode, struct file *filp);

#else

static inline void accel_core_exit(void)
{
}

static inline int __init accel_core_init(void)
{
	/* Return 0 to allow drm_core_init to complete successfully */
	return 0;
}

static inline void accel_minor_remove(int index)
{
}

static inline int accel_minor_alloc(void)
{
	return -EOPNOTSUPP;
}

static inline int accel_minor_replace(struct drm_minor *minor, int index)
{
	return -EOPNOTSUPP;
}

static inline void accel_set_device_instance_params(struct device *kdev, int index)
{
}

#endif /* IS_ENABLED(CONFIG_ACCEL) */

#endif /* DRM_ACCEL_H_ */
