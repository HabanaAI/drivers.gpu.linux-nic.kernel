// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/xarray.h>

#include <drm/drm_accel.h>
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_print.h>

static DEFINE_XARRAY_ALLOC(accel_minors_xa);

static struct dentry *accel_debugfs_root;
static struct class *accel_class;

static struct device_type accel_sysfs_device_minor = {
	.name = "accel_minor"
};

static char *accel_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "accel/%s", dev_name(dev));
}

static CLASS_ATTR_STRING(accel_version, 0444, "accel 1.0.0 20221018");

static int accel_sysfs_init(void)
{
	int err;

	accel_class = class_create(THIS_MODULE, "accel");
	if (IS_ERR(accel_class))
		return PTR_ERR(accel_class);

	err = class_create_file(accel_class, &class_attr_accel_version.attr);
	if (err) {
		class_destroy(accel_class);
		accel_class = NULL;
		return err;
	}

	accel_class->devnode = accel_devnode;

	return 0;
}

static void accel_sysfs_destroy(void)
{
	if (IS_ERR_OR_NULL(accel_class))
		return;
	class_remove_file(accel_class, &class_attr_accel_version.attr);
	class_destroy(accel_class);
	accel_class = NULL;
}

/**
 * accel_set_device_instance_params() - Set some device parameters for accel device
 * @kdev: Pointer to the device instance.
 * @index: The minor's index
 *
 * This function creates the dev_t of the device using the accel major and
 * the device's minor number. In addition, it sets the class and type of the
 * device instance to the accel sysfs class and device type, respectively.
 */
void accel_set_device_instance_params(struct device *kdev, int index)
{
	kdev->devt = MKDEV(ACCEL_MAJOR, index);
	kdev->class = accel_class;
	kdev->type = &accel_sysfs_device_minor;
}

/**
 * accel_minor_alloc() - Allocates a new accel minor
 *
 * This function access the accel minors xarray and allocates from it
 * a new id to represent a new accel minor
 *
 * Return: A new id on success or error code in case xa_alloc failed
 */
int accel_minor_alloc(void)
{
	int rc, index;

	rc = xa_alloc(&accel_minors_xa, &index, NULL,
			XA_LIMIT(0, ACCEL_MAX_MINORS - 1), GFP_KERNEL);
	if (rc < 0)
		return rc;

	return index;
}

/**
 * accel_minor_remove() - Remove an accel minor
 * @index: The minor id to remove.
 *
 * This function access the accel minors xarray and removes from
 * it the member with the id that is passed to this function.
 */
void accel_minor_remove(int index)
{
	xa_erase(&accel_minors_xa, index);
}

/**
 * accel_minor_replace() - Replace minor pointer in accel minors xarray.
 * @minor: Pointer to the new minor.
 * @index: The minor id to replace.
 *
 * This function access the accel minors xarray structure and replaces the pointer
 * that is associated with an existing id. Because the minor pointer can be
 * NULL, we need to explicitly pass the index.
 *
 * Return: 0 for success, negative value for error
 */
int accel_minor_replace(struct drm_minor *minor, int index)
{
	if (minor) {
		void *entry;

		entry = xa_cmpxchg(&accel_minors_xa, index, NULL, minor, GFP_KERNEL);
		if (xa_is_err(entry))
			return xa_err(entry);
	} else {
		xa_store(&accel_minors_xa, index, NULL, GFP_KERNEL);
	}

	return 0;
}

/*
 * Looks up the given minor-ID and returns the respective DRM-minor object. The
 * refence-count of the underlying device is increased so you must release this
 * object with accel_minor_release().
 *
 * The object can be only a drm_minor that represents an accel device.
 *
 * As long as you hold this minor, it is guaranteed that the object and the
 * minor->dev pointer will stay valid! However, the device may get unplugged and
 * unregistered while you hold the minor.
 */
static struct drm_minor *accel_minor_acquire(unsigned int minor_id)
{
	struct drm_minor *minor;

	xa_lock(&accel_minors_xa);
	minor = xa_load(&accel_minors_xa, minor_id);
	if (minor)
		drm_dev_get(minor->dev);
	xa_unlock(&accel_minors_xa);

	if (!minor) {
		return ERR_PTR(-ENODEV);
	} else if (drm_dev_is_unplugged(minor->dev)) {
		drm_dev_put(minor->dev);
		return ERR_PTR(-ENODEV);
	}

	return minor;
}

static void accel_minor_release(struct drm_minor *minor)
{
	drm_dev_put(minor->dev);
}

/**
 * accel_open - open method for ACCEL file
 * @inode: device inode
 * @filp: file pointer.
 *
 * This function must be used by drivers as their &file_operations.open method.
 * It looks up the correct ACCEL device and instantiates all the per-file
 * resources for it. It also calls the &drm_driver.open driver callback.
 *
 * Return: 0 on success or negative errno value on failure.
 */
int accel_open(struct inode *inode, struct file *filp)
{
	struct drm_device *dev;
	struct drm_minor *minor;
	int retcode;

	minor = accel_minor_acquire(iminor(inode));
	if (IS_ERR(minor))
		return PTR_ERR(minor);

	dev = minor->dev;

	atomic_fetch_inc(&dev->open_count);

	/* share address_space across all char-devs of a single device */
	filp->f_mapping = dev->anon_inode->i_mapping;

	retcode = drm_open_helper(filp, minor);
	if (retcode)
		goto err_undo;

	return 0;

err_undo:
	atomic_dec(&dev->open_count);
	accel_minor_release(minor);
	return retcode;
}
EXPORT_SYMBOL_GPL(accel_open);

static int accel_stub_open(struct inode *inode, struct file *filp)
{
	const struct file_operations *new_fops;
	struct drm_minor *minor;
	int err;

	DRM_DEBUG("\n");

	minor = accel_minor_acquire(iminor(inode));
	if (IS_ERR(minor))
		return PTR_ERR(minor);

	new_fops = fops_get(minor->dev->driver->fops);
	if (!new_fops) {
		err = -ENODEV;
		goto out;
	}

	replace_fops(filp, new_fops);
	if (filp->f_op->open)
		err = filp->f_op->open(inode, filp);
	else
		err = 0;

out:
	accel_minor_release(minor);

	return err;
}

static const struct file_operations accel_stub_fops = {
	.owner = THIS_MODULE,
	.open = accel_stub_open,
	.llseek = noop_llseek,
};

void accel_core_exit(void)
{
	unregister_chrdev(ACCEL_MAJOR, "accel");
	debugfs_remove(accel_debugfs_root);
	accel_sysfs_destroy();
	WARN_ON(!xa_empty(&accel_minors_xa));
}

int __init accel_core_init(void)
{
	int ret;

	ret = accel_sysfs_init();
	if (ret < 0) {
		DRM_ERROR("Cannot create ACCEL class: %d\n", ret);
		goto error;
	}

	accel_debugfs_root = debugfs_create_dir("accel", NULL);

	ret = register_chrdev(ACCEL_MAJOR, "accel", &accel_stub_fops);
	if (ret < 0)
		goto error;

error:
	/* Any cleanup will be done in drm_core_exit() that will call
	 * to accel_core_exit()
	 */
	return ret;
}
