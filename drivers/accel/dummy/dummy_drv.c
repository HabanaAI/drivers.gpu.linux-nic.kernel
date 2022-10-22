// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/platform_device.h>

#include <drm/drm_accel.h>
#include <drm/drm_drv.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_print.h>

#define DRIVER_NAME	"accel_dummy"
#define DRIVER_DESC	"Driver for a dummy compute accelerator"
#define DRIVER_DATE	"20221022"
#define DRIVER_MAJOR	1
#define DRIVER_MINOR	0

MODULE_AUTHOR("Oded Gabbay");
MODULE_DESCRIPTION("Driver for a dummy compute accelerator");
MODULE_LICENSE("GPL");

struct accel_dummy_device {
	struct drm_device drm;
	struct platform_device *platform;
};

static struct accel_dummy_device *add;

static void accel_dummy_release(struct drm_device *dev)
{
	DRM_INFO("%s called", __func__);
}

static void accel_dummy_debugfs_init(struct drm_minor *minor)
{
	DRM_INFO("%s called", __func__);
}

static const struct file_operations accel_dummy_driver_fops = {
	.owner = THIS_MODULE,
	.open = accel_open,
	.release = drm_release,
	.unlocked_ioctl = drm_ioctl,
	.poll = drm_poll,
	.read = drm_read,
	.llseek = noop_llseek
};

static const struct drm_driver accel_dummy_driver = {
	.driver_features	= DRIVER_COMPUTE_ACCEL,
	.release		= accel_dummy_release,
	.fops			= &accel_dummy_driver_fops,
	.debugfs_init           = accel_dummy_debugfs_init,
	.name			= DRIVER_NAME,
	.desc			= DRIVER_DESC,
	.date			= DRIVER_DATE,
	.major			= DRIVER_MAJOR,
	.minor			= DRIVER_MINOR,
};

static void __exit accel_dummy_exit(void)
{
	struct platform_device *pdev;

	DRM_INFO("%s called", __func__);

	if (IS_ERR_OR_NULL(add)) {
		DRM_INFO("accel_dummy_device wasn't initialized\n");
		return;
	}

	pdev = add->platform;

	drm_dev_unregister(&add->drm);
	devres_release_group(&pdev->dev, NULL);
	platform_device_unregister(pdev);

	kfree(add);
	add = NULL;
}

static int __init accel_dummy_init(void)
{
	struct platform_device *pdev;
	int ret;

	DRM_INFO("%s called", __func__);

	pdev = platform_device_register_simple(DRIVER_NAME, -1, NULL, 0);
	if (IS_ERR(pdev))
		return PTR_ERR(pdev);

	if (!devres_open_group(&pdev->dev, NULL, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto out_unregister;
	}

	add = devm_drm_dev_alloc(&pdev->dev, &accel_dummy_driver,
				struct accel_dummy_device, drm);
	if (IS_ERR(add)) {
		ret = PTR_ERR(add);
		goto out_devres;
	}
	add->platform = pdev;

	ret = drm_dev_register(&add->drm, 0);
	if (ret)
		goto out_devres;

	return 0;

out_devres:
	devres_release_group(&pdev->dev, NULL);
out_unregister:
	platform_device_unregister(pdev);
	return ret;
}

module_init(accel_dummy_init);
module_exit(accel_dummy_exit);
