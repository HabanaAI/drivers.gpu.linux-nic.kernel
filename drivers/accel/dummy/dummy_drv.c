// SPDX-License-Identifier: GPL-2.0

#include <linux/dma-mapping.h>
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

static void accel_dummy_debugfs_init(struct drm_minor *minor);

static struct platform_device *accel_dummy_drm;

DEFINE_DRM_ACCEL_FOPS(accel_dummy_driver_fops);

static const struct drm_driver accel_dummy_drm_driver = {
	.driver_features	= DRIVER_COMPUTE_ACCEL,
	.fops			= &accel_dummy_driver_fops,
	.debugfs_init           = accel_dummy_debugfs_init,
	.name			= DRIVER_NAME,
	.desc			= DRIVER_DESC,
	.date			= DRIVER_DATE,
	.major			= DRIVER_MAJOR,
	.minor			= DRIVER_MINOR,
};

static void accel_dummy_debugfs_init(struct drm_minor *minor)
{
	DRM_INFO("%s called\n", __func__);
}

static int accel_dummy_pdev_probe(struct platform_device *pdev)
{
	struct drm_device *drm;
	struct device *dev;
	int ret;

	DRM_INFO("%s called\n", __func__);

	dev = &pdev->dev;

	drm = drm_dev_alloc(&accel_dummy_drm_driver, dev);
	if (IS_ERR(drm))
		return PTR_ERR(drm);

	dma_set_max_seg_size(dev, SZ_2G);

	dev_set_drvdata(dev, drm);

	ret = drm_dev_register(drm, 0);
	if (ret)
		goto out_put;

	return 0;

out_put:
	drm_dev_put(drm);

	return ret;
}

static int accel_dummy_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct drm_device *drm = dev_get_drvdata(dev);

	DRM_INFO("%s called\n", __func__);

	drm_dev_unregister(drm);

	drm_dev_put(drm);

	return 0;
}

static struct platform_driver accel_dummy_platform_driver = {
	.probe      = accel_dummy_pdev_probe,
	.remove     = accel_dummy_remove,
	.driver     = {
		.name   = "accel_dummy",
	},
};

static void __exit accel_dummy_exit(void)
{
	DRM_INFO("%s called\n", __func__);

	if (IS_ERR_OR_NULL(accel_dummy_drm)) {
		DRM_INFO("accel_dummy_drm wasn't initialized\n");
		return;
	}

	platform_device_unregister(accel_dummy_drm);
	platform_driver_unregister(&accel_dummy_platform_driver);

	accel_dummy_drm = NULL;
}

static int __init accel_dummy_init(void)
{
	struct platform_device *pdev;
	int ret;

	DRM_INFO("%s called\n", __func__);

	ret = platform_driver_register(&accel_dummy_platform_driver);
	if (ret != 0)
		return ret;

	pdev = platform_device_alloc("accel_dummy", PLATFORM_DEVID_NONE);
	if (!pdev) {
		ret = -ENOMEM;
		goto unregister_platform_driver;
	}

	ret = platform_device_add(pdev);
	if (ret) {
		platform_device_put(pdev);
		goto unregister_platform_driver;
	}

	accel_dummy_drm = pdev;

	return 0;

unregister_platform_driver:
	platform_driver_unregister(&accel_dummy_platform_driver);
	return ret;
}

module_init(accel_dummy_init);
module_exit(accel_dummy_exit);
