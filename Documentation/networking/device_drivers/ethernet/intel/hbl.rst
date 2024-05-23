.. SPDX-License-Identifier: GPL-2.0
======================================================================
Linux kernel drivers for HabanaLabs (an Intel company) Network
======================================================================

Copyright 2020-2024 HabanaLabs, Ltd.
Copyright(c) 2023-2024 Intel Corporation.

Contents
========

- Overview
- Identifying Your Adapter
- Important Notes
- Support
- Trademarks

Overview
========

These drivers enables the infrastructure for network functionality which is part
of the GAUDI ASIC family of AI Accelerators.

The network interfaces are mainly used for scaling the training of AI neural
networks through ROCEv2 protocol.

Driver's information can be obtained using lspci.

For questions related to hardware requirements, refer to the documentation
supplied with your HabanaLabs adapter. All hardware requirements listed apply to
use with Linux.

The included network drivers are Core Network, Ethernet and InfiniBand which are
all based on the habanalabs driver which serves as the compute driver and the
general platform.
This is the drivers scheme:

+------------+  |      +-----+       |    +-------+
| INFINIBAND |  |      | NET |       |    | ACCEL |
+------------+  |      +-----+       |    +-------+
                |                    |
    +----+      |  +----+   +----+   |  +------------+
    | IB |      |  | EN <---| CN |   |  | HABANALABS |
    +-^--+      |  +----+   +---^+   |  +------------+
      |                       | |              |
      +-----------------------+ +--------------+

The parent driver is at the arrow base and the son is at the arrow head.
The CN driver is both a parent and a son driver.

Identifying Your Adapter
========================
For information on how to identify your adapter, and for the latest Intel
network drivers, refer to the Intel Support website:
https://www.intel.com/support

Important Notes
===============

hbl_cn main goal is to provide core functionalities that are shared between the
Ethernet (hbl_en) and the InfiniBand (hbl) drivers.
It contains all core logic that is needed to operate the satellite drivers while
keeping them as minimal as possible. Only pure Ethernet/InfiniBand code should
reside in the satellite drivers.
This code structure ensures a single and common infrastructure layer for both
functionalities which makes it easier to modify and maintain.

Support
=======
For general information, go to the Intel support website at:
https://www.intel.com/support/

If an issue is identified with the released source code on a supported kernel
with a supported adapter, email the specific information related to the issue
to intel-wired-lan@lists.osuosl.org.

Trademarks
==========
Intel is a trademark or registered trademark of Intel Corporation or its
subsidiaries in the United States and/or other countries.

* Other names and brands may be claimed as the property of others.
