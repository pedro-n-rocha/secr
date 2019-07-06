/************** COPYRIGHT AND CONFIDENTIALITY INFORMATION *********************
**                                                                          **
** Copyright (c) 2012 Technicolor                                           **
** All Rights Reserved                                                      **
**                                                                          **
** This program contains proprietary information which is a trade           **
** secret of TECHNICOLOR and/or its affiliates and also is protected as     **
** an unpublished work under applicable Copyright laws. Recipient is        **
** to retain this program in confidence and is not permitted to use or      **
** make copies thereof other than as permitted in a written agreement       **
** with TECHNICOLOR, UNLESS OTHERWISE EXPRESSLY ALLOWED BY APPLICABLE LAWS. **
**                                                                          **
******************************************************************************/


/** @file
 *
 * File containing kernel API to access the Remote Inventory Parameters (RIP).
 */

#ifndef __RIPDRV_H__
#define __RIPDRV_H__

/* contains definitions for the linux ioctl routines for the rip
 * (Remote Inventory PROM)  
 *
 */
#include <linux/ioctl.h>

#define RIP_DEVICE			"/dev/rip"
#define RIP_IOC_MAGIC		'D' /* same as asm-s390/dasd.h but unlikely to be conflicting */

/* ioctl definitions for rip access */
#define RIP_IOCTL_READ		_IOWR(RIP_IOC_MAGIC, 1, int)
#define RIP_IOCTL_WRITE		_IOWR(RIP_IOC_MAGIC, 2, int)
#define RIP_IOCTL_FLAGS		_IOWR(RIP_IOC_MAGIC, 3, int)
#define RIP_IOCTL_LOCK		_IOWR(RIP_IOC_MAGIC, 4, int)

typedef struct rip_ioctl_data
{
	unsigned long len;
	unsigned short id;
	unsigned char *data;
	unsigned long attrHi;
	unsigned long attrLo;
} rip_ioctl_data_t;

#endif //__RIPDRV_H__
