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
 * File containing identifiers for items in the Remote Inventory Parameters (RIP).
 */

#ifndef __RIP_IDS_H__
#define __RIP_IDS_H__

#define RIP_ID_LOWER_CHECKSUM                0x0000 /**<  RIP CheckSum */
#define RIP_ID_UNPROT_FREE1                  0x0002 /**<  Customization Pattern */
#define RIP_ID_PART_NBR_VARIANT              0x0004 /**<  PBA Code */
#define RIP_ID_ICS                           0x0010 /**<  PBA ICS */
#define RIP_ID_BOARD_SERIAL_NBR              0x0012 /**<  PBA Serial nr */
#define RIP_ID_FACTORY_RELEASE_DATE          0x0022 /**<  Product Date */
#define RIP_ID_FIA                           0x0028 /**<  FIA code */
#define RIP_ID_HANDOVER_DATE                 0x002C /**<  Repair Date */
#define RIP_ID_LAN_ADDR                      0x0032 /**<  Ethernet MAC */
#define RIP_ID_COMPANY_ID                    0x0038 /**<  Company ID */
#define RIP_ID_FACTORY_ID                    0x003C /**<  Factory ID */
#define RIP_ID_BOARD_NAME                    0x0040 /**<  Board Name */
#define RIP_ID_MEMORY_CONFIG                 0x0048 /**<  Memory Configuration */
#define RIP_ID_USB_LAN_ADDR                  0x004C /**<  USB MAC address */
#define RIP_ID_MODEM_ACCESS_CODE             0x0083 /**<  Access Code */
#define RIP_ID_SECURE_REMOTE_MANG_PASWD      0x0088 /**<  Remote Mgr Pwd */
#define RIP_ID_WLAN_LAN_ADDR                 0x008D /**<  WiFi MAC */

#define RIP_ID_PUBLIC_DSA_SYST               0x0100 /**< DSA Public Key, for Regular Firmware Signature */
#define RIP_ID_PUBLIC_DSA_RESC               0x0101 /**< DSA Public Key, for Rescue Firmware Signature */
#define RIP_ID_MODELNAME                     0x0102 /**< String, Represents the board (ex: Livebox Mini...) */
#define RIP_ID_PRODUCT_CLASS                 0x0103 /**< String, Represents the product type (ex: Livebox, Livebox2...) */
#define RIP_ID_LB_CLIENT_CERTIFICATE         0x0104 /**< PEM (x509v3), Unique Device Certificate */
#define RIP_ID_PRIVATE_KEY                   0x0105 /**< PEM (PKCS#1), RSA Private Key (unique per device) */
#define RIP_ID_H235_KEY                      0x0106 /**< String, Secret Key (unique per device) for voice activation */
#define RIP_ID_RANDOM_KEY_A                  0x0107 /**< Random number 1 (256 bit) */
#define RIP_ID_RANDOM_KEY_B                  0x0108 /**< Random number 2 (512 bit) */
#define RIP_ID_KEY_PWD                       0x0109 /**< Key password, will return if possible RANDOM_KEY_A or a RIP calculated key */
#define RIP_ID_RALINK_CALIBRATION_DATA       0x0112 /**< Ralink wlan calibration data (256 bytes) */
#define RIP_ID_CHIPID                        0x0115 /**< The unique ID of the CPU where the erip is coupled to */
#define RIP_ID_PUBLIC_RSA_KEY                0x0116 /**< Used for BLI RSA public key in eRIPv2 board. Called in /vobs/fsn/lib/ipkg/bli2_verify.c  */
#define RIP_ID_SERIAL_NBR_BYTES              0x0118 /**< Unique Serial Number bytes ( to construct GPON ONT-Serial Number) (32 bit) */
#define RIP_ID_CLIENT_CERTIFICATE            0x011A /**< PEM (x509v3), Unique Device Certificate for recent boards */
#define RIP_ID_OPTICAL_FRONT_END             0x011B /**< Optical Front End type (1 Triplexer, 2 Diplexer, 3 Active Ethernet) (8 bit) */
#define RIP_ID_DUID_LLT                      0x011C /**< DHCP Unique Identifier Link Local Timestamp */
#define RIP_ID_EIK                           0x011E /**< Public RSA key for signature verification of encrypted eRIPv2 items */
#define RIP_ID_ECK                           0x011F /**< AES key for decryption encrypted eRIPv2 items*/
#define RIP_ID_OSIK                          0x0120 /**< OS integrity key; used to verify signatures in RSA signed BLIs and flash contents */
#define RIP_ID_OSCK                          0x0121 /**< OS confidentiality key; used to decrypt AES-CBC encrypted BLIs */
#define RIP_ID_RESTRICTED_DOWNGR_TS          0x0122 /**< Restricted downgrade timestamp (unsigned int) */
#define RIP_ID_RESTRICTED_DOWNGR_OPT         0x0123 /**< Restricted downgrade options (8 bit) */
#define RIP_ID_GENERIC_ACCESS_KEY_LIST       0x0124 /**< Contains 10 access keys of 8 alphanumeric characters */
#define RIP_ID_UNLOCK_TAG                    0x0125 /* Bootloader unlock tag, to convert production gateway into an unlocked gateway (to run unsigned builds) */
#define RIP_ID_OLYMPUS_IK                    0x0127 /* Olympus integrity key; used to verify signatures in RSA LER signed BLIs */
#define RIP_ID_OLYMPUS_CK                    0x0128 /* Olympus confidentiality key; used to decrypt AES-CBC encrypted LER BLIs */

#define RIP_ID_ID_DECT_CFG                   (0x4001) /**< DECT calibration data */

#define SS_RIP_ID_PREFIX                     (0x8000) /**< Values from the old Secure Storage start at 0x8000 */
#define RIP_ID_PRODID                        (SS_RIP_ID_PREFIX + 1)  /**< Product ID */
#define RIP_ID_PRODNAME                      (SS_RIP_ID_PREFIX + 2)  /**< Product friendly name */
#define RIP_ID_VARID                         (SS_RIP_ID_PREFIX + 3)  /**< Variant ID */
#define RIP_ID_VARNAME                       (SS_RIP_ID_PREFIX + 4)  /**< Variant friendly name */

#define RIP_CP_DSL_POTS    0x0 // Annex A HW
#define RIP_CP_DSL_ISDN    0x4 // Annex B HW
#define RIP_CP_DSL_M    0x0200 // Annex M HW
#define RIP_CP_DSL_BJ   0x1004  // Annex B / J HW
#define RIP_CP_DSL_MASK 0x1204


#endif //__RIP_IDS_H__
