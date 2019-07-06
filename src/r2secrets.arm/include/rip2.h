/*************************************************************************************

*************************************************************************************/

#ifndef __T_RIP2_H__
#define __T_RIP2_H__

#include "rip2_config.h"

#define RIP2_SZ         (0x20000)   /* 128kB */
#define CRC_SZ          (4)

#define RIP2_START      (0)       /* base address for the relative T_RIP2_HDR.addr */

#ifndef RIP2_OFFSET		/* GPON LILAC board has 256KB bootloader, the RIP2_OFFSET will be 0x40000 */
#define RIP2_OFFSET     (0x20000) /* start of the RIP2 sector */
#endif

#define RIP2_SUCCESS		(1)
#define RIP2_ERR_INV_RIP	(-1)
#define RIP2_ERR_NOMEM		(-2)
#define RIP2_ERR_NOELEM		(-3)
#define RIP2_ERR_BADCRC		(-4)
#define RIP2_ERR_PERM		(-5)
#define RIP2_ERR_BADCRYPTO	(-6)

/* implement in target dependant platform.c file */
extern int rip2_flash_init(void *base, size_t size);
extern int rip2_flash_read(loff_t from, size_t len, size_t *retlen, unsigned char *buf);
extern int rip2_flash_write(loff_t to, size_t len, size_t *retlen, unsigned char *buf);
extern int rip2_flash_clear(loff_t to, size_t len, size_t *retlen);
extern void rip2_flash_release(void);
extern unsigned long rip2_crc32(unsigned char *data, unsigned count);


typedef union {
    struct {
        uint8_t version;
        uint8_t reserved[3];
    }         str;
    uint32_t  val;
} __attribute__((__packed__)) T_RIP2_HDR;
#define RIP_VERSION_2    (0x02)

typedef uint16_t  T_RIP2_ID;

typedef struct {
    T_RIP2_ID ID;
    uint32_t  addr;
    uint32_t  attr[2];
    uint32_t  length;
} __attribute__((__packed__)) T_RIP2_ITEM;


#define RIP2_ATTR_ANY           0xFFFFFFFF
/* Inverted definition of CRC check bit, this way it's harder to bypass a CRC
 * check, since it now means setting this bit from 0 -> 1, whereas in the past 
 * it was from 1 -> 0 (easy to do in flash) */
#define RIP2_ATTR_CRC_MSK		0x80000000
#define RIP2_ATTR_CHK_CRC		(~RIP2_ATTR_CRC_MSK)
#define RIP2_ATTR_DONT_CHK_CRC	(RIP2_ATTR_CRC_MSK)
#define RIP2_ATTR_WRITABLE      0x40000000
#define RIP2_ATTR_VALID         0x20000000
/* Crypto flags interpretation is reversed ! */
#define RIP2_ATTR_N_EIK_SIGN    0x10000000 /* 60 */
#define RIP2_ATTR_N_ECK_ENCR    0x08000000 /* 59 */
#define RIP2_ATTR_N_MCV_SIGN    0x04000000 /* 58 */
#define RIP2_ATTR_N_BEK_ENCR    0x02000000 /* 57 */
#define ATTR_HI                 1
#define ATTR_LO                 0

#define RIP2_ATTR_HI_MASK		0xE0000000
/* default value is: check crc|!writable|valid */
#define RIP2_ATTR_DEFAULT       ((RIP2_ATTR_ANY & ~RIP2_ATTR_HI_MASK) | RIP2_ATTR_VALID)

#define RIP2_ATTR_CRYPTO		(RIP2_ATTR_N_EIK_SIGN | RIP2_ATTR_N_ECK_ENCR | RIP2_ATTR_N_MCV_SIGN | RIP2_ATTR_N_BEK_ENCR)

typedef struct {
    T_RIP2_HDR  hdr;
    T_RIP2_ITEM index[];
} __attribute__((__packed__)) T_RIP2_IDX;

/*
 * Create an empty rip2 with just a header field
 * IN: ripPtr: a pointer to a memory buffer that will be used to store the
 *             rip2.
 *     verify: determines whether we are in verification of generation mode
 *     size: the size of the RIP2 sector
 * 
 * RETURNS: RIP2_SUCCESS when successful, RIP2_ERR_INV_RIP or RIP2_ERR_NOMEM 
 *          upon error.
 */
int rip2_init(uint8_t       *ripPtr,
              int           verify,
              unsigned int  size);


/*
 * Finds the first index item with the given RIP2 ID and the valid flag set
 * item is filled with the exact contents of the flash, untranslated.
 *
 * RETURNS: RIP2_ERR_NOELEM if no matching index found, 
 *          RIP2_SUCCESS otherwise
 */
int rip2_get_idx(T_RIP2_ID    id,
                 T_RIP2_ITEM  *item);

/*
 * find the first index item with the given RIP2 ID and the valid flag set.
 * fields of item are translated and ready for use
 */
int rip2_get_item(T_RIP2_ID id,
                  T_RIP2_ITEM *item);

/*
 * Returns the data pointer for the first index item with the given RIP2 ID
 * and the valid flag set.  Returns length if length!=NULL.
 * If raw != 0 then data is returned as they are present in rip2.
 *
 * RETURNS: RIP2_ERR_NOELEM if no matching index found
 *          RIP2_ERR_BADCRC if a CRC error was detected
 *          RIP2_SUCCESS otherwise
 */
int rip2_get_data_ex(uint8_t    *ripStart,
                     T_RIP2_ID  id,
                     uint8_t    *data,
                     uint32_t   *length,
                     int        raw);

/*
 * Returns the data pointer for the first index item with the given RIP2 ID
 * and the valid flag set
 *
 * RETURNS: RIP2_ERR_NOELEM if no matching index found
 *          RIP2_ERR_BADCRC if a CRC error was detected
 *          RIP2_SUCCESS otherwise
 */
int rip2_get_data(uint8_t   *ripStart,
                  T_RIP2_ID id,
                  uint8_t   *data);

/*
 * Copies the data for the first index item with the given RIP2 ID
 * and the valid flag set and updates length accordingly.
 *
 * RETURNS: RIP2_ERR_NOELEM if no matching index found
 *          RIP2_ERR_BADCRC if a CRC error was detected
 *          RIP2_SUCCESS otherwise
 */

int rip2_drv_read (unsigned long *length, T_RIP2_ID id, void *data);

/*
 * Returns the length for the first index item with the given RIP2 ID
 * and the valid flag set.
 *
 * RETURNS: RIP2_ERR_NOELEM if no matching index found
 *          RIP2_ERR_BADCRC if a CRC error was detected
 *          RIP2_SUCCESS otherwise
 */

static inline int rip2_drv_read_length(unsigned long *length, T_RIP2_ID id)
{
    return rip2_drv_read(length, id, NULL);
}

/*
 * Updates a rip2 field; if it does not yet exist, this performs rip2_add_item
 *
 * RETURNS: RIP2_SUCCESS if the item was successfully written
 *          RIP2_ERR_PERM if the flags don't match or there are no write
 *          permissions
 *          RIP2_ERR_NOELEM if no matching element was found (should not
 *          happen).
 */

int rip2_drv_write (uint8_t       *data,
                    size_t	  len,
                    T_RIP2_ID     id,
                    uint32_t      attrHi,
                    uint32_t      attrLo);

/*
 * Locks the data corresponding to RIP2 ID id by disabling the
 * writable flag (if set).
 *
 * RETURNS: 0 if no matching id found
 *          1 otherwise
 */
int rip2_lock(T_RIP2_ID id);

/*
 * Checks if data contains valid signature using EIK and sets flag.
 *
 * RETURNS: RIP2_ERR_NOELEM if no matching id found
 *          RIP2_ERR_PERM if the flags don't match or there are no write
 *          permissions
 *          RIP2_SUCCESS otherwise
 */
int rip2_set_signed(T_RIP2_ID id);

/*
 * Encrypts the data corresponding to RIP2 ID id using ECK.
 * First checks if item has RIP2_ATTR_N_EIK_SIGN flag set.
 *
 * RETURNS: RIP2_ERR_NOELEM if no matching id found
 *          RIP2_ERR_PERM if the flags don't match or there are no write
 *          permissions
 *          RIP2_SUCCESS otherwise
 */
int rip2_encrypt(T_RIP2_ID id);

/*
 * Performs some checks to determine whether the RIP2 content is ok:
 * - A CRC check on all elements
 * - Verify required crypto settings
 *
 * RETURNS: RIP2_SUCCESS if all ok
 *          RIP2_ERR_BADCRC if CRC is invalid
 *          RIP2_ERR_BADCRYPTO if some crypto requirement is not met
 */
int rip2_is_valid(uint8_t *ripStart);


/*
 * Iterates over all index items which match the flags passed as an argument.
 * In case a NULL iterator was passed, the iterator will be restarted from
 * the RIP start address.
 * In case a non-NULL iterator was passed, the iterator continues from the last
 * entry it returned.
 *
 * RETURNS: RIP2_ERR_INV_RIP if an invalid start address was passed,
 *          RIP2_ERR_NOELEM if no matching index found
 *          RIP2_SUCCESS otherwise
 */
int rip2_get_next(T_RIP2_ITEM     **from,
                  const uint32_t  flags,
                  T_RIP2_ITEM     *item);


int rip2_verify_crc(uint8_t *ripStart);


#endif /* __T_RIP2_H__ */
