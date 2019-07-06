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
** Programmer(s) : Gino Peeters (email : gino.peeters@technicolor.com)      **
**                                                                          **
******************************************************************************/

#include "rip2.h"

#define INTEGRKEYSIZE     256
#define CONFIDKEYSIZE     16

typedef struct crypt_key_t {
    int           length;     /* in bytes */
    unsigned char *key;       /* Only pointers; we don't to copy the BEK */
    unsigned char *iv;
} crypt_key;

#define SKIP_SIGNATURE_CHECK    ((unsigned char *) 0xFFFFFFFE)

typedef struct sign_key_t {
    int           length;       /* in bytes*/
    unsigned char *key;
} sign_key;

extern crypt_key    bek;
extern crypt_key    eck;
extern sign_key     eik;
extern sign_key     mcv;

#define RIP2SECRETSMAGIC    0xD104EA5B

typedef struct {
    T_RIP2_ID     id;
    uint32_t      length;
    unsigned char *data;
} Rip2SecretsItem;

typedef struct {
    unsigned int    magic;
    unsigned int    version;
    Rip2SecretsItem items[];
} Rip2Secrets;

/*
 * Initializes the rip2 crypto module
 * IN: ripStart: reference address for all RIPv2 actions (usually beginning of the flash)
 * 
 * RETURNS: RIP2_SUCCESS when successful, RIP2_ERR_BADCRYPTO upon error.
 */
int rip2_crypto_init(uint8_t *ripStart);

/*
 * Verifies whether all cryptographic requirements of the eRIPv2 are met
 * IN: ripStart: reference address for all RIPv2 actions (usually beginning of the flash)
 * 
 * RETURNS: RIP2_SUCCESS when successful, RIP2_ERR_BADCRYPTO upon error.
 */
int rip2_crypto_check(uint8_t *ripStart);

/*
 * Stores the keys to be passed to the OS in ram, and returns a pointer to this data 
 *
 * RETURNS: pointer when successful, 0 upon error
 */
unsigned char *rip2_crypto_pass_linux(void);

int rip2_crypto_import_eik(unsigned char *data, int length);
int rip2_crypto_import_eck(unsigned char *data, int length);

/*
 * Process an item with a crypto attribute set; processing means checking the signature and/or 
 * decrypting the item.  
 * IN: data: the raw data (signed/crypted) as found in the eRIPv2 sector
 *     length: total length of the raw data; on successful return this becomes the real length
 *     crypto_attr: the cryptographic attributes
 * 
 * RETURNS: RIP2_SUCCESS when successful, RIP2_ERR_BADCRYPTO upon error.
 */
int rip2_crypto_process(uint8_t       *data,
                        uint32_t      *length,
                        uint32_t      crypto_attr,
                        T_RIP2_ID     id);

int rip2_crypto_encrypt_with_ECK (uint8_t *data, uint32_t *length);

