#ifndef __CRYPTO_API_H__
#define __CRYPTO_API_H__

#define RSA_KEYFORMAT_2048_PUBLICMODULUSONLY    2
#define RSA_KEYFORMAT_1024_PUBLICMODULUSONLY    3

int aes_create_crypto(unsigned char *iv, unsigned char *key, int key_len_bits, void *crypto_ctx, int size_of_ctx);
int aes_encrypt_blocks(void *crypto_ctx, unsigned char *idata, unsigned int numBytes, unsigned char *odata);
int aes_decrypt_blocks(void *crypto_ctx, unsigned char *idata, unsigned int numBytes, unsigned char *odata);
int aes_destroy_crypto(void *crypto_ctx, int size_of_ctx);

int rsa_create_crypto(unsigned char *key,
                      int           keyformat,
                      void          *crypto_ctx,
                      int           size_of_ctx);
int rsa_delete_crypto(void *crypto_ctx);

int rsa_verifysig_pss_sha256(void           *crypto_ctx,
                             unsigned char  *sig,
                             int            siglen,
                             unsigned char  *data,
                             int            datalen);

void random_get_data(unsigned char *buf, int len);

#include "crypto_api_target.h"

#endif
