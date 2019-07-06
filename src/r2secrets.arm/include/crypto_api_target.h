
#define CAPI_MAX_ENC_CTX_SIZE   632 /* AES (Rijndael keyInstance * 2) */
#define CAPI_MAX_AUTH_CTX_SIZE  256

#define MIN_RSA_MODULUS_BITS 508
#define MAX_RSA_MODULUS_BITS 2048
#define MAX_RSA_MODULUS_LEN ((MAX_RSA_MODULUS_BITS + 7) / 8)

#define RSA_MODULUS_LEN     256
#define RSA_PRIME_LEN       128

typedef struct {
    unsigned int  bits;                         /* length in bits of modulus */
    unsigned char modulus[RSA_MODULUS_LEN];     /* modulus */
    unsigned char exponent[RSA_MODULUS_LEN];    /* public exponent */
} R_RSA_PUBLIC_KEY;

typedef struct {
    unsigned int  bits;                             /* length in bits of modulus */
    unsigned char modulus[RSA_MODULUS_LEN];         /* modulus */
    unsigned char publicExponent[RSA_MODULUS_LEN];  /* public exponent */
    unsigned char exponent[RSA_MODULUS_LEN];        /* private exponent */
    unsigned char prime[2][RSA_PRIME_LEN];          /* prime factors */
    unsigned char primeExponent[2][RSA_PRIME_LEN];  /* exponents for CRT */
    unsigned char coefficient[RSA_PRIME_LEN];       /* CRT coefficient */
} R_RSA_PRIVATE_KEY;

#define RSA_CTX_SIZE                            (sizeof(R_RSA_PRIVATE_KEY) + 4)

#define IV_LENGTH 16

