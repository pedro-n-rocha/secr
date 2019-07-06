#include "rip2_config.h"

#if defined(__BYTE_ORDER)
 #if __BYTE_ORDER == __BIG_ENDIAN
  #define HTOBE16(x)    (x)
  #define HTOBE32(x)    (x)
  #define BETOH16(x)    (x)
  #define BETOH32(x)    (x)
 #elif __BYTE_ORDER == __LITTLE_ENDIAN
  #define HTOBE16(x)    ( bswap_16(x))
  #define HTOBE32(x)    ( bswap_32(x))
  #define BETOH16(x)    ( bswap_16(x))
  #define BETOH32(x)    ( bswap_32(x))
 #else
  #error Please define the correct endianness (__BYTE_ORDER defined)
 #endif
#else
 #if defined(__BIG_ENDIAN)
  #define HTOBE16(x)    (x)
  #define HTOBE32(x)    (x)
  #define BETOH16(x)    (x)
  #define BETOH32(x)    (x)
 #elif defined (__LITTLE_ENDIAN)
  #define HTOBE16(x)    ( bswap_16(x))
  #define HTOBE32(x)    ( bswap_32(x))
  #define BETOH16(x)    ( bswap_16(x))
  #define BETOH32(x)    ( bswap_32(x))
 #else
  #error Please define the correct endianness (__BYTE_ORDER not defined)
 #endif
#endif


int rip2_crypto_init(uint8_t *ripStart);

