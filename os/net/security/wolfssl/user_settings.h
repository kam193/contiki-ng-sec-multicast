/* Additional configuration for wolfSSL */
/* This configuration is prepared for multicas secure layer */
/* You can override it by putting 'user_settings.h' in your project's catalog */

#ifndef WOLF_USER_SETTINGS_H_
#define WOLF_USER_SETTINGS_H_

#define HAVE_ECC
#define FP_ECC
#define HAVE_ECC_ENCRYPT
#define HAVE_HKDF

#define WOLFCRYPT_ONLY

#define NO_ERROR_STRINGS
#define NO_MD5
#define NO_SHA
#define NO_PSK
#define NO_RC4
#define NO_PWDBASED
#define NO_RSA
#define NO_DH
#define NO_PKCS12
#undef WOLFSSL_PEM_TO_DER
#undef HAVE_HASHDRBG

#define CURVED25519_SMALL

#define NO_DSA
#define WC_NO_HARDEN

#define WOLFSSL_USER_CURRTIME
#define NO_WOLFSSL_MEMORY
#define NO_OLD_RNGNAME
#define WOLFSSL_SMALL_STACK
#define SINGLE_THREADED
#define NO_SIG_WRAPPER
#define HAVE_SHA512
#define WOLFSSL_SHA512
#define ECC_TIMING_RESISTANT
#define NO_WRITEV
#define NO_DEV_RANDOM
#define NO_FILESYSTEM
#define NO_MAIN_DRIVER
#define NO_MD4
#define NO_RABBIT
#define NO_HC128
#define NO_RC4
#define NO_DES3
#define WOLFSSL_USER_IO

#include <contiki.h>
#include "lib/random.h"
#include "contiki-net.h"

#define CUSTOM_RAND_TYPE uint16_t
#define CUSTOM_RAND_GENERATE random_rand

#define USER_TICKS
static inline unsigned int
LowResTimer(void)
{
  return clock_seconds();
}
#endif