// Additional configuration for wolfSSL
// You can override it by putting 'user_settings.h' in your project's catalog

#ifndef WOLF_USER_SETTINGS_H_
#define WOLF_USER_SETTINGS_H_

// TODO: Analyze following defines, group it logically and remove unused
#define HAVE_ECC
#define FP_ECC
#define HAVE_ECC_ENCRYPT
#define HAVE_HKDF

#define WOLFSSL_SP_SMALL

#define NO_DSA
#define WC_NO_HARDEN

#define WOLFSSL_UIP
#define WOLFSSL_USER_CURRTIME
#define NO_WOLFSSL_MEMORY
#define RSA_LOW_MEM
#define NO_OLD_RNGNAME
#define SMALL_SESSION_CACHE
#define WOLFSSL_SMALL_STACK

#define SINGLE_THREADED
#define NO_SIG_WRAPPER

#define HAVE_FFDHE_2048
#define HAVE_CHACHA
#define HAVE_CURVE25519
#define CURVED25519_SMALL
#define HAVE_ONE_TIME_AUTH
#define WOLFSSL_DH_CONST

#define HAVE_ED25519
#define HAVE_POLY1305
#define HAVE_SHA512
#define WOLFSSL_SHA512

#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

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
static inline unsigned int LowResTimer(void)
{
    return clock_seconds();
}

#endif