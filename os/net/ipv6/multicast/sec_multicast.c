/**
 * \file
 *         This file shows the implementations of additional security layer
 *         for multicast communication.
 *
 * \author  Kamil Mańkowski
 *
 */

#include "contiki.h"
#include "contiki-net.h"
// #include "net/ipv6/uip.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/multicast/sec_multicast.h"
#include "net/packetbuf.h"

#ifndef WOLFSSL_TYPES
#ifndef byte
typedef unsigned char byte;
#endif
#ifdef WC_16BIT_CPU
typedef unsigned int word16;
typedef unsigned long word32;
#else
typedef unsigned short word16;
typedef unsigned int word32;
#endif
typedef byte word24[3];
#endif

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

static unsigned char buffer[120];
static unsigned char mess_buffer[120];
ecc_key reciver_key, sender_key;
int was_error = 0;

extern uint16_t uip_slen;

void
check(int code, char desc[])
{
  if(code != 0) {
    PRINTF("ERROR: %d! In: %s\n", code, desc);
    /* exit(code); */
    was_error = code;
  }
}
void
print_chars(int len, unsigned char buffer[])
{
  PRINTF("Out: %i    ", len);
  // for(int i = 0; i < len; i++) {
  //   PRINTF("%c", buffer[i]);
  // }
  PRINTF("%.*s", len, buffer);
  PRINTF("\n");
}
static void
init()
{
  if(was_error == 0) {
    check(wc_ecc_init(&reciver_key), "ecc_init_receiver");
    check(wc_ecc_init(&sender_key), "ecc_init_sender");

    byte pub[] = { 0x4, 0x1c, 0x24, 0x89, 0xd5, 0xaf, 0xd4, 0x57, 0x24, 0xb0, 0x50, 0x31, 0xdf, 0x27, 0x3, 0x75, 0xc8, 0x33, 0x66, 0x94,
                   0xf6, 0x5c, 0xeb, 0xda, 0, 0x1e, 0x1, 0x11, 0x56, 0x12, 0x8f, 0xff, 0x5b };
    byte priv[] = { 0x42, 0xc5, 0x33, 0xe4, 0x7c, 0x36, 0x97, 0xd8, 0xbe, 0x31, 0xd6, 0xc, 0x40, 0x2e, 0x23, 0x48 };
    check(wc_ecc_import_private_key(priv, sizeof(priv), pub, sizeof(pub), &reciver_key), "import");

    byte pub2[] = { 0x4, 0xc3, 0xbc, 0xb1, 0xf9, 0x39, 0xe8, 0x5b, 0xca, 0x8e, 0x68, 0xf3, 0x7a, 0x48, 0xc5, 0xe3, 0xa6, 0x2a, 0xe2, 0x6, 0xa1, 0x7d, 0x7f, 0x4e, 0x4, 0xe5, 0x12, 0x46, 0x6d, 0x61, 0x8a, 0xa4, 0x40 };
    byte priv2[] = { 0x98, 0x32, 0xa, 0xfe, 0x83, 0x9f, 0xc1, 0xe, 0x6a, 0x48, 0xfb, 0x4f, 0, 0xf8, 0x37, 0xaf };
    check(wc_ecc_import_private_key(priv2, sizeof(priv2), pub2, sizeof(pub2), &sender_key), "import send");
  } else {
    PRINTF("SKIPPED\n");
  }

  SEC_MULTICAST_BASE_DRIVER.init();
}
/*---------------------------------------------------------------------------*/
static void
out(void)
{
  if(was_error == 0) {
    uint32_t data_len, out_size;
    memset(buffer, 0, sizeof(buffer));
    /* check(wc_ecc_init(&sender_key), "ecc_init"); */

    data_len = uip_len - UIP_IPUDPH_LEN;
    out_size = sizeof(buffer);

    memcpy(mess_buffer, &(uip_buf[UIP_IPUDPH_LEN]), data_len);

    print_chars(data_len, mess_buffer);

    check(wc_ecc_encrypt(&sender_key, &reciver_key, mess_buffer, data_len, buffer, &out_size, NULL), "enc");

    memcpy(mess_buffer, buffer, out_size);
    print_chars(out_size, mess_buffer);


    // Updata packet and length -> TODO: safe (check size)
    memcpy(&uip_buf[UIP_IPUDPH_LEN], buffer, out_size);
    print_chars(out_size, &uip_buf[UIP_IPUDPH_LEN]);
    uip_slen = out_size;
    uip_len = UIP_IPUDPH_LEN + out_size;
    uipbuf_set_len_field(UIP_IP_BUF, uip_len - UIP_IPH_LEN);
    UIP_UDP_BUF->udplen = UIP_HTONS(out_size + UIP_UDPH_LEN);

    // TODO: updating checksum
    /* uint32_t secret = 123; */
    /* uint32_t i; */

    /* for(i = 0; i < data_len; i++) { */
    /*   uip_buf[UIP_IPUDPH_LEN + i] = (uip_buf[UIP_IPUDPH_LEN + i]) ^ secret; */
    /* } */

    /* wc_ecc_free(&reciver_key); */
    /* wc_ecc_free(&sender_key); */
  } else {
    PRINTF("SKIPPED OUT\n");
  }

  SEC_MULTICAST_BASE_DRIVER.out();
}
/*---------------------------------------------------------------------------*/
static uint8_t
in()
{
  /* uint32_t secret = 123; */
  /* uint32_t i; */
  uint32_t data_len;
  uint8_t decision;
  uint32_t mess_size;

  /* PRINTF("INPUT DATA: "); */
  /* for(i = 0; i < data_len; i++) { */
  /*   PRINTF("%u", uip_buf[UIP_IPUDPH_LEN + i]); */
  /* } */
  /* PRINTF("\n"); */

  decision = SEC_MULTICAST_BASE_DRIVER.in();

  /* / * Decrypt message before processing to upper layers * / */
  /* if(decision == UIP_MCAST6_ACCEPT) { */
  /*   data_len = uip_len - UIP_IPUDPH_LEN; */
  /*   for(i = 0; i < data_len; i++) { */
  /*     uip_buf[UIP_IPUDPH_LEN + i] = (uip_buf[UIP_IPUDPH_LEN + i]) ^ secret; */
  /*   } */
  /* } */

  if(decision == UIP_MCAST6_ACCEPT) {
    mess_size = sizeof(buffer);
    data_len = uip_len - UIP_IPUDPH_LEN;
    print_chars(data_len, &uip_buf[UIP_IPUDPH_LEN]);
    check(wc_ecc_decrypt(&reciver_key, &sender_key, &uip_buf[UIP_IPUDPH_LEN], data_len, buffer, &mess_size, NULL), "decrypt");
    print_chars(mess_size, buffer);
    memcpy(&uip_buf[UIP_IPUDPH_LEN], buffer, mess_size);
    // print_chars(out_size, &uip_buf[UIP_IPUDPH_LEN]);
    uip_slen = mess_size;
    uip_len = UIP_IPUDPH_LEN + mess_size;
    uipbuf_set_len_field(UIP_IP_BUF, uip_len - UIP_IPH_LEN);
    UIP_UDP_BUF->udplen = UIP_HTONS(mess_size + UIP_UDPH_LEN);
  }

  return decision;
}
/*---------------------------------------------------------------------------*/
const struct uip_mcast6_driver sec_multicast_driver = {
  "SEC_MULTICAST",
  init,
  out,
  in,
};
/*---------------------------------------------------------------------------*/
