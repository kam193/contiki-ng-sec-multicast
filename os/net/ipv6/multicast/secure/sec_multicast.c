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
#include "net/ipv6/multicast/secure/sec_multicast.h"
#include "net/packetbuf.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

static unsigned char buffer[120];
static unsigned char mess_buffer[120];
int was_error = 0;
Aes encryption_engine;
Aes decryption_engine;

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
    byte key[] = "abcdabcdabcdabcd";
    byte iv[]  = "1234123412341234";
    check(wc_AesSetKey(&encryption_engine, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION), "init_enc");
    check(wc_AesSetKey(&decryption_engine, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION), "init_dec");
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
    uint32_t data_len;
    memset(buffer, 0, sizeof(buffer));
    
    // TODO: Data need to be aligned!
    data_len = uip_len - UIP_IPUDPH_LEN;
    // out_size = sizeof(buffer);

    memcpy(mess_buffer, &(uip_buf[UIP_IPUDPH_LEN]), data_len);

    // print_chars(data_len, mess_buffer);

    check(wc_AesCbcEncrypt(&encryption_engine, buffer, mess_buffer, data_len), "encrypt");
    
    memcpy(mess_buffer, buffer, data_len);
    print_chars(data_len, mess_buffer);


    // Updata packet and length -> TODO: safe (check size)
    memcpy(&uip_buf[UIP_IPUDPH_LEN], buffer, data_len);
    uip_slen = data_len;
    uip_len = UIP_IPUDPH_LEN + data_len;
    uipbuf_set_len_field(UIP_IP_BUF, uip_len - UIP_IPH_LEN);
    UIP_UDP_BUF->udplen = UIP_HTONS(data_len + UIP_UDPH_LEN);
    PRINT6ADDR(&UIP_IP_BUF->destipaddr);
    PRINTF("<-send\n");

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
    data_len = uip_len - UIP_IPUDPH_LEN;
    print_chars(data_len, &uip_buf[UIP_IPUDPH_LEN]);
    check(wc_AesCbcDecrypt(&decryption_engine, buffer, &uip_buf[UIP_IPUDPH_LEN], data_len), "decrypt");
    print_chars(data_len, buffer);
    memcpy(&uip_buf[UIP_IPUDPH_LEN], buffer, data_len);
    // print_chars(out_size, &uip_buf[UIP_IPUDPH_LEN]);
    uip_slen = data_len;
    uip_len = UIP_IPUDPH_LEN + data_len;
    uipbuf_set_len_field(UIP_IP_BUF, uip_len - UIP_IPH_LEN);
    UIP_UDP_BUF->udplen = UIP_HTONS(data_len + UIP_UDPH_LEN);
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
