
/* #include "utils.h" */
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/uip-ds6.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

#include "utils.h"

uip_ipaddr_t NETWORK_A = { { 0xFF, 0x1E, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x89, 0xA0, 0x0D } };

static char buf[MAX_PAYLOAD_LEN];

/*---------------------------------------------------------------------------*/
/* Receiving helpers */
/*---------------------------------------------------------------------------*/
uip_ds6_maddr_t *
join_mcast_group(const uip_ipaddr_t *maddr)
{
  uip_ds6_maddr_t *rv;
  uip_ipaddr_t tmp;
  const uip_ipaddr_t *default_prefix = uip_ds6_default_prefix();

  /* First, set our v6 global */
  uip_ip6addr_copy(&tmp, default_prefix);
  uip_ds6_set_addr_iid(&tmp, &uip_lladdr);
  uip_ds6_addr_add(&tmp, 0, ADDR_AUTOCONF);

  rv = uip_ds6_maddr_add(maddr);

  if(rv) {
    PRINTF("[SIMULATION] Joined multicast group ");
    PRINT6ADDR(&uip_ds6_maddr_lookup(maddr)->ipaddr);
    PRINTF("\n");
  }
  return rv;
}
/*---------------------------------------------------------------------------*/
void
tcpip_handler(void)
{
  if(uip_newdata()) {
    SIMPRINTF("Got: %.*s\n", uip_len, (unsigned char *)uip_appdata);
  }
  return;
}
/*---------------------------------------------------------------------------*/
/* Sending helpers */
/*---------------------------------------------------------------------------*/
void
multicast_send(struct uip_udp_conn *connection, const char message[], size_t len)
{
  SIMPRINTF("Sending message to ");
  PRINT6ADDR(&connection->ripaddr);
  PRINTF("\n");
  memset(buf, 0, MAX_PAYLOAD_LEN);
  memcpy(buf, message, len);
  uip_udp_packet_send(connection, buf, len);
}
/*---------------------------------------------------------------------------*/
void
prepare_mcast(uip_ipaddr_t *addr, struct uip_udp_conn **connection)
{
  *connection = udp_new(addr, UIP_HTONS(MCAST_SINK_UDP_PORT), NULL);
}