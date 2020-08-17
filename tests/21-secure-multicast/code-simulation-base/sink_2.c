/* Based on one of examples */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/multicast/secure/engine.h"
#include "random.h"

#include "certs.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

#define FAIL_NOT_0(expr) if((expr) != 0) { PRINTF("[CRITICAL]\n"); PROCESS_EXIT(); }

#define MCAST_SINK_UDP_PORT 3001

static struct uip_udp_conn *sink_conn;
static uip_ipaddr_t addr;

/*---------------------------------------------------------------------------*/
PROCESS(mcast_sink_process, "Multicast Sink NETWORK 2");
AUTOSTART_PROCESSES(&mcast_sink_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  if(uip_newdata()) {
    PRINTF("[SIMULATION] Got: %.*s\n", uip_len, (unsigned char *)uip_appdata);
  }
  return;
}
/*---------------------------------------------------------------------------*/
static uip_ds6_maddr_t *
join_mcast_group(uip_ipaddr_t *maddr)
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
PROCESS_THREAD(mcast_sink_process, ev, data)
{
  PROCESS_BEGIN();

  uip_ip6addr(&addr, 0xFF1E, 0, 0, 0, 0, 0, 0x89, 0xA00D);

  if(join_mcast_group(&addr) == NULL) {
    PRINTF("Failed to join multicast group\n");
    FAIL_NOT_0(0);
  }

  sink_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(sink_conn, UIP_HTONS(MCAST_SINK_UDP_PORT));

  static struct etimer periodic_timer;
  etimer_set(&periodic_timer, 200);

  FAIL_NOT_0(certexch_import_ca_key(&ca));
  FAIL_NOT_0(certexch_import_own_cert(&c4_private_cert));

  uip_ipaddr_t root_addr;
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
    if(NETSTACK_ROUTING.node_is_reachable() && NETSTACK_ROUTING.get_root_ipaddr(&root_addr)) {
      FAIL_NOT_0(get_rp_cert());
      PRINTF("[SIMULATION] Got RP cert\n");
      break;
    }
    etimer_set(&periodic_timer, 200);
  }

  /* Since get_rp_cert is not-blocking */
  etimer_set(&periodic_timer, 2 * CLOCK_SECOND);
  PROCESS_YIELD_UNTIL(etimer_expired(&periodic_timer));
  etimer_stop(&periodic_timer);

  FAIL_NOT_0(get_certificate_for(&addr));
  PRINTF("[SIMULATION] Manually get cert for ");
  PRINT6ADDR(&addr);
  PRINTF("\n");

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
