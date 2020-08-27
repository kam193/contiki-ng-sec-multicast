/* File comes from contiki examples */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/multicast/secure/engine.h"
#include "net/ipv6/multicast/secure/authorization.h"
#include "net/ipv6/multicast/secure/remote_engine.h"
#include "net/ipv6/multicast/secure/server.h"

#include "certs.h"

#include <string.h>
#include <inttypes.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"
#include "net/routing/routing.h"

#define FAIL() PRINTF("[CRITICAL]\n"); PROCESS_EXIT();
#define FAIL_NOT_0(expr) if((expr) != 0) { FAIL(); }

#define MAX_PAYLOAD_LEN 120
#define MCAST_SINK_UDP_PORT 3001
#define SEND_INTERVAL CLOCK_SECOND
#define ITERATIONS 5

/* Start sending messages START_DELAY secs after we start so that routing can
 * converge */
#define START_DELAY 30

static struct uip_udp_conn *mcast_net_1;
static struct uip_udp_conn *mcast_net_2;

static char test_message[] = "this_is_test";
static uip_ipaddr_t ipaddr_net1;
static uip_ipaddr_t ipaddr_net2;

static char buf[MAX_PAYLOAD_LEN];

/*---------------------------------------------------------------------------*/
PROCESS(rpl_root_process, "RPL ROOT, Multicast Sender");
AUTOSTART_PROCESSES(&rpl_root_process);
/*---------------------------------------------------------------------------*/
static void
multicast_send(struct uip_udp_conn *connection)
{
  PRINTF("[SIMULATION] Sending message to ");
  PRINT6ADDR(&connection->ripaddr);
  PRINTF("\n");
  memset(buf, 0, MAX_PAYLOAD_LEN);
  memcpy(buf, test_message, sizeof(test_message));
  uip_udp_packet_send(connection, buf, sizeof(test_message));
}
/*---------------------------------------------------------------------------*/
static void
prepare_mcast(uip_ipaddr_t *addr, struct uip_udp_conn **connection)
{
  *connection = udp_new(addr, UIP_HTONS(MCAST_SINK_UDP_PORT), NULL);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rpl_root_process, ev, data)
{
  static struct etimer et;

  PROCESS_BEGIN();

  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);

  uip_ip6addr(&ipaddr_net1, 0xFF1E, 0, 0, 0, 0, 0, 0x89, 0xABCD);
  uip_ip6addr(&ipaddr_net2, 0xFF1E, 0, 0, 0, 0, 0, 0x89, 0xA00D);

  FAIL_NOT_0(secure_group(&ipaddr_net1, SEC_MODE_AES_CBC, 5));
  FAIL_NOT_0(secure_group(&ipaddr_net2, SEC_MODE_AES_CBC, 5));
  if(secure_group(&ipaddr_net2, SEC_MODE_AES_CBC, 5) != ERR_GROUP_EXISTS) {
    FAIL();
  }

  FAIL_NOT_0(auth_import_ca_cert(&ca));
  FAIL_NOT_0(auth_import_own_cert(&rp_private_cert));

  NETSTACK_ROUTING.root_start();

  prepare_mcast(&ipaddr_net1, &mcast_net_1);
  prepare_mcast(&ipaddr_net2, &mcast_net_2);

  FAIL_NOT_0(init_cert_server());

  etimer_set(&et, START_DELAY * CLOCK_SECOND);
  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&et)) {
      multicast_send(mcast_net_1);
      multicast_send(mcast_net_2);
      etimer_set(&et, 10 * CLOCK_SECOND);
      PROCESS_YIELD_UNTIL(etimer_expired(&et));
      multicast_send(mcast_net_1);
      multicast_send(mcast_net_2);
      break;
    }
  }

  PRINTF("[SIMULATION] [DONE]\n");

  etimer_set(&et, 10 * CLOCK_SECOND);
  while(1) {
    PROCESS_YIELD();
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
