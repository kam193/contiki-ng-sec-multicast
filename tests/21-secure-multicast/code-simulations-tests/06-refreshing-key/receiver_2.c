/* Based on one of examples */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/multicast/secure/engine.h"
#include "net/ipv6/multicast/secure/end_device.h"
#include "sys/clock.h"
#include "random.h"

#include "../certs.h"
#include "../utils.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

static struct uip_udp_conn *sink_conn;

/* An access to the non-public function due to not possible clock set */
struct sec_certificate *get_certificate(uip_ip6addr_t *group_addr);

static struct sec_certificate tmp;

/*---------------------------------------------------------------------------*/
PROCESS(mcast_sink_process, "Multicast Receiver NETWORK A");
AUTOSTART_PROCESSES(&mcast_sink_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(mcast_sink_process, ev, data)
{
  static struct etimer timer;
  PROCESS_BEGIN();

  if(join_mcast_group(&NETWORK_A) == NULL) {
    SIMPRINTF("Failed to join multicast group\n");
    FAIL_NOT_0(0);
  }

  sink_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(sink_conn, UIP_HTONS(MCAST_SINK_UDP_PORT));

  FAIL_NOT_0(auth_import_ca_cert(&ca));
  FAIL_NOT_0(auth_import_own_cert(&c4_private_cert));
  FAIL_NOT_0(get_rp_cert());

  WAIT_UNTIL_ROOT_CERT();

  PROCESS_YIELD_UNTIL(ev == tcpip_event);
  tcpip_handler();

  /*clock_set_seconds(clock_seconds() - 5); - this function is not supported in the simulator */

  /* Now do a magic to reuse the same key in the future */
  struct sec_certificate *cert = get_certificate(&NETWORK_A);
  FAIL_NOT_0(copy_certificate(&tmp, cert));

  etimer_set(&timer, (cert->valid_until - clock_seconds() + 1) * CLOCK_SECOND);
  tmp.valid_until = clock_seconds() + 20;
  PROCESS_YIELD_UNTIL(etimer_expired(&timer));
  import_group_security_descriptor(&tmp);

  etimer_set(&timer, 20 * CLOCK_SECOND);

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    } else if (ev == PROCESS_EVENT_TIMER && etimer_expired(&timer))
    {
      SIMPRINTF("Timeout\n");
      break;
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
