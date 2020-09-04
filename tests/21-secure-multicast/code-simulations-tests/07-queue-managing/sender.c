/* Based on one of examples */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/multicast/secure/engine.h"
#include "net/ipv6/multicast/secure/end_device.h"
#include "random.h"

#include "../certs.h"
#include "../utils.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

static struct uip_udp_conn *mcast_net_1;

/* Start sending messages START_DELAY secs after we start so that routing can
 * converge */
#define START_DELAY 30

/*---------------------------------------------------------------------------*/
PROCESS(sender, "Multicast Sender Network A");
AUTOSTART_PROCESSES(&sender);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(sender, ev, data)
{
  PROCESS_BEGIN();

  static struct etimer timer;

  prepare_mcast(&NETWORK_A, &mcast_net_1);

  FAIL_NOT_0(auth_import_ca_cert(&ca));
  FAIL_NOT_0(auth_import_own_cert(&c2_private_cert));
  FAIL_NOT_0(get_root_cert());

  WAIT_UNTIL_ROOT_CERT();

  /* Send a few packets to overflow queue */
  for(int i = 0; i < SEC_MAX_QUEUE_SIZE + 2; ++i) {
    multicast_send(mcast_net_1, "this_is_test", 12);
  }
  SIMPRINTF("Queue overflowed.\n");

  // Now wait until queue is empty by retry limit
  etimer_set(&timer, 10 * CLOCK_SECOND);
  PROCESS_YIELD_UNTIL(etimer_expired(&timer));

  /* Now send packets that be sent */
  for(int i = 0; i < SEC_MAX_QUEUE_SIZE + 2; ++i) {
    multicast_send(mcast_net_1, "this_is_test", 12);
  }
  SIMPRINTF("DONE\n");

  while(1) {
    PROCESS_YIELD();
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
