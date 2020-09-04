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

#include "../simconf.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

static struct uip_udp_conn *mcast_net_1;
static char buffer[EXPECTED_LENGTH];
static clock_time_t current;

/*---------------------------------------------------------------------------*/
PROCESS(sender, "Multicast Sender Network A");
AUTOSTART_PROCESSES(&sender);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(sender, ev, data)
{
  static uint32_t sent_messages = 0;
  PROCESS_BEGIN();

  static struct etimer timer;
  etimer_set(&timer, 200);

  prepare_mcast(&NETWORK_A, &mcast_net_1);

  FAIL_NOT_0(auth_import_ca_cert(&ca));
  FAIL_NOT_0(auth_import_own_cert(&c2_private_cert));
  FAIL_NOT_0(get_root_cert());

  WAIT_UNTIL_ROOT_CERT();
  
  etimer_set(&timer, START_DELAY * CLOCK_SECOND);
  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&timer)) {
      
      memcpy(buffer, guard, sizeof(guard));
      current = clock_time();
      memcpy(buffer+sizeof(guard), &current, sizeof(current));

      multicast_send(mcast_net_1, buffer, sizeof(buffer));
      PRINTF("[--note--] Send on %d\n", current);
      ++sent_messages;

      if(sent_messages >= MESSAGES) {
        break;
      }
      etimer_set(&timer, PAUSE * CLOCK_SECOND);
    }
  }

  SIMPRINTF("[DONE]\n");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
