/* File comes from contiki examples */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/multicast/secure/engine.h"
#include "net/ipv6/multicast/secure/authorization.h"
#include "net/ipv6/multicast/secure/remote_engine.h"
#include "net/ipv6/multicast/secure/server.h"

#include "../certs.h"
#include "../utils.h"

#include <string.h>
#include <inttypes.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"
#include "net/routing/routing.h"

/*---------------------------------------------------------------------------*/
PROCESS(rpl_root_process, "ROOT");
AUTOSTART_PROCESSES(&rpl_root_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rpl_root_process, ev, data)
{
  static struct etimer timer;

  PROCESS_BEGIN();

  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);

  FAIL_NOT_0(auth_import_ca_cert(&ca));
  FAIL_NOT_0(auth_import_own_cert(&rp_private_cert));

  NETSTACK_ROUTING.root_start();
  FAIL_NOT_0(start_group_descriptors_server());
  SIMPRINTF("Root initialized\n");

  etimer_set(&timer, 11 * CLOCK_SECOND);

  PROCESS_YIELD_UNTIL(etimer_expired(&timer));
  FAIL_NOT_0(register_group_security(&NETWORK_A, SEC_MODE_AES_CBC, 90));
  SIMPRINTF("Group security set\n");

  while(1) {
    PROCESS_YIELD();
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
