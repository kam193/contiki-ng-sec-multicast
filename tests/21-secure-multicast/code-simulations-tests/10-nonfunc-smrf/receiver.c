#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"

#include "../certs.h"
#include "../utils.h"

#include "../simconf.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

static struct uip_udp_conn *sink_conn;
// static char guard[] = "mytest";
static clock_time_t current, tmp;

/*---------------------------------------------------------------------------*/
PROCESS(mcast_sink_process, "Multicast Receiver NETWORK A");
AUTOSTART_PROCESSES(&mcast_sink_process);
/*---------------------------------------------------------------------------*/
void
test_handler(void)
{
  current = clock_time();
  if(uip_newdata()) {
    if(uip_len != EXPECTED_LENGTH || memcmp(uip_appdata, guard, sizeof(guard))) {
      PRINTF("[--failed--]\n");
      return;
    }

    memcpy(&tmp, uip_appdata + sizeof(guard), sizeof(tmp));
    PRINTF("[--got--] %d (%d -> %d)\n", current - tmp, tmp, current);
  }
  return;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(mcast_sink_process, ev, data)
{
  PROCESS_BEGIN();

  if(join_mcast_group(&NETWORK_A) == NULL) {
    SIMPRINTF("Failed to join multicast group\n");
    FAIL_NOT_0(0);
  }

  sink_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(sink_conn, UIP_HTONS(MCAST_SINK_UDP_PORT));

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      test_handler();
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/