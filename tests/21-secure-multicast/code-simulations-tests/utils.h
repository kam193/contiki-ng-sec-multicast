#ifndef UTILS_H_
#define UTILS_H_

#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/multicast/uip-mcast6.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

#define FAIL() PRINTF("[CRITICAL]\n"); PROCESS_EXIT();
#define FAIL_NOT_0(expr) if((expr) != 0) { FAIL(); }

#define SIMPRINTF(...) PRINTF("[SIMULATION] "); PRINTF(__VA_ARGS__);

#define MAX_PAYLOAD_LEN 120
#define MCAST_SINK_UDP_PORT 3001

#define WAIT_UNTIL_ROOT_CERT() do { \
    static struct etimer _cert_waiting_timer; \
    while(1) \
    { \
      if(is_root_cert()) { \
        PRINTF("We have the root cert!\n"); \
        break; \
      } \
      etimer_set(&_cert_waiting_timer, 200); \
      PROCESS_YIELD_UNTIL(etimer_expired(&_cert_waiting_timer)); \
    } \
} while(0); \

uip_ds6_maddr_t *join_mcast_group(const uip_ipaddr_t *maddr);
void tcpip_handler(void);

void prepare_mcast(uip_ipaddr_t *addr, struct uip_udp_conn **connection);
void multicast_send(struct uip_udp_conn *connection, const char message[], size_t len);

extern uip_ipaddr_t NETWORK_A;

#endif