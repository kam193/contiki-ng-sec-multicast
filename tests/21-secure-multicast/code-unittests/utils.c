#include <stdio.h>
#include <memory.h>

#include "net/ipv6/uip-ds6.h"

#include "ext-ut.h"

static char module_name[MAX_MODULE_NAME + 1] = { 0 };

uip_ipaddr_t NETWORK_A = { { 0xFF, 0x1E, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x89, 0xA0, 0x0D } };
uip_ipaddr_t NETWORK_NOT_SUPPORTED = { { 0xFF, 0x1E, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x89, 0xA1, 0x1D } };

void
register_module_name(const char *name, int len)
{
  memset(module_name, 0, MAX_MODULE_NAME + 1);
  memcpy(module_name, name, MIN(len, MAX_MODULE_NAME));
}
void
print_test_report(const unit_test_t *utp)
{
  printf("[=check-me=] %s: %s... ", module_name, utp->descr);
  if(utp->result == unit_test_failure) {
    printf("FAILED at line %u\n", utp->exit_line);
  } else {
    printf("SUCCEEDED\n");
  }
}