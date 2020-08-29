#include <stdio.h>
#include <memory.h>

#include "ext-ut.h"

static char module_name[MAX_MODULE_NAME + 1] = { 0 };

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