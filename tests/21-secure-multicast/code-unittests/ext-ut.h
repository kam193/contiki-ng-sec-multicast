#ifndef EXT_UT_H_
#define EXT_UT_H_

#include "contiki.h"
#include "services/unit-test/unit-test.h"

#define ASSERT_0(expr) UNIT_TEST_ASSERT((expr) == 0);
#define ASSERT_TRUE(expr) UNIT_TEST_ASSERT((expr) == true);
#define ASSERT_FALSE(expr) UNIT_TEST_ASSERT((expr) == false);

#ifdef EXT_SETUP_FUNCTION
#define EXT_SETUP() EXT_SETUP_FUNCTION();
void EXT_SETUP_FUNCTION();
#else
#define EXT_SETUP()
#endif

#ifdef EXT_TEARDOWN_FUNCTION
#define EXT_TEARDOWN() EXT_TEARDOWN_FUNCTION();
void EXT_TEARDOWN_FUNCTION();
#else
#define EXT_TEARDOWN()
#endif

#define EXT_UT_RUN(name) do { \
    EXT_SETUP(); \
    UNIT_TEST_RUN(name); \
    EXT_TEARDOWN(); \
} while(0);

#define MAX_MODULE_NAME 99

void register_module_name(const char *name, int len);

extern uip_ipaddr_t NETWORK_A;
extern uip_ipaddr_t NETWORK_NOT_SUPPORTED;

#endif