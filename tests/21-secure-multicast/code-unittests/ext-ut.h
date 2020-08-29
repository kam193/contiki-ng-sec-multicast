#ifndef EXT_UT_H_
#define EXT_UT_H_

#include "contiki.h"
#include "services/unit-test/unit-test.h"

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

#endif