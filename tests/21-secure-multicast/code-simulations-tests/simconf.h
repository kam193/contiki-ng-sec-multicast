#ifndef SIM_CONF_H_
#define SIM_CONF_H_

#include "clock.h"

#define REFRESH_KEY 120
#define MESSAGES 1000
#define PAUSE 10
#define START_DELAY 180

char guard[] = "mytest";

#define EXPECTED_LENGTH sizeof(guard) + sizeof(clock_time_t)

#endif