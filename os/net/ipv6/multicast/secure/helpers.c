
#include "contiki.h"
#include "lib/random.h"

#include "helpers.h"

void
generate_random_chars(uint8_t *dest, size_t length)
{
  while(length > 0) {
    dest[length - 1] = RANDOM_CHAR();
    length--;
  }
}