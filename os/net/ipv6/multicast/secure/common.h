
/* IS_0 if expr is 0, otherwise return -1 */
#define CHECK_0(expr)   if((expr) != 0) { return -1; }

#define CHECK_1(expr)   if((expr) != 1) { return -1; }

#define RANDOM_CHAR() (uint8_t)(random_rand() % 256)