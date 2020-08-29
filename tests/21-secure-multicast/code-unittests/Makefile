all: test-authorization
PROJECT_SOURCEFILES += utils.c

CONTIKI = ../../..

include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_NET_DIR)/ipv6/multicast/secure
MODULES += $(CONTIKI_NG_SERVICES_DIR)/unit-test

MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC
include $(CONTIKI)/Makefile.include
