CONTIKI_PROJECT = root
all: $(CONTIKI_PROJECT)

PROJECT_SOURCEFILES += ../utils.c

CONTIKI = ../../../..

include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_NET_DIR)/ipv6/multicast/secure

MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC
include $(CONTIKI)/Makefile.include
