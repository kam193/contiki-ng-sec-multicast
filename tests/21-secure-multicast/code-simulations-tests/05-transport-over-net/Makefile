CONTIKI_PROJECT = intermidiate
all: $(CONTIKI_PROJECT)

CONTIKI = ../../../..

include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_NET_DIR)/ipv6/multicast

MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC
include $(CONTIKI)/Makefile.include
