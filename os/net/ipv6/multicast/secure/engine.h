/**
 * \file
 *    Header for providing secure functions for messages. This is
 *    Local Secure Functions Module
 *
 *
 * \author  Kamil Mańkowski
 *
 */

#ifndef ENGINE_H_
#define ENGINE_H_

#include "contiki.h"
#include <stdint.h>

#include "net/ipv6/uip.h"
#include "errors.h"
#include "common_engine.h"
#include "aes_cbc.h"

/* Configurations and constants */

#ifndef SEC_MAX_GROUP_DESCRIPTORS
#define SEC_MAX_GROUP_DESCRIPTORS 3
#endif

#ifndef SEC_MAX_QUEUE_SIZE
#define SEC_MAX_QUEUE_SIZE 5
#endif

#define KEY_REQUEST_DATA_SIZE (TIMESTAMP_SIZE + sizeof(uip_ip6addr_t))

/* When retry get cert */
#ifndef SEC_QUEUE_RETRY_TIME
#define SEC_QUEUE_RETRY_TIME 500
#endif

#ifndef SEC_QUEUE_MAX_RETRY
#define SEC_QUEUE_MAX_RETRY 3
#endif

#ifndef SEC_MODE_DRIVERS_LIST
#define SEC_MODE_DRIVERS_PTR_LIST &aes_cbc_driver
#endif

/* Packet processing */

#define PROCESS_UPPER   0
#define DROP_PACKET     1

/* Functions */

int decode_bytes_to_security_descriptor(struct sec_certificate *cert, const uint8_t *data, uint16_t size);
int import_group_security_descriptor(struct sec_certificate *certificate);

/* TODO: general init engine */

int process_incoming_packet(uip_ip6addr_t *dest_addr, uint8_t *message, uint16_t message_len, uint8_t *out_buffer, uint32_t *out_len);
int process_outcomming_packet(uip_ip6addr_t *dest_addr, uint8_t *message, uint16_t message_len, uint8_t *out_buffer, uint32_t *out_len);

#endif /* ENGINE_H_ */
