
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

#include "aes_cbc.h"
#include "common_engine.h"
#include "helpers.h"
#include "errors.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"
#include "tmp_debug.h"

uint32_t return_code = 0;
extern uint8_t buffer[UIP_BUFSIZE];

/*---------------------------------------------------------------------------*/
/* AES helpers                                                               */
/*---------------------------------------------------------------------------*/
static int
count_aes_padded_size(uint8_t size)
{
  uint8_t padded_size = (size / 16) * 16;
  if(padded_size < size) {
    padded_size += 16;
  }
  return padded_size;
}
int
aes_cbc_encrypt(struct sec_certificate *cert, uint16_t message_len, unsigned char *out_buffer, uint32_t *out_len)
{
  struct secure_descriptor *current_descriptor = cert->secure_descriptor;

  Aes encryption_engine;
  if((return_code = wc_AesSetKey(&encryption_engine, current_descriptor->aes_key,
                                 AES_BLOCK_SIZE, current_descriptor->aes_vi, AES_ENCRYPTION)) != 0) {
    return return_code;
  }

  uint16_t padded_size = count_aes_padded_size(message_len);
  if(padded_size > sizeof(buffer)) {
    return ERR_LIMIT_EXCEEDED;
  }
  for(size_t i = message_len; i < padded_size; ++i) {
    buffer[i] = RANDOM_CHAR();
  }
  print_chars(padded_size - 2, buffer + 2);

  if((return_code = wc_AesCbcEncrypt(&encryption_engine, out_buffer, buffer, padded_size)) != 0) {
    return return_code;
  }

  *out_len = padded_size;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
aes_cbc_decrypt(struct sec_certificate *cert, unsigned char *message,
                uint16_t message_len, unsigned char *out_buffer, uint32_t *out_len)
{
  struct secure_descriptor *current_descriptor = cert->secure_descriptor;

  Aes encryption_engine;
  if((return_code = wc_AesSetKey(&encryption_engine, current_descriptor->aes_key,
                                 AES_BLOCK_SIZE, current_descriptor->aes_vi, AES_DECRYPTION)) != 0) {
    return return_code;
  }

  if((return_code = wc_AesCbcDecrypt(&encryption_engine, out_buffer, message, message_len)) != 0) {
    return return_code;
  }

  *out_len = message_len;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
aes_cbc_bytes_to_descriptor(struct sec_certificate *cert, const uint8_t *data, uint16_t size)
{
  if(sizeof(struct secure_descriptor) > size) {
    return ERR_INCORRECT_DATA;
  }
  cert->secure_descriptor = malloc(sizeof(struct secure_descriptor));
  if(cert->secure_descriptor == NULL) {
    return ERR_MEMORY;
  }
  memcpy(cert->secure_descriptor, data, sizeof(struct secure_descriptor));
  return 0;
}
/*---------------------------------------------------------------------------*/
int
aes_cbc_copy_descriptor(struct sec_certificate *dest, struct sec_certificate *src)
{
  dest->secure_descriptor = malloc(sizeof(struct secure_descriptor));
  if(dest->secure_descriptor == NULL) {
    return ERR_MEMORY;
  }
  memcpy(dest->secure_descriptor, src->secure_descriptor, sizeof(struct secure_descriptor));
  return 0;
}
/*---------------------------------------------------------------------------*/
/* Functions used on coordinator */
/*---------------------------------------------------------------------------*/
int
init_aes_cbc_descriptor(struct sec_certificate *descriptor)
{
  descriptor->secure_descriptor = malloc(sizeof(struct secure_descriptor));
  if(descriptor->secure_descriptor == NULL) {
    return ERR_MEMORY;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
int
aes_cbc_descriptor_to_bytes(struct sec_certificate *cert, uint8_t *buff, uint32_t *size)
{
  if(sizeof(struct secure_descriptor) > *size) {
    return ERR_RESULT_TOO_LONG;
  }
  memcpy(buff, cert->secure_descriptor, sizeof(struct secure_descriptor));
  *size = sizeof(struct secure_descriptor);
  return 0;
}
/*---------------------------------------------------------------------------*/
int
aes_cbc_refresh_key(struct sec_certificate *key_descriptor)
{
  struct secure_descriptor *key_desc = key_descriptor->secure_descriptor;
  generate_random_chars(key_desc->aes_key, sizeof(key_desc->aes_key));
  generate_random_chars(key_desc->aes_vi, sizeof(key_desc->aes_vi));
  return 0;
}
/*---------------------------------------------------------------------------*/
const secure_mode_driver_t aes_cbc_driver = {
  .mode = SEC_MODE_AES_CBC,
  .init_descriptor = init_aes_cbc_descriptor,
  .refresh_key = aes_cbc_refresh_key,
  .copy_descriptor = aes_cbc_copy_descriptor,
  .free_descriptor = NULL,

  .descriptor_to_bytes = aes_cbc_descriptor_to_bytes,
  .descriptor_from_bytes = aes_cbc_bytes_to_descriptor,

  .encrypt = aes_cbc_encrypt,
  .decrypt = aes_cbc_decrypt,
};