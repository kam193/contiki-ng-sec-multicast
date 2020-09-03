/*
 * Copyright (c) 2020, Kamil Mańkowski
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * \addtogroup sec-multicast
 * @{
 */
/**
 * \defgroup sec-multicast-auth Authorization and Communication Module
 *
 *  A module responsible for authorize devices and communicate nodes and server.
 *
 * @{
 */
/**
 * \file
 * Headers for common authorization module functions.
 *
 * \author Kamil Mańkowski <kam193@wp.pl>
 *
 */

#ifndef AUTHORIZATION_H_
#define AUTHORIZATION_H_

#include "contiki.h"
#include "net/ipv6/uip.h"

#define CERT_HASH_LEN      32 /**< Length of the certificate hash */

/**
 * \name Certificate types
 * @{
 */
#define CERT_SERVER_PUB    1 /**< The server public certificate type */
#define CERT_NODE_PUB      2 /**< The end device certificate type */
/** @} */

/**
 * The issuer certificate structure.
 *
 * Aliased as \ref ca_cert_t
 */
struct ca_cert {
  uint16_t size;  /**< Size of the issuer ECC public key */
  uint8_t *pub;   /**< The ECC public key in the X963 format */
};
typedef struct ca_cert ca_cert_t; /**< Alias to the struct ca_cert */

/**
 * \struct device_cert
 *
 * The device certificate structure. Aliased as \ref device_cert_t
 */
struct device_cert {
  uint8_t owner_addr[16];   /**< IP address of the owner (as an identifyier) */
  uint8_t flags;            /**< Type of the certificate (server, node or both) */
  uint8_t pub_len;          /**< Length of the public ECC key */
  uint8_t signature_len;    /**< Length of the signature */
  uint8_t *pub;             /**< The ECC public key in X963 format */
  uint8_t *signature;       /**< The signature - sign by the issuer */

  uint8_t priv_len;         /**< Length of the private key (OPTIONAL) */
  uint8_t *priv;            /**< The private ECC key (OPTIONAL) */
};
typedef struct device_cert device_cert_t;   /**< Alias to the struct device_cert */

/**
 * \brief Import issuer certificate
 *
 * \param cert Pointer to the issuer certificate
 * \return int 0 on success
 */
int auth_import_ca_cert(const ca_cert_t *cert);

/**
 * \brief Verify the certificate
 *
 * \param cert Pointer to the device certificate
 * \return int On success 0
 */
int auth_verify_cert(const device_cert_t *cert);

/**
 * \brief Import device own certificate (with public and private key)
 *
 * \param cert Pointer to the certificate
 * \return int On success 0
 */
int auth_import_own_cert(const device_cert_t *cert);

/**
 * \brief Get the device own certificate (with public key only)
 *
 * \return const device_cert_t* Pointer to the cert or NULL on failure
 */
const device_cert_t *auth_own_pub_cert();

/**
 * \brief Check is issuer certificate imported
 *
 * \return true
 * \return false
 */
bool is_auth_ca_cert();

/**
 * \brief Decode the byte array into a device certificate
 *
 * \param dest_cert
 * \param src_data
 * \param src_len
 * \return int 0 on success
 */
int auth_decode_cert(device_cert_t *dest_cert, const uint8_t *src_data, uint16_t src_len);

/**
 * \brief Encode the certificate into a byte array
 *
 * \param dest_data
 * \param dest_len
 * \param src_cert
 * \return int 0 on success
 */
int auth_encode_cert(uint8_t *dest_data, uint16_t *dest_len, const device_cert_t *src_cert);

/**
 * \brief Encrypt data using own private key ang given public
 *
 * \param dest_data
 * \param dest_len
 * \param src_data
 * \param src_len
 * \param receiver_pub
 * \return int 0 on success
 */
int auth_encrypt_data(uint8_t *dest_data, uint32_t *dest_len,
                      const uint8_t *src_data, uint32_t src_len,
                      const device_cert_t *receiver_pub);

/**
 * \brief Decrypt given data using own private key and given public
 *
 * \param dest_data
 * \param dest_len
 * \param src_data
 * \param src_len
 * \param sender_pub
 * \return int
 */
int auth_decrypt_data(uint8_t *dest_data, uint32_t *dest_len,
                      const uint8_t *src_data, uint32_t src_len,
                      const device_cert_t *sender_pub);

/**
 * \brief Count the size paddet to 16-bytes blocks.
 *
 * This function is specified to use with 1 byte-length size only.
 *
 * \param size
 * \return uint8_t
 */
uint8_t auth_count_padding(uint8_t size);

/**
 * \brief Deep copy of the public certificate.
 *
 * Private part, if exists, is ignored.
 *
 * \param dest
 * \param src
 * \return int
 */
int auth_copy_pub_cert(device_cert_t *dest, const device_cert_t *src);

/**
 * \brief Free the fields inside device certificate
 *
 * \param cert
 */
void auth_free_device_cert(device_cert_t *cert);

/**
 * \brief Free common resources used by authentication service
 *
 */
void auth_free_service();

typedef void (*request_handler_t)(const uip_ipaddr_t *sender_addr,
                                  uint16_t sender_port,
                                  const uint8_t *data,
                                  uint16_t datalen);

#endif
/** @} */
/** @} */
