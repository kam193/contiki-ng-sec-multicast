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

#include "net/ipv6/multicast/secure/engine.h"
#include "net/ipv6/multicast/secure/authorization.h"

/* CA CERT */

unsigned char pub[] = { 0x4, 0x1c, 0x24, 0x89, 0xd5, 0xaf, 0xd4, 0x57, 0x24, 0xb0, 0x50, 0x31, 0xdf, 0x27, 0x3, 0x75, 0xc8, 0x33, 0x66, 0x94,
                        0xf6, 0x5c, 0xeb, 0xda, 0, 0x1e, 0x1, 0x11, 0x56, 0x12, 0x8f, 0xff, 0x5b };
ca_cert_t ca = { sizeof(pub), pub };

/* ROOT cert */

uint8_t rp_pub[] = { 0x4, 0x15, 0x1e, 0xd7, 0x94, 0xef, 0x7f, 0x9e, 0x80, 0x9e, 0xf7, 0x6, 0x2f, 0x40, 0xf8, 0x7d, 0x9a, 0xa5, 0x4e, 0x12, 0x1b, 0x51, 0xa1, 0x94, 0xcf, 0x30, 0x7f, 0xda, 0xed, 0x2a, 0x42, 0xa1, 0xff, 0xda, 0xd3, 0x82, 0x70, 0xa, 0x1d, 0x2d, 0xef };
uint8_t rp_priv[] = { 0x8b, 0x40, 0xde, 0xfc, 0x80, 0, 0x3a, 0x67, 0x49, 0x87, 0x2, 0xfa, 0xca, 0x2a, 0xde, 0x45, 0xcc, 0xf8, 0x5e, 0xe0 };
uint8_t rp_signature[] = { 0x30, 0x26, 0x2, 0x11, 0, 0xac, 0x2b, 0x91, 0x8f, 0x1d, 0x8, 0xb1, 0xf, 0x22, 0xfe, 0xa0, 0x6d, 0xa8, 0xa1, 0x59, 0x74, 0x2, 0x11, 0, 0xa0, 0x78, 0x39, 0x6c, 0x1c, 0xec, 0xe2, 0x43, 0x8c, 0x10, 0xb, 0x53, 0xec, 0x9f, 0x51, 0xa0 };

device_cert_t rp_private_cert = { .owner_addr = { 0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x01, 0x1, 0x1, 0x1 },
                                  .flags = CERT_SERVER_PUB,
                                  .pub_len = 41,
                                  .priv_len = 20,
                                  .signature_len = 40,
                                  .pub = rp_pub,
                                  .priv = rp_priv,
                                  .signature = rp_signature };

/* CLIENT 2 */

uint8_t c2_pub[] = { 0x4, 0x97, 0xd9, 0x32, 0x30, 0x4d, 0x7c, 0x7f, 0xee, 0x72, 0xea, 0xa2, 0x24, 0xda, 0xa3, 0xdd, 0x5f, 0xc3, 0x55, 0x3e, 0xdd, 0xe9, 0x46, 0xdd, 0xc6, 0xd0, 0x3d, 0x4f, 0x74, 0x61, 0x99, 0xee, 0x23, 0x67, 0xb6, 0x45, 0xa8, 0xe8, 0x31, 0xf7, 0xa9 };
uint8_t c2_priv[] = { 0x60, 0xb8, 0x13, 0x40, 0xc9, 0x17, 0x78, 0xe, 0x91, 0xea, 0x3c, 0xa9, 0xc0, 0x93, 0xe, 0xae, 0x53, 0x7c, 0x8c, 0xe8 };
uint8_t c2_signature[] = { 0x30, 0x24, 0x2, 0x10, 0x28, 0x7, 0x96, 0x2d, 0x23, 0x74, 0x8f, 0xcc, 0xde, 0xaf, 0xf4, 0x67, 0x71, 0x62, 0x1f, 0x95, 0x2, 0x10, 0x62, 0x7f, 0xe5, 0xc8, 0xa0, 0x85, 0, 0x42, 0x81, 0xbf, 0xab, 0xa9, 0x41, 0x26, 0x9e, 0x52 };

device_cert_t c2_private_cert = { .owner_addr = { 0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x02, 0x2, 0x2, 0x2 },
                                  .flags = CERT_NODE_PUB,
                                  .pub_len = 41,
                                  .priv_len = 20,
                                  .signature_len = 38,
                                  .pub = c2_pub,
                                  .priv = c2_priv,
                                  .signature = c2_signature };

/* CLIENT 3 */

uint8_t c3_pub[] = { 0x4, 0x9b, 0x69, 0x5d, 0x66, 0x45, 0x75, 0x16, 0x9d, 0xa3, 0x59, 0x51, 0x5d, 0x66, 0xe8, 0xa2, 0x6, 0x21, 0x9e, 0x21, 0x8d, 0xa7, 0x6f, 0xec, 0x95, 0x9c, 0x24, 0x39, 0x31, 0xd0, 0x19, 0xaf, 0x82, 0x5a, 0xe0, 0xf, 0x29, 0x9e, 0x4c, 0xa7, 0x16 };
uint8_t c3_priv[] = { 0x12, 0xc6, 0xa3, 0xff, 0xfa, 0x3b, 0xd6, 0x9b, 0x89, 0xb9, 0xc2, 0xa0, 0xb8, 0x96, 0x24, 0x26, 0x10, 0x24, 0xa0, 0x36 };
uint8_t c3_signature[] = { 0x30, 0x25, 0x2, 0x11, 0, 0xe3, 0x18, 0x1a, 0x13, 0xc5, 0x7c, 0x17, 0x4e, 0xb5, 0x88, 0x43, 0xc6, 0xa2, 0x52, 0x82, 0x7d, 0x2, 0x10, 0x13, 0x3d, 0xef, 0x72, 0x50, 0x4f, 0x1a, 0x1, 0x5, 0x9c, 0x7, 0x64, 0x8b, 0x3a, 0x5b, 0xe9 };

device_cert_t c3_private_cert = { .owner_addr = { 0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x03, 0x3, 0x3, 0x3 },
                                  .flags = CERT_NODE_PUB,
                                  .pub_len = 41,
                                  .priv_len = 20,
                                  .signature_len = 39,
                                  .pub = c3_pub,
                                  .priv = c3_priv,
                                  .signature = c3_signature };

/* CLIENT 4 */

uint8_t c4_pub[] = { 0x4, 0xb8, 0xc8, 0xd6, 0x7, 0x67, 0x76, 0x79, 0xa1, 0x7c, 0x2a, 0x38, 0xda, 0x48, 0x9d, 0xe7, 0x44, 0x76, 0x70, 0x7, 0x7b, 0x12, 0xa1, 0x8a, 0x1d, 0xcb, 0xe4, 0xec, 0xbf, 0xd5, 0x20, 0x34, 0x96, 0x64, 0x89, 0x4b, 0x83, 0xa7, 0xec, 0x20, 0xb1 };
uint8_t c4_priv[] = { 0x3b, 0xbc, 0x15, 0xfe, 0x1e, 0x62, 0x9f, 0x28, 0xbf, 0x96, 0x66, 0xc4, 0xa2, 0xa9, 0xb5, 0x85, 0xca, 0xd, 0x36, 0xc };
uint8_t c4_signature[] = { 0x30, 0x24, 0x2, 0x10, 0x2, 0x48, 0x4a, 0x9f, 0x53, 0x78, 0x5e, 0x45, 0xfc, 0xfb, 0xa2, 0x3c, 0x34, 0x38, 0x71, 0xcd, 0x2, 0x10, 0xf, 0xd0, 0x9f, 0xbb, 0xe6, 0x31, 0xa9, 0xec, 0xda, 0x7c, 0x48, 0x36, 0x12, 0xad, 0x26, 0x27 };

device_cert_t c4_private_cert = { .owner_addr = { 0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x04, 0x4, 0x4, 0x4 },
                                  .flags = CERT_NODE_PUB,
                                  .pub_len = 41,
                                  .priv_len = 20,
                                  .signature_len = 38,
                                  .pub = c4_pub,
                                  .priv = c4_priv,
                                  .signature = c4_signature };

/* ALTERNATIVE */

uint8_t alternative_ca_pub[] = { 0x4, 0xae, 0xe, 0x47, 0x9e, 0xe1, 0x95, 0xed, 0x1e, 0x66, 0xa8, 0x49, 0x35, 0xfd, 0xd0, 0xec, 0x4b, 0x6f, 0xd, 0xff, 0x85, 0xed, 0xdf, 0xec, 0x92, 0x43, 0x19, 0x2, 0x56, 0x48, 0x9b, 0xa3, 0x45 };
ca_cert_t alternative_ca = { sizeof(alternative_ca_pub), alternative_ca_pub };

uint8_t alt_pub[] = { 0x4, 0xf1, 0xfb, 0xaf, 0xae, 0x5e, 0x3c, 0x1, 0x8c, 0x69, 0x43, 0xb6, 0xa1, 0xb2, 0x85, 0xb, 0xe1, 0xd8, 0xd, 0x83, 0x5e, 0x9b, 0xcb, 0xc5, 0xe, 0x4e, 0x1b, 0xa7, 0x1f, 0xf8, 0xc3, 0x2e, 0x1c, 0x7b, 0xc4, 0xab, 0x60, 0xa8, 0x56, 0x17, 0x19 };
uint8_t alt_priv[] = { 0x79, 0x73, 0xed, 0x3d, 0xe4, 0xc7, 0x96, 0x3e, 0xe7, 0x16, 0x8, 0xd2, 0x5, 0xeb, 0x78, 0x65, 0xd8, 0xa7, 0xa5, 0x4a };
uint8_t alt_signature[] = { 0x30, 0x25, 0x2, 0x10, 0x2f, 0x9a, 0x12, 0xbb, 0x1a, 0x15, 0x89, 0xee, 0x83, 0x56, 0x6e, 0x24, 0xa9, 0x62, 0xf9, 0xa8, 0x2, 0x11, 0, 0x81, 0x54, 0x8e, 0xb0, 0xa0, 0x46, 0x93, 0x32, 0xc8, 0x7a, 0x19, 0xad, 0xee, 0x9e, 0x2b, 0xcd };

device_cert_t alt_private_cert = { .owner_addr = { 0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x04, 0x4, 0x4, 0x4 },
                                   .flags = CERT_NODE_PUB,
                                   .pub_len = sizeof(alt_pub),
                                   .priv_len = sizeof(alt_priv),
                                   .signature_len = sizeof(alt_signature),
                                   .pub = alt_pub,
                                   .priv = alt_priv,
                                   .signature = alt_signature };