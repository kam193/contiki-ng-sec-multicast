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
 * \file
 * Helper functions and macros
 *
 * \author Kamil Mańkowski <kam193@wp.pl>
 *
 */
#ifndef HELPERS_H_
#define HELPERS_H_

#include <stdlib.h>
#include "net/ipv6/uip.h"

#include "contiki.h"
#include "errors.h"

/**
 * \name Helpers
 * @{
 */
/**
 * \brief If expr is not 0, break function and return \ref ERR_OTHER
 * 
 * \param expr
 */
#define CHECK_0(expr)   if((expr) != 0) { return ERR_OTHER; }

/**
 * \brief If expr is not 1, break function and return \ref ERR_OTHER
 * 
 * \param expr
 */
#define CHECK_1(expr)   if((expr) != 1) { return ERR_OTHER; }

/**
 * \brief Generate random char
 * 
 */
#define RANDOM_CHAR()   (uint8_t)(random_rand() % 256)

/**
 * \brief Generate a random from -100 to 100
 * 
 */
#define RANDOMIZE()     (random_rand() % 200) - 100

/**
 * \brief Generate random chars array of given length
 * 
 * \param dest 
 * \param length 
 */
void generate_random_chars(uint8_t *dest, size_t length);
/** @} */

#endif
/** @} */