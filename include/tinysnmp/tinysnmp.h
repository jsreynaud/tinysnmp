#ifndef _TINYSNMP_H
#define _TINYSNMP_H

/*
 * Copyright (c) Abraham vd Merwe <abz@blio.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of other contributors
 *	  may be used to endorse or promote products derived from this software
 *	  without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <abz/typedefs.h>
#include <ber/ber.h>

#define SNMP_VERSION_1	0

typedef struct
{
   uint8_t type;					/* PDU type (either BER_GetRequest, BER_GetResponse, or BER_GetNextRequest)	*/
   int32_t version;					/* what SNMP version we should use											*/
   octet_string_t community;		/* the SNMP community string												*/
   int32_t RequestID;				/* Request ID used to ensure we got the right packet from the agent			*/
   uint32_t **oid;					/* a list of object identifiers to retrieve from agent						*/
   uint32_t n;						/* the number of object identifiers in the list								*/
} snmp_pdu_t;

typedef union
{
   int32_t INTEGER;
   uint32_t Counter32;
   uint32_t Gauge32;
   uint32_t TimeTicks;
   uint64_t Counter64;
   uint32_t IpAddress;
   uint32_t *OID;
   octet_string_t OCTET_STRING;
} snmp_data_t;

typedef struct
{
   uint8_t type;
   snmp_data_t data;
} snmp_value_t;

typedef struct
{
   uint32_t *oid;
   snmp_value_t value;
} snmp_next_value_t;

typedef struct
{
   uint32_t **oid;
   uint8_t type;
   snmp_data_t *data;
   uint32_t n;
} snmp_table_t;

#endif	/* #ifndef _TINYSNMP_H */
