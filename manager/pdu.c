
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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <tinysnmp/tinysnmp.h>
#include <tinysnmp/manager/snmp.h>

#include <ber/ber.h>
#include <abz/error.h>
#include <debug/memory.h>

#include "pdu.h"

int pdu_encode (ber_t *ber,const snmp_pdu_t *pdu)
{
   int i;
   uint32_t offset;

   for (i = pdu->n - 1; i >= 0; i--)
	 {
		offset = ber->offset;

		/*
		 * value NULL
		 * name OBJECT IDENTIFIER
		 * VarBind ::= SEQUENCE
		 */
		if (ber_encode_null (ber) ||
			ber_encode_oid (ber,pdu->oid[i]) ||
			ber_encode_sequence (ber,ber->offset - offset))
		  return (-1);
	 }

   /*
	* VarBindList ::= SEQUENCE OF
	* ErrorIndex INTEGER
	* ErrorStatus INTEGER { noError(0) }
	* Request-ID INTEGER
	*/

   if (ber_encode_sequence (ber,ber->offset) ||
	   ber_encode_integer (ber,0) ||
	   ber_encode_integer (ber,0) ||
	   ber_encode_integer (ber,pdu->RequestID))
	 return (-1);

   switch (pdu->type)
	 {
	  case BER_GetRequest:
		if (ber_encode_get_request (ber))
		  return (-1);
		break;
	  case BER_GetNextRequest:
		if (ber_encode_get_next_request (ber))
		  return (-1);
		break;
	  default:
		abz_set_error ("unsupported pdu: 0x%02x",pdu->type);
		return (-1);
	 }

   /*
	* community OCTET STRING
	* version INTEGER { version-1(0) }
	* Message ::= SEQUENCE
	*/

   if (ber_encode_octet_string (ber,&pdu->community) ||
	   ber_encode_integer (ber,pdu->version) ||
	   ber_encode_sequence (ber,ber->offset))
	 return (-1);

   return (0);
}

static int octet_string_compare (const octet_string_t *a,const octet_string_t *b)
{
   if (a->len < b->len)
	 return (-1);

   if (a->len > b->len)
	 return (1);

   return (memcmp (a->buf,b->buf,a->len));
}

static int decode_response_prefix (ber_t *ber,const snmp_pdu_t *pdu)
{
   int32_t version,RequestID,ErrorStatus,ErrorIndex;
   octet_string_t community;

   /*
	* Message ::= SEQUENCE
	* version INTEGER { version-1(0) }
	* community OCTET STRING
	* PDU { GetResponse-PDU(0) }
	* Request-ID INTEGER
	* ErrorStatus INTEGER { noError(0) }
	* ErrorIndex INTEGER
	* VarBindList ::= SEQUENCE OF
	*/

   if (ber_decode_sequence (ber) ||
	   ber_decode_integer (&version,ber) ||
	   ber_decode_octet_string (&community,ber) ||
	   ber_decode_get_response (ber) ||
	   ber_decode_integer (&RequestID,ber) ||
	   ber_decode_integer (&ErrorStatus,ber) ||
	   ber_decode_integer (&ErrorIndex,ber) ||
	   ber_decode_sequence (ber))
	 {
		if (community.len)
		  mem_free (community.buf);

		return (-1);
	 }

   if (community.len)
	 mem_free (community.buf);

   if (version != pdu->version)
	 {
		abz_set_error ("version mismatch");
		return (-1);
	 }

   if (octet_string_compare (&community,&pdu->community))
	 {
		abz_set_error ("community string mismatch");
		return (-1);
	 }

   if (RequestID != pdu->RequestID)
	 {
		abz_set_error ("request id mismatch");
		return (-1);
	 }

   return (0);
}

static int decode_oid_sequence (snmp_next_value_t *seq,ber_t *ber)
{
   int result;

   /*
	* VarBind ::= SEQUENCE
	* name OBJECT IDENTIFIER
	*/

   if (ber_decode_sequence (ber) || ber_decode_oid (&seq->oid,ber))
	 return (-1);

   if (ber->offset >= ber->size)
	 {
		abz_set_error ("buffer offset exceed buffer size");
		mem_free (seq->oid);
		return (-1);
	 }

   /*
	* value ObjectSyntax
	*/

   switch (ber->buf[ber->offset])
	 {
	  case BER_INTEGER:
		seq->value.type = BER_INTEGER;
		result = ber_decode_integer (&seq->value.data.INTEGER,ber);
		break;
	  case BER_Counter32:
		seq->value.type = BER_Counter32;
		result = ber_decode_counter32 (&seq->value.data.Counter32,ber);
		break;
	  case BER_Gauge32:
		seq->value.type = BER_Gauge32;
		result = ber_decode_gauge32 (&seq->value.data.Gauge32,ber);
		break;
	  case BER_TimeTicks:
		seq->value.type = BER_TimeTicks;
		result = ber_decode_timeticks (&seq->value.data.TimeTicks,ber);
		break;
	  case BER_Counter64:
		seq->value.type = BER_Counter64;
		result = ber_decode_counter64 (&seq->value.data.Counter64,ber);
		break;
	  case BER_OID:
		seq->value.type = BER_OID;
		result = ber_decode_oid (&seq->value.data.OID,ber);
		break;
	  case BER_OCTET_STRING:
		seq->value.type = BER_OCTET_STRING;
		result = ber_decode_octet_string (&seq->value.data.OCTET_STRING,ber);
		break;
	  case BER_NULL:
		seq->value.type = BER_NULL;
		result = ber_decode_null (ber);
		break;
	  case BER_IpAddress:
		seq->value.type = BER_IpAddress;
		result = ber_decode_ipaddress (&seq->value.data.IpAddress,ber);
		break;
	  default:
		abz_set_error ("unsupported ber value: 0x%02x",ber->buf[ber->offset]);
		result = -1;
	 }

   if (result)
	 mem_free (seq->oid);

   return (result);
}

int pdu_decode (ber_t *ber,const snmp_pdu_t *pdu,snmp_value_t *value)
{
   uint32_t i;
   snmp_next_value_t tmp;

   abz_clear_error ();

   if (decode_response_prefix (ber,pdu))
	 return (-1);

   for (i = 0; i < pdu->n; i++)
	 {
		if (decode_oid_sequence (&tmp,ber))
		  {
			 snmp_free (value,i);
			 return (-1);
		  }

		if (memcmp (tmp.oid,pdu->oid[i],(tmp.oid[0] + 1) * sizeof (uint32_t)))
		  {
			 abz_set_error ("object identifier mismatch");
			 snmp_free (value,i);
			 mem_free (tmp.oid);
			 return (-1);
		  }

		mem_free (tmp.oid);

		memcpy (value + i,&tmp.value,sizeof (snmp_value_t));
	 }

   if (ber->offset != ber->size)
	 {
		abz_set_error ("buffer contains garbage at the end");
		snmp_free (value,pdu->n);
		return (-1);
	 }

   return (0);
}

int pdu_decode_next (ber_t *ber,const snmp_pdu_t *pdu,snmp_next_value_t *next)
{
   uint32_t i;

   abz_clear_error ();

   if (decode_response_prefix (ber,pdu))
	 return (-1);

   if (!pdu->n)
	 {
		abz_set_error ("no object identifiers in pdu");
		return (-1);
	 }

   if (ber->offset != ber->size)
	 {
		for (i = 0; i < pdu->n; i++)
		  if (decode_oid_sequence (next + i,ber))
			{
			   snmp_free_next (next,i);
			   return (-1);
			}

		if (ber->offset != ber->size)
		  {
			 snmp_free_next (next,i);
			 return (-1);
		  }
	 }

   return (0);
}

