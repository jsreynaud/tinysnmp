
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

#include <debug/memory.h>
#include <tinysnmp/tinysnmp.h>
#include <ber/ber.h>

#include <abz/typedefs.h>
#include <abz/error.h>

#include "snmp.h"
#include "module.h"

enum
{
   noError		= 0,
   tooBig		= 1,
   noSuchName	= 2,
   badValue		= 3,
   readOnly		= 4,
   genErr		= 5
};

struct encode
{
   ber_t *ber;
   uint8_t status;
   uint32_t index;
   time_t timeout;
};

static const char *pdu_type_str (uint8_t type)
{
   static const struct
	 {
		const char *name;
		uint8_t value;
	 } list[] =
	 {
		{ "GetRequest", BER_GetRequest },
		{ "GetNextRequest", BER_GetNextRequest },
		{ "GetResponse", BER_GetResponse },
		{ "SetRequest", BER_SetRequest },
		{ "SNMPv1-Trap", BER_Trap },
		{ "GetBulkRequest", BER_GetBulkRequest },
		{ "InformRequest", BER_InformRequest },
		{ "SNMPv2-Trap", BER_SNMPv2_Trap }
	 };
   static char buf[] = "unknown(0x00)";
   int i;

   for (i = 0; i < ARRAYSIZE (list); i++)
	 if (list[i].value == type)
	   return (list[i].name);

   buf[ARRAYSIZE (buf) - 4] = type >> 4;
   buf[ARRAYSIZE (buf) - 3] = type & 15;

   return (buf);
}

void snmp_free (snmp_pdu_t *pdu)
{
   if (pdu->community.len)
	 mem_free (pdu->community.buf);

   if (pdu->oid != NULL)
	 {
		uint32_t i;

		for (i = 0; i < pdu->n; i++)
		  mem_free (pdu->oid[i]);

		mem_free (pdu->oid);
	 }
}

static int decode_varbind_list (snmp_pdu_t *pdu,ber_t *ber)
{
   uint32_t i;

   if (ber_decode_sequence (ber))
	 {
		snmp_stats.snmpInASNParseErrs++;
		return (-1);
	 }

   for (i = 0; ber->offset < ber->size; i++)
	 {
		uint32_t *oid;
		void *ptr;

		if (ber_decode_sequence (ber) || ber_decode_oid (&oid,ber) || ber_decode_null (ber))
		  {
			 snmp_stats.snmpInASNParseErrs++;
			 if (oid != NULL) mem_free (oid);
			 return (-1);
		  }

		if ((ptr = mem_realloc (pdu->oid,(pdu->n + 1) * sizeof (uint32_t *))) == NULL)
		  {
			 abz_set_error ("failed to allocate memory: %m");
			 if (oid != NULL) mem_free (oid);
			 return (-1);
		  }

		pdu->oid = ptr;
		pdu->oid[i] = oid;
		pdu->n++;
	 }

   return (0);
}

static int decode_pdu_type (snmp_pdu_t *pdu,ber_t *ber)
{
   uint32_t offset = ber->offset;

   if (!ber_decode_get_request (ber))
	 {
		snmp_stats.snmpInGetRequests++;
		pdu->type = BER_GetRequest;
		return (0);
	 }

   abz_clear_error ();
   ber->offset = offset;

   if (!ber_decode_get_next_request (ber))
	 {
		snmp_stats.snmpInGetNexts++;
		pdu->type = BER_GetNextRequest;
		return (0);
	 }

   /* ...more types to follow */

   abz_clear_error ();
   abz_set_error ("failed to decode pdu type");
   return (-1);
}

static int decode_message (snmp_pdu_t *pdu,ber_t *ber)
{
   int32_t status,index;

   if (ber_decode_sequence (ber) || ber_decode_integer (&pdu->version,ber))
	 {
		snmp_stats.snmpInASNParseErrs++;
		return (-1);
	 }

   if (pdu->version != SNMP_VERSION_1)
	 {
		snmp_stats.snmpInBadVersions++;
		abz_set_error ("unsupported snmp version (%u) in %s pdu",
					   pdu->version,pdu_type_str (pdu->type));
		return (-1);
	 }

   if (ber_decode_octet_string (&pdu->community,ber) ||
	   decode_pdu_type (pdu,ber) ||
	   ber_decode_integer (&pdu->RequestID,ber) ||
	   ber_decode_integer (&status,ber) ||
	   ber_decode_integer (&index,ber))
	 {
		snmp_stats.snmpInASNParseErrs++;
		return (-1);
	 }

   if (status || index)
	 {
		switch (status)
		  {
		   case tooBig:
			 snmp_stats.snmpInTooBigs++;
			 break;
		   case noSuchName:
			 snmp_stats.snmpInNoSuchNames++;
			 break;
		   case badValue:
			 snmp_stats.snmpInBadValues++;
			 break;
		   case readOnly:
			 snmp_stats.snmpInReadOnlys++;
			 break;
		   case genErr:
			 snmp_stats.snmpInGenErrs++;
		  }

		abz_set_error ("non-zero %s field in %s pdu",
					   status ? "ErrorStatus" : "ErrorIndex",
					   pdu_type_str (pdu->type));
		return (-1);
	 }

   if (decode_varbind_list (pdu,ber))
	 return (-1);

   if (pdu->type == BER_GetRequest && !pdu->n)
	 {
		abz_set_error ("empty %s pdu",pdu_type_str (pdu->type));
		return (-1);
	 }

   if (ber->offset != ber->size)
	 {
		abz_set_error ("garbage (%d bytes) at end of packet",ber->size - ber->offset);
		return (-1);
	 }

   return (0);
}

int snmp_decode (snmp_pdu_t *pdu,ber_t *ber)
{
   abz_clear_error ();

   memset (pdu,0L,sizeof (snmp_pdu_t));

   if (decode_message (pdu,ber))
	 {
		snmp_free (pdu);
		return (-1);
	 }

   return (0);
}

static int encode_type (ber_t *ber,const snmp_value_t *value,uint32_t n)
{
   switch (value->type)
	 {
	  case BER_INTEGER:
		return (ber_encode_integer (ber,value->data.INTEGER));
	  case BER_Counter32:
		return (ber_encode_counter32 (ber,value->data.Counter32));
	  case BER_Gauge32:
		return (ber_encode_gauge32 (ber,value->data.Gauge32));
	  case BER_TimeTicks:
		return (ber_encode_timeticks (ber,value->data.TimeTicks));
	  case BER_Counter64:
		return (ber_encode_counter64 (ber,value->data.Counter64));
	  case BER_OID:
		return (ber_encode_oid (ber,value->data.OID));
	  case BER_OCTET_STRING:
		return (ber_encode_octet_string (ber,&value->data.OCTET_STRING));
	  case BER_IpAddress:
		return (ber_encode_ipaddress (ber,value->data.IpAddress));
	 }

   return (-1);
}

static int encode_value (struct encode *encode,const uint32_t *oid,uint32_t n)
{
   const snmp_value_t *value;
   uint32_t offset = encode->ber->offset;

   if ((value = module_find (oid,encode->timeout)) == NULL)
	 {
		snmp_stats.snmpOutNoSuchNames++;
		encode->status = noSuchName;
		encode->index = n;
		if (ber_encode_null (encode->ber))
		  return (-1);
	 }
   else
	 {
		snmp_stats.snmpInTotalReqVars++;

		if (encode_type (encode->ber,value,n))
		  return (-1);
	 }

   return (ber_encode_oid (encode->ber,oid) ||
		   ber_encode_sequence (encode->ber,encode->ber->offset - offset) ?
		   -1 : 0);
}

static int encode_next_value (struct encode *encode,const uint32_t *oid,uint32_t n)
{
   snmp_next_value_t *next;
   uint32_t offset = encode->ber->offset;

   if ((next = module_find_next (oid,encode->timeout)) == NULL)
	 {
		/*
		 * What am I supposed to do when there are no ObjectID's in the MIB?
		 * At the moment, the query will fail if that is the case.
		 */

		if (oid == NULL)
		  return (-1);

		snmp_stats.snmpOutNoSuchNames++;
		encode->status = noSuchName;
		encode->index = n;

		if (ber_encode_null (encode->ber) ||
			ber_encode_oid (encode->ber,oid) ||
			ber_encode_sequence (encode->ber,encode->ber->offset - offset))
		  return (-1);
	 }
   else
	 {
		int result = encode_type (encode->ber,&next->value,n);

		if (next->value.type == BER_OID)
		  mem_free (next->value.data.OID);
		else if (next->value.type == BER_OCTET_STRING && next->value.data.OCTET_STRING.len)
		  mem_free (next->value.data.OCTET_STRING.buf);

		if (!result)
		  result = ber_encode_oid (encode->ber,next->oid);

		mem_free (next->oid);
		mem_free (next);

		if (result)
		  return (-1);

		return (ber_encode_sequence (encode->ber,encode->ber->offset - offset));
	 }

   return (0);
}

static int encode_varbind_list (struct encode *encode,const snmp_pdu_t *pdu)
{
   if (pdu->type == BER_GetRequest)
	 {
		uint32_t i;

		for (i = pdu->n; i > 0; i--)
		  if (encode_value (encode,pdu->oid[i - 1],i))
			return (-1);
	 }
   else
	 {
		if (pdu->n)
		  {
			 uint32_t i;

			 for (i = pdu->n; i > 0; i--)
			   if (encode_next_value (encode,pdu->oid[i - 1],i))
				 return (-1);
		  }
		else if (encode_next_value (encode,NULL,0))
		  return (-1);
	 }

   return (ber_encode_sequence (encode->ber,encode->ber->offset));
}

int snmp_encode (ber_t *ber,const snmp_pdu_t *pdu,time_t timeout)
{
   struct encode encode =
	 {
		.ber		= ber,
		.status		= noError,
		.index		= 0,
		.timeout	= timeout
	 };

   abz_clear_error ();

   snmp_stats.snmpOutGetResponses++;

   return (encode_varbind_list (&encode,pdu) ||
		   ber_encode_integer (ber,encode.index) ||
		   ber_encode_integer (ber,encode.status) ||
		   ber_encode_integer (ber,pdu->RequestID) ||
		   ber_encode_get_response (ber) ||
		   ber_encode_octet_string (ber,&pdu->community) ||
		   ber_encode_integer (ber,pdu->version) ||
		   ber_encode_sequence (ber,ber->offset) ?
		   -1 : 0);
}

