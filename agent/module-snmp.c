
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

#include <stdint.h>
#include <string.h>

#include <tinysnmp/tinysnmp.h>
#include <tinysnmp/agent/odb.h>
#include <tinysnmp/agent/module.h>

#include "module.h"

enum
{
   SNMPINPKTS				= 1,
   SNMPOUTPKTS				= 2,
   SNMPINBADVERSIONS		= 3,
   SNMPINBADCOMMUNITYNAMES	= 4,
   SNMPINBADCOMMUNITYUSES	= 5,
   SNMPINASNPARSEERRS		= 6,
   SNMPINTOOBIGS			= 8,
   SNMPINNOSUCHNAMES		= 9,
   SNMPINBADVALUES			= 10,
   SNMPINREADONLYS			= 11,
   SNMPINGENERRS			= 12,
   SNMPINTOTALREQVARS		= 13,
   SNMPINTOTALSETVARS		= 14,
   SNMPINGETREQUESTS		= 15,
   SNMPINGETNEXTS			= 16,
   SNMPINSETREQUESTS		= 17,
   SNMPINGETRESPONSES		= 18,
   SNMPINTRAPS				= 19,
   SNMPOUTTOOBIGS			= 20,
   SNMPOUTNOSUCHNAMES		= 21,
   SNMPOUTBADVALUES			= 22,
   SNMPOUTGENERRS			= 24,
   SNMPOUTGETREQUESTS		= 25,
   SNMPOUTGETNEXTS			= 26,
   SNMPOUTSETREQUESTS		= 27,
   SNMPOUTGETRESPONSES		= 28,
   SNMPOUTTRAPS				= 29,
   SNMPENABLEAUTHENTRAPS	= 30,
   SNMPSILENTDROPS			= 31,
   SNMPPROXYDROPS			= 32
};

struct snmp_stats snmp_stats;

static int snmp_open (void)
{
   memset (&snmp_stats,0L,sizeof (struct snmp_stats));
   return (0);
}

static int snmp_update (struct odb **odb)
{
   static struct
	 {
		uint32_t index;
		uint32_t *value;
	 } list[] =
	 {
		{ SNMPINPKTS, &snmp_stats.snmpInPkts },
		{ SNMPOUTPKTS, &snmp_stats.snmpOutPkts },
		{ SNMPINBADVERSIONS, &snmp_stats.snmpInBadVersions },
		{ SNMPINBADCOMMUNITYNAMES, &snmp_stats.snmpInBadCommunityNames },
		{ SNMPINBADCOMMUNITYUSES, &snmp_stats.snmpInBadCommunityUses },
		{ SNMPINASNPARSEERRS, &snmp_stats.snmpInASNParseErrs },
		{ SNMPINTOOBIGS, &snmp_stats.snmpInTooBigs },
		{ SNMPINNOSUCHNAMES, &snmp_stats.snmpInNoSuchNames },
		{ SNMPINBADVALUES, &snmp_stats.snmpInBadValues },
		{ SNMPINREADONLYS, &snmp_stats.snmpInReadOnlys },
		{ SNMPINGENERRS, &snmp_stats.snmpInGenErrs },
		{ SNMPINTOTALREQVARS, &snmp_stats.snmpInTotalReqVars },
		{ SNMPINTOTALSETVARS, &snmp_stats.snmpInTotalSetVars },
		{ SNMPINGETREQUESTS, &snmp_stats.snmpInGetRequests },
		{ SNMPINGETNEXTS, &snmp_stats.snmpInGetNexts },
		{ SNMPINSETREQUESTS, &snmp_stats.snmpInSetRequests },
		{ SNMPINGETRESPONSES, &snmp_stats.snmpInGetResponses },
		{ SNMPINTRAPS, &snmp_stats.snmpInTraps },
		{ SNMPOUTTOOBIGS, &snmp_stats.snmpOutTooBigs },
		{ SNMPOUTNOSUCHNAMES, &snmp_stats.snmpOutNoSuchNames },
		{ SNMPOUTBADVALUES, &snmp_stats.snmpOutBadValues },
		{ SNMPOUTGENERRS, &snmp_stats.snmpOutGenErrs },
		{ SNMPOUTGETREQUESTS, &snmp_stats.snmpOutGetRequests },
		{ SNMPOUTGETNEXTS, &snmp_stats.snmpOutGetNexts },
		{ SNMPOUTSETREQUESTS, &snmp_stats.snmpOutSetRequests },
		{ SNMPOUTGETRESPONSES, &snmp_stats.snmpOutGetResponses },
		{ SNMPOUTTRAPS, &snmp_stats.snmpOutTraps },
		{ SNMPSILENTDROPS, &snmp_stats.snmpSilentDrops },
		{ SNMPPROXYDROPS, &snmp_stats.snmpProxyDrops }
	 };
   static uint32_t oid[9] = { 8, 43, 6, 1, 2, 1, 11, 0, 0 };
   snmp_value_t value;
   size_t i;

   value.type = BER_Counter32;

   for (i = 0; i < ARRAYSIZE (list); i++)
	 {
		oid[oid[0] - 1] = list[i].index;
		value.data.Counter32 = *(list[i].value);

		if (odb_add (odb,oid,&value))
		  return (-1);
	 }

   oid[oid[0] - 1] = SNMPENABLEAUTHENTRAPS;
   value.type = BER_INTEGER;
   value.data.INTEGER = 2;

   return (odb_add (odb,oid,&value));
}

/* iso.org.dod.internet.mgmt.mib-2.snmp */
static const uint32_t snmp[7] = { 6, 43, 6, 1, 2, 1, 11 };

struct module module_snmp =
{
   .name	= "snmp",
   .descr	= NULL,
   .mod_oid	= snmp,
   .con_oid	= NULL,
   .parse	= NULL,
   .open	= snmp_open,
   .update	= snmp_update,
   .close	= NULL
};

