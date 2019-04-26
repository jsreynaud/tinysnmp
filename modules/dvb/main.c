
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
#include <stddef.h>
#include <string.h>
#include <sys/sysinfo.h>

#include <tinysnmp/tinysnmp.h>
#include <tinysnmp/agent/module.h>
#include <tinysnmp/agent/odb.h>

#include <abz/error.h>

#include "dvb.h"

enum
{
   dvbIndex				= 1,
   dvbDescr				= 2,
   dvbVersion			= 3,
   dvbHWAddr			= 4,
   dvbStatus			= 5,
   dvbRxPackets			= 6,
   dvbRxRate			= 7,
   dvbLNBLock			= 8,
   dvbBitErrorRate		= 9,
   dvbErrorsCorrected	= 10,
   dvbErrorsUncorrected	= 11,
   dvbSNRatio			= 12,
   dvbLastUpdated		= 13
};

/* iso.org.dod.internet.private.enterprises.frogfoot.servers.system.dvb.dvbNumber.0 */
static const uint32_t dvbNumber[12] = { 11, 43, 6, 1, 4, 1, 10002, 1, 1, 3, 1, 0 };

/* iso.org.dod.internet.private.enterprises.frogfoot.servers.system.dvb.dvbTable.dvbEntry.x.y */
static uint32_t dvbEntry[14] = { 13, 43, 6, 1, 4, 1, 10002, 1, 1, 3, 2, 1, 0, 0 };

static void update_descr (snmp_value_t *value,struct dvb *dvb)
{
   value->type = BER_OCTET_STRING;
   value->data.OCTET_STRING.len = strlen (dvb->dvbDescr);
   value->data.OCTET_STRING.buf = (uint8_t *) dvb->dvbDescr;
}

static void update_version (snmp_value_t *value,struct dvb *dvb)
{
   value->type = BER_OCTET_STRING;
   value->data.OCTET_STRING.len = strlen (dvb->dvbVersion);
   value->data.OCTET_STRING.buf = (uint8_t *) dvb->dvbVersion;
}

static void update_hwaddr (snmp_value_t *value,struct dvb *dvb)
{
   value->type = BER_OCTET_STRING;
   value->data.OCTET_STRING.len = sizeof (dvb->dvbHWAddr);
   value->data.OCTET_STRING.buf = dvb->dvbHWAddr;
}

static void update_status (snmp_value_t *value,struct dvb *dvb)
{
   value->type = BER_INTEGER;
   value->data.INTEGER = dvb->dvbStatus;
}

static void update_rxpackets (snmp_value_t *value,struct dvb *dvb)
{
   value->type = BER_Counter32;
   value->data.Counter32 = dvb->dvbRxPackets;
}

static void update_rxrate (snmp_value_t *value,struct dvb *dvb)
{
   value->type = BER_Gauge32;
   value->data.Gauge32 = dvb->dvbRxRate;
}

static void update_lock (snmp_value_t *value,struct dvb *dvb)
{
   value->type = BER_INTEGER;
   value->data.INTEGER = dvb->dvbLNBLock;
}

static void update_ber (snmp_value_t *value,struct dvb *dvb)
{
   value->type = BER_Gauge32;
   value->data.Gauge32 = dvb->dvbBitErrorRate;
}

static void update_corrected (snmp_value_t *value,struct dvb *dvb)
{
   value->type = BER_Counter32;
   value->data.Counter32 = dvb->dvbErrorsCorrected;
}

static void update_uncorrected (snmp_value_t *value,struct dvb *dvb)
{
   value->type = BER_Counter32;
   value->data.Counter32 = dvb->dvbErrorsUncorrected;
}

static void update_signal (snmp_value_t *value,struct dvb *dvb)
{
   value->type = BER_Gauge32;
   value->data.Gauge32 = dvb->dvbSNRatio;
}

static void update_index (snmp_value_t *value,uint32_t index)
{
   value->type = BER_INTEGER;
   value->data.INTEGER = index;
}

static int update_timestamp (snmp_value_t *value)
{
   struct sysinfo si;

   abz_clear_error ();

   if (sysinfo (&si))
	 {
		abz_set_error ("sysinfo: %m");
		return (-1);
	 }

   value->type = BER_TimeTicks;
   value->data.TimeTicks = si.uptime * 100;

   return (0);
}

static int pentanet_update (struct odb **odb,const struct if_nameindex *dev)
{
   static struct
	 {
		uint32_t mask;
		void (*update) (snmp_value_t *,struct dvb *);
	 } list[] =
	 {
		{ DVB_DESCR, update_descr },
		{ DVB_VERSION, update_version },
		{ DVB_HWADDR, update_hwaddr },
		{ DVB_STATUS, update_status },
		{ DVB_RXPACKETS, update_rxpackets },
		{ DVB_RXRATE, update_rxrate },
		{ DVB_LOCK, update_lock },
		{ DVB_BER, update_ber },
		{ DVB_CORRECTED, update_corrected },
		{ DVB_UNCORRECTED, update_uncorrected },
		{ DVB_SIGNAL, update_signal },
	 };
   struct dvb dvb;
   snmp_value_t value;
   size_t i,j;
   uint32_t mask;
   int n = 0;

   /*
	* This works because the Pent@VALUE is just a stripped down version
	* of the Pent@NET card and uses the same library (just an older
	* version)
	*/

   for (i = 0; dev[i].if_name != NULL; i++)
	 if (!strncmp (dev[i].if_name,"pentanet",8) ||
		 !strncmp (dev[i].if_name,"pentaval",8))
	   {
		  dvbEntry[dvbEntry[0]] = dev[i].if_index;
		  mask = dvb_query (&dvb,dev[i].if_name);

		  for (j = 0; j < ARRAYSIZE (list); j++)
			if (mask & list[j].mask)
			  {
				 dvbEntry[dvbEntry[0] - 1] = dvbDescr + j;
				 list[j].update (&value,&dvb);

				 if (odb_add (odb,dvbEntry,&value))
				   return (-1);
			  }

		  dvbEntry[dvbEntry[0] - 1] = dvbIndex;
		  update_index (&value,dev[i].if_index);

		  if (odb_add (odb,dvbEntry,&value) || update_timestamp (&value))
			return (-1);

		  dvbEntry[dvbEntry[0] - 1] = dvbLastUpdated;

		  if (odb_add (odb,dvbEntry,&value))
			return (-1);

		  n++;
	   }

   return (n);
}

static int update_all (struct odb **odb,const struct if_nameindex *dev)
{
   static int (*update[]) (struct odb **,const struct if_nameindex *) =
	 {
		pentanet_update,
		/* pentaval_update */
	 };
   snmp_value_t value;
   size_t i;
   int r,n = 0;

   for (i = 0; i < ARRAYSIZE (update); i++)
	 {
		if ((r = update[i] (odb,dev)) < 0)
		  return (-1);

		n += r;
	 }

   value.type = BER_INTEGER;
   value.data.INTEGER = n;

   return (odb_add (odb,dvbNumber,&value));
}

static int dvb_update (struct odb **odb)
{
   struct if_nameindex *dev;
   int result;

   abz_clear_error ();

   if ((dev = if_nameindex ()) == NULL)
	 {
		abz_set_error ("failed to get interfaces: %m");
		return (-1);
	 }

   result = update_all (odb,dev);

   if_freenameindex (dev);

   return (result);
}

/* iso.org.dod.internet.private.enterprises.frogfoot.servers.system.dvb */
static const uint32_t dvb[10] = { 9, 43, 6, 1, 4, 1, 10002, 1, 1, 3 };

/* iso.org.dod.internet.private.enterprises.frogfoot.servers.system.dvb.dvMIB */
static const uint32_t dvbMIB[11] = { 10, 43, 6, 1, 4, 1, 10002, 1, 1, 3, 31 };

struct module module =
{
   .name	= "dvb",
   .descr	= "The MIB module to describe DVB Data receivers",
   .mod_oid	= dvb,
   .con_oid	= dvbMIB,
   .parse	= NULL,
   .open	= NULL,
   .update	= dvb_update,
   .close	= NULL
};

