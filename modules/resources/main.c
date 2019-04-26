
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

#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include <tinysnmp/tinysnmp.h>
#include <tinysnmp/agent/module.h>
#include <tinysnmp/agent/odb.h>
#include <tinysnmp/unaligned.h>

#include <ber/ber.h>

#include <abz/typedefs.h>
#include <abz/error.h>

#include "meminfo.h"
#include "diskinfo.h"
#include "loadinfo.h"

static struct diskinfo *dlist = NULL;
static struct loadinfo load;

static int memory_update (struct odb **odb)
{
   uint32_t oid[13] = { 12, 43, 6, 1, 4, 1, 10002, 1, 1, 1, 1, 0, 0 };
   snmp_value_t value;
   struct meminfo info;

   if (getmeminfo (&info))
	 return (-1);

   value.type = BER_Gauge32;

   oid[11] = 1;
   value.data.Gauge32 = info.mem_total / 1024;

   if (odb_add (odb,oid,&value))
	 return (-1);

   oid[11] = 2;
   value.data.Gauge32 = info.mem_free / 1024;

   if (odb_add (odb,oid,&value))
	 return (-1);

   oid[11] = 3;
   value.data.Gauge32 = info.mem_buffer / 1024;

   if (odb_add (odb,oid,&value))
	 return (-1);

   oid[11] = 4;
   value.data.Gauge32 = info.mem_cache / 1024;

   return (odb_add (odb,oid,&value));
}

static int swap_update (struct odb **odb)
{
   uint32_t oid[13] = { 12, 43, 6, 1, 4, 1, 10002, 1, 1, 1, 2, 0, 0 };
   snmp_value_t value;
   struct swapinfo info;

   if (getswapinfo (&info))
	 return (-1);

   value.type = BER_Gauge32;

   oid[11] = 1;
   value.data.Gauge32 = info.swap_total / 1024;

   if (odb_add (odb,oid,&value))
	 return (-1);

   oid[11] = 2;
   value.data.Gauge32 = info.swap_free / 1024;

   return (odb_add (odb,oid,&value));
}

static void diskIndex (snmp_value_t *value,const struct diskinfo *disk)
{
   value->type = BER_INTEGER;
   value->data.INTEGER = disk->d_index;
}

static void diskDev (snmp_value_t *value,const struct diskinfo *disk)
{
   value->type = BER_OCTET_STRING;
   value->data.OCTET_STRING.len = strlen (disk->d_dev);
   value->data.OCTET_STRING.buf = (uint8_t *) disk->d_dev;
}

static void diskDir (snmp_value_t *value,const struct diskinfo *disk)
{
   value->type = BER_OCTET_STRING;
   value->data.OCTET_STRING.len = strlen (disk->d_dir);
   value->data.OCTET_STRING.buf = (uint8_t *) disk->d_dir;
}

static void diskFSType (snmp_value_t *value,const struct diskinfo *disk)
{
   value->type = BER_INTEGER;
   value->data.INTEGER = disk->d_type;
}

static void diskTotal (snmp_value_t *value,const struct diskinfo *disk)
{
   value->type = BER_Gauge32;
   copy_unaligned (&value->data.Gauge32,&disk->d_total);
}

static void diskFree (snmp_value_t *value,const struct diskinfo *disk)
{
   value->type = BER_Gauge32;
   copy_unaligned (&value->data.Gauge32,&disk->d_free);
}

static int storage_update (struct odb **odb)
{
   static const uint32_t diskNumber[13] = { 12, 43, 6, 1, 4, 1, 10002, 1, 1, 1, 3, 1, 0 };
   static uint32_t diskEntry[15] = { 14, 43, 6, 1, 4, 1, 10002, 1, 1, 1, 3, 2, 1, 0, 0 };
   static void (*save[]) (snmp_value_t *,const struct diskinfo *) =
	 {
		diskIndex,
		diskDev,
		diskDir,
		diskFSType,
		diskTotal,
		diskFree
	 };
   snmp_value_t value;
   struct diskinfo *tmp;
   uint32_t i,n;

   if (disk_update (&dlist))
	 return (-1);

   for (tmp = dlist, n = 0; tmp != NULL; tmp = tmp->next, n++)
	 {
		diskEntry[diskEntry[0]] = tmp->d_index;

		for (i = 0; i < ARRAYSIZE (save); i++)
		  {
			 diskEntry[diskEntry[0] - 1] = i + 1;
			 save[i] (&value,tmp);

			 if (odb_add (odb,diskEntry,&value))
			   return (-1);
		  }
	 }

   value.type = BER_INTEGER;
   value.data.INTEGER = n;

   return (odb_add (odb,diskNumber,&value));
}

static void loadIndex (snmp_value_t *value,size_t n)
{
   value->type = BER_INTEGER;
   value->data.INTEGER = n + 1;
}

static void loadDescr (snmp_value_t *value,size_t n)
{
   value->type = BER_OCTET_STRING;
   value->data.OCTET_STRING.len = strlen (load.descr[n]);
   value->data.OCTET_STRING.buf = (uint8_t *) load.descr[n];
}

static void loadValue (snmp_value_t *value,size_t n)
{
   value->type = BER_Gauge32;
   value->data.Gauge32 = load.value[n];
}

static int _load_update (struct odb **odb)
{
   static const uint32_t loadNumber[13] = { 12, 43, 6, 1, 4, 1, 10002, 1, 1, 1, 4, 1, 0 };
   static uint32_t loadEntry[15] = { 14, 43, 6, 1, 4, 1, 10002, 1, 1, 1, 4, 2, 1, 0, 0 };
   static void (*save[]) (snmp_value_t *,size_t n) =
	 {
		loadIndex,
		loadDescr,
		loadValue
	 };
   snmp_value_t value;
   uint32_t i,j;

   if (load_update (&load))
	 return (-1);

   for (i = 0; i < load.n; i++)
	 {
		loadEntry[loadEntry[0]] = i + 1;

		for (j = 0; j < ARRAYSIZE (save); j++)
		  {
			 loadEntry[loadEntry[0] - 1] = j + 1;
			 save[j] (&value,i);

			 if (odb_add (odb,loadEntry,&value))
			   return (-1);
		  }
	 }

   value.type = BER_INTEGER;
   value.data.INTEGER = load.n;

   return (odb_add (odb,loadNumber,&value));
}

static int res_open (void)
{
   return (load_create (&load));
}

static int res_update (struct odb **odb)
{
   if (memory_update (odb) ||
	   swap_update (odb) ||
	   storage_update (odb) ||
	   _load_update (odb))
	 return (-1);

   return (0);
}

static void res_close (void)
{
   disk_destroy (&dlist);
   load_destroy (&load);
}

/* iso.org.dod.internet.private.enterprises.frogfoot.servers.system.resources */
static const uint32_t resources[10] = { 9, 43, 6, 1, 4, 1, 10002, 1, 1, 1 };

/* iso.org.dod.internet.private.enterprises.frogfoot.servers.system.resources.resMIB */
static const uint32_t resMIB[11] = { 10, 43, 6, 1, 4, 1, 10002, 1, 1, 1, 31 };

struct module module =
{
   .name	= "resources",
   .descr	= "The MIB module to describe system resources",
   .mod_oid	= resources,
   .con_oid	= resMIB,
   .parse	= NULL,
   .open	= res_open,
   .update	= res_update,
   .close	= res_close
};

