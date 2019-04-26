
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
#include <unistd.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>

#include <debug/memory.h>

#include <abz/typedefs.h>
#include <abz/error.h>
#include <abz/tokens.h>
#include <abz/bcat.h>

#include <tinysnmp/tinysnmp.h>
#include <tinysnmp/agent/odb.h>
#include <tinysnmp/agent/module.h>

#include "module.h"

#define LAYER(x) (1 << ((x) - 1))

#define sysORIndex	1
#define sysORID		2
#define sysORDescr	3
#define sysORUpTime	4

static char *contact = NULL;		/* contact person for this managed node		*/
static char *location = NULL;		/* the physical location of this node		*/

static void out_of_memory (void)
{
   abz_set_error ("failed to allocate memory: %m");
}

static void parse_error (const struct tokens *tokens,const char *suffix)
{
   abz_set_error ("usage: %s %s",tokens->argv[0],suffix);
}


static void already_defined (const struct tokens *tokens)
{
   abz_set_error ("`%s' already defined",tokens->argv[0]);
}

static int parse_contact (struct tokens *tokens)
{
   if (contact != NULL)
	 {
		already_defined (tokens);
		return (-1);
	 }

   if (tokens->argc != 2)
	 {
		parse_error (tokens,"<contact-string>");
		return (-1);
	 }

   if ((contact = bcat (tokens->argv[1],NULL)) == NULL)
	 {
		out_of_memory ();
		return (-1);
	 }

   return (1);
}

static int parse_location (struct tokens *tokens)
{
   if (location != NULL)
	 {
		already_defined (tokens);
		return (-1);
	 }

   if (tokens->argc != 2)
	 {
		parse_error (tokens,"<location-string>");
		return (-1);
	 }

   if ((location = bcat (tokens->argv[1],NULL)) == NULL)
	 {
		out_of_memory ();
		return (-1);
	 }

   return (1);
}

static int system_parse (struct tokens *tokens)
{
   static const struct
	 {
		const char *name;
		int (*parse) (struct tokens *);
	 } command[] =
	 {
		{ "contact", parse_contact },
		{ "location", parse_location }
	 };
   size_t i;

   abz_clear_error ();

   if (tokens == NULL)
	 {
		const char *missing =
		  contact == NULL ? "contact" :
		  location == NULL ? "location" :
		  NULL;

		if (missing != NULL)
		  {
			 abz_set_error ("unexpected end of file. `%s' statement missing",missing);
			 return (-1);
		  }

		return (0);
	 }

   for (i = 0; i < ARRAYSIZE (command); i++)
	 if (!strcmp (tokens->argv[0],command[i].name))
	   return (command[i].parse (tokens));

   return (0);
}

static int update_descr (struct odb **odb)
{
   static const uint32_t sysDescr[9] = { 8, 43, 6, 1, 2, 1, 1, 1, 0 };
   snmp_value_t value;
   struct utsname buf;
   char *str;

   if (uname (&buf))
	 {
		abz_get_error ("uname: %m");
		return (-1);
	 }

   if ((str = bcat (buf.sysname," ",buf.release," ",buf.version," ",buf.machine,NULL)) == NULL)
	 {
		out_of_memory ();
		return (-1);
	 }

   value.type = BER_OCTET_STRING;
   value.data.OCTET_STRING.len = strlen (str);
   value.data.OCTET_STRING.buf = (uint8_t *) str;

   if (odb_add (odb,sysDescr,&value))
	 {
		mem_free (str);
		return (-1);
	 }

   mem_free (str);

   return (0);
}

static int update_oid (struct odb **odb)
{
   static const uint32_t sysObjectID[9] = { 8, 43, 6, 1, 2, 1, 1, 2, 0 };
   static uint32_t servers[8] = { 7, 43, 6, 1, 4, 1, 10002, 1 };
   snmp_value_t value;

   /*
	* This should be specified in the configuration file
	*/

   value.type = BER_OID;
   value.data.OID = servers;

   return (odb_add (odb,sysObjectID,&value));
}

static int update_uptime (struct odb **odb)
{
   static const uint32_t sysUpTime[9] = { 8, 43, 6, 1, 2, 1, 1, 3, 0 };
   snmp_value_t value;
   struct sysinfo si;

   odb_remove (odb,sysUpTime);

   if (sysinfo (&si))
	 {
		abz_set_error ("sysinfo: %m");
		return (-1);
	 }

   value.type = BER_TimeTicks;
   value.data.TimeTicks = si.uptime * 100;

   return (odb_add (odb,sysUpTime,&value));
}

static int update_contact (struct odb **odb)
{
   static const uint32_t sysContact[9] = { 8, 43, 6, 1, 2, 1, 1, 4, 0 };
   snmp_value_t value;

   value.type = BER_OCTET_STRING;
   value.data.OCTET_STRING.len = strlen (contact);
   value.data.OCTET_STRING.buf = (uint8_t *) contact;

   return (odb_add (odb,sysContact,&value));
}

static int update_hostname (struct odb **odb)
{
   static const uint32_t sysName[9] = { 8, 43, 6, 1, 2, 1, 1, 5, 0 };
   struct utsname buf;
   snmp_value_t value;

   if (uname (&buf))
	 {
		abz_get_error ("uname: %m");
		return (-1);
	 }

   value.type = BER_OCTET_STRING;
   value.data.OCTET_STRING.len = strlen (buf.nodename);
   value.data.OCTET_STRING.buf = (uint8_t *) buf.nodename;

   return (odb_add (odb,sysName,&value));
}

static int update_location (struct odb **odb)
{
   static const uint32_t sysLocation[9] = { 8, 43, 6, 1, 2, 1, 1, 6, 0 };
   snmp_value_t value;

   value.type = BER_OCTET_STRING;
   value.data.OCTET_STRING.len = strlen (location);
   value.data.OCTET_STRING.buf = (uint8_t *) location;

   return (odb_add (odb,sysLocation,&value));
}

static int update_services (struct odb **odb)
{
   static const uint32_t sysServices[9] = { 8, 43, 6, 1, 2, 1, 1, 7, 0 };
   snmp_value_t value;

   value.type = BER_INTEGER;
   value.data.INTEGER = LAYER(1) | LAYER(2) | LAYER(3) | LAYER(4) | LAYER(7);

   return (odb_add (odb,sysServices,&value));
}

/*
 * Note that object identifiers are NOT removed prior
 * to calling this function (or afterwards if the function
 * fails). The reason for this is explained in modules.c.
 *
 * All oids which are periodically updated (in this case
 * sysUpTime and sysORLastChange) should be removed before
 * adding by the module itself.
 */

static int system_update (struct odb **odb)
{
   static struct
	 {
		int (*update) (struct odb **);
		int once;
	 } list[] =
	 {
		{ update_descr, 1 },
		{ update_oid, 1 },
		{ update_uptime, 0 },
		{ update_contact, 1 },
		{ update_hostname, 1 },
		{ update_location, 1 },
		{ update_services, 1 }
	 };
   size_t i;

   abz_clear_error ();

   for (i = 0; i < ARRAYSIZE (list); i++)
	 if (list[i].once >= 0)
	   {
		  if (list[i].update (odb))
			return (-1);

		  list[i].once = -list[i].once;
	   }

   return (0);
}

static void system_close (void)
{
   if (contact != NULL)
	 mem_free (contact);

   if (location != NULL)
	 mem_free (location);
}

/* iso.org.dod.internet.mgmt.mib-2.system */
static const uint32_t system[7] = { 6, 43, 6, 1, 2, 1, 1 };

struct module module_system =
{
   .name	= "system",
   .descr	= NULL,
   .mod_oid	= system,
   .con_oid	= NULL,
   .parse	= system_parse,
   .open	= NULL,
   .update	= system_update,
   .close	= system_close
};

int module_extend (const uint32_t *oid,const char *descr)
{
   static const uint32_t sysORLastChange[9] = { 8, 43, 6, 1, 2, 1, 1, 8, 0 };
   static uint32_t sysOREntry[11] = { 10, 43, 6, 1, 2, 1, 1, 9, 1, 0, 0 };
   static uint32_t n = 1;
   struct sysinfo si;
   snmp_value_t value;

   sysOREntry[sysOREntry[0]] = n++;

   if (sysinfo (&si))
	 {
		abz_set_error ("sysinfo: %m");
		return (-1);
	 }

   sysOREntry[sysOREntry[0] - 1] = sysORIndex;
   value.type = BER_INTEGER;
   value.data.INTEGER = sysOREntry[sysOREntry[0]];

   if (odb_add (&module_system.cache,sysOREntry,&value))
	 return (-1);

   sysOREntry[sysOREntry[0] - 1] = sysORID;
   value.type = BER_OID;
   value.data.OID = (uint32_t *) oid;

   if (odb_add (&module_system.cache,sysOREntry,&value))
	 return (-1);

   sysOREntry[sysOREntry[0] - 1] = sysORDescr;
   value.type = BER_OCTET_STRING;
   value.data.OCTET_STRING.len = strlen (descr);
   value.data.OCTET_STRING.buf = (uint8_t *) descr;

   if (odb_add (&module_system.cache,sysOREntry,&value))
	 return (-1);

   sysOREntry[sysOREntry[0] - 1] = sysORUpTime;
   value.type = BER_TimeTicks;
   value.data.TimeTicks = si.uptime * 100;

   if (odb_add (&module_system.cache,sysOREntry,&value))
	 return (-1);

   odb_remove (&module_system.cache,sysORLastChange);

   return (odb_add (&module_system.cache,sysORLastChange,&value));
}

