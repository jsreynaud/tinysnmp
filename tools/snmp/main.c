
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

#include <stdlib.h>

#include <debug/log.h>
#include <debug/memory.h>
#include <abz/error.h>
#include <tinysnmp/manager/snmp.h>

#include "config.h"
#include "show.h"

static int snmpget (struct config *config)
{
   snmp_value_t *value;
   size_t i;

   if ((value = mem_alloc (config->n * sizeof (snmp_value_t))) == NULL)
	 {
		log_printf (LOG_ERROR,"failed to allocate memory: %m\n");
		return (-1);
	 }

   for (i = 0; i <= config->retries; i++)
	 {
		if (!snmp_get_s (&config->agent,config->oid,value,config->n,config->timeout))
		  {
			 for (i = 0; i < config->n; i++)
			   show (config->oid[i],value + i);

			 snmp_free (value,config->n);
			 mem_free (value);

			 return (0);
		  }

		log_printf (LOG_WARNING,"%s\n",abz_get_error ());
	 }

   mem_free (value);
   return (0);
}

static int snmpgetnext (struct config *config)
{
   snmp_next_value_t *next;
   size_t i;

   if ((next = mem_alloc (config->n * sizeof (snmp_next_value_t))) == NULL)
	 {
		log_printf (LOG_ERROR,"failed to allocate memory: %m\n");
		return (-1);
	 }

   for (i = 0; i <= config->retries; i++)
	 {
		if (!snmp_get_next_s (&config->agent,config->oid,next,config->n,config->timeout))
		  {
			 for (i = 0; i < config->n; i++)
			   show (next[i].oid,&next[i].value);

			 snmp_free_next (next,config->n);
			 mem_free (next);

			 return (0);
		  }

		log_printf (LOG_WARNING,"%s\n",abz_get_error ());
	 }

   mem_free (next);
   return (0);
}

static int subtree (const uint32_t *base,const uint32_t *leaf)
{
   uint32_t i = 0;

   if (base[0] == 1 && base[1] == 0)
	 return (1);

   if (base[i] >= leaf[0])
	 return (0);

   for (i = 1; i <= base[0]; i++)
	 if (base[i] != leaf[i])
	   return (0);

   return (1);
}

static int snmpwalk (struct config *config)
{
   snmp_next_value_t prev,next;
   size_t i;

   for (i = 0; i <= config->retries; i++)
	 {
		if (!snmp_get_next_s (&config->agent,config->oid,&next,1,config->timeout))
		  break;

		log_printf (LOG_WARNING,"%s\n",abz_get_error ());
	 }

   if (i > config->retries)
	 return (-1);

   while (next.value.type != BER_NULL && subtree (config->oid[0],next.oid))
	 {
		show (next.oid,&next.value);
		prev = next;

		for (i = 0; i <= config->retries; i++)
		  {
			 if (!snmp_get_next_s (&config->agent,&prev.oid,&next,1,config->timeout))
			   break;

			 log_printf (LOG_WARNING,"%s\n",abz_get_error ());
		  }

		snmp_free_next (&prev,1);

		if (i > config->retries)
		  return (-1);
	 }

   snmp_free_next (&next,1);

   return (0);
}

int main (int argc,char *argv[])
{
   static int (*callback[]) (struct config *) =
	 {
		[SNMPGET] snmpget,
		[SNMPGETNEXT] snmpgetnext,
		[SNMPWALK] snmpwalk
	 };
   struct config *config;
   int result;

   mem_open (NULL);
   log_open (NULL,LOG_NORMAL,LOG_HAVE_COLORS);
   atexit (log_close);
   atexit (mem_close);

   config = config_parse (argc,argv);
   atexit (config_destroy);

   if (snmp_open_s (&config->agent,config->timeout))
	 {
		log_printf (LOG_ERROR,"%s\n",abz_get_error ());
		exit (EXIT_FAILURE);
	 }

   result = callback[config->applet] (config);

   snmp_close (&config->agent);

   exit (result ? EXIT_FAILURE : EXIT_SUCCESS);
}

