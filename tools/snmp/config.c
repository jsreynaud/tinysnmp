
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
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>

#include <debug/log.h>
#include <debug/memory.h>

#include <abz/error.h>
#include <abz/atou32.h>

#include <tinysnmp/tinysnmp.h>
#include <tinysnmp/manager/snmp.h>

#include <ber/ber.h>

#include "config.h"

static struct config *config = NULL;

static __attribute__ ((noreturn)) void help (const char *progname,int applet,int verbose)
{
#ifndef GETHOSTBYNAME
   static const char host[] = "<address>[:<port>]";
#else	/* #ifndef GETHOSTBYNAME */
   static const char host[] = "<hostname>[:<service>]";
#endif	/* #ifndef GETHOSTBYNAME */
   static const char *args[] =
	 {
		[SNMPGET]     "<objectID> [[objectID] ... ]",
		[SNMPGETNEXT] "[objectID [[objectID] ... ]]",
		[SNMPWALK]    "[objectID]"
	 };

   log_printf (LOG_ERROR,
			   "usage: %s [options] %s <community> %s\n",
			   progname,host,args[applet]);

   if (verbose)
	 log_printf (LOG_ERROR,
				 "\n"
				 "   -t | --timeout=<seconds>   timeout between operations (default: %u)\n"
				 "   -r | --retries=<n>         times to retry sending requests to agent (default: %u)\n"
				 "   -h | --help                show this help message\n"
				 "\n",
				 TIMEOUT,RETRIES);

   config_destroy ();

   exit (EXIT_FAILURE);
}

static __attribute__ ((noreturn)) void error (const char *fmt, ...)
{
   va_list ap;

   va_start (ap,fmt);
   log_vprintf (LOG_ERROR,fmt,ap);
   va_end (ap);

   config_destroy ();

   exit (EXIT_FAILURE);
}

struct config *config_parse (int argc,char *argv[])
{
   static const struct option option[] =
	 {
		{ "timeout", 1, NULL, 't' },
		{ "retries", 1, NULL, 'r' },
		{ "help", 0, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	 };
   static const char *applet[] =
	 {
		[SNMPGET]		"tinysnmpget",
		[SNMPGETNEXT]	"tinysnmpgetnext",
		[SNMPWALK]		"tinysnmpwalk"
	 };
   uint32_t value;
   int finished = 0;
   const char *progname;
   size_t i;

   opterr = 0;
   optind = 1;

   if ((config = mem_alloc (sizeof (struct config))) == NULL)
	 error ("failed to allocate memory: %m\n");

   memset (config,0L,sizeof (struct config));
   snmp_init (&config->agent);
   config->timeout = TIMEOUT;
   config->retries = RETRIES;

   (progname = strrchr (argv[0],'/')) ? progname++ : (progname = argv[0]);

   for (i = 0; i < ARRAYSIZE (applet); i++)
	 if (!strcmp (progname,applet[i]))
	   break;

   if (i == ARRAYSIZE (applet))
	 {
		log_printf (LOG_ERROR,
					"this program should be invoked as one of the following commands:\n");

		for (i = 0; i < ARRAYSIZE (applet); i++)
		  log_printf (LOG_ERROR,"    %s\n",applet[i]);

		config_destroy ();

		exit (EXIT_FAILURE);
	 }

   config->applet = i;

   while (!finished)
	 switch (getopt_long (argc,argv,"p:t:r:h",option,NULL))
	   {
		case -1:
		  finished = 1;
		  break;
		case 't':
		  if (atou32 (optarg,&value) || value > 86400)
			error ("%s: timeout must be 0-86400 seconds\n",progname);
		  config->timeout = value;
		  break;
		case 'r':
		  if (atou32 (optarg,&value) || value > 1000)
			error ("%s: number of retries must be 0-1000\n",progname);
		  config->retries = value;
		  break;
		case ':':
		  error ("%s: option `%s' requires an argument\n",progname,argv[optind]);
		case '?':
		  error ("%s: unrecognized option `%s'\n",progname,argv[optind]);
		default:
		  help (progname,config->applet,1);
	   }

   if (optind + 2 > argc)
	 help (progname,config->applet,0);

   if (snmp_init_addr (&config->agent,argv[optind++]))
	 error ("%s: %s\n",abz_get_error ());

   snmp_init_community (&config->agent,argv[optind++]);

   config->n = argc - optind;

   if ((!config->n && config->applet == SNMPGET) ||
	   (config->n > 1 && config->applet == SNMPWALK))
	 help (progname,config->applet,0);

   if (config->n)
	 {
		if ((config->oid = mem_alloc (config->n * sizeof (uint32_t *))) == NULL)
		  error ("failed to allocate memory: %m\n");

		for (i = 0; optind < argc; i++, optind++)
		  if ((config->oid[i] = makeoid (argv[optind])) == NULL)
			{
			   config->n = i;
			   error ("invalid object identifier %s: %s\n",argv[optind],abz_get_error ());
			}
	 }
   else
	 {
		if ((config->oid = mem_alloc (sizeof (uint32_t *))) == NULL ||
			(config->oid[0] = mem_alloc (2 * sizeof (uint32_t))) == NULL)
		  error ("failed to allocate memory: %m\n");

		config->n = 1;
		config->oid[0][0] = 1;
		config->oid[0][1] = 0;
	 }

   return (config);
}

void config_destroy (void)
{
   if (config != NULL)
	 {
		if (config->oid != NULL)
		  {
			 size_t i;

			 for (i = 0; i < config->n; i++)
			   mem_free (config->oid[i]);

			 mem_free (config->oid);
		  }

		mem_free (config);
		config = NULL;
	 }
}

