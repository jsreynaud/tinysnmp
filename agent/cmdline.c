
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
#include <string.h>
#include <getopt.h>

#include <debug/log.h>
#include <debug/memory.h>

#include <abz/typedefs.h>
#include <abz/bprintf.h>

#include "cmdline.h"

static struct cmdline cmdline;

void cmdline_destroy (void)
{
   if (cmdline.syslog != NULL)
	 {
		mem_free (cmdline.syslog);
		cmdline.syslog = NULL;
	 }
}

static __attribute__ ((noreturn)) void usage (const char *progname)
{
   log_printf (LOG_ERROR,
			   "usage: %s [options] <configfile> <modulepath>\n"
			   "\n"
			   "    -f | --logfile=FILENAME   Location of log file. By default, messages will be\n"
			   "                              logged to the console.\n"
			   "\n"
			   "    -s | --syslog=FACILITY    The following facilities can be specified:\n"
			   "\n"
			   "                                  authpriv  security/authorization messages\n"
			   "                                  cron      clock daemon\n"
			   "                                  daemon    system daemons without separate facility\n"
			   "                                  ftp       ftp daemon\n"
			   "                                  kern      kernel messages\n"
			   "                                  lpr       line printer subsystem\n"
			   "                                  mail      mail subsystem\n"
			   "                                  news      usenet news subsystem\n"
			   "                                  syslog    messages generated internally by syslogd\n"
			   "                                  user      generic user-level messages\n"
			   "                                  uucp      uucp subsystem\n"
			   "                                  local0    reserved for local use\n"
			   "                                  ...\n"
			   "                                  local7\n"
			   "\n"
			   "                              If this option is specified, messages will be logged\n"
			   "                              to syslog. By default, messages will be logged to the\n"
			   "                              console.\n"
			   "\n"
			   "    -l | --loglevel=LEVEL     The following levels can be specified (in increasing\n"
			   "                              order of verbosity):\n"
			   "\n"
			   "                                  quiet     No messages will be logged\n"
			   "                                  errors    Only errors will be logged\n"
			   "                                  warnings  Warnings & errors will be logged\n"
			   "                                  normal    Default messages and all of the above\n"
			   "                                  verbose   Verbose messages will also be logged\n"
			   "                                  debug     Log debug messages as well\n"
			   "                                  noisy     Noisy debug messages will be logged as well\n"
			   "\n"
			   "                              If a log file or facility is specified, %s defaults to\n"
			   "                              `verbose', otherwise, `noisy' is selected.\n"
			   "\n"
			   "    -d | --daemon             Run in the background. You need to specify a log file or\n"
			   "                              a syslog facility if you want to use this option.\n"
			   "\n"
			   "    -h | --help               Show this help message.\n"
			   "\n"
			   "    <configfile>              Location of %s configuration file.\n"
			   "\n"
			   "    <modulepath>              Path where mib libraries reside.\n"
			   "\n",
			   progname,progname,progname);

   cmdline_destroy ();

   exit (EXIT_FAILURE);
}

static __attribute__ ((noreturn)) void fmterr (const char *fmt, ...)
{
   va_list ap;

   va_start (ap,fmt);
   log_vprintf (LOG_ERROR,fmt,ap);
   va_end (ap);

   cmdline_destroy ();

   exit (EXIT_FAILURE);
}

static void getlog (char **syslog,const char *ident,const char *facility)
{
   static const char *facilitynames[] =
	 {
		"authpriv",
		"cron",
		"daemon",
		"ftp",
		"kern",
		"lpr",
		"mail",
		"news",
		"syslog",
		"user",
		"uucp",
		"local0",
		"local1",
		"local2",
		"local3",
		"local4",
		"local5",
		"local6",
		"local7"
	 };
   size_t i;

   for (i = 0; i < ARRAYSIZE (facilitynames); i++)
	 if (!strcmp (facility,facilitynames[i]))
	   {
		  if ((*syslog = bprintf ("%s.%s",ident,facility)) == NULL)
			fmterr ("%s: failed to allocate memory: %m\n",ident);

		  return;
	   }

   fmterr ("%s: invalid syslog facility: %s\n",ident,facility);
}

static void getlevel (int *level,const char *ident,const char *str)
{
   static const char *loglevels[] =
	 {
		[LOG_QUIET] "quiet",
		[LOG_ERROR] "errors",
		[LOG_WARNING] "warnings",
		[LOG_NORMAL] "normal",
		[LOG_VERBOSE] "verbose",
		[LOG_DEBUG] "debug",
		[LOG_NOISY] "noisy"
	 };

   for (*level = 0; *level < ARRAYSIZE (loglevels); (*level)++)
	 if (!strcmp (str,loglevels[*level]))
	   return;

   fmterr ("%s: invalid log level: %s\n",ident,str);
}

const struct cmdline *cmdline_parse (int argc,char *argv[])
{
   static const struct option option[] =
	 {
		{ "logfile", 1, NULL, 'f' },
		{ "syslog", 1, NULL, 's' },
		{ "loglevel", 1, NULL, 'l' },
		{ "daemon", 0, NULL, 'd' },
		{ "help", 0, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	 };
   int finished = 0;

   opterr = 0;
   optind = 1;

   memset (&cmdline,0L,sizeof (struct cmdline));

   (cmdline.progname = strrchr (argv[0],'/')) != NULL ?
	 cmdline.progname++ : (cmdline.progname = argv[0]);

   cmdline.loglevel = -1;

   while (!finished)
	 {
		switch (getopt_long (argc,argv,"f:s:l:dh",option,NULL))
		  {
		   case -1:
			 finished = 1;
			 break;
		   case 'f':
			 cmdline.logfile = optarg;
			 break;
		   case 's':
			 getlog (&cmdline.syslog,cmdline.progname,optarg);
			 break;
		   case 'l':
			 getlevel (&cmdline.loglevel,cmdline.progname,optarg);
			 break;
		   case 'd':
			 cmdline.daemon = 1;
			 break;
		   case '?':
			 fmterr ("%s: invalid option or missing argument\n",cmdline.progname);
		   default:
			 usage (cmdline.progname);
		  }
	 }

   if (cmdline.daemon && cmdline.logfile == NULL && cmdline.syslog == NULL)
	 fmterr ("%s: not allowed to log to console if running as daemon\n",cmdline.progname);

   if (cmdline.logfile != NULL && cmdline.syslog != NULL)
	 fmterr ("%s: `logfile' and `syslog' options are mutually exclusive\n",cmdline.progname);

   if (optind + 2 > argc)
	 fmterr ("usage: %s [options] <configfile> <modulepath>\n"
			 "try `%s --help' for more information\n",
			 cmdline.progname,cmdline.progname);

   cmdline.configfile = argv[optind++];
   cmdline.modulepath = argv[optind++];

   if (cmdline.loglevel == -1)
	 cmdline.loglevel =
	   cmdline.logfile == NULL && cmdline.syslog == NULL ?
	   LOG_NOISY : LOG_VERBOSE;

   return (&cmdline);
}

#ifdef DEBUG
void cmdline_print_stub (const char *filename,int line,const char *function,int level)
{
   static const char *loglevel[] =
	 {
		[LOG_QUIET]   "quiet",
		[LOG_ERROR]   "errors",
		[LOG_WARNING] "warnings",
		[LOG_NORMAL]  "normal",
		[LOG_VERBOSE] "verbose",
		[LOG_DEBUG]   "debug",
		[LOG_NOISY]   "noisy"
	 };

   log_puts_stub (filename,line,function,level,"# cmdline\n");

   if (cmdline.logfile != NULL)
	 log_printf_stub (filename,line,function,level,"logfile \"%s\"\n",cmdline.logfile);
   else if (cmdline.syslog != NULL)
	 log_printf_stub (filename,line,function,level,"syslog \"%s\"\n",cmdline.syslog);
   else
	 log_puts_stub (filename,line,function,level,"no logfile\n");

   log_printf_stub (filename,line,function,level,
					"loglevel %s\n"
					"%sdaemon\n"
					"configfile \"%s\"\n"
					"modulepath \"%s\"\n",
					loglevel[cmdline.loglevel],
					cmdline.daemon ? "" : "no ",
					cmdline.configfile,
					cmdline.modulepath);
}
#endif	/* #ifdef DEBUG */

