
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
#include <stdio.h>
#include <unistd.h>
#include <event.h>
#include <signal.h>
#include <sys/types.h>

#include <debug/memory.h>
#include <debug/log.h>

#include <abz/error.h>
#include <abz/pidfile.h>

#include "cmdline.h"
#include "agent.h"
#include "config.h"
#include "module.h"
#include "network.h"

static const int sigset_ignore[] = { SIGUSR1, SIGUSR2, SIGTSTP };
static const int sigset_accept[] = { SIGHUP, SIGINT, SIGTERM };
static struct event events[ARRAYSIZE (sigset_accept)];
static struct agent agent;

static __inline__ int safe_mode (uid_t uid,gid_t gid,const char *filename)
{
   abz_clear_error ();

   if (filename != NULL && chown (filename,uid,gid))
	 {
		abz_set_error ("failed to change ownership of %s to uid %u, gid %u: %m",
					   filename,uid,gid);
		return (-1);
	 }

   if (setregid (gid,gid))
	 {
		abz_set_error ("failed to set process group id to %u",gid);
		return (-1);
	 }

   if (setreuid (uid,uid))
	 {
		abz_set_error ("failed to set process user id to %u",uid);
		return (-1);
	 }

   return (0);
}

static __inline__ int daemon_init (const char *filename)
{
   abz_clear_error ();

   if (daemon (0,0))
	 {
		abz_set_error ("failed to daemonize myself: %m");
		return (-1);
	 }

   if (pidfile (filename))
	 {
		abz_set_error ("failed to create pid file %s: %m",filename);
		return (-1);
	 }

   return (0);
}

static void agent_close (void)
{
   agent_destroy (&agent);
}

static void signal_event (int fd,short event,void *arg)
{
   int i;

   log_printf (LOG_VERBOSE,"caught signal %d\n",fd);

   if (fd == SIGHUP && !log_reset ())
	 return;

   for (i = 0; i < ARRAYSIZE (sigset_accept); i++)
	 signal_del (events + i);

   network_close (&agent);
}

void signal_open (void)
{
   int i;

   for (i = 0; i < ARRAYSIZE (sigset_ignore); i++)
	 signal (sigset_ignore[i],SIG_IGN);

   for (i = 0; i < ARRAYSIZE (sigset_accept); i++)
	 {
		signal_set (events + i,sigset_accept[i],signal_event,NULL);
		signal_add (events + i,NULL);
	 }
}

void signal_close (void)
{
   static volatile int called = 0;

   if (!called)
	 {
		int i;

		network_close (&agent);

		for (i = 0; i < ARRAYSIZE (sigset_accept); i++)
		  {
			 signal_del (events + i);
			 signal (sigset_accept[i],SIG_DFL);
		  }

		for (i = 0; i < ARRAYSIZE (sigset_ignore); i++)
		  signal (sigset_ignore[i],SIG_DFL);

		called = 1;
	 }
}

int main (int argc,char *argv[])
{
   const struct cmdline *cmdline;
   const char *logstr;
   int flags;

   mem_open (NULL);
   log_open (NULL,LOG_NORMAL,LOG_HAVE_COLORS);
   atexit (log_close);
   atexit (mem_close);

   cmdline = cmdline_parse (argc,argv);
   atexit (cmdline_destroy);

   logstr = cmdline->logfile == NULL ? cmdline->syslog : cmdline->logfile;

   flags = logstr != NULL ?
	 LOG_DEBUG_PREFIX_ONLY | LOG_DETECT_FLOODING :
     LOG_HAVE_COLORS;

   log_close ();

   if (log_open (logstr,cmdline->loglevel,flags))
	 {
		fprintf (stderr,"failed to initialize logging system: %m\n");
		exit (EXIT_FAILURE);
	 }

   if (module_open (cmdline->modulepath))
	 exit (EXIT_FAILURE);

   agent_create (&agent);

   atexit (module_close);
   atexit (agent_close);

   if (config_parse (&agent,cmdline->configfile))
	 {
		log_printf (LOG_ERROR,"%s: %s\n",cmdline->configfile,abz_get_error ());
		exit (EXIT_FAILURE);
	 }

   cmdline_print (LOG_DEBUG);
   agent_print (LOG_DEBUG,&agent);
   module_print (LOG_DEBUG);

   putenv ("EVENT_NOEPOLL=");
   event_init ();

   if (network_open (&agent))
	 exit (EXIT_FAILURE);

   if ((cmdline->daemon && daemon_init (agent.pidfile)) ||
	   safe_mode (agent.uid,agent.gid,cmdline->logfile))
	 {
		log_printf (LOG_ERROR,"%s\n",abz_get_error ());
		network_close (&agent);
		exit (EXIT_FAILURE);
	 }

   signal_open ();
   atexit (signal_close);

   exit (event_dispatch () ? EXIT_FAILURE : EXIT_SUCCESS);
}

