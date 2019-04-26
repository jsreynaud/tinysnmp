
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
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

#include <debug/memory.h>

#include <abz/error.h>
#include <abz/tokens.h>
#include <abz/atou32.h>
#include <abz/atos.h>
#include <abz/atop.h>
#include <abz/aton.h>

#include "agent.h"
#include "module.h"

#define IGNORE	0x01
#define ACCEPT	0x02

static void out_of_memory (void)
{
   abz_set_error ("failed to allocate memory: %m");
}

static void parse_error (const struct tokens *tokens,const char *suffix)
{
   if (suffix)
	 abz_set_error ("usage: %s %s",tokens->argv[0],suffix);
   else
	 abz_set_error ("usage: %s",tokens->argv[0]);
}

static void already_defined (const struct tokens *tokens)
{
   abz_set_error ("`%s' already defined",tokens->argv[0]);
}

void agent_create (struct agent *agent)
{
   memset (agent,0L,sizeof (struct agent));
   agent->uid = (uid_t) -1;
   agent->gid = (gid_t) -1;
   agent->listen.sin_addr.s_addr = INADDR_NONE;
}

void agent_destroy (struct agent *agent)
{
   if (agent->pidfile != NULL)
	 mem_free (agent->pidfile);

   while (agent->allow != NULL)
	 {
		struct allow *allow = agent->allow;

		agent->allow = agent->allow->next;
		mem_free (allow);
	 }

   if (agent->community != NULL)
	 mem_free (agent->community);
}

static int agent_parse_end (struct agent *agent)
{
   const char *missing;

   if (agent->parse_module != NULL)
	 {
		if (agent->parse_module (NULL))
		  return (-1);

		agent->parse_module = NULL;
	 }

   missing = agent->uid == (uid_t) -1 ? "user" :
      agent->gid == (gid_t) -1 ? "group" :
      agent->pidfile == NULL ? "pidfile" :
      agent->allow == NULL ? "allow" :
      agent->community == NULL ? "community" :
      agent->comment ? "endif" :
      NULL;

   if (missing != NULL)
	 {
		abz_set_error ("unexpected end of file. `%s' statement missing",missing);
		return (-1);
	 }

   return (0);
}

static int parse_user (struct agent *agent,struct tokens *tokens)
{
   uint32_t uid;

   if (agent->uid != (uid_t) -1)
	 {
		already_defined (tokens);
		return (-1);
	 }

   if (tokens->argc != 2)
	 {
		parse_error (tokens,"{ <userid> | <username> }");
		return (-1);
	 }

   if (atou32 (tokens->argv[1],&uid))
	 {
		struct passwd *pw;

		if ((pw = getpwnam (tokens->argv[1])) == NULL)
		  {
			 abz_set_error ("failed to convert user name %s to uid",tokens->argv[1]);
			 return (-1);
		  }

		uid = pw->pw_uid;
	 }

   agent->uid = uid;

   return (0);
}

static int parse_group (struct agent *agent,struct tokens *tokens)
{
   uint32_t gid;

   if (agent->gid != (gid_t) -1)
	 {
		already_defined (tokens);
		return (-1);
	 }

   if (tokens->argc != 2)
	 {
		parse_error (tokens,"{ <groupid> | <groupname> }");
		return (-1);
	 }

   if (atou32 (tokens->argv[1],&gid))
	 {
		struct group *gr;

		if ((gr = getgrnam (tokens->argv[1])) == NULL)
		  {
			 abz_set_error ("failed to convert user name %s to gid",tokens->argv[1]);
			 return (-1);
		  }

		gid = gr->gr_gid;
	 }

   agent->gid = gid;

   return (0);
}

static int parse_pidfile (struct agent *agent,struct tokens *tokens)
{
   if (agent->pidfile != NULL)
	 {
		already_defined (tokens);
		return (-1);
	 }

   if (tokens->argc != 2)
	 {
		parse_error (tokens,"<filename>");
		return (-1);
	 }

   if ((agent->pidfile = mem_alloc (strlen (tokens->argv[1]) + 1)) == NULL)
     {
		out_of_memory ();
		return (-1);
	 }

   strcpy (agent->pidfile,tokens->argv[1]);

   return (0);
}

static int parse_listen (struct agent *agent,struct tokens *tokens)
{
   if (agent->listen.sin_addr.s_addr != INADDR_NONE)
	 {
		already_defined (tokens);
		return (-1);
	 }

   if (tokens->argc != 2)
	 {
		parse_error (tokens,"{ <host> | <addr> } [ : { <service> | <port> } ]");
		return (-1);
	 }

   if (atos (&agent->listen,tokens->argv[1]))
	 {
		abz_set_error ("failed to parse %s: %m",tokens->argv[1]);
		return (-1);
	 }

   if (!agent->listen.sin_port)
	 {
#ifdef GETSERVBYNAME
		if (atop (&agent->listen.sin_port,"snmp"))
#endif	/* #ifdef GETSERVBYNAME */
		  agent->listen.sin_port = htons (161);
	 }

   return (0);
}

static int parse_allow (struct agent *agent,struct tokens *tokens)
{
   struct allow *allow;

   if (tokens->argc != 2)
	 {
		parse_error (tokens,"{ <host> | <addr> | <network> [ / <cidr-mask> ] }");
		return (-1);
	 }

   if ((allow = mem_alloc (sizeof (struct allow))) == NULL)
	 {
		out_of_memory ();
		return (-1);
	 }

   memset (allow,0L,sizeof (struct allow));

   if (aton (&allow->network,tokens->argv[1]))
	 {
		abz_set_error ("failed to parse %s: %m",tokens->argv[1]);
		mem_free (allow);
		return (-1);
	 }

   if (agent->allow != NULL)
	 {
		struct allow *tmp = agent->allow;

		while (tmp->next != NULL)
		  tmp = tmp->next;

		tmp->next = allow;
	 }
   else agent->allow = allow;

   return (0);
}

static int parse_community (struct agent *agent,struct tokens *tokens)
{
   if (agent->community != NULL)
	 {
		already_defined (tokens);
		return (-1);
	 }

   if (tokens->argc != 2)
	 {
		parse_error (tokens,"<community-string>");
		return (-1);
	 }

   if ((agent->community = mem_alloc (strlen (tokens->argv[1]) + 1)) == NULL)
     {
		out_of_memory ();
		return (-1);
	 }

   strcpy (agent->community,tokens->argv[1]);

   return (0);
}

static int parse_cache (struct agent *agent,struct tokens *tokens)
{
   uint32_t value;

   if (agent->timeout)
	 {
		already_defined (tokens);
		return (-1);
	 }

   if (tokens->argc != 2 || atou32 (tokens->argv[1],&value) || !value)
	 {
		parse_error (tokens,"<timeout-in-seconds>");
		return (-1);
	 }

   agent->timeout = value;

   return (0);
}

static int parse_module (struct agent *agent,struct tokens *tokens)
{
   if (tokens->argc != 2)
	 {
		parse_error (tokens,"<module-name>");
		return (-1);
	 }

   return ((agent->parse_module = module_parse (tokens->argv[1])) != NULL ? 0 : -1);
}

static int comment_open (struct agent *agent,struct tokens *tokens)
{
   if (tokens->argc != 2)
	 {
		parse_error (tokens,"<module-name>");
		return (-1);
	 }

   if (agent->comment)
	 {
		abz_set_error ("nested %s's not allowed",tokens->argv[0]);
		return (-1);
	 }

   agent->comment = module_present (tokens->argv[1]) ? ACCEPT : IGNORE;

   return (0);
}

static int comment_close (struct agent *agent,struct tokens *tokens)
{
   if (tokens->argc != 1)
	 {
		parse_error (tokens,NULL);
		return (-1);
	 }

   if (!agent->comment)
	 {
		abz_set_error ("endif without ifdef");
		return (-1);
	 }

   agent->comment = 0;

   return (0);
}

int agent_parse (struct agent *agent,struct tokens *tokens)
{
   static const struct
	 {
		const char *name;
		int (*parse) (struct agent *,struct tokens *);
	 } command[] =
	 {
		{ "user", parse_user },
		{ "group", parse_group },
		{ "pidfile", parse_pidfile },
		{ "listen", parse_listen },
		{ "allow", parse_allow },
		{ "community", parse_community },
		{ "cache", parse_cache },
		{ "module", parse_module },
		{ "ifdef", comment_open },
		{ "endif", comment_close }
	 };

   abz_clear_error ();

   if (tokens == NULL)
	 return (agent_parse_end (agent));

   if (agent->parse_module == NULL)
	 {
		uint32_t i;

		if (agent->comment == IGNORE &&
			strcmp (tokens->argv[0],"ifdef") &&
			strcmp (tokens->argv[0],"endif"))
		  return (0);

		for (i = 0; i < ARRAYSIZE (command); i++)
		  if (!strcmp (tokens->argv[0],command[i].name))
			return (command[i].parse (agent,tokens));

		abz_set_error ("unknown statement %s",tokens->argv[0]);
	 }
   else
	 {
		int result;

		if ((result = agent->parse_module (tokens)) >= 0)
		  {
			 if (!result)
			   {
				  agent->parse_module = NULL;
				  return (agent_parse (agent,tokens));
			   }

			 return (0);
		  }
	 }

   return (-1);
}

#ifdef DEBUG
#include <debug/log.h>
void agent_print_stub (const char *filename,int line,const char *function,int level,
					   const struct agent *agent)
{
   const struct allow *allow;

   log_printf_stub (filename,line,function,level,
					"# agent\n"
					"user %u\n"
					"group %u\n"
					"pidfile \"%s\"\n"
					"listen %u.%u.%u.%u:%u\n"
					"community \"%s\"\n",
					agent->uid,
					agent->gid,
					agent->pidfile,
					NIPQUAD (agent->listen.sin_addr.s_addr),
					ntohs (agent->listen.sin_port),
					agent->community);

   if (agent->timeout)
	 log_printf_stub (filename,line,function,level,
					  "cache %lu seconds\n",
					  agent->timeout);
   else
	 log_puts_stub (filename,line,function,level,"cache disabled\n");

   for (allow = agent->allow; allow != NULL; allow = allow->next)
	 log_printf_stub (filename,line,function,level,
					  "allow %u.%u.%u.%u/%u.%u.%u.%u\n",
					  NIPQUAD (allow->network.address),
					  NIPQUAD (allow->network.netmask));
}
#endif	/* #ifdef DEBUG */

