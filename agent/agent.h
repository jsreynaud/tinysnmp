#ifndef AGENT_H
#define AGENT_H

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

#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <event.h>

#include <abz/typedefs.h>
#include <abz/tokens.h>
#include <abz/aton.h>

#include <ber/ber.h>

#include "module.h"

struct allow
{
   struct network network;
   struct allow *next;
};

struct agent
{
   uid_t uid;
   gid_t gid;
   char *pidfile;
   struct sockaddr_in listen;
   struct allow *allow;
   char *community;
   module_parse_t parse_module;
   uint8_t comment;
   int fd;
   struct event event;
   ber_t packet;
   time_t timeout;
};

/*
 * Initialize agent structure. This should be called before any of the
 * other functions that deal with `struct agent'.
 */
extern void agent_create (struct agent *agent);

/*
 * Parse an entry in the configuration file. The function is either
 * called with a set of tokens or NULL at the end of the file. It
 * returns 0 if successful, -1 if some error occurred. Call
 * abz_get_error() to retrieve the error message.
 */
extern int agent_parse (struct agent *agent,struct tokens *tokens);

/*
 * Free memory allocated to agent structure.
 */
extern void agent_destroy (struct agent *agent);

/*
 * Print command-line parameters. The log system should be initialized
 * before calling this function.
 */
#ifdef DEBUG
#define agent_print(level,agent) agent_print_stub(__FILE__,__LINE__,__FUNCTION__,level,agent)
extern void agent_print_stub (const char *filename,int line,const char *function,int level,const struct agent *agent);
#else	/* #ifdef DEBUG */
#define agent_print(level,agent) do { } while(0)
#endif	/* #ifdef DEBUG */

#endif	/* #ifndef AGENT_H */
