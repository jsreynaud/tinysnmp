
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
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <debug/log.h>
#include <debug/memory.h>

#include <abz/error.h>
#include <abz/atoa.h>
#include <abz/atop.h>

#include <tinysnmp/tinysnmp.h>
#include <tinysnmp/manager/snmp.h>
#include <ber/ber.h>

#include "pdu.h"

void snmp_init (snmp_agent_t *agent)
{
   assert (agent != NULL);
   memset (agent,0L,sizeof (snmp_agent_t));
   agent->state = SNMP_SUCCESS;
   agent->fd = -1;

#ifdef MSG_NOSIGNAL
   agent->flags |= MSG_NOSIGNAL;
#endif	/* #ifdef MSG_NOSIGNAL */

#if defined(MSG_CONFIRM) && !defined(COMPAT22)
   /* this is good, but only Linux 2.3+ supports it (see send(2)) */
   agent->flags |= MSG_CONFIRM;
#endif	/* #if defined(MSG_CONFIRM) && !defined(COMPAT22) */
}

int snmp_init_addr (snmp_agent_t *agent,char *host)
{
   char *port = NULL;

   assert (agent != NULL && host != NULL);
   abz_clear_error ();

   memset (&agent->addr,0L,sizeof (agent->addr));
   agent->addr.sin_family = PF_INET;

   if ((port = strchr (host,':')) != NULL)
	 *port++ = '\0';

   if (atoa (&agent->addr.sin_addr.s_addr,host))
	 {
		abz_set_error ("invalid hostname: %s",host);
		return (-1);
	 }

   if (port != NULL)
	 {
		if (atop (&agent->addr.sin_port,port))
		  {
			 abz_set_error ("invalid service/port: %s",port);
			 return (-1);
		  }

		*--port = ':';
	 }
   else
	 {
#ifdef GETSERVBYNAME
		if (atop (&agent->addr.sin_port,"snmp"))
#endif	/* #ifdef GETSERVBYNAME */
		  agent->addr.sin_port = htons (161);
	 }

   return (0);
}

void snmp_init_community (snmp_agent_t *agent,char *string)
{
   assert (agent != NULL && string != NULL);
   agent->community.buf = (uint8_t *) string;
   agent->community.len = strlen (string);
}

void snmp_close (snmp_agent_t *agent)
{
   assert (agent != NULL);

   if (agent->fd != -1)
	 close (agent->fd);

   snmp_init (agent);
}

int snmp_open (snmp_agent_t *agent)
{
   assert (agent != NULL);
   abz_clear_error ();

   if (agent->state == SNMP_SUCCESS)
	 {
		int flags;

		if ((agent->fd = socket (agent->addr.sin_family,SOCK_DGRAM,IPPROTO_UDP)) < 0)
		  {
			 abz_set_error ("socket: %m");
			 return (SNMP_ERROR);
		  }

		if ((flags = fcntl (agent->fd,F_GETFL)) < 0 ||
			fcntl (agent->fd,F_SETFL,flags | O_NONBLOCK) < 0)
		  {
			 abz_set_error ("fcntl: %m");
			 snmp_close (agent);
			 return (SNMP_ERROR);
		  }

		if (!connect (agent->fd,(const struct sockaddr *) &agent->addr,sizeof (agent->addr)))
		  return (SNMP_SUCCESS);

		if (errno == EINPROGRESS)
		  {
			 agent->state = SNMP_WRITE;
			 return (agent->state);
		  }
	 }
   else
	 {
		int optval;
		socklen_t optlen = sizeof (int);

		if (getsockopt (agent->fd,SOL_SOCKET,SO_ERROR,&optval,&optlen))
		  {
			 abz_set_error ("getsockopt: %m");
			 snmp_close (agent);
			 return (SNMP_ERROR);
		  }

		if (!optval)
		  {
			 agent->state = SNMP_SUCCESS;
			 return (SNMP_SUCCESS);
		  }
	 }

   abz_set_error ("connect %u.%u.%u.%u:%u: %m",
				  NIPQUAD (agent->addr.sin_addr.s_addr),
				  ntohs (agent->addr.sin_port));

   snmp_close (agent);
   return (SNMP_ERROR);
}

static void free_data (uint8_t type,snmp_data_t *data)
{
   if (type == BER_OID)
	 mem_free (data->OID);
   else if (type == BER_OCTET_STRING && data->OCTET_STRING.len)
	 mem_free (data->OCTET_STRING.buf);
}

void snmp_free (snmp_value_t *value,size_t n)
{
   size_t i;

   assert (value != NULL);

   for (i = 0; i < n; i++)
	 free_data (value[i].type,&value[i].data);
}

static int32_t make_request_id (void)
{
   struct timeval tv;

   if (gettimeofday (&tv,NULL))
	 return (0x13a48f75);

   return (tv.tv_sec | tv.tv_usec);
}

static int getpdu (snmp_agent_t *agent,uint32_t **oid,size_t n)
{
   int result;

   abz_clear_error ();

   if (agent->state == SNMP_SUCCESS)
	 {
		agent->ber.buf = agent->data;
		agent->ber.size = sizeof (agent->data);
		agent->ber.offset = 0;

		agent->pdu.version = SNMP_VERSION_1;
		agent->pdu.community = agent->community;
		agent->pdu.RequestID = make_request_id ();
		agent->pdu.n = n;
		agent->pdu.oid = oid;

		if (pdu_encode (&agent->ber,&agent->pdu))
		  return (SNMP_ERROR);

		agent->state = SNMP_WRITE;
	 }

   if (agent->state == SNMP_WRITE)
	 {
		result = send (agent->fd,
					   agent->ber.buf + agent->ber.size - agent->ber.offset,
					   agent->ber.offset,
					   agent->flags);

		if (result < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
		  {
			 abz_set_error ("send: %m");
			 return (SNMP_ERROR);
		  }

		if (result <= 0)
		  return (agent->state);

		agent->ber.offset = 0;
		agent->state = SNMP_READ;
	 }

   if (agent->state == SNMP_READ);
	 {
		result = recv (agent->fd,
					   agent->ber.buf,
					   agent->ber.size,
					   agent->flags);

		if (result < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
		  {
			 abz_set_error ("recv: %m");
			 return (SNMP_ERROR);
		  }

		if (result <= 0)
		  return (agent->state);

		agent->ber.size = result;
		agent->state = SNMP_SUCCESS;
	 }

   return (agent->state);
}

int snmp_get (snmp_agent_t *agent,uint32_t **oid,snmp_value_t *value,size_t n)
{
   int result;

   assert (agent != NULL && oid != NULL && value != NULL && n);

   if (agent->state == SNMP_SUCCESS)
	 agent->pdu.type = BER_GetRequest;

   result = getpdu (agent,oid,n);

   if (result == SNMP_SUCCESS && pdu_decode (&agent->ber,&agent->pdu,value))
	 return (SNMP_ERROR);

   return (result);
}

int snmp_get_next (snmp_agent_t *agent,uint32_t **oid,snmp_next_value_t *next,size_t n)
{
   int result;

   assert (agent != NULL && oid != NULL && next != NULL && n);

   if (agent->state == SNMP_SUCCESS)
	 agent->pdu.type = BER_GetNextRequest;

   result = getpdu (agent,oid,n);

   if (result == SNMP_SUCCESS && pdu_decode_next (&agent->ber,&agent->pdu,next))
	 return (SNMP_ERROR);

   return (result);
}

void snmp_free_next (snmp_next_value_t *next,size_t n)
{
   size_t i;

   assert (next != NULL && n);

   for (i = 0; i < n; i++)
	 {
		mem_free (next[i].oid);
		free_data (next[i].value.type,&next[i].value.data);
	 }
}

static int gettime (struct timeval *tv)
{
   abz_clear_error ();

   if (gettimeofday (tv,NULL))
	 {
		abz_set_error ("gettimeofday: %m");
		return (-1);
	 }

   return (0);
}

static int settime (struct timeval *tv,const struct timeval *st,time_t timeout)
{
   abz_clear_error ();

   if (gettime (tv))
	 return (-1);

   tv->tv_sec = st->tv_sec + timeout - tv->tv_sec;
   tv->tv_usec = st->tv_usec - tv->tv_usec;

   if (tv->tv_usec < 0 )
	 {
		tv->tv_sec--;
		tv->tv_usec += 1000000;
	 }

   if (tv->tv_sec < 0)
	 {
		abz_set_error ("timeout after %ld seconds",timeout);
		return (-1);
	 }

   return (0);
}

int snmp_open_s (snmp_agent_t *agent,time_t timeout)
{
   int result,again = 1;
   fd_set wfd;
   struct timeval tv,st;

   abz_clear_error ();

   if (gettime (&st))
	 return (-1);

   for (;;)
	 {
		if (again && (result = snmp_open (agent)) != SNMP_WRITE)
		  return (result == SNMP_ERROR ? -1 : 0);

		FD_ZERO (&wfd);
		FD_SET (agent->fd,&wfd);

		if (settime (&tv,&st,timeout))
		  return (-1);

		switch (select (agent->fd + 1,NULL,&wfd,NULL,&tv))
		  {
		   case -1:
			 if (errno != EINTR && errno != EAGAIN)
			   {
				  abz_set_error ("select: %m");
				  return (-1);
			   }
		   case 0:
			 again = 0;
			 break;
		   default:
			 again = 1;
		  }
	 }
}

int snmp_get_s (snmp_agent_t *agent,uint32_t **oid,snmp_value_t *value,size_t n,time_t timeout)
{
   int result = -1,again = 1;
   fd_set rfd,wfd;
   struct timeval tv,st;

   abz_clear_error ();

   if (gettime (&st))
	 return (-1);

   for (;;)
	 {
		if (again)
		  {
			 result = snmp_get (agent,oid,value,n);

			 if (result == SNMP_ERROR || result == SNMP_SUCCESS)
			   return (result == SNMP_ERROR ? -1 : 0);

			 again = 0;
		  }

		FD_ZERO (&rfd);
		FD_ZERO (&wfd);

		if (result == SNMP_READ)
		  FD_SET (agent->fd,&rfd);

		if (result == SNMP_WRITE)
		  FD_SET (agent->fd,&wfd);

		if (settime (&tv,&st,timeout))
		  return (-1);

		switch (select (agent->fd + 1,&rfd,&wfd,NULL,&tv))
		  {
		   case -1:
			 if (errno != EINTR && errno != EAGAIN)
			   {
				  abz_set_error ("select: %m");
				  return (-1);
			   }
		   case 0:
			 break;
		   default:
			 again = 1;
		  }
	 }
}

int snmp_get_next_s (snmp_agent_t *agent,uint32_t **oid,snmp_next_value_t *next,size_t n,time_t timeout)
{
   int result = -1,again = 1;
   fd_set rfd,wfd;
   struct timeval tv,st;

   abz_clear_error ();

   if (gettime (&st))
	 return (-1);

   for (;;)
	 {
		if (again)
		  {
			 result = snmp_get_next (agent,oid,next,n);

			 if (result == SNMP_ERROR || result == SNMP_SUCCESS)
			   return (result == SNMP_ERROR ? -1 : 0);

			 again = 0;
		  }

		FD_ZERO (&rfd);
		FD_ZERO (&wfd);

		if (result == SNMP_READ)
		  FD_SET (agent->fd,&rfd);

		if (result == SNMP_WRITE)
		  FD_SET (agent->fd,&wfd);

		if (settime (&tv,&st,timeout))
		  return (-1);

		switch (select (agent->fd + 1,&rfd,&wfd,NULL,&tv))
		  {
		   case -1:
			 if (errno != EINTR && errno != EAGAIN)
			   {
				  abz_set_error ("select: %m");
				  return (-1);
			   }
		   case 0:
			 break;
		   default:
			 again = 1;
		  }
	 }
}

