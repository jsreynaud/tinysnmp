
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
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <event.h>

#include <debug/log.h>
#include <debug/memory.h>
#include <debug/hex.h>

#include <abz/error.h>
#include <tinysnmp/tinysnmp.h>
#include <ber/ber.h>

#include "module.h"
#include "agent.h"
#include "network.h"
#include "snmp.h"

/* maximum UDP datagram size */
#define UDP_DATAGRAM_SIZE 65536

static int network_transmit (struct agent *agent,struct sockaddr *addr)
{
   int result,flags = MSG_WAITALL;

   abz_clear_error ();

#ifdef MSG_NOSIGNAL
   flags |= MSG_NOSIGNAL;
#endif	/* #ifdef MSG_NOSIGNAL */

#if defined(MSG_CONFIRM) && !defined(COMPAT22)
   /* this is good, but only Linux 2.3+ supports it (see sendto(2)) */
   flags |= MSG_CONFIRM;
#endif	/* #if defined(MSG_CONFIRM) && !defined(COMPAT22) */

   result = sendto (agent->fd,
					agent->packet.buf + agent->packet.size - agent->packet.offset,
					agent->packet.offset,
					flags,
					addr,
					sizeof (struct sockaddr));

   if (result > 0)
	 snmp_stats.snmpOutPkts++;

   if (result != agent->packet.offset)
	 {
		if (result < 0)
		  abz_set_error ("sendto failed: %m");
		else
		  abz_set_error ("short write count: %u/%u bytes sent",result,agent->packet.offset);

		return (-1);
	 }

#ifdef DEBUG
   log_printf (LOG_DEBUG,
			   "sent %u bytes to %u.%u.%u.%u:%u\n",
			   agent->packet.offset,
			   NIPQUAD (((const struct sockaddr_in *) addr)->sin_addr.s_addr),
			   ntohs (((const struct sockaddr_in *) addr)->sin_port));

   hexdump (LOG_NOISY,
			agent->packet.buf + agent->packet.size - agent->packet.offset,
			agent->packet.offset);
#endif	/* #ifdef DEBUG */

   return (0);
}

static int network_receive (struct agent *agent,struct sockaddr *addr)
{
   int result,flags = MSG_WAITALL;
   socklen_t length = sizeof (struct sockaddr);
   struct allow *allow;

   abz_clear_error ();

#ifdef MSG_NOSIGNAL
   flags |= MSG_NOSIGNAL;
#endif	/* #ifdef MSG_NOSIGNAL */

   result = recvfrom (agent->fd,agent->packet.buf,UDP_DATAGRAM_SIZE,flags,addr,&length);

   if (result > 0)
	 snmp_stats.snmpInPkts++;

   if (result <= 0 || result > UDP_DATAGRAM_SIZE)
	 {
		memset (addr,0L,sizeof (struct sockaddr));

		if (result < 0)
		  abz_set_error ("recvfrom failed: %m");
		else if (!result)
		  abz_set_error ("received empty packet");
		else
		  abz_set_error ("incoming packet too big");

		return (-1);
	 }

   agent->packet.offset = 0;
   agent->packet.size = result;

#ifdef DEBUG
   log_printf (LOG_DEBUG,
			   "received %u bytes from %u.%u.%u.%u:%u\n",
			   agent->packet.size,
			   NIPQUAD (((const struct sockaddr_in *) addr)->sin_addr.s_addr),
			   ntohs (((const struct sockaddr_in *) addr)->sin_port));

   hexdump (LOG_NOISY,agent->packet.buf,agent->packet.size);
#endif	/* #ifdef DEBUG */

   for (allow = agent->allow; allow != NULL; allow = allow->next)
	 if ((((struct sockaddr_in *) addr)->sin_addr.s_addr & allow->network.netmask) == allow->network.address)
	   return (0);

   abz_set_error ("not in list of allowed clients");

   return (-1);
}

static int network_process (struct agent *agent,uint32_t *type)
{
   snmp_pdu_t pdu;

   if (snmp_decode (&pdu,&agent->packet))
	 {
		abz_set_error ("failed to decode packet");
		return (-1);
	 }

   if (pdu.community.len != strlen (agent->community) ||
	   memcmp (pdu.community.buf,agent->community,pdu.community.len))
	 {
		snmp_stats.snmpInBadCommunityNames++;
		snmp_free (&pdu);
		abz_set_error ("invalid community string");
		return (-1);
	 }

   agent->packet.offset = 0;
   agent->packet.size = UDP_DATAGRAM_SIZE;

   if (snmp_encode (&agent->packet,&pdu,agent->timeout))
	 {
		snmp_free (&pdu);
		abz_set_error ("failed to encode pdu");
		return (-1);
	 }

   *type = pdu.type;

   snmp_free (&pdu);

   return (0);
}

static void network_accept (int fd,short event,void *arg)
{
   struct agent *agent = arg;
   struct sockaddr addr;
   uint32_t type;

   abz_clear_error ();

   if (network_receive (agent,&addr) || network_process (agent,&type))
	 {
		struct sockaddr_in *client = (struct sockaddr_in *) &addr;

		if (client->sin_addr.s_addr || client->sin_port)
		  log_printf (LOG_WARNING,
					  "rejected packet from %u.%u.%u.%u:%u: ",
					  NIPQUAD (client->sin_addr.s_addr),
					  ntohs (client->sin_port));

		log_printf (LOG_WARNING,"%s\n",abz_get_error ());
	 }
   else if (network_transmit (agent,&addr))
	 {
		struct sockaddr_in *client = (struct sockaddr_in *) &addr;

		log_printf (LOG_WARNING,
					"reply to %s from %u.%u.%u.%u:%u failed: %s\n",
					type == BER_GetRequest ? "get-request" : "get-next-request",
					NIPQUAD (client->sin_addr.s_addr),
					ntohs (client->sin_port),
					abz_get_error ());
	 }
}

int network_open (struct agent *agent)
{
   int flags;

   if ((agent->packet.buf = mem_alloc (UDP_DATAGRAM_SIZE)) == NULL)
	 {
		log_printf (LOG_ERROR,"failed to allocate memory: %m\n");
		return (-1);
	 }

   if ((agent->fd = socket (AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0)
	 {
		log_printf (LOG_ERROR,"unable to create socket: %m\n");
		mem_free (agent->packet.buf);
		return (-1);
	 }

   if ((flags = fcntl (agent->fd,F_GETFL)) < 0 || fcntl (agent->fd,F_SETFL,flags | O_NONBLOCK))
	 {
		log_printf (LOG_ERROR,"failed to set non-blocking i/o: %m\n");
		mem_free (agent->packet.buf);
		close (agent->fd);
		return (-1);
	 }

#ifdef DEBUG
   do
	 {
		const int enable = 1;

		if (setsockopt (agent->fd,SOL_SOCKET,SO_REUSEADDR,&enable,sizeof (enable)))
		  log_printf (LOG_WARNING,"failed to reuse local addresses: %m\n");
	 }
   while (0);
#endif	/* #ifdef DEBUG */

   if (bind (agent->fd,(struct sockaddr *) &agent->listen,sizeof (struct sockaddr)))
	 {
		log_printf (LOG_ERROR,"failed to bind to socket: %m\n");
		mem_free (agent->packet.buf);
		close (agent->fd);
		return (-1);
	 }

   event_set (&agent->event,agent->fd,EV_READ | EV_PERSIST,network_accept,agent);

   if (event_add (&agent->event,NULL))
	 {
		log_printf (LOG_ERROR,"failed to add event handler: %m\n");
		mem_free (agent->packet.buf);
		close (agent->fd);
		return (-1);
	 }

   log_printf (LOG_VERBOSE,
			   "listening on %u.%u.%u.%u:%u [udp]\n",
			   NIPQUAD (agent->listen.sin_addr.s_addr),
			   ntohs (agent->listen.sin_port));

   return (0);
}

void network_close (struct agent *agent)
{
   static volatile int called = 0;

   if (!called)
	 {
		mem_free (agent->packet.buf);
		event_del (&agent->event);
		close (agent->fd);

		called = 1;
	 }
}

