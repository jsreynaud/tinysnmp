#ifndef _MANAGER_SNMP_H
#define _MANAGER_SNMP_H

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

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <tinysnmp/tinysnmp.h>
#include <ber/ber.h>

/* maximum UDP datagram size */
#define UDP_DATAGRAM_SIZE 65535

typedef struct
{
   struct sockaddr_in addr;
   octet_string_t community;
   ber_t ber;
   snmp_pdu_t pdu;
   int state;
   int fd;
   int flags;
   uint8_t data[UDP_DATAGRAM_SIZE];
} snmp_agent_t;

enum
{
   SNMP_ERROR	= -1,
   SNMP_SUCCESS	= 0,
   SNMP_WRITE	= 1,
   SNMP_READ	= 2
};

/*
 * Initialize agent structure.
 *
 *     agent        snmp agent info
 */
extern void snmp_init (snmp_agent_t *agent);

/*
 * Set address/port of agent.
 *
 *     agent        snmp agent info
 *     host         string in the form <hostname>[:<service>]
 *
 * Returns 0 if successful, -1 if some error occurred. The
 * caller may retrieve the error message with abz_get_error().
 *
 * The agent structure must be initialized with snmp_init()
 * before calling this function.
 */
extern int snmp_init_addr (snmp_agent_t *agent,char *host);

/*
 * Initialize community structure.
 *
 *     agent        snmp agent info
 *     string       community string used for authentication
 *
 * The string parameter must remain valid for the duration of
 * use of the initialized community parameter as it contains
 * a pointer to string.
 *
 * The agent structure must be initialized with snmp_init()
 * before calling this function.
 */
extern void snmp_init_community (snmp_agent_t *agent,char *string);

/*
 * Free resources allocated by snmp_open() function.
 *
 *     agent        snmp agent info
 */
extern void snmp_close (snmp_agent_t *agent);

/*
 * Open a connection to the agent. The agent data structure should
 * be initialized before calling this function.
 *
 *     agent        snmp agent info
 *
 * Returns SNMP_SUCCESS if successful, SNMP_WRITE if the function
 * should be called again, or SNMP_ERROR if some error occurred.
 *
 * If SNMP_WRITE is returned, the caller should wait until the file
 * descriptor becomes writable.
 *
 * If SNMP_ERROR is returned, the caller may retrieve the error
 * message with abz_get_error().
 */
extern int snmp_open (snmp_agent_t *agent);

/*
 * Open a connection to the agent. The agent data structure should
 * be initialized before calling this function.
 *
 *     agent        snmp agent info
 *     timeout      timeout in seconds
 *
 * Returns 0 if successful, -1 if some error occurred. The caller
 * may retrieve the error message using abz_get_error().
 */
extern int snmp_open_s (snmp_agent_t *agent,time_t timeout);

/*
 * Free memory allocated by snmp_get() function.
 *
 *     value        array of snmp values
 *     n            number of values in array
 */
extern void snmp_free (snmp_value_t *value,size_t n);

/*
 * Retrieve values from the agent. A connection should be opened
 * with snmp_open() before calling this function.
 *
 *     agent        snmp agent info
 *     oid          array of ObjectID's to retrieve
 *     value        array of values fetched from agent
 *     n            number of ObjectID's in list
 *
 * Returns SNMP_SUCCESS if successful, SNMP_READ or SNMP_WRITE if
 * the function should be called again, or SNMP_ERROR if some
 * error occurred.
 *
 * If SNMP_WRITE is returned, the caller should wait until the file
 * descriptor becomes writable.
 *
 * If SNMP_READ is returned, the caller should wait until the file
 * descriptor becomes readable.
 *
 * If SNMP_ERROR is returned, the caller mey retrieve the error
 * message with abz_get_error().
 */
extern int snmp_get (snmp_agent_t *agent,uint32_t **oid,snmp_value_t *value,size_t n);

/*
 * Retrieve values from the agent. A connection should be opened
 * with snmp_open() before calling this function.
 *
 *     agent        snmp agent info
 *     oid          array of ObjectID's to retrieve
 *     value        array of values fetched from agent
 *     n            number of ObjectID's in list
 *     timeout      timeout in seconds
 *
 * Returns 0 if successful, -1 if some error occurred. The caller
 * may retrieve the error message using abz_get_error().
 */
extern int snmp_get_s (snmp_agent_t *agent,uint32_t **oid,snmp_value_t *value,size_t n,time_t timeout);

/*
 * Retrieve all the values (and their corresponding ObjectID's) that
 * lexigraphically succeeds the specified ObjectID's from the agent.
 * A connection should be opened with snmp_open() before calling this
 * function.
 *
 *     agent        snmp agent info
 *     oid          array of (partial) ObjectID's to send to agent
 *     next         array of next values fetched from agent
 *     n            number of ObjectID's in list
 *
 * Returns SNMP_SUCCESS if successful, SNMP_READ or SNMP_WRITE if
 * the function should be called again, or SNMP_ERROR if some
 * error occurred.
 *
 * If SNMP_WRITE is returned, the caller should wait until the file
 * descriptor becomes writable.
 *
 * If SNMP_READ is returned, the caller should wait until the file
 * descriptor becomes readable.
 *
 * If SNMP_ERROR is returned, the caller mey retrieve the error
 * message with abz_get_error().
 */
extern int snmp_get_next (snmp_agent_t *agent,uint32_t **oid,snmp_next_value_t *next,size_t n);

/*
 * Retrieve all the values (and their corresponding ObjectID's) that
 * lexigraphically succeeds the specified ObjectID's from the agent.
 * A connection should be opened with snmp_open() before calling this
 * function.
 *
 *     agent        snmp agent info
 *     oid          array of (partial) ObjectID's to send to agent
 *     next         array of next values fetched from agent
 *     n            number of ObjectID's in list
 *     timeout      timeout in seconds
 *
 * Returns 0 if successful, -1 if some error occurred. The caller
 * may retrieve the error message using abz_get_error().
 */
extern int snmp_get_next_s (snmp_agent_t *agent,uint32_t **oid,snmp_next_value_t *next,size_t n,time_t timeout);

/*
 * Free memory allocated by snmp_get_next() function.
 *
 *     value        array of snmp next value/oid pairs
 *     n            number of next value/oid pairs in array
 */
extern void snmp_free_next (snmp_next_value_t *next,size_t n);

#endif	/* #ifndef _MANAGER_SNMP_H */
