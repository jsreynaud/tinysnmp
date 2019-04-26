#ifndef _AGENT_ODB_H
#define _AGENT_ODB_H

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

#include <tinysnmp/tinysnmp.h>

typedef enum { NODE, VALUE } node_t;

struct odb
{
   node_t type;
   union
	 {
		uint32_t node;
		snmp_value_t value;
	 } data;
   struct odb *parent;
   struct odb *sibling;
   struct odb *child;
};

/*
 * Create an ObjectID database.
 */
extern void odb_create (struct odb **odb);

/*
 * Destroy an ObjectID database. When this function returns, the
 * database is in exactly the same state as when initialized.
 */
extern void odb_destroy (struct odb **odb);

/*
 * Add a new ObjectID to the ObjectID database. Returns 0 if
 * successful, -1 otherwise. Call abz_get_error() to retrieve
 * the error message.
 */
extern int odb_add (struct odb **odb,const uint32_t *oid,const snmp_value_t *value);

/*
 * Remove an ObjectID (or collection of ObjectID's) from the ObjectID
 * database.
 */
extern void odb_remove (struct odb **odb,const uint32_t *oid);

/*
 * Find an ObjectID in the ObjectID database. Return the value of
 * an existing ObjectID in the database if successful, or NULL if
 * the ObjectID doesn't exist.
 */
extern const snmp_value_t *odb_find (const struct odb *odb,const uint32_t *oid);

/*
 * Find the ObjectID in the ObjectID database that lexographically
 * succeeds the specified one or NULL if one doesn't exist. The
 * specified ObjectID doesn't need to exist in the database and can
 * also be a partial ObjectID. The function may also return NULL if
 * there is not enough memory for temporary storage. Call abz_get_error()
 * to retrieve any possible error messages.
 */
extern snmp_next_value_t *odb_find_next (const struct odb *odb,const uint32_t *oid);

/*
 * Display an ObjectID database. Returns 0 if successful, or -1 if some
 * error occurred. Call abz_get_error() to retrieve the error message.
 */
#ifdef DEBUG
#define odb_show(level,odb) odb_show_stub(__FILE__,__LINE__,__FUNCTION__,level,odb)
extern int odb_show_stub (const char *filename,int line,const char *function,int level,const struct odb *odb);
#else	/* #ifdef DEBUG */
#define odb_show(level,odb) do { } while(0)
#endif	/* #ifdef DEBUG */

#endif	/* #ifndef _AGENT_ODB_H */
