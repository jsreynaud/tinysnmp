#ifndef MODULE_H
#define MODULE_H

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
#include <sys/time.h>

#include <abz/typedefs.h>
#include <abz/tokens.h>

#include <tinysnmp/tinysnmp.h>
#include <tinysnmp/agent/odb.h>
#include <tinysnmp/agent/module.h>

struct snmp_stats
{
   uint32_t snmpInPkts;
   uint32_t snmpOutPkts;
   uint32_t snmpInBadVersions;
   uint32_t snmpInBadCommunityNames;
   uint32_t snmpInBadCommunityUses;
   uint32_t snmpInASNParseErrs;
   uint32_t snmpInTooBigs;
   uint32_t snmpInNoSuchNames;
   uint32_t snmpInBadValues;
   uint32_t snmpInReadOnlys;
   uint32_t snmpInGenErrs;
   uint32_t snmpInTotalReqVars;
   uint32_t snmpInTotalSetVars;
   uint32_t snmpInGetRequests;
   uint32_t snmpInGetNexts;
   uint32_t snmpInSetRequests;
   uint32_t snmpInGetResponses;
   uint32_t snmpInTraps;
   uint32_t snmpOutTooBigs;
   uint32_t snmpOutNoSuchNames;
   uint32_t snmpOutBadValues;
   uint32_t snmpOutGenErrs;
   uint32_t snmpOutGetRequests;
   uint32_t snmpOutGetNexts;
   uint32_t snmpOutSetRequests;
   uint32_t snmpOutGetResponses;
   uint32_t snmpOutTraps;
   uint32_t snmpSilentDrops;
   uint32_t snmpProxyDrops;
};

typedef int (*module_parse_t) (struct tokens *);

/* internal modules */
extern struct module module_system;
extern struct module module_snmp;

/* snmp counters */
extern struct snmp_stats snmp_stats;

/*
 * Load modules. This function will print warnings if it encounter errors
 * while loading modules. Failure to load modules are not considered fatal,
 * but if no modules can be loaded for some reason, an error message will
 * be printed and it will return -1. On success, 0 is returned.
 */
extern int module_open (const char *modulepath);

/*
 * Close modules and free memory allocated for module list.
 */
extern void module_close (void);

/*
 * Find an ObjectID. Return the value of * an existing ObjectID if
 * successful, or NULL if the ObjectID doesn't exist.
 */
extern const snmp_value_t *module_find (const uint32_t *oid,time_t timeout);

/*
 * Find an ObjectID that lexographically succeeds the specified one
 * or NULL if one doesn't exist. The specified ObjectID doesn't need
 * to exist in the database and can also be a partial ObjectID. The
 * returned object must be freed by the caller.
 */
extern snmp_next_value_t *module_find_next (const uint32_t *oid,time_t timeout);

/*
 * Return the parse callback of a module or NULL if none is found.
 * Call abz_get_error() to retrieve error messages if any.
 */
extern module_parse_t module_parse (const char *name);

/*
 * Check that all modules with parse callbacks have been been parsed
 * successfully. Call abz_get_error() to retrieve error messages if
 * any.
 */
extern int module_parse_end (void);

/*
 * Returns a non-zero integer if a module with the given name was
 * loaded, or zero if not.
 */
extern int module_present (const char *name);

/*
 * Add module to sysORTable. Returns 0 if successful, -1 if some
 * error occurred. Call abz_get_error() to retrieve error messages
 * if any.
 */
extern int module_extend (const uint32_t *oid,const char *descr);

/*
 * Print command-line parameters. The log system should be initialized
 * before calling this function.
 */
#ifdef DEBUG
#define module_print(level) module_print_stub(__FILE__,__LINE__,__FUNCTION__,level)
extern void module_print_stub (const char *filename,int line,const char *function,int level);
#else	/* #ifdef DEBUG */
#define module_print(level) do { } while(0)
#endif	/* #ifdef DEBUG */

#endif	/* #ifndef MODULE_H */
