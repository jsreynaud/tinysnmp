
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
#include <stdint.h>

#include <tinysnmp/agent/module.h>
#include <ber/ber.h>
#include <debug/memory.h>
#include <abz/error.h>

#define test_add(odb,counter,str) test_add_stub(__FILE__,__LINE__,__FUNCTION__,odb,counter,str)
static int test_add_stub (const char *filename,int line,const char *function,
						  struct odb **odb,int32_t *counter,const char *str)
{
   snmp_value_t value;
   uint32_t *oid;

   value.type = BER_INTEGER;
   value.data.INTEGER = *counter;

   if ((oid = makeoid_stub (filename,line,function,str)) == NULL)
	 return (-1);

   if (odb_add (odb,oid,&value))
	 {
		mem_free (oid);
		return (-1);
	 }

   mem_free (oid);

   (*counter)++;

   return (0);
}

static int test_update (struct odb **odb)
{
   int32_t value = 1;
   int result = 0;

   abz_clear_error ();

   odb_destroy (odb);

   result |= test_add (odb,&value,"1.2.8.1.2.1.4.7");
   result |= test_add (odb,&value,"1.2.8.1.2.3.1");
   result |= test_add (odb,&value,"1.2.8.1.2.3.2.1.1");
   result |= test_add (odb,&value,"1.2.8.1.2.3.2.1.2");
   result |= test_add (odb,&value,"1.2.8.1.2.3.2.1.3");
   result |= test_add (odb,&value,"1.2.8.1.2.1.5.7");
   result |= test_add (odb,&value,"1.2.8.1.2.1.4.6");

   return (result);
}

static const uint32_t test[] = { 4, 42, 8, 1, 2 };

struct module module =
{
   .name	= "test",
   .descr	= "The MIB module to test TinySNMPd",
   .mod_oid	= test,
   .con_oid	= test,
   .parse	= NULL,
   .open	= NULL,
   .update	= test_update,
   .close	= NULL
};

