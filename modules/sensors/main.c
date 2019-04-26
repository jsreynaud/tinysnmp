
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
#include <stddef.h>

#include <tinysnmp/tinysnmp.h>
#include <tinysnmp/agent/module.h>
#include <tinysnmp/agent/odb.h>

static int sensors_update (struct odb **odb)
{
   return (0);
}

/* iso.org.dod.internet.private.enterprises.frogfoot.servers.system.sensors */
static const uint32_t sensors[10] = { 9, 43, 6, 1, 4, 1, 10002, 1, 1, 2 };

/* iso.org.dod.internet.private.enterprises.frogfoot.servers.system.sensors.senMIB */
static const uint32_t senMIB[11] = { 10, 43, 6, 1, 4, 1, 10002, 1, 1, 2, 31 };

struct module module =
{
   .name	= "sensors",
   .descr	= "The MIB module to describe sensors",
   .mod_oid	= sensors,
   .con_oid	= senMIB,
   .parse	= NULL,
   .open	= NULL,
   .update	= sensors_update,
   .close	= NULL
};

