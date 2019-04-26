#ifndef _UNALIGNED_H
#define _UNALIGNED_H

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

/*
 * i386 can do unaligned accesses itself.
 *
 * The strange macros are there to make sure these can't
 * be misused in a way that makes them not work on other
 * architectures where unaligned accesses aren't as simple.
 */

/*
 * get_unaligned - get value from possibly mis-aligned location
 * @ptr: pointer to value
 *
 * This macro should be used for accessing values larger in size than
 * single bytes at locations that are expected to be improperly aligned,
 * e.g. retrieving a u16 value from a location not u16-aligned.
 *
 * Note that unaligned accesses can be very expensive on some architectures.
 **/
#define get_unaligned(ptr) (*(ptr))

/*
 * put_unaligned - put value to a possibly mis-aligned location
 * @val: value to place
 * @ptr: pointer to location
 *
 * This macro should be used for placing values larger in size than
 * single bytes at locations that are expected to be improperly aligned,
 * e.g. writing a u16 value to a location not u16-aligned.
 *
 * Note that unaligned accesses can be very expensive on some architectures.
 */
#define put_unaligned(val,ptr) ((void) (*(ptr) = (val)))

/*
 * copy_unaligned = copy value to/from possibly mis-aligned locations
 * @to: pointer to destination
 * @from: pointer to source
 */
#define copy_unaligned(to,from) put_unaligned(get_unaligned(from),to)

#endif	/* #ifndef _UNALIGNED_H */
