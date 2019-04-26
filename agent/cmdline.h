#ifndef CMDLINE_H
#define CMDLINE_H

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

struct cmdline
{
   const char *progname;		/* what are we called?							*/
   const char *logfile;			/* location of log file							*/
   char *syslog;				/* syslog string								*/
   int loglevel;				/* logging system verbosity						*/
   int daemon;					/* are we a daemon?								*/
   const char *configfile;		/* location of configuration file				*/
   const char *modulepath;		/* path where loadable modules reside			*/
};

/*
 * Parse command-line parameters. This function takes care of printing
 * help messages and exiting if the parameters are incorrect.
 */
extern const struct cmdline *cmdline_parse (int argc,char *argv[]);

/*
 * Free memory allocated for storing configuration.
 */
extern void cmdline_destroy (void);

/*
 * Print command-line parameters. The log system should be initialized
 * before calling this function.
 */
#ifdef DEBUG
#define cmdline_print(level) cmdline_print_stub(__FILE__,__LINE__,__FUNCTION__,level)
extern void cmdline_print_stub (const char *filename,int line,const char *function,int level);
#else	/* #ifdef DEBUG */
#define cmdline_print(level) do { } while(0)
#endif	/* #ifdef DEBUG */

#endif	/* #ifndef CMDLINE_H */