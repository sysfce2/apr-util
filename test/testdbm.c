/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * This file came from the SDBM package (written by oz@nexus.yorku.ca).
 * That package was under public domain. This file has been ported to
 * APR, updated to ANSI C and other, newer idioms, and added to the Apache
 * codebase under the above copyright and license.
 */

/*
 * testdbm: Simple APR dbm tester.
 * Automatic test case: ./testdbm auto foo
 *  - Attempts to store and fetch values from the DBM.
 *
 * Run the program for more help.
 */

#include "apr.h"
#include "apr_general.h"
#include "apr_pools.h"
#include "apr_errno.h"
#include "apr_getopt.h"
#include "apr_time.h"

#if APR_HAVE_STDIO_H
#include <stdio.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>     /* for atexit(), malloc() */
#include <string.h>

#include "apr_dbm.h"

static const char *progname;
static int rflag;

#define DERROR      0
#define DLOOK       1

#define DDELETE     3
#define DCAT        4
#define DBUILD      5
#define DPRESS      6
#define DCREAT      7
#define DNAME       8
#define DTRUNC      9
#define DAUTO      10

#define LINEMAX     8192

typedef struct {
    const char *sname;
    int scode;
    int flags;
} cmd;

static const cmd cmds[] = {

    { "fetch",   DLOOK,   APR_DBM_READONLY },
    { "get",     DLOOK,   APR_DBM_READONLY },
    { "look",    DLOOK,   APR_DBM_READONLY },
    { "add",     DBUILD,  APR_DBM_READWRITE },
    { "insert",  DBUILD,  APR_DBM_READWRITE },
    { "store",   DBUILD,  APR_DBM_READWRITE },
    { "delete",  DDELETE, APR_DBM_READWRITE },
    { "remove",  DDELETE, APR_DBM_READWRITE },
    { "dump",    DCAT,    APR_DBM_READONLY },
    { "list",    DCAT,    APR_DBM_READONLY },
    { "cat",     DCAT,    APR_DBM_READONLY },
    { "build",   DBUILD,  APR_DBM_RWCREATE },    /** this one creates the DB */
    { "creat",   DCREAT,  APR_DBM_RWCREATE },
    { "trunc",   DTRUNC,  APR_DBM_RWTRUNC },
    { "new",     DCREAT,  APR_DBM_RWCREATE },
    { "names",   DNAME,   APR_DBM_READONLY },
#if 0
    {"squash",   DPRESS,  APR_DBM_READWRITE, },
    {"compact",  DPRESS,  APR_DBM_READWRITE, },
    {"compress", DPRESS,  APR_DBM_READWRITE, },
#endif
    { "auto",    DAUTO,   APR_DBM_RWCREATE },
};

#define CMD_SIZE (sizeof(cmds)/sizeof(cmd))

static void doit(const cmd *act, const char*type, const char *file, apr_pool_t *pool);
static const cmd *parse_command(const char *str);
static void prdatum(FILE *stream, apr_datum_t d);
static void oops(apr_dbm_t *dbm, apr_status_t rv, const char *s1,
                 const char *s2);
static void show_usage();

int main(int argc, const char * const * argv)
{
    apr_pool_t *pool;
    const cmd *act;
    apr_getopt_t *os;
    char optch;
    const char *optarg;
    const char*dbtype;

    (void) apr_initialize();
    apr_pool_create(&pool, NULL);
    atexit(apr_terminate);

    (void) apr_getopt_init(&os, pool, argc, argv);

    progname = argv[0];
    dbtype = "default";

    while (apr_getopt(os, "Rt:", &optch, &optarg) == APR_SUCCESS) {
        switch (optch) {
        case 'R':       /* raw processing  */
            rflag++;
            break;
        case 't':
            dbtype = optarg;
            break;
        default:
            show_usage();
            fputs("unknown option.",stderr);
            exit(-1);
            break;
        }
    }

    if (argc <= os->ind) {
        show_usage();
        fputs("Note: If you have no clue what this program is, start with:\n", stderr);
        fputs("      ./testdbm auto foo\n", stderr);
        fputs("      where foo is the DBM prefix.\n", stderr);
        exit(-2);
    }

    if ((act = parse_command(argv[os->ind])) == NULL) {
        show_usage();
        fprintf(stderr, "unrecognized command: %s\n", argv[os->ind]);
        exit(-3);
    }

    if (++os->ind >= argc) {
        show_usage();
        fputs("please supply a DB file to use (may be created)\n", stderr);
        exit(-4);
    }

    doit(act, dbtype, argv[os->ind], pool);

    apr_pool_destroy(pool);

    return 0;
}

static void doit(const cmd *act, const char*type, const char *file, 
                 apr_pool_t *pool)
{
    apr_status_t rv;
    apr_datum_t key;
    apr_datum_t val;
    apr_dbm_t *db;
    char *op;
    int n;
    char *line;
    const char *use1;
    const char *use2;
#ifdef TIME
    long start;
    extern long time();
#endif

    rv = apr_dbm_open_ex(&db, type, file, act->flags, APR_OS_DEFAULT, pool);
    if (rv != APR_SUCCESS)
        oops(db, rv, "cannot open: %s", file);

    line = (char *) apr_palloc(pool,LINEMAX);

    switch (act->scode) {

    case DLOOK:
        while (fgets(line, LINEMAX, stdin) != NULL) {
            n = strlen(line) - 1;
            line[n] = 0;
            if (n == 0)
                break;

            key.dptr = line;
            key.dsize = n;
            rv = apr_dbm_fetch(db, key, &val);
            if (rv == APR_SUCCESS) {
                prdatum(stdout, val);
                putchar('\n');
                continue;
            }
            prdatum(stderr, key);
            fprintf(stderr, ": not found.\n");
        }
        break;

    case DDELETE:
        while (fgets(line, LINEMAX, stdin) != NULL) {
            n = strlen(line) - 1;
            line[n] = 0;
            if (n == 0)
                break;

            key.dptr = line;
            key.dsize = n;
            if (apr_dbm_delete(db, key) != APR_SUCCESS) {
                prdatum(stderr, key);
                fprintf(stderr, ": not found.\n");
            }
        }
        break;
    case DCAT:
        rv = apr_dbm_firstkey(db, &key);
        if (rv != APR_SUCCESS)
            oops(db, rv, "could not fetch first key: %s", file);

        while (key.dptr != NULL) {
            prdatum(stdout, key);
            putchar('\t');
            rv = apr_dbm_fetch(db, key, &val);
            if (rv != APR_SUCCESS)
                oops(db, rv, "apr_dbm_fetch", "failure");
            prdatum(stdout, val);
            putchar('\n');
            rv = apr_dbm_nextkey(db, &key);
            if (rv != APR_SUCCESS)
                oops(db, rv, "NextKey", "failure");
        }
        break;
    case DBUILD:
#ifdef TIME
        start = time(0);
#endif
        while (fgets(line, LINEMAX, stdin) != NULL) {
            n = strlen(line) - 1;
            line[n] = 0;
            if (n == 0)
                break;

            key.dptr = line;
            if ((op = strchr(line, '\t')) != 0) {
                key.dsize = op - line;
                *op++ = 0;
                val.dptr = op;
                val.dsize = line + n - op;
            }
            else
                oops(NULL, APR_EGENERAL, "bad input: %s", line);

            rv = apr_dbm_store(db, key, val);
            if (rv != APR_SUCCESS) {
                prdatum(stderr, key);
                fprintf(stderr, ": ");
                oops(db, rv, "store: %s", "failed");
            }
        }
#ifdef TIME
        printf("done: %d seconds.\n", time(0) - start);
#endif
        break;
    case DPRESS:
        break;
    case DCREAT:
        break;
    case DTRUNC:
        break;
    case DNAME:
        apr_dbm_get_usednames(pool, file, &use1, &use2);
        fprintf(stderr, "%s %s\n", use1, use2);
        break;
    case DAUTO:
        {
            int i;
            char *valdata = "0123456789";
            fprintf(stderr, "Generating data: ");
            for (i = 0; i < 10; i++) {
                int j;
                char c, keydata[10];
                for (j = 0, c = 'A' + (i % 16); j < 10; j++, c++) {
                    keydata[j] = c;
                }
                key.dptr = keydata;
                key.dsize = 10;
                val.dptr = valdata;
                val.dsize = 10;
                rv = apr_dbm_store(db, key, val);
                if (rv != APR_SUCCESS) {
                    prdatum(stderr, key);
                    fprintf(stderr, ": ");
                    oops(db, rv, "store: %s", "failed");
                }
            }
            fputs("OK\n", stderr);
            fputs("Testing retrieval: ", stderr);
            for (i = 0; i < 10; i++) {
                int j;
                char c, keydata[10];
                for (j = 0, c = 'A' + (i % 16); j < 10; j++, c++) {
                    keydata[j] = c;
                }
                key.dptr = keydata;
                key.dsize = 10;
                rv = apr_dbm_fetch(db, key, &val);
                if (rv != APR_SUCCESS || val.dsize != 10 ||
                    (strncmp(val.dptr, valdata, 10) != 0) ) { 
                    prdatum(stderr, key);
                    fprintf(stderr, ": ");
                    oops(db, rv, "fetch: %s", "failed");
                }
            }
            fputs("OK\n", stderr);
        }
        break;
    }

    apr_dbm_close(db);
}

static const cmd *parse_command(const char *str)
{
    int i;

    for (i = 0; i < CMD_SIZE; i++)
        if (strcasecmp(cmds[i].sname, str) == 0)
            return &cmds[i];

    return NULL;
}

static void prdatum(FILE *stream, apr_datum_t d)
{
    int c;
    const char *p = d.dptr;
    int n = d.dsize;

    while (n--) {
        c = *p++ & 0377;
        if (c & 0200) {
            fprintf(stream, "M-");
            c &= 0177;
        }
        if (c == 0177 || c < ' ') 
            fprintf(stream, "^%c", (c == 0177) ? '?' : c + '@');
        else
            putc(c, stream);
    }
}

static void oops(apr_dbm_t * dbm, apr_status_t rv, const char *s1,
                 const char *s2)
{
    char errbuf[200];

    if (progname) {
        fprintf(stderr, "%s: ", progname);
    }
    fprintf(stderr, s1, s2);
#if !defined(sun)
    if (errno > 0 && errno < sys_nerr)
        fprintf(stderr, " (%s)", sys_errlist[errno]);
#endif

    fprintf(stderr, "\n");

    if (rv != APR_SUCCESS) {
        apr_strerror(rv, errbuf, sizeof(errbuf));
        fprintf(stderr, "APR Error %d - %s\n", rv, errbuf);

        if (dbm) {
            apr_dbm_geterror(dbm, &rv, errbuf, sizeof(errbuf));
            fprintf(stderr, "APR_DB Error %d - %s\n", rv, errbuf);
        }
    }
    exit(1);
}

static void show_usage()
{
    int i;

    if (!progname) {
        progname = "testdbm";
    }

    fprintf(stderr, "%s [-t DBM-type] [-R] [commands] dbm-file-path\n", 
            progname);

    fputs("Available DBM-types:", stderr);
#if APU_HAVE_GDBM
    fputs(" GDBM", stderr);
#endif
#if APU_HAVE_SDBM
    fputs(" SDBM", stderr);
#endif
#if APU_HAVE_DB
    fputs(" DB", stderr);
#endif
    fputs(" default\n", stderr);

    fputs("Available commands:\n", stderr);
    for (i = 0; i < CMD_SIZE; i++) {
        fprintf(stderr, "%-8s%c", cmds[i].sname,
                ((i + 1) % 6 == 0) ? '\n' : ' ');
    }
    fputs("\n", stderr);
}
