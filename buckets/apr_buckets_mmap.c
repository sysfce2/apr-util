/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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
 */

#include "apr_buckets.h"
#define APR_WANT_MEMFUNC
#include "apr_want.h"
#include <stdlib.h>

#if APR_HAS_MMAP

static apr_status_t mmap_read(apr_bucket *b, const char **str, 
			      apr_size_t *length, apr_read_type_e block)
{
    apr_bucket_mmap *m = b->data;
    apr_status_t ok;
    void *addr;
    
    ok = apr_mmap_offset(&addr, m->mmap, b->start);
    if (ok != APR_SUCCESS) {
	return ok;
    }
    *str = addr;
    *length = b->length;
    return APR_SUCCESS;
}

static void mmap_destroy(void *data)
{
    apr_bucket_mmap *m = data;

    if (apr_bucket_shared_destroy(m)) {
        /* no need to apr_mmap_delete(m->mmap) here... it will
         * get done automatically when the pool gets cleaned up. */
        free(m);
    }
}

/*
 * XXX: are the start and length arguments useful?
 */
APU_DECLARE(apr_bucket *) apr_bucket_mmap_make(apr_bucket *b,
		apr_mmap_t *mm, apr_off_t start, apr_size_t length)
{
    apr_bucket_mmap *m;

    m = malloc(sizeof(*m));
    if (m == NULL) {
	return NULL;
    }
    m->mmap = mm;

    b = apr_bucket_shared_make(b, m, start, length);
    b->type     = &apr_bucket_type_mmap;

    return b;
}


APU_DECLARE(apr_bucket *) apr_bucket_mmap_create(
		apr_mmap_t *mm, apr_off_t start, apr_size_t length)
{
    apr_bucket *b = (apr_bucket *)malloc(sizeof(*b));

    APR_BUCKET_INIT(b);
    b->free = free;
    return apr_bucket_mmap_make(b, mm, start, length);
}

static apr_status_t mmap_setaside(apr_bucket *data, apr_pool_t *p)
{
    apr_bucket_mmap *m = data->data;
    apr_mmap_t *mm = m->mmap;
    apr_mmap_t *new_mm;
    apr_status_t ok;

    if (apr_pool_is_ancestor(mm->cntxt, p)) {
        return APR_SUCCESS;
    }

    ok = apr_mmap_dup(&new_mm, mm, p, 1);
    if (ok != APR_SUCCESS) {
        return ok;
    }
    m->mmap = new_mm;
    return APR_SUCCESS;
}

APU_DECLARE_DATA const apr_bucket_type_t apr_bucket_type_mmap = {
    "MMAP", 5,
    mmap_destroy,
    mmap_read,
    mmap_setaside,
    apr_bucket_shared_split,
    apr_bucket_shared_copy
};

#endif
