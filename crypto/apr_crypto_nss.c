/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apr_lib.h"
#include "apu.h"
#include "apu_config.h"
#include "apu_errno.h"

#include <ctype.h>
#include <stdlib.h>

#include "apr_strings.h"
#include "apr_time.h"
#include "apr_buckets.h"

#include "apr_crypto_internal.h"

#if APU_HAVE_CRYPTO

#include <prerror.h>

#ifdef HAVE_NSS_NSS_H
#include <nss/nss.h>
#endif
#ifdef HAVE_NSS_H
#include <nss.h>
#endif

#ifdef HAVE_NSS_PK11PUB_H
#include <nss/pk11pub.h>
#endif
#ifdef HAVE_PK11PUB_H
#include <pk11pub.h>
#endif

struct apr_crypto_t {
    apr_pool_t *pool;
    const apr_crypto_driver_t *provider;
    apu_err_t *result;
    apr_crypto_config_t *config;
    apr_hash_t *digests;
    apr_hash_t *types;
    apr_hash_t *modes;
};

struct apr_crypto_config_t {
       void *opaque;
};

struct apr_crypto_key_t {
    apr_pool_t *pool;
    const apr_crypto_driver_t *provider;
    const apr_crypto_t *f;
    const apr_crypto_key_rec_t *rec;
    CK_MECHANISM_TYPE cipherMech;
    CK_MECHANISM_TYPE hashMech;
    SECOidTag cipherOid;
    SECOidTag hashAlg;
    PK11SymKey *symKey;
    int ivSize;
    int keyLength;
};

struct apr_crypto_block_t {
    apr_pool_t *pool;
    const apr_crypto_driver_t *provider;
    const apr_crypto_t *f;
    PK11Context *ctx;
    const apr_crypto_key_t *key;
    SECItem *secParam;
    int blockSize;
};

struct apr_crypto_digest_t {
    apr_pool_t *pool;
    const apr_crypto_driver_t *provider;
    const apr_crypto_t *f;
    apr_crypto_digest_rec_t *rec;
    PK11Context *ctx;
    const apr_crypto_key_t *key;
    SECItem *secParam;
};

static struct apr_crypto_block_key_digest_t key_digests[] =
{
{ APR_CRYPTO_DIGEST_MD5, 16, 64 },
{ APR_CRYPTO_DIGEST_SHA1, 20, 64 },
{ APR_CRYPTO_DIGEST_SHA224, 28, 64 },
{ APR_CRYPTO_DIGEST_SHA256, 32, 64 },
{ APR_CRYPTO_DIGEST_SHA384, 48, 128 },
{ APR_CRYPTO_DIGEST_SHA512, 64, 128 } };

static struct apr_crypto_block_key_type_t key_types[] =
{
{ APR_KEY_3DES_192, 24, 8, 8 },
{ APR_KEY_AES_128, 16, 16, 16 },
{ APR_KEY_AES_192, 24, 16, 16 },
{ APR_KEY_AES_256, 32, 16, 16 } };

static struct apr_crypto_block_key_mode_t key_modes[] =
{
{ APR_MODE_ECB },
{ APR_MODE_CBC } };

/* sufficient space to wrap a key */
#define BUFFER_SIZE 128

/**
 * Fetch the most recent error from this driver.
 */
static apr_status_t crypto_error(const apu_err_t **result,
        const apr_crypto_t *f)
{
    *result = f->result;
    return APR_SUCCESS;
}

/**
 * Shutdown the crypto library and release resources.
 *
 * It is safe to shut down twice.
 */
static apr_status_t crypto_shutdown(void)
{
    if (NSS_IsInitialized()) {
        SECStatus s = NSS_Shutdown();
        if (s != SECSuccess) {
            fprintf(stderr, "NSS failed to shutdown, possible leak: %d: %s",
                PR_GetError(), PR_ErrorToName(s));
            return APR_EINIT;
        }
    }
    return APR_SUCCESS;
}

static apr_status_t crypto_shutdown_helper(void *data)
{
    return crypto_shutdown();
}

/**
 * Initialise the crypto library and perform one time initialisation.
 */
static apr_status_t crypto_init(apr_pool_t *pool, const char *params,
        const apu_err_t **result)
{
    SECStatus s;
    const char *dir = NULL;
    const char *keyPrefix = NULL;
    const char *certPrefix = NULL;
    const char *secmod = NULL;
    int noinit = 0;
    PRUint32 flags = 0;

    struct {
        const char *field;
        const char *value;
        int set;
    } fields[] = {
        { "dir", NULL, 0 },
        { "key3", NULL, 0 },
        { "cert7", NULL, 0 },
        { "secmod", NULL, 0 },
        { "noinit", NULL, 0 },
        { NULL, NULL, 0 }
    };
    const char *ptr;
    size_t klen;
    char **elts = NULL;
    char *elt;
    int i = 0, j;
    apr_status_t status;

    if (params) {
        if (APR_SUCCESS != (status = apr_tokenize_to_argv(params, &elts, pool))) {
            return status;
        }
        while ((elt = elts[i])) {
            ptr = strchr(elt, '=');
            if (ptr) {
                for (klen = ptr - elt; klen && apr_isspace(elt[klen - 1]); --klen)
                    ;
                ptr++;
            }
            else {
                for (klen = strlen(elt); klen && apr_isspace(elt[klen - 1]); --klen)
                    ;
            }
            elt[klen] = 0;

            for (j = 0; fields[j].field != NULL; ++j) {
                if (klen && !strcasecmp(fields[j].field, elt)) {
                    fields[j].set = 1;
                    if (ptr) {
                        fields[j].value = ptr;
                    }
                    break;
                }
            }

            i++;
        }
        dir = fields[0].value;
        keyPrefix = fields[1].value;
        certPrefix = fields[2].value;
        secmod = fields[3].value;
        noinit = fields[4].set;
    }

    /* if we've been asked to bypass, do so here */
    if (noinit) {
        return APR_SUCCESS;
    }

    /* sanity check - we can only initialise NSS once */
    if (NSS_IsInitialized()) {
        return APR_EREINIT;
    }

    if (keyPrefix || certPrefix || secmod) {
        s = NSS_Initialize(dir, certPrefix, keyPrefix, secmod, flags);
    }
    else if (dir) {
        s = NSS_InitReadWrite(dir);
    }
    else {
        s = NSS_NoDB_Init(NULL);
    }
    if (s != SECSuccess) {
        if (result) {
            /* Note: all memory must be owned by the caller, in case we're unloaded */
            apu_err_t *err = apr_pcalloc(pool, sizeof(apu_err_t));
            err->rc = PR_GetError();
            err->msg = apr_pstrdup(pool, PR_ErrorToName(s));
            err->reason = apr_pstrdup(pool, "Error during 'nss' initialisation");
            *result = err;
        }

        return APR_ECRYPT;
    }

    apr_pool_cleanup_register(pool, pool, crypto_shutdown_helper,
            apr_pool_cleanup_null);

    return APR_SUCCESS;

}

/**
 * @brief Clean encryption / decryption context.
 * @note After cleanup, a context is free to be reused if necessary.
 * @param f The context to use.
 * @return Returns APR_ENOTIMPL if not supported.
 */
static apr_status_t crypto_block_cleanup(apr_crypto_block_t *block)
{

    if (block->secParam) {
        SECITEM_FreeItem(block->secParam, PR_TRUE);
        block->secParam = NULL;
    }

    if (block->ctx) {
        PK11_DestroyContext(block->ctx, PR_TRUE);
        block->ctx = NULL;
    }

    return APR_SUCCESS;

}

/**
 * @brief Clean sign / verify context.
 * @note After cleanup, a context is free to be reused if necessary.
 * @param f The context to use.
 * @return Returns APR_ENOTIMPL if not supported.
 */
static apr_status_t crypto_digest_cleanup(apr_crypto_digest_t *digest)
{

    if (digest->secParam) {
        SECITEM_FreeItem(digest->secParam, PR_TRUE);
        digest->secParam = NULL;
    }

    if (digest->ctx) {
        PK11_DestroyContext(digest->ctx, PR_TRUE);
        digest->ctx = NULL;
    }

    return APR_SUCCESS;

}

static apr_status_t crypto_block_cleanup_helper(void *data)
{
    apr_crypto_block_t *block = (apr_crypto_block_t *) data;
    return crypto_block_cleanup(block);
}

static apr_status_t crypto_digest_cleanup_helper(void *data)
{
    apr_crypto_digest_t *digest = (apr_crypto_digest_t *) data;
    return crypto_digest_cleanup(digest);
}

static apr_status_t crypto_key_cleanup(void *data)
{
    apr_crypto_key_t *key = data;
    if (key->symKey) {
        PK11_FreeSymKey(key->symKey);
        key->symKey = NULL;
    }
    return APR_SUCCESS;
}
/**
 * @brief Clean encryption / decryption context.
 * @note After cleanup, a context is free to be reused if necessary.
 * @param f The context to use.
 * @return Returns APR_ENOTIMPL if not supported.
 */
static apr_status_t crypto_cleanup(apr_crypto_t *f)
{
    return APR_SUCCESS;
}

static apr_status_t crypto_cleanup_helper(void *data)
{
    apr_crypto_t *f = (apr_crypto_t *) data;
    return crypto_cleanup(f);
}

/**
 * @brief Create a context for supporting encryption. Keys, certificates,
 *        algorithms and other parameters will be set per context. More than
 *        one context can be created at one time. A cleanup will be automatically
 *        registered with the given pool to guarantee a graceful shutdown.
 * @param f - context pointer will be written here
 * @param provider - provider to use
 * @param params - parameter string
 * @param pool - process pool
 * @return APR_ENOENGINE when the engine specified does not exist. APR_EINITENGINE
 * if the engine cannot be initialised.
 */
static apr_status_t crypto_make(apr_crypto_t **ff,
        const apr_crypto_driver_t *provider, const char *params,
        apr_pool_t *pool)
{
    apr_crypto_config_t *config = NULL;
    apr_crypto_t *f;
    int i;

    f = apr_pcalloc(pool, sizeof(apr_crypto_t));
    if (!f) {
        return APR_ENOMEM;
    }
    *ff = f;
    f->pool = pool;
    f->provider = provider;
    config = f->config = apr_pcalloc(pool, sizeof(apr_crypto_config_t));
    if (!config) {
        return APR_ENOMEM;
    }
    f->result = apr_pcalloc(pool, sizeof(apu_err_t));
    if (!f->result) {
        return APR_ENOMEM;
    }

    f->digests = apr_hash_make(pool);
    if (!f->digests) {
        return APR_ENOMEM;
    }
    apr_hash_set(f->digests, "md5", APR_HASH_KEY_STRING, &(key_digests[i = 0]));
    apr_hash_set(f->digests, "sha1", APR_HASH_KEY_STRING, &(key_digests[++i]));
    apr_hash_set(f->digests, "sha224", APR_HASH_KEY_STRING, &(key_digests[++i]));
    apr_hash_set(f->digests, "sha256", APR_HASH_KEY_STRING, &(key_digests[++i]));
    apr_hash_set(f->digests, "sha384", APR_HASH_KEY_STRING, &(key_digests[++i]));
    apr_hash_set(f->digests, "sha512", APR_HASH_KEY_STRING, &(key_digests[++i]));

    f->types = apr_hash_make(pool);
    if (!f->types) {
        return APR_ENOMEM;
    }
    apr_hash_set(f->types, "3des192", APR_HASH_KEY_STRING, &(key_types[i = 0]));
    apr_hash_set(f->types, "aes128", APR_HASH_KEY_STRING, &(key_types[++i]));
    apr_hash_set(f->types, "aes192", APR_HASH_KEY_STRING, &(key_types[++i]));
    apr_hash_set(f->types, "aes256", APR_HASH_KEY_STRING, &(key_types[++i]));

    f->modes = apr_hash_make(pool);
    if (!f->modes) {
        return APR_ENOMEM;
    }
    apr_hash_set(f->modes, "ecb", APR_HASH_KEY_STRING, &(key_modes[i = 0]));
    apr_hash_set(f->modes, "cbc", APR_HASH_KEY_STRING, &(key_modes[++i]));

    apr_pool_cleanup_register(pool, f, crypto_cleanup_helper,
            apr_pool_cleanup_null);

    return APR_SUCCESS;

}

/**
 * @brief Get a hash table of key digests, keyed by the name of the digest against
 * a pointer to apr_crypto_block_key_digest_t.
 *
 * @param digests - hashtable of key digests keyed to constants.
 * @param f - encryption context
 * @return APR_SUCCESS for success
 */
static apr_status_t crypto_get_block_key_digests(apr_hash_t **digests,
        const apr_crypto_t *f)
{
    *digests = f->digests;
    return APR_SUCCESS;
}

/**
 * @brief Get a hash table of key types, keyed by the name of the type against
 * a pointer to apr_crypto_block_key_type_t.
 *
 * @param types - hashtable of key types keyed to constants.
 * @param f - encryption context
 * @return APR_SUCCESS for success
 */
static apr_status_t crypto_get_block_key_types(apr_hash_t **types,
        const apr_crypto_t *f)
{
    *types = f->types;
    return APR_SUCCESS;
}

/**
 * @brief Get a hash table of key modes, keyed by the name of the mode against
 * a pointer to apr_crypto_block_key_mode_t.
 *
 * @param modes - hashtable of key modes keyed to constants.
 * @param f - encryption context
 * @return APR_SUCCESS for success
 */
static apr_status_t crypto_get_block_key_modes(apr_hash_t **modes,
        const apr_crypto_t *f)
{
    *modes = f->modes;
    return APR_SUCCESS;
}

/*
 * Work out which mechanism to use.
 */
static apr_status_t crypto_cipher_mechanism(apr_crypto_key_t *key,
        const apr_crypto_block_key_type_e type,
        const apr_crypto_block_key_mode_e mode, const int doPad)
{

    /* decide on what cipher mechanism we will be using */
    switch (type) {

    case (APR_KEY_3DES_192):
        if (APR_MODE_CBC == mode) {
            key->cipherOid = SEC_OID_DES_EDE3_CBC;
        }
        else if (APR_MODE_ECB == mode) {
            return APR_ENOCIPHER;
            /* No OID for CKM_DES3_ECB; */
        }
        key->keyLength = 24;
        break;
    case (APR_KEY_AES_128):
        if (APR_MODE_CBC == mode) {
            key->cipherOid = SEC_OID_AES_128_CBC;
        }
        else {
            key->cipherOid = SEC_OID_AES_128_ECB;
        }
        key->keyLength = 16;
        break;
    case (APR_KEY_AES_192):
        if (APR_MODE_CBC == mode) {
            key->cipherOid = SEC_OID_AES_192_CBC;
        }
        else {
            key->cipherOid = SEC_OID_AES_192_ECB;
        }
        key->keyLength = 24;
        break;
    case (APR_KEY_AES_256):
        if (APR_MODE_CBC == mode) {
            key->cipherOid = SEC_OID_AES_256_CBC;
        }
        else {
            key->cipherOid = SEC_OID_AES_256_ECB;
        }
        key->keyLength = 32;
        break;
    default:
        /* unknown key type, give up */
        return APR_EKEYTYPE;
    }

    /* AES_128_CBC --> CKM_AES_CBC --> CKM_AES_CBC_PAD */
    key->cipherMech = PK11_AlgtagToMechanism(key->cipherOid);
    if (key->cipherMech == CKM_INVALID_MECHANISM) {
        return APR_ENOCIPHER;
    }
    if (doPad) {
        CK_MECHANISM_TYPE paddedMech;
        paddedMech = PK11_GetPadMechanism(key->cipherMech);
        if (CKM_INVALID_MECHANISM == paddedMech
                || key->cipherMech == paddedMech) {
            return APR_EPADDING;
        }
        key->cipherMech = paddedMech;
    }

    key->ivSize = PK11_GetIVLength(key->cipherMech);

    return APR_SUCCESS;
}

/**
 * @brief Create a key from the provided secret or passphrase. The key is cleaned
 *        up when the context is cleaned, and may be reused with multiple encryption
 *        or decryption operations.
 * @note If *key is NULL, a apr_crypto_key_t will be created from a pool. If
 *       *key is not NULL, *key must point at a previously created structure.
 * @param key The key returned, see note.
 * @param rec The key record, from which the key will be derived.
 * @param f The context to use.
 * @param p The pool to use.
 * @return Returns APR_ENOKEY if the pass phrase is missing or empty, or if a backend
 *         error occurred while generating the key. APR_ENOCIPHER if the type or mode
 *         is not supported by the particular backend. APR_EKEYTYPE if the key type is
 *         not known. APR_EPADDING if padding was requested but is not supported.
 *         APR_ENOTIMPL if not implemented.
 */
static apr_status_t crypto_key(apr_crypto_key_t **k,
        const apr_crypto_key_rec_t *rec, const apr_crypto_t *f, apr_pool_t *p)
{
    apr_status_t rv = APR_SUCCESS;
    PK11SlotInfo *slot, *tslot;
    PK11SymKey *tkey;
    SECItem secretItem;
    SECItem wrappedItem;
    SECItem *secParam;
    PK11Context *ctx;
    SECStatus s;
    SECItem passItem;
    SECItem saltItem;
    SECAlgorithmID *algid;
    void *wincx = NULL; /* what is wincx? */
    apr_crypto_key_t *key;
    int blockSize;
    int remainder;

    key = *k;
    if (!key) {
        *k = key = apr_pcalloc(p, sizeof *key);
        if (!key) {
            return APR_ENOMEM;
        }
        apr_pool_cleanup_register(p, key, crypto_key_cleanup,
                                  apr_pool_cleanup_null);
    }

    key->pool = p;
    key->f = f;
    key->provider = f->provider;
    key->rec = rec;

    switch (rec->ktype) {

    case APR_CRYPTO_KTYPE_PASSPHRASE: {

        /* decide on what cipher mechanism we will be using */
        rv = crypto_cipher_mechanism(key, rec->type, rec->mode, rec->pad);
        if (APR_SUCCESS != rv) {
            return rv;
        }

        /* Turn the raw passphrase and salt into SECItems */
        passItem.data = (unsigned char*) rec->k.passphrase.pass;
        passItem.len = rec->k.passphrase.passLen;
        saltItem.data = (unsigned char*) rec->k.passphrase.salt;
        saltItem.len = rec->k.passphrase.saltLen;

        /* generate the key */
        /* pbeAlg and cipherAlg are the same. */
        algid = PK11_CreatePBEV2AlgorithmID(key->cipherOid, key->cipherOid,
                SEC_OID_HMAC_SHA1, key->keyLength,
                rec->k.passphrase.iterations, &saltItem);
        if (algid) {
            slot = PK11_GetBestSlot(key->cipherMech, wincx);
            if (slot) {
                key->symKey = PK11_PBEKeyGen(slot, algid, &passItem, PR_FALSE,
                        wincx);
                PK11_FreeSlot(slot);
            }
            SECOID_DestroyAlgorithmID(algid, PR_TRUE);
        }

        /* sanity check? */
        if (!key->symKey) {
            PRErrorCode perr = PORT_GetError();
            if (perr) {
                f->result->rc = perr;
                f->result->msg = PR_ErrorToName(perr);
                rv = APR_ENOKEY;
            }
        }

        break;
    }

    case APR_CRYPTO_KTYPE_SECRET: {

        /* decide on what cipher mechanism we will be using */
        rv = crypto_cipher_mechanism(key, rec->type, rec->mode, rec->pad);
        if (APR_SUCCESS != rv) {
            return rv;
        }

        /*
         * NSS is by default in FIPS mode, which disallows the use of unencrypted
         * symmetrical keys. As per http://permalink.gmane.org/gmane.comp.mozilla.crypto/7947
         * we do the following:
         *
         * 1. Generate a (temporary) symmetric key in NSS.
         * 2. Use that symmetric key to encrypt your symmetric key as data.
         * 3. Unwrap your wrapped symmetric key, using the symmetric key
         * you generated in Step 1 as the unwrapping key.
         *
         * http://permalink.gmane.org/gmane.comp.mozilla.crypto/7947
         */

        /* generate the key */
        slot = PK11_GetBestSlot(key->cipherMech, NULL);
        if (slot) {
            unsigned char data[BUFFER_SIZE];

            /* sanity check - key correct size? */
            if (rec->k.secret.secretLen != key->keyLength) {
                PK11_FreeSlot(slot);
                return APR_EKEYLENGTH;
            }

            tslot = PK11_GetBestSlot(CKM_AES_ECB, NULL);
            if (tslot) {

                /* generate a temporary wrapping key */
                tkey = PK11_KeyGen(tslot, CKM_AES_ECB, 0, PK11_GetBestKeyLength(tslot, CKM_AES_ECB), 0);

                /* prepare the key to wrap */
                secretItem.data = (unsigned char *) rec->k.secret.secret;
                secretItem.len = rec->k.secret.secretLen;

                /* ensure our key matches the blocksize */
                secParam = PK11_GenerateNewParam(CKM_AES_ECB, tkey);
                blockSize = PK11_GetBlockSize(CKM_AES_ECB, secParam);
                remainder = rec->k.secret.secretLen % blockSize;
                if (remainder) {
                    secretItem.data =
                            apr_pcalloc(p, rec->k.secret.secretLen + remainder);
                    apr_crypto_clear(p, secretItem.data,
                            rec->k.secret.secretLen);
                    memcpy(secretItem.data, rec->k.secret.secret,
                            rec->k.secret.secretLen);
                    secretItem.len += remainder;
                }

                /* prepare a space for the wrapped key */
                wrappedItem.data = data;

                /* wrap the key */
                ctx = PK11_CreateContextBySymKey(CKM_AES_ECB, CKA_ENCRYPT, tkey,
                        secParam);
                if (ctx) {
                    s = PK11_CipherOp(ctx, wrappedItem.data,
                            (int *) (&wrappedItem.len), BUFFER_SIZE,
                            secretItem.data, secretItem.len);
                    if (s == SECSuccess) {

                        /* unwrap the key again */
                        key->symKey = PK11_UnwrapSymKeyWithFlags(tkey,
                                CKM_AES_ECB, NULL, &wrappedItem,
                                key->cipherMech, CKA_ENCRYPT,
                                rec->k.secret.secretLen, 0);

                    }

                    PK11_DestroyContext(ctx, PR_TRUE);
                }

                /* clean up */
                SECITEM_FreeItem(secParam, PR_TRUE);
                PK11_FreeSymKey(tkey);
                PK11_FreeSlot(tslot);

            }

            PK11_FreeSlot(slot);
        }

        /* sanity check? */
        if (!key->symKey) {
            PRErrorCode perr = PORT_GetError();
            if (perr) {
                f->result->rc = perr;
                f->result->msg = PR_ErrorToName(perr);
                rv = APR_ENOKEY;
            }
        }

        break;
    }

    case APR_CRYPTO_KTYPE_HASH: {

        switch (rec->k.hash.digest) {
        case APR_CRYPTO_DIGEST_MD5:
            key->hashAlg = SEC_OID_MD5;
            break;
        case APR_CRYPTO_DIGEST_SHA1:
            key->hashAlg = SEC_OID_SHA1;
            break;
        case APR_CRYPTO_DIGEST_SHA224:
            key->hashAlg = SEC_OID_SHA224;
            break;
        case APR_CRYPTO_DIGEST_SHA256:
            key->hashAlg = SEC_OID_SHA256;
            break;
        case APR_CRYPTO_DIGEST_SHA384:
            key->hashAlg = SEC_OID_SHA384;
            break;
        case APR_CRYPTO_DIGEST_SHA512:
            key->hashAlg = SEC_OID_SHA512;
            break;
        default:
            return APR_ENODIGEST;
        }

        break;
    }
    case APR_CRYPTO_KTYPE_HMAC: {

        switch (rec->k.hmac.digest) {
        case APR_CRYPTO_DIGEST_MD5:
            key->hashMech = CKM_MD5_HMAC;
            break;
        case APR_CRYPTO_DIGEST_SHA1:
            key->hashMech = CKM_SHA_1_HMAC;
            break;
        case APR_CRYPTO_DIGEST_SHA224:
            key->hashMech = CKM_SHA224_HMAC;
            break;
        case APR_CRYPTO_DIGEST_SHA256:
            key->hashMech = CKM_SHA256_HMAC;
            break;
        case APR_CRYPTO_DIGEST_SHA384:
            key->hashMech = CKM_SHA384_HMAC;
            break;
        case APR_CRYPTO_DIGEST_SHA512:
            key->hashMech = CKM_SHA512_HMAC;
            break;
        default:
            return APR_ENODIGEST;
        }

        /* generate the key */
        slot = PK11_GetBestSlot(key->hashMech, NULL);
        if (slot) {

            /* prepare the key to wrap */
            secretItem.data = (unsigned char *) rec->k.hmac.secret;
            secretItem.len = rec->k.hmac.secretLen;

            key->symKey = PK11_ImportSymKey(slot, key->hashMech, PK11_OriginDerive,
                                           CKA_SIGN, &secretItem, NULL);

            /* sanity check? */
            if (!key->symKey) {
                PRErrorCode perr = PORT_GetError();
                if (perr) {
                    f->result->rc = perr;
                    f->result->msg = PR_ErrorToName(perr);
                    rv = APR_ENOKEY;
                }
            }

            PK11_FreeSlot(slot);
        }

        break;
    }

    case APR_CRYPTO_KTYPE_CMAC: {

        return APR_ENOTIMPL;

    }

    default: {

        return APR_ENOKEY;

    }
    }

    return rv;
}

/**
 * @brief Create a key from the given passphrase. By default, the PBKDF2
 *        algorithm is used to generate the key from the passphrase. It is expected
 *        that the same pass phrase will generate the same key, regardless of the
 *        backend crypto platform used. The key is cleaned up when the context
 *        is cleaned, and may be reused with multiple encryption or decryption
 *        operations.
 * @note If *key is NULL, a apr_crypto_key_t will be created from a pool. If
 *       *key is not NULL, *key must point at a previously created structure.
 * @param key The key returned, see note.
 * @param ivSize The size of the initialisation vector will be returned, based
 *               on whether an IV is relevant for this type of crypto.
 * @param pass The passphrase to use.
 * @param passLen The passphrase length in bytes
 * @param salt The salt to use.
 * @param saltLen The salt length in bytes
 * @param type 3DES_192, AES_128, AES_192, AES_256.
 * @param mode Electronic Code Book / Cipher Block Chaining.
 * @param doPad Pad if necessary.
 * @param iterations Iteration count
 * @param f The context to use.
 * @param p The pool to use.
 * @return Returns APR_ENOKEY if the pass phrase is missing or empty, or if a backend
 *         error occurred while generating the key. APR_ENOCIPHER if the type or mode
 *         is not supported by the particular backend. APR_EKEYTYPE if the key type is
 *         not known. APR_EPADDING if padding was requested but is not supported.
 *         APR_ENOTIMPL if not implemented.
 */
static apr_status_t crypto_passphrase(apr_crypto_key_t **k, apr_size_t *ivSize,
        const char *pass, apr_size_t passLen, const unsigned char * salt,
        apr_size_t saltLen, const apr_crypto_block_key_type_e type,
        const apr_crypto_block_key_mode_e mode, const int doPad,
        const int iterations, const apr_crypto_t *f, apr_pool_t *p)
{
    apr_status_t rv = APR_SUCCESS;
    PK11SlotInfo * slot;
    SECItem passItem;
    SECItem saltItem;
    SECAlgorithmID *algid;
    void *wincx = NULL; /* what is wincx? */
    apr_crypto_key_t *key = *k;
    apr_crypto_key_rec_t *rec;

    if (!key) {
        *k = key = apr_pcalloc(p, sizeof *key);
        if (!key) {
            return APR_ENOMEM;
        }
        apr_pool_cleanup_register(p, key, crypto_key_cleanup,
                                  apr_pool_cleanup_null);
    }

    key->f = f;
    key->provider = f->provider;
    key->rec = rec = apr_pcalloc(p, sizeof(apr_crypto_key_rec_t));
    if (!key->rec) {
        return APR_ENOMEM;
    }
    rec->ktype = APR_CRYPTO_KTYPE_PASSPHRASE;

    /* decide on what cipher mechanism we will be using */
    rv = crypto_cipher_mechanism(key, type, mode, doPad);
    if (APR_SUCCESS != rv) {
        return rv;
    }

    /* Turn the raw passphrase and salt into SECItems */
    passItem.data = (unsigned char*) pass;
    passItem.len = passLen;
    saltItem.data = (unsigned char*) salt;
    saltItem.len = saltLen;

    /* generate the key */
    /* pbeAlg and cipherAlg are the same. */
    algid = PK11_CreatePBEV2AlgorithmID(key->cipherOid, key->cipherOid,
            SEC_OID_HMAC_SHA1, key->keyLength, iterations, &saltItem);
    if (algid) {
        slot = PK11_GetBestSlot(key->cipherMech, wincx);
        if (slot) {
            key->symKey = PK11_PBEKeyGen(slot, algid, &passItem, PR_FALSE,
                    wincx);
            PK11_FreeSlot(slot);
        }
        SECOID_DestroyAlgorithmID(algid, PR_TRUE);
    }

    /* sanity check? */
    if (!key->symKey) {
        PRErrorCode perr = PORT_GetError();
        if (perr) {
            f->result->rc = perr;
            f->result->msg = PR_ErrorToName(perr);
            rv = APR_ENOKEY;
        }
    }

    if (ivSize) {
        *ivSize = key->ivSize;
    }

    return rv;
}

/**
 * @brief Initialise a context for encrypting arbitrary data using the given key.
 * @note If *ctx is NULL, a apr_crypto_block_t will be created from a pool. If
 *       *ctx is not NULL, *ctx must point at a previously created structure.
 * @param ctx The block context returned, see note.
 * @param iv Optional initialisation vector. If the buffer pointed to is NULL,
 *           an IV will be created at random, in space allocated from the pool.
 *           If the buffer pointed to is not NULL, the IV in the buffer will be
 *           used.
 * @param key The key structure.
 * @param blockSize The block size of the cipher.
 * @param p The pool to use.
 * @return Returns APR_ENOIV if an initialisation vector is required but not specified.
 *         Returns APR_EINIT if the backend failed to initialise the context. Returns
 *         APR_ENOTIMPL if not implemented.
 */
static apr_status_t crypto_block_encrypt_init(apr_crypto_block_t **ctx,
        const unsigned char **iv, const apr_crypto_key_t *key,
        apr_size_t *blockSize, apr_pool_t *p)
{
    PRErrorCode perr;
    SECItem ivItem;
    unsigned char * usedIv;
    apr_crypto_block_t *block = *ctx;
    if (!block) {
        *ctx = block = apr_pcalloc(p, sizeof(apr_crypto_block_t));
    }
    if (!block) {
        return APR_ENOMEM;
    }
    block->f = key->f;
    block->pool = p;
    block->provider = key->provider;
    block->key = key;

    apr_pool_cleanup_register(p, block, crypto_block_cleanup_helper,
            apr_pool_cleanup_null);

    switch (key->rec->ktype) {

    case APR_CRYPTO_KTYPE_PASSPHRASE:
    case APR_CRYPTO_KTYPE_SECRET: {

        if (key->ivSize) {
            if (iv == NULL) {
                return APR_ENOIV;
            }
            if (*iv == NULL) {
                SECStatus s;
                usedIv = apr_pcalloc(p, key->ivSize);
                if (!usedIv) {
                    return APR_ENOMEM;
                }
                apr_crypto_clear(p, usedIv, key->ivSize);
                s = PK11_GenerateRandom(usedIv, key->ivSize);
                if (s != SECSuccess) {
                    return APR_ENOIV;
                }
                *iv = usedIv;
            }
            else {
                usedIv = (unsigned char *) *iv;
            }
            ivItem.data = usedIv;
            ivItem.len = key->ivSize;
            block->secParam = PK11_ParamFromIV(key->cipherMech, &ivItem);
        }
        else {
            block->secParam = PK11_GenerateNewParam(key->cipherMech, key->symKey);
        }
        block->blockSize = PK11_GetBlockSize(key->cipherMech, block->secParam);
        block->ctx = PK11_CreateContextBySymKey(key->cipherMech, CKA_ENCRYPT,
                key->symKey, block->secParam);

        /* did an error occur? */
        perr = PORT_GetError();
        if (perr || !block->ctx) {
            key->f->result->rc = perr;
            key->f->result->msg = PR_ErrorToName(perr);
            return APR_EINIT;
        }

        if (blockSize) {
            *blockSize = PK11_GetBlockSize(key->cipherMech, block->secParam);
        }

        return APR_SUCCESS;

    }
    default: {

        return APR_EINVAL;

    }
    }

}

/**
 * @brief Encrypt data provided by in, write it to out.
 * @note The number of bytes written will be written to outlen. If
 *       out is NULL, outlen will contain the maximum size of the
 *       buffer needed to hold the data, including any data
 *       generated by apr_crypto_block_encrypt_finish below. If *out points
 *       to NULL, a buffer sufficiently large will be created from
 *       the pool provided. If *out points to a not-NULL value, this
 *       value will be used as a buffer instead.
 * @param out Address of a buffer to which data will be written,
 *        see note.
 * @param outlen Length of the output will be written here.
 * @param in Address of the buffer to read.
 * @param inlen Length of the buffer to read.
 * @param ctx The block context to use.
 * @return APR_ECRYPT if an error occurred. Returns APR_ENOTIMPL if
 *         not implemented.
 */
static apr_status_t crypto_block_encrypt(unsigned char **out,
        apr_size_t *outlen, const unsigned char *in, apr_size_t inlen,
        apr_crypto_block_t *block)
{
    switch (block->key->rec->ktype) {

    case APR_CRYPTO_KTYPE_PASSPHRASE:
    case APR_CRYPTO_KTYPE_SECRET: {

        unsigned char *buffer;
        int outl = (int) *outlen;
        SECStatus s;
        if (!out) {
            *outlen = inlen + block->blockSize;
            return APR_SUCCESS;
        }
        if (!*out) {
            buffer = apr_palloc(block->pool, inlen + block->blockSize);
            if (!buffer) {
                return APR_ENOMEM;
            }
            apr_crypto_clear(block->pool, buffer, inlen + block->blockSize);
            *out = buffer;
        }

        s = PK11_CipherOp(block->ctx, *out, &outl, inlen, (unsigned char*) in,
                inlen);
        if (s != SECSuccess) {
            PRErrorCode perr = PORT_GetError();
            if (perr) {
                block->f->result->rc = perr;
                block->f->result->msg = PR_ErrorToName(perr);
            }
            return APR_ECRYPT;
        }
        *outlen = outl;

        return APR_SUCCESS;

    }
    default: {

        return APR_EINVAL;

    }
    }

}

/**
 * @brief Encrypt final data block, write it to out.
 * @note If necessary the final block will be written out after being
 *       padded. Typically the final block will be written to the
 *       same buffer used by apr_crypto_block_encrypt, offset by the
 *       number of bytes returned as actually written by the
 *       apr_crypto_block_encrypt() call. After this call, the context
 *       is cleaned and can be reused by apr_crypto_block_encrypt_init().
 * @param out Address of a buffer to which data will be written. This
 *            buffer must already exist, and is usually the same
 *            buffer used by apr_evp_crypt(). See note.
 * @param outlen Length of the output will be written here.
 * @param ctx The block context to use.
 * @return APR_ECRYPT if an error occurred.
 * @return APR_EPADDING if padding was enabled and the block was incorrectly
 *         formatted.
 * @return APR_ENOTIMPL if not implemented.
 */
static apr_status_t crypto_block_encrypt_finish(unsigned char *out,
        apr_size_t *outlen, apr_crypto_block_t *block)
{
    switch (block->key->rec->ktype) {

    case APR_CRYPTO_KTYPE_PASSPHRASE:
    case APR_CRYPTO_KTYPE_SECRET: {

        apr_status_t rv = APR_SUCCESS;
        unsigned int outl = *outlen;

        SECStatus s = PK11_DigestFinal(block->ctx, out, &outl, block->blockSize);
        *outlen = outl;

        if (s != SECSuccess) {
            PRErrorCode perr = PORT_GetError();
            if (perr) {
                block->f->result->rc = perr;
                block->f->result->msg = PR_ErrorToName(perr);
            }
            rv = APR_ECRYPT;
        }
        crypto_block_cleanup(block);

        return rv;

    }
    default: {

        return APR_EINVAL;

    }
    }

}

/**
 * @brief Initialise a context for decrypting arbitrary data using the given key.
 * @note If *ctx is NULL, a apr_crypto_block_t will be created from a pool. If
 *       *ctx is not NULL, *ctx must point at a previously created structure.
 * @param ctx The block context returned, see note.
 * @param blockSize The block size of the cipher.
 * @param iv Optional initialisation vector. If the buffer pointed to is NULL,
 *           an IV will be created at random, in space allocated from the pool.
 *           If the buffer is not NULL, the IV in the buffer will be used.
 * @param key The key structure.
 * @param p The pool to use.
 * @return Returns APR_ENOIV if an initialisation vector is required but not specified.
 *         Returns APR_EINIT if the backend failed to initialise the context. Returns
 *         APR_ENOTIMPL if not implemented.
 */
static apr_status_t crypto_block_decrypt_init(apr_crypto_block_t **ctx,
        apr_size_t *blockSize, const unsigned char *iv,
        const apr_crypto_key_t *key, apr_pool_t *p)
{
    switch (key->rec->ktype) {

    case APR_CRYPTO_KTYPE_PASSPHRASE:
    case APR_CRYPTO_KTYPE_SECRET: {

        PRErrorCode perr;
        apr_crypto_block_t *block = *ctx;
        if (!block) {
            *ctx = block = apr_pcalloc(p, sizeof(apr_crypto_block_t));
        }
        if (!block) {
            return APR_ENOMEM;
        }
        block->f = key->f;
        block->pool = p;
        block->provider = key->provider;
        block->key = key;

        apr_pool_cleanup_register(p, block, crypto_block_cleanup_helper,
                apr_pool_cleanup_null);

        if (key->ivSize) {
            SECItem ivItem;
            if (iv == NULL) {
                return APR_ENOIV; /* Cannot initialise without an IV */
            }
            ivItem.data = (unsigned char*) iv;
            ivItem.len = key->ivSize;
            block->secParam = PK11_ParamFromIV(key->cipherMech, &ivItem);
        }
        else {
            block->secParam = PK11_GenerateNewParam(key->cipherMech, key->symKey);
        }
        block->blockSize = PK11_GetBlockSize(key->cipherMech, block->secParam);
        block->ctx = PK11_CreateContextBySymKey(key->cipherMech, CKA_DECRYPT,
                key->symKey, block->secParam);

        /* did an error occur? */
        perr = PORT_GetError();
        if (perr || !block->ctx) {
            key->f->result->rc = perr;
            key->f->result->msg = PR_ErrorToName(perr);
            return APR_EINIT;
        }

        if (blockSize) {
            *blockSize = PK11_GetBlockSize(key->cipherMech, block->secParam);
        }

        return APR_SUCCESS;

    }
    default: {

        return APR_EINVAL;

    }
    }

}

/**
 * @brief Decrypt data provided by in, write it to out.
 * @note The number of bytes written will be written to outlen. If
 *       out is NULL, outlen will contain the maximum size of the
 *       buffer needed to hold the data, including any data
 *       generated by apr_crypto_block_decrypt_finish below. If *out points
 *       to NULL, a buffer sufficiently large will be created from
 *       the pool provided. If *out points to a not-NULL value, this
 *       value will be used as a buffer instead.
 * @param out Address of a buffer to which data will be written,
 *        see note.
 * @param outlen Length of the output will be written here.
 * @param in Address of the buffer to read.
 * @param inlen Length of the buffer to read.
 * @param ctx The block context to use.
 * @return APR_ECRYPT if an error occurred. Returns APR_ENOTIMPL if
 *         not implemented.
 */
static apr_status_t crypto_block_decrypt(unsigned char **out,
        apr_size_t *outlen, const unsigned char *in, apr_size_t inlen,
        apr_crypto_block_t *block)
{
    switch (block->key->rec->ktype) {

    case APR_CRYPTO_KTYPE_PASSPHRASE:
    case APR_CRYPTO_KTYPE_SECRET: {

        unsigned char *buffer;
        int outl = (int) *outlen;
        SECStatus s;
        if (!out) {
            *outlen = inlen + block->blockSize;
            return APR_SUCCESS;
        }
        if (!*out) {
            buffer = apr_palloc(block->pool, inlen + block->blockSize);
            if (!buffer) {
                return APR_ENOMEM;
            }
            apr_crypto_clear(block->pool, buffer, inlen + block->blockSize);
            *out = buffer;
        }

        s = PK11_CipherOp(block->ctx, *out, &outl, inlen, (unsigned char*) in,
                inlen);
        if (s != SECSuccess) {
            PRErrorCode perr = PORT_GetError();
            if (perr) {
                block->f->result->rc = perr;
                block->f->result->msg = PR_ErrorToName(perr);
            }
            return APR_ECRYPT;
        }
        *outlen = outl;

        return APR_SUCCESS;

    }
    default: {

        return APR_EINVAL;

    }
    }

}

/**
 * @brief Decrypt final data block, write it to out.
 * @note If necessary the final block will be written out after being
 *       padded. Typically the final block will be written to the
 *       same buffer used by apr_crypto_block_decrypt, offset by the
 *       number of bytes returned as actually written by the
 *       apr_crypto_block_decrypt() call. After this call, the context
 *       is cleaned and can be reused by apr_crypto_block_decrypt_init().
 * @param out Address of a buffer to which data will be written. This
 *            buffer must already exist, and is usually the same
 *            buffer used by apr_evp_crypt(). See note.
 * @param outlen Length of the output will be written here.
 * @param ctx The block context to use.
 * @return APR_ECRYPT if an error occurred.
 * @return APR_EPADDING if padding was enabled and the block was incorrectly
 *         formatted.
 * @return APR_ENOTIMPL if not implemented.
 */
static apr_status_t crypto_block_decrypt_finish(unsigned char *out,
        apr_size_t *outlen, apr_crypto_block_t *block)
{
    switch (block->key->rec->ktype) {

    case APR_CRYPTO_KTYPE_PASSPHRASE:
    case APR_CRYPTO_KTYPE_SECRET: {

        apr_status_t rv = APR_SUCCESS;
        unsigned int outl = *outlen;

        SECStatus s = PK11_DigestFinal(block->ctx, out, &outl, block->blockSize);
        *outlen = outl;

        if (s != SECSuccess) {
            PRErrorCode perr = PORT_GetError();
            if (perr) {
                block->f->result->rc = perr;
                block->f->result->msg = PR_ErrorToName(perr);
            }
            rv = APR_ECRYPT;
        }
        crypto_block_cleanup(block);

        return rv;

    }
    default: {

        return APR_EINVAL;

    }
    }

}

static apr_status_t crypto_digest_init(apr_crypto_digest_t **d,
        const apr_crypto_key_t *key, apr_crypto_digest_rec_t *rec, apr_pool_t *p)
{
    PRErrorCode perr;
    SECStatus s;
    apr_crypto_digest_t *digest = *d;
    if (!digest) {
        *d = digest = apr_pcalloc(p, sizeof(apr_crypto_digest_t));
    }
    if (!digest) {
        return APR_ENOMEM;
    }
    digest->f = key->f;
    digest->pool = p;
    digest->provider = key->provider;
    digest->key = key;
    digest->rec = rec;

    apr_pool_cleanup_register(p, digest, crypto_digest_cleanup_helper,
            apr_pool_cleanup_null);

    switch (key->rec->ktype) {

    case APR_CRYPTO_KTYPE_HASH: {

        digest->ctx = PK11_CreateDigestContext(key->hashAlg);

        s = PK11_DigestBegin(digest->ctx);
        if (s != SECSuccess) {
            PRErrorCode perr = PORT_GetError();
            if (perr) {
                digest->f->result->rc = perr;
                digest->f->result->msg = PR_ErrorToName(perr);
            }
            return APR_ECRYPT;
        }

        return APR_SUCCESS;

    }
    case APR_CRYPTO_KTYPE_HMAC: {

        digest->secParam = PK11_GenerateNewParam(key->cipherMech, key->symKey);
        digest->ctx = PK11_CreateContextBySymKey(key->hashMech, CKA_SIGN,
                key->symKey, digest->secParam);

        /* did an error occur? */
        perr = PORT_GetError();
        if (perr || !digest->ctx) {
            key->f->result->rc = perr;
            key->f->result->msg = PR_ErrorToName(perr);
            return APR_EINIT;
        }

        s = PK11_DigestBegin(digest->ctx);
        if (s != SECSuccess) {
            PRErrorCode perr = PORT_GetError();
            if (perr) {
                digest->f->result->rc = perr;
                digest->f->result->msg = PR_ErrorToName(perr);
            }
            return APR_ECRYPT;
        }

        return APR_SUCCESS;

    }
    case APR_CRYPTO_KTYPE_CMAC: {

        return APR_ENOTIMPL;

    }
    default: {

        return APR_EINVAL;

    }
    }

}

static apr_status_t crypto_digest_update(apr_crypto_digest_t *digest,
        const unsigned char *in, apr_size_t inlen)
{
    switch (digest->key->rec->ktype) {

    case APR_CRYPTO_KTYPE_HASH:
    case APR_CRYPTO_KTYPE_HMAC: {

        SECStatus s;

        s = PK11_DigestOp(digest->ctx, (unsigned char*) in,
                inlen);
        if (s != SECSuccess) {
            PRErrorCode perr = PORT_GetError();
            if (perr) {
                digest->f->result->rc = perr;
                digest->f->result->msg = PR_ErrorToName(perr);
            }
            return APR_ECRYPT;
        }

        return APR_SUCCESS;

    }
    case APR_CRYPTO_KTYPE_CMAC: {

        return APR_ENOTIMPL;

    }
    default: {

        return APR_EINVAL;

    }
    }

}

static apr_status_t crypto_digest_final(apr_crypto_digest_t *digest)
{
    switch (digest->key->rec->ktype) {

    case APR_CRYPTO_KTYPE_HASH:
    case APR_CRYPTO_KTYPE_HMAC: {

        apr_status_t status = APR_SUCCESS;
        unsigned int len;

        /* first, determine the signature length */
        SECStatus s = PK11_DigestFinal(digest->ctx, NULL, &len, 0);
        if (s != SECSuccess) {
            PRErrorCode perr = PORT_GetError();
            if (perr) {
                digest->f->result->rc = perr;
                digest->f->result->msg = PR_ErrorToName(perr);
            }
            status = APR_ECRYPT;
        }
        else {

            switch (digest->rec->dtype) {
            case APR_CRYPTO_DTYPE_HASH: {

                /* must we allocate the output buffer from a pool? */
                if (!digest->rec->d.hash.s || digest->rec->d.hash.slen != len) {
                    digest->rec->d.hash.slen = len;
                    digest->rec->d.hash.s = apr_palloc(digest->pool, len);
                    if (!digest->rec->d.hash.s) {
                        return APR_ENOMEM;
                    }
                    apr_crypto_clear(digest->pool, digest->rec->d.hash.s, len);
                }

                /* then, determine the signature */
                SECStatus s = PK11_DigestFinal(digest->ctx,
                        digest->rec->d.hash.s, &len, digest->rec->d.hash.slen);
                if (s != SECSuccess) {
                    PRErrorCode perr = PORT_GetError();
                    if (perr) {
                        digest->f->result->rc = perr;
                        digest->f->result->msg = PR_ErrorToName(perr);
                    }
                    status = APR_ECRYPT;
                }

                break;
            }
            case APR_CRYPTO_DTYPE_SIGN: {

                /* must we allocate the output buffer from a pool? */
                if (!digest->rec->d.sign.s || digest->rec->d.sign.slen != len) {
                    digest->rec->d.sign.slen = len;
                    digest->rec->d.sign.s = apr_palloc(digest->pool, len);
                    if (!digest->rec->d.sign.s) {
                        return APR_ENOMEM;
                    }
                    apr_crypto_clear(digest->pool, digest->rec->d.sign.s, len);
                }

                /* then, determine the signature */
                SECStatus s = PK11_DigestFinal(digest->ctx,
                        digest->rec->d.sign.s, &len, digest->rec->d.sign.slen);
                if (s != SECSuccess) {
                    PRErrorCode perr = PORT_GetError();
                    if (perr) {
                        digest->f->result->rc = perr;
                        digest->f->result->msg = PR_ErrorToName(perr);
                    }
                    status = APR_ECRYPT;
                }

                break;
            }
            case APR_CRYPTO_DTYPE_VERIFY: {

                /* must we allocate the output buffer from a pool? */
                if (!digest->rec->d.verify.s
                        || digest->rec->d.verify.slen != len) {
                    digest->rec->d.verify.slen = len;
                    digest->rec->d.verify.s = apr_palloc(digest->pool, len);
                    if (!digest->rec->d.verify.s) {
                        return APR_ENOMEM;
                    }
                    apr_crypto_clear(digest->pool, digest->rec->d.verify.s,
                            len);
                }

                /* then, determine the signature */
                SECStatus s = PK11_DigestFinal(digest->ctx,
                        digest->rec->d.verify.s, &len,
                        digest->rec->d.verify.slen);
                if (s != SECSuccess) {
                    PRErrorCode perr = PORT_GetError();
                    if (perr) {
                        digest->f->result->rc = perr;
                        digest->f->result->msg = PR_ErrorToName(perr);
                    }
                    status = APR_ECRYPT;
                } else if (digest->rec->d.verify.slen
                        == digest->rec->d.verify.vlen) {
                    status =
                            apr_crypto_equals(digest->rec->d.verify.s,
                                    digest->rec->d.verify.v,
                                    digest->rec->d.verify.slen) ?
                            APR_SUCCESS : APR_ENOVERIFY;
                } else {
                    status = APR_ENOVERIFY;
                }

                break;
            }
            default: {
                status = APR_ENODIGEST;
            }
            }

        }

        crypto_digest_cleanup(digest);

        return status;

    }
    case APR_CRYPTO_KTYPE_CMAC: {

        return APR_ENOTIMPL;

    }
    default: {

        return APR_EINVAL;

    }
    }

}

static apr_status_t crypto_digest(
        const apr_crypto_key_t *key, apr_crypto_digest_rec_t *rec, const unsigned char *in,
        apr_size_t inlen, apr_pool_t *p)
{
    apr_crypto_digest_t *digest = NULL;
    apr_status_t status = APR_SUCCESS;

    status = crypto_digest_init(&digest, key, rec, p);
    if (APR_SUCCESS == status) {
        status = crypto_digest_update(digest, in, inlen);
        if (APR_SUCCESS == status) {
            status = crypto_digest_final(digest);
        }
    }

    return status;
}

static apr_status_t cprng_stream_ctx_make(cprng_stream_ctx_t **psctx,
        apr_crypto_t *f, apr_crypto_cipher_e cipher, apr_pool_t *pool)
{
    return APR_ENOTIMPL;
}

static void cprng_stream_ctx_free(cprng_stream_ctx_t *sctx)
{
}

static apr_status_t cprng_stream_ctx_bytes(cprng_stream_ctx_t **pctx,
        unsigned char *key, unsigned char *to, apr_size_t n, const unsigned char *z)
{
    return APR_ENOTIMPL;
}

/**
 * NSS module.
 */
APU_MODULE_DECLARE_DATA const apr_crypto_driver_t apr_crypto_nss_driver = {
    "nss", crypto_init, crypto_make, crypto_get_block_key_digests, crypto_get_block_key_types,
    crypto_get_block_key_modes, crypto_passphrase,
    crypto_block_encrypt_init, crypto_block_encrypt,
    crypto_block_encrypt_finish, crypto_block_decrypt_init,
    crypto_block_decrypt, crypto_block_decrypt_finish,
    crypto_digest_init, crypto_digest_update, crypto_digest_final, crypto_digest,
    crypto_block_cleanup, crypto_digest_cleanup, crypto_cleanup, crypto_shutdown, crypto_error,
    crypto_key, cprng_stream_ctx_make, cprng_stream_ctx_free, cprng_stream_ctx_bytes
};

#endif
