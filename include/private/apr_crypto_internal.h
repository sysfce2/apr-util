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

#ifndef APR_CRYPTO_INTERNAL_H
#define APR_CRYPTO_INTERNAL_H

#include <stdarg.h>

#include "apr_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#if APU_HAVE_CRYPTO

/**
 * Structure representing the streaming context for the CPRNG.
 */
typedef struct cprng_stream_ctx_t cprng_stream_ctx_t;

/**
 * Key size for the CPRNG.
 */
#define CPRNG_KEY_SIZE 32

struct apr_crypto_driver_t {

    /** name */
    const char *name;

    /**
     * @brief: allow driver to perform once-only initialisation.
     * Called once only.
     * @param pool The pool to register the cleanup in.
     * @param params Optional init parameter string.
     * @param rc Driver-specific additional error code
     */
    apr_status_t (*init)(apr_pool_t *pool, const char *params,
            const apu_err_t **result);

    /**
     * @brief Create a context for supporting encryption. Keys, certificates,
     *        algorithms and other parameters will be set per context. More than
     *        one context can be created at one time. A cleanup will be automatically
     *        registered with the given pool to guarantee a graceful shutdown.
     * @param f - context pointer will be written here
     * @param provider - provider to use
     * @param params - array of key parameters
     * @param pool - process pool
     * @return APR_ENOENGINE when the engine specified does not exist. APR_EINITENGINE
     * if the engine cannot be initialised.
     */
    apr_status_t (*make)(apr_crypto_t **f, const apr_crypto_driver_t *provider,
            const char *params, apr_pool_t *pool);

    /**
     * @brief Get a hash table of key digests, keyed by the name of the digest against
     * a pointer to apr_crypto_block_key_digest_t.
     *
     * @param digests - hashtable of key digests keyed to constants.
     * @param f - encryption context
     * @return APR_SUCCESS for success
     */
    apr_status_t (*get_block_key_digests)(apr_hash_t **types,
            const apr_crypto_t *f);

    /**
     * @brief Get a hash table of key types, keyed by the name of the type against
     * a pointer to apr_crypto_block_key_type_t.
     *
     * @param types - hashtable of key types keyed to constants.
     * @param f - encryption context
     * @return APR_SUCCESS for success
     */
    apr_status_t (*get_block_key_types)(apr_hash_t **types,
            const apr_crypto_t *f);

    /**
     * @brief Get a hash table of key modes, keyed by the name of the mode against
     * a pointer to apr_crypto_block_key_mode_t.
     *
     * @param modes - hashtable of key modes keyed to constants.
     * @param f - encryption context
     * @return APR_SUCCESS for success
     */
    apr_status_t (*get_block_key_modes)(apr_hash_t **modes,
            const apr_crypto_t *f);

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
    apr_status_t (*passphrase)(apr_crypto_key_t **key, apr_size_t *ivSize,
            const char *pass, apr_size_t passLen, const unsigned char * salt,
            apr_size_t saltLen, const apr_crypto_block_key_type_e type,
            const apr_crypto_block_key_mode_e mode, const int doPad,
            const int iterations, const apr_crypto_t *f, apr_pool_t *p);

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
    apr_status_t (*block_encrypt_init)(apr_crypto_block_t **ctx,
            const unsigned char **iv, const apr_crypto_key_t *key,
            apr_size_t *blockSize, apr_pool_t *p);

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
    apr_status_t (*block_encrypt)(unsigned char **out, apr_size_t *outlen,
            const unsigned char *in, apr_size_t inlen, apr_crypto_block_t *ctx);

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
    apr_status_t (*block_encrypt_finish)(unsigned char *out,
            apr_size_t *outlen, apr_crypto_block_t *ctx);

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
    apr_status_t (*block_decrypt_init)(apr_crypto_block_t **ctx,
            apr_size_t *blockSize, const unsigned char *iv,
            const apr_crypto_key_t *key, apr_pool_t *p);

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
    apr_status_t (*block_decrypt)(unsigned char **out, apr_size_t *outlen,
            const unsigned char *in, apr_size_t inlen, apr_crypto_block_t *ctx);

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
    apr_status_t (*block_decrypt_finish)(unsigned char *out,
            apr_size_t *outlen, apr_crypto_block_t *ctx);

    /**
     * @brief Initialise a context for signing or verifying arbitrary data using the
     *        given key.
     * @note If *d is NULL, a apr_crypto_digest_t will be created from a pool. If
     *       *d is not NULL, *d must point at a previously created structure.
     * @param d The digest context returned, see note.
     * @param key The key structure to use.
     * @param rec The digest record.
     * @param p The pool to use.
     * @return APR_ENOIV if an initialisation vector is required but not specified.
     * @return APR_EINIT if the backend failed to initialise the context.
     * @return APR_ENOTIMPL if not implemented.
     * @return APR_NOKEY if the key type does not support the given operation.
     */
    apr_status_t (*digest_init)(apr_crypto_digest_t **d,
            const apr_crypto_key_t *key, apr_crypto_digest_rec_t *rec, apr_pool_t *p);

    /**
     * @brief Update the digest with data provided by in.
     * @param in Address of the buffer to read.
     * @param inlen Length of the buffer to read.
     * @param digest The digest context to use.
     * @return APR_ECRYPT if an error occurred.
     * @return APR_ENOTIMPL if not implemented.
     * @return APR_NOKEY if the key type does not support the given operation.
     */
    apr_status_t (*digest_update)(apr_crypto_digest_t *digest,
            const unsigned char *in, apr_size_t inlen);

    /**
     * @brief Finalise the digest and write the result.
     * @note After this call, the context is cleaned and can be reused by
     *   apr_crypto_digest_init().
     * @param digest The digest context to use.
     * @return APR_ECRYPT if an error occurred.
     * @return APR_EPADDING if padding was enabled and the block was incorrectly
     *         formatted.
     * @return APR_ENOTIMPL if not implemented.
     * @return APR_NOKEY if the key type does not support the given operation.
     */
    apr_status_t (*digest_final)(apr_crypto_digest_t *digest);

    /**
     * @brief One shot digest on a single memory buffer.
     * @param key The key structure to use.
     * @param rec The digest record.
     * @param in Address of the buffer to digest.
     * @param inlen Length of the buffer to digest.
     * @param p The pool to use.
     * @return APR_ENOIV if an initialisation vector is required but not specified.
     * @return APR_EINIT if the backend failed to initialise the context.
     * @return APR_ENOTIMPL if not implemented.
     * @return APR_NOKEY if the key type does not support the given operation.
     */
    apr_status_t (*digest)(const apr_crypto_key_t *key,
            apr_crypto_digest_rec_t *rec, const unsigned char *in,
            apr_size_t inlen, apr_pool_t *p);

    /**
     * @brief Clean encryption / decryption context.
     * @note After cleanup, a context is free to be reused if necessary.
     * @param ctx The block context to use.
     * @return Returns APR_ENOTIMPL if not supported.
     */
    apr_status_t (*block_cleanup)(apr_crypto_block_t *ctx);

    /**
     * @brief Clean sign / verify context.
     * @note After cleanup, a context is free to be reused if necessary.
     * @param ctx The digest context to use.
     * @return Returns APR_ENOTIMPL if not supported.
     */
    apr_status_t (*digest_cleanup)(apr_crypto_digest_t *ctx);

    /**
     * @brief Clean encryption / decryption context.
     * @note After cleanup, a context is free to be reused if necessary.
     * @param f The context to use.
     * @return Returns APR_ENOTIMPL if not supported.
     */
    apr_status_t (*cleanup)(apr_crypto_t *f);

    /**
     * @brief Clean encryption / decryption context.
     * @note After cleanup, a context is free to be reused if necessary.
     * @return Returns APR_ENOTIMPL if not supported.
     */
    apr_status_t (*shutdown)(void);

    /**
     * @brief: fetch the most recent error from this driver.
     * @param result - the result structure
     * @param f - context pointer
     * @return APR_SUCCESS for success.
     */
    apr_status_t (*error)(const apu_err_t **result, const apr_crypto_t *f);

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
    apr_status_t (*key)(apr_crypto_key_t **key, const apr_crypto_key_rec_t *rec,
            const apr_crypto_t *f, apr_pool_t *p);

    /**
     * @brief Create the context for encrypting the CPRNG stream.
     * @param pctx The pointer where the context will be returned.
     * @param f The crypto context to use.
     * @param cipher The cipher to use.
     * @param pool The pool to use.
     */
    apr_status_t (*cprng_stream_ctx_make)(cprng_stream_ctx_t **pctx, apr_crypto_t *f,
            apr_crypto_cipher_e cipher, apr_pool_t *pool);

    /**
     * @brief Free the context for encrypting the CPRNG stream.
     * @param ctx The context to free.
     */
    void (*cprng_stream_ctx_free)(cprng_stream_ctx_t *ctx);

    /**
     * @brief Return further encrypted bytes, rekeying as necessary.
     * @param pctx The context.
     * @param key The key to use while rekeying.
     * @param to Encrypted bytes are written here.
     * @param n Length of encrypted bytes.
     * @param z The IV to use.
     */
    apr_status_t (*cprng_stream_ctx_bytes)(cprng_stream_ctx_t **pctx, unsigned char *key,
            unsigned char *to, apr_size_t n, const unsigned char *z);

};

#if APU_HAVE_OPENSSL
const char *apr__crypto_openssl_version(void);
apr_status_t apr__crypto_openssl_init(const char *params,
                                      const apu_err_t **result,
                                      apr_pool_t *pool);
apr_status_t apr__crypto_openssl_term(void);
#endif

#endif

#ifdef __cplusplus
}
#endif

#endif
