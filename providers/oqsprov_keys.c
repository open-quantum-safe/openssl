/* 
 * OQS OpenSSL 3 key handler.
 * 
 * Code strongly inspired by OpenSSL crypto/ec key handler but relocated here 
 * to have code within provider.
 *
 * TBC: OQS license
 */

#include <openssl/err.h>
#include "prov/oqsx.h"

/// Provider code

PROV_OQS_CTX *oqsx_newprovctx(OSSL_LIB_CTX *libctx, const OSSL_CORE_HANDLE *handle) {
    PROV_OQS_CTX * ret = OPENSSL_zalloc(sizeof(PROV_OQS_CTX));
    if (ret) {
       ret->libctx = libctx;
       ret->handle = handle;
    }
    return ret;
}

void oqsx_freeprovctx(PROV_OQS_CTX *ctx) {
    OPENSSL_free(ctx);
}

/// Key code

OQSX_KEY *oqsx_key_new(OSSL_LIB_CTX *libctx, char* oqs_name, int is_kem, const char *propq)
{
    OQSX_KEY *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        return NULL;

    printf("Creating new %s key (type %d)\n", oqs_name, is_kem);
    if (is_kem) {
        ret->key.k = OQS_KEM_new(oqs_name);
        ret->privkeylen = ret->key.k->length_secret_key;
        ret->pubkeylen = ret->key.k->length_public_key;
        ret->iskem = 1;
    }
    else {
        ret->key.s = OQS_SIG_new(oqs_name);
        ret->privkeylen = ret->key.s->length_secret_key;
        ret->pubkeylen = ret->key.s->length_public_key;
        ret->iskem = 0;
    }
    ret->libctx = libctx;
    ret->references = 1;

    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        if (ret->propq == NULL)
            goto err;
    }

    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL)
        goto err;
    return ret;
err:
    ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
    OPENSSL_free(ret);
    return NULL;
}

void oqsx_key_free(OQSX_KEY *key)
{
    int i;

    if (key == NULL)
        return;

    CRYPTO_DOWN_REF(&key->references, &i, key->lock);
    REF_PRINT_COUNT("OQSX_KEY", key);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    OPENSSL_free(key->propq);
    OPENSSL_secure_clear_free(key->privkey, key->privkeylen);
    OPENSSL_secure_clear_free(key->pubkey, key->pubkeylen);
    if (key->iskem) OQS_KEM_free(key->key.k);
    else OQS_SIG_free(key->key.s);
    CRYPTO_THREAD_lock_free(key->lock);
    OPENSSL_free(key);
}

int oqsx_key_up_ref(OQSX_KEY *key)
{
    int i;

    if (CRYPTO_UP_REF(&key->references, &i, key->lock) <= 0) 
        return 0;

    REF_PRINT_COUNT("OQSX_KEY", key);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

int oqsx_key_allocate_keymaterial(OQSX_KEY *key)
{
    key->privkey = OPENSSL_secure_zalloc(key->privkeylen);
    key->pubkey = OPENSSL_secure_zalloc(key->pubkeylen);

    if (key->privkey == NULL || key->pubkey == NULL) return 1;

    return 0;
}

int oqsx_key_gen(OQSX_KEY *key)
{
    if (key->privkey == NULL || key->pubkey == NULL) oqsx_key_allocate_keymaterial(key);

    if (key->iskem)
        return OQS_KEM_keypair(key->key.k, key->pubkey, key->privkey);
    else
        return OQS_SIG_keypair(key->key.s, key->pubkey, key->privkey);
}

