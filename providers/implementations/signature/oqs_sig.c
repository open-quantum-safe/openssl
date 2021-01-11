/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL DSA signature provider.
 *
 * ToDo: Everything: This is just a template that needs to be completed with 
 * OQS calls.
 * Significant hurdle: Signature providers of new algorithms are not utilized 
 * properly in OpenSSL3 yet -> Integration won't be seamless and probably 
 * requires quite some (upstream) OpenSSL3 dev investment.
 */

#include "oqs/sig.h"

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "prov/oqsx.h"

// Required OSSL internal defines: I don't think I like this...
// TBD: Need to understand properly separated EVP use...
#define OSSL_MAX_NAME_SIZE 50
#define OSSL_MAX_PROPQUERY_SIZE     256 /* Property query strings */
#define OSSL_MAX_ALGORITHM_ID_SIZE  256 /* AlgorithmIdentifier DER */
#define PROV_R_DIGEST_NOT_ALLOWED                        174
#define PROV_R_INVALID_DIGEST                            122
// internal, but useful OSSL define:
# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))



static OSSL_FUNC_signature_newctx_fn oqs_sig_newctx;
static OSSL_FUNC_signature_sign_init_fn oqs_sig_sign_init;
static OSSL_FUNC_signature_verify_init_fn oqs_sig_verify_init;
static OSSL_FUNC_signature_sign_fn oqs_sig_sign;
static OSSL_FUNC_signature_verify_fn oqs_sig_verify;
static OSSL_FUNC_signature_digest_sign_init_fn oqs_sig_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn oqs_sig_digest_signverify_update;
static OSSL_FUNC_signature_digest_sign_final_fn oqs_sig_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn oqs_sig_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_update_fn oqs_sig_digest_signverify_update;
static OSSL_FUNC_signature_digest_verify_final_fn oqs_sig_digest_verify_final;
static OSSL_FUNC_signature_freectx_fn oqs_sig_freectx;
static OSSL_FUNC_signature_dupctx_fn oqs_sig_dupctx;
static OSSL_FUNC_signature_get_ctx_params_fn oqs_sig_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn oqs_sig_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn oqs_sig_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn oqs_sig_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_md_params_fn oqs_sig_get_ctx_md_params;
static OSSL_FUNC_signature_gettable_ctx_md_params_fn oqs_sig_gettable_ctx_md_params;
static OSSL_FUNC_signature_set_ctx_md_params_fn oqs_sig_set_ctx_md_params;
static OSSL_FUNC_signature_settable_ctx_md_params_fn oqs_sig_settable_ctx_md_params;

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 */

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    OQSX_KEY *sig;

    /*
     * Flag to determine if the hash function can be changed (1) or not (0)
     * Because it's dangerous to change during a DigestSign or DigestVerify
     * operation, this flag is cleared by their Init function, and set again
     * by their Final function.
     */
    unsigned int flag_allow_md : 1;

    char mdname[OSSL_MAX_NAME_SIZE];

    /* The Algorithm Identifier of the combined signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    unsigned char *aid;
    size_t  aid_len;

    /* main digest */
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    size_t mdsize;
    int operation;
} PROV_OQSSIG_CTX;


static size_t oqs_sig_get_md_size(const PROV_OQSSIG_CTX *poqs_sigctx)
{
    printf("OQS SIG provider: get_med_size called\n");
    if (poqs_sigctx->md != NULL)
        return EVP_MD_size(poqs_sigctx->md);
    return 0;
}

static void *oqs_sig_newctx(void *provctx, const char *propq)
{
    PROV_OQSSIG_CTX *poqs_sigctx;

    printf("OQS SIG provider: newctx called\n");

    poqs_sigctx = OPENSSL_zalloc(sizeof(PROV_OQSSIG_CTX));
    if (poqs_sigctx == NULL)
        return NULL;

    poqs_sigctx->libctx = ((PROV_OQS_CTX*)provctx)->libctx;
    poqs_sigctx->flag_allow_md = 0; // TBC
    if (propq != NULL && (poqs_sigctx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(poqs_sigctx);
        poqs_sigctx = NULL;
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    }
    return poqs_sigctx;
}

/*
 * Internal library code deals with NIDs, so we need to translate from a name.
 * We do so using EVP_MD_is_a(), and therefore need a name to NID map.
 */
static int digest_md_to_nid(const EVP_MD *md, const OSSL_ITEM *it, size_t it_len)
{
    size_t i;

    if (md == NULL)
        return NID_undef;

    for (i = 0; i < it_len; i++)
        if (EVP_MD_is_a(md, it[i].ptr))
            return (int)it[i].id;
    return NID_undef;
}

/*
 * Retrieve one of the FIPs approved hash algorithms by nid.
 * See FIPS 180-4 "Secure Hash Standard" and FIPS 202 - SHA-3.
 */
static int digest_get_approved_nid(const EVP_MD *md)
{
    static const OSSL_ITEM name_to_nid[] = {
        { NID_sha1,      OSSL_DIGEST_NAME_SHA1      },
        { NID_sha224,    OSSL_DIGEST_NAME_SHA2_224  },
        { NID_sha256,    OSSL_DIGEST_NAME_SHA2_256  },
        { NID_sha384,    OSSL_DIGEST_NAME_SHA2_384  },
        { NID_sha512,    OSSL_DIGEST_NAME_SHA2_512  },
        { NID_sha512_224, OSSL_DIGEST_NAME_SHA2_512_224 },
        { NID_sha512_256, OSSL_DIGEST_NAME_SHA2_512_256 },
        { NID_sha3_224,  OSSL_DIGEST_NAME_SHA3_224  },
        { NID_sha3_256,  OSSL_DIGEST_NAME_SHA3_256  },
        { NID_sha3_384,  OSSL_DIGEST_NAME_SHA3_384  },
        { NID_sha3_512,  OSSL_DIGEST_NAME_SHA3_512  },
    };

    return digest_md_to_nid(md, name_to_nid, OSSL_NELEM(name_to_nid));
}


static int oqs_sig_setup_md(PROV_OQSSIG_CTX *ctx,
                        const char *mdname, const char *mdprops)
{
    printf("OQS SIG provider: setup_md called\n");
    if (mdprops == NULL)
        mdprops = ctx->propq;

    if (mdname != NULL) {
        //int sha1_allowed = (ctx->operation != EVP_PKEY_OP_SIGN);
        //WPACKET pkt;
        EVP_MD *md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
        int md_nid = digest_get_approved_nid(md);
        size_t mdname_len = strlen(mdname);

        if (md == NULL || md_nid == NID_undef) {
            if (md == NULL)
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                               "%s could not be fetched", mdname);
            if (md_nid == NID_undef)
                ERR_raise_data(ERR_LIB_PROV, PROV_R_DIGEST_NOT_ALLOWED,
                               "digest=%s", mdname);
            if (mdname_len >= sizeof(ctx->mdname))
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                               "%s exceeds name buffer length", mdname);
            EVP_MD_free(md);
            return 0;
        }

        EVP_MD_CTX_free(ctx->mdctx);
        EVP_MD_free(ctx->md);

        /*
         * TODO(3.0) Should we care about DER writing errors?
         * All it really means is that for some reason, there's no
         * AlgorithmIdentifier to be had, but the operation itself is
         * still valid, just as long as it's not used to construct
         * anything that needs an AlgorithmIdentifier.
         */
        ctx->aid_len = 0;
/* TBC: Get OIDs
        if (WPACKET_init_der(&pkt, ctx->aid_buf, sizeof(ctx->aid_buf))
            && ossl_DER_w_algorithmIdentifier_DSA_with_MD(&pkt, -1, ctx->sig,
                                                          md_nid)
            && WPACKET_finish(&pkt)) {
            WPACKET_get_total_written(&pkt, &ctx->aid_len);
            ctx->aid = WPACKET_get_curr(&pkt);
        }
        WPACKET_cleanup(&pkt);
*/

        ctx->mdctx = NULL;
        ctx->md = md;
        OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
    }
    return 1;
}

static int oqs_sig_signverify_init(void *vpoqs_sigctx, void *voqssig, int operation)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    printf("OQS SIG provider: signverify_init called\n");
    if ( poqs_sigctx == NULL
            || voqssig == NULL
            || !oqsx_key_up_ref(voqssig))
        return 0;
    oqsx_key_free(poqs_sigctx->sig);
    poqs_sigctx->sig = voqssig;
    poqs_sigctx->operation = operation;
/* TBD: key check
    if (!oqs_sig_check_key(voqssig, operation == EVP_PKEY_OP_SIGN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }
*/
    return 1;
}

static int oqs_sig_sign_init(void *vpoqs_sigctx, void *voqssig)
{
    printf("OQS SIG provider: sign_init called\n");
    return oqs_sig_signverify_init(vpoqs_sigctx, voqssig, EVP_PKEY_OP_SIGN);
}

static int oqs_sig_verify_init(void *vpoqs_sigctx, void *voqssig)
{
    printf("OQS SIG provider: verify_init called\n");
    return oqs_sig_signverify_init(vpoqs_sigctx, voqssig, EVP_PKEY_OP_VERIFY);
}

static int oqs_sig_sign(void *vpoqs_sigctx, unsigned char *sig, size_t *siglen,
                    size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;
    int ret = 0;
    unsigned int sltmp;
    size_t oqs_sigsize = poqs_sigctx->sig->key.s->length_signature;
    size_t mdsize = oqs_sig_get_md_size(poqs_sigctx);

    printf("OQS SIG provider: sign called\n");

    if (sig == NULL) {
        *siglen = oqs_sigsize;
        return 1;
    }

    if (sigsize < (size_t)oqs_sigsize)
        return 0;

    if (mdsize != 0 && tbslen != mdsize)
        return 0;

    // TBD: ret = oqs_sig_sign_int(0, tbs, tbslen, sig, &sltmp, poqs_sigctx->sig);
    if (ret <= 0)
        return 0;

    *siglen = sltmp;
    return 1;
}

static int oqs_sig_verify(void *vpoqs_sigctx, const unsigned char *sig, size_t siglen,
                      const unsigned char *tbs, size_t tbslen)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;
    size_t mdsize = oqs_sig_get_md_size(poqs_sigctx);

    printf("OQS SIG provider: verify called\n");
    if (mdsize != 0 && tbslen != mdsize)
        return 0;

    // TBD: Actually call into OQS
    //return DSA_verify(0, tbs, tbslen, sig, siglen, poqs_sigctx->sig);
    return 0; // not yet ready....
}

static int oqs_sig_digest_signverify_init(void *vpoqs_sigctx, const char *mdname,
                                      void *voqssig, int operation)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    printf("OQS SIG provider: digest_signverify called\n");

    poqs_sigctx->flag_allow_md = 0;
    if (!oqs_sig_signverify_init(vpoqs_sigctx, voqssig, operation))
        return 0;

    if (!oqs_sig_setup_md(poqs_sigctx, mdname, NULL))
        return 0;

    poqs_sigctx->mdctx = EVP_MD_CTX_new();
    if (poqs_sigctx->mdctx == NULL)
        goto error;

    if (!EVP_DigestInit_ex(poqs_sigctx->mdctx, poqs_sigctx->md, NULL))
        goto error;

    return 1;

 error:
    EVP_MD_CTX_free(poqs_sigctx->mdctx);
    EVP_MD_free(poqs_sigctx->md);
    poqs_sigctx->mdctx = NULL;
    poqs_sigctx->md = NULL;
    return 0;
}

static int oqs_sig_digest_sign_init(void *vpoqs_sigctx, const char *mdname,
                                      void *voqssig)
{
    printf("OQS SIG provider: digest_sign_init called\n");
    return oqs_sig_digest_signverify_init(vpoqs_sigctx, mdname, voqssig, EVP_PKEY_OP_SIGN);
}

static int oqs_sig_digest_verify_init(void *vpoqs_sigctx, const char *mdname, void *voqssig)
{
    printf("OQS SIG provider: get_med_size called\n");
    return oqs_sig_digest_signverify_init(vpoqs_sigctx, mdname, voqssig, EVP_PKEY_OP_VERIFY);
}

int oqs_sig_digest_signverify_update(void *vpoqs_sigctx, const unsigned char *data,
                                 size_t datalen)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    printf("OQS SIG provider: digest_signverify_update called\n");
    if (poqs_sigctx == NULL || poqs_sigctx->mdctx == NULL)
        return 0;

    return EVP_DigestUpdate(poqs_sigctx->mdctx, data, datalen);
}

int oqs_sig_digest_sign_final(void *vpoqs_sigctx, unsigned char *sig, size_t *siglen,
                          size_t sigsize)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    printf("OQS SIG provider: digest_sign_final called\n");
    if (poqs_sigctx == NULL || poqs_sigctx->mdctx == NULL)
        return 0;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to oqs_sig_sign.
     */
    if (sig != NULL) {
        /*
         * TODO(3.0): There is the possibility that some externally provided
         * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
         * but that problem is much larger than just in DSA.
         */
        if (!EVP_DigestFinal_ex(poqs_sigctx->mdctx, digest, &dlen))
            return 0;
    }

    poqs_sigctx->flag_allow_md = 1;

    return oqs_sig_sign(vpoqs_sigctx, sig, siglen, sigsize, digest, (size_t)dlen);
}


int oqs_sig_digest_verify_final(void *vpoqs_sigctx, const unsigned char *sig,
                            size_t siglen)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    printf("OQS SIG provider: digest_verify_final called\n");
    if (poqs_sigctx == NULL || poqs_sigctx->mdctx == NULL)
        return 0;

    /*
     * TODO(3.0): There is the possibility that some externally provided
     * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
     * but that problem is much larger than just in DSA.
     */
    if (!EVP_DigestFinal_ex(poqs_sigctx->mdctx, digest, &dlen))
        return 0;

    poqs_sigctx->flag_allow_md = 1;

    return oqs_sig_verify(vpoqs_sigctx, sig, siglen, digest, (size_t)dlen);
}

static void oqs_sig_freectx(void *vpoqs_sigctx)
{
    PROV_OQSSIG_CTX *ctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    printf("OQS SIG provider: freectx called\n");
    OPENSSL_free(ctx->propq);
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    ctx->propq = NULL;
    ctx->mdctx = NULL;
    ctx->md = NULL;
    ctx->mdsize = 0;
    oqsx_key_free(ctx->sig);
    OPENSSL_free(ctx);
}

static void *oqs_sig_dupctx(void *vpoqs_sigctx)
{
    PROV_OQSSIG_CTX *srcctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;
    PROV_OQSSIG_CTX *dstctx;

    printf("OQS SIG provider: dupctx called\n");

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    dstctx->sig = NULL;
    dstctx->md = NULL;
    dstctx->mdctx = NULL;

    if (srcctx->sig != NULL && !oqsx_key_up_ref(srcctx->sig))
        goto err;
    dstctx->sig = srcctx->sig;

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md))
        goto err;
    dstctx->md = srcctx->md;

    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_new();
        if (dstctx->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx))
            goto err;
    }

    return dstctx;
 err:
    oqs_sig_freectx(dstctx);
    return NULL;
}

static int oqs_sig_get_ctx_params(void *vpoqs_sigctx, OSSL_PARAM *params)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;
    OSSL_PARAM *p;

    printf("OQS SIG provider: get_ctx_params called\n");
    if (poqs_sigctx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p, poqs_sigctx->aid, poqs_sigctx->aid_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, poqs_sigctx->mdname))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *oqs_sig_gettable_ctx_params(ossl_unused void *vctx)
{
    printf("OQS SIG provider: gettable_ctx_params called\n");
    return known_gettable_ctx_params;
}

static int oqs_sig_set_ctx_params(void *vpoqs_sigctx, const OSSL_PARAM params[])
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;
    const OSSL_PARAM *p;

    printf("OQS SIG provider: set_ctx_params called\n");
    if (poqs_sigctx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    /* Not allowed during certain operations */
    if (p != NULL && !poqs_sigctx->flag_allow_md)
        return 0;
    if (p != NULL) {
        char mdname[OSSL_MAX_NAME_SIZE] = "", *pmdname = mdname;
        char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pmdprops = mdprops;
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_PROPERTIES);

        if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;
        if (propsp != NULL
            && !OSSL_PARAM_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))
            return 0;
        if (!oqs_sig_setup_md(poqs_sigctx, mdname, mdprops))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *oqs_sig_settable_ctx_params(ossl_unused void *provctx)
{
    /*
     * TODO(3.0): Should this function return a different set of settable ctx
     * params if the ctx is being used for a DigestSign/DigestVerify? In that
     * case it is not allowed to set the digest size/digest name because the
     * digest is explicitly set as part of the init.
     * NOTE: Ideally we would check poqs_sigctx->flag_allow_md, but this is
     * problematic because there is no nice way of passing the
     * PROV_OQSSIG_CTX down to this function...
     * Because we have API's that dont know about their parent..
     * e.g: EVP_SIGNATURE_gettable_ctx_params(const EVP_SIGNATURE *sig).
     * We could pass NULL for that case (but then how useful is the check?).
     */
    printf("OQS SIG provider: settable_ctx_params called\n");
    return known_settable_ctx_params;
}

static int oqs_sig_get_ctx_md_params(void *vpoqs_sigctx, OSSL_PARAM *params)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    printf("OQS SIG provider: get_ctx_md_params called\n");
    if (poqs_sigctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_get_params(poqs_sigctx->mdctx, params);
}

static const OSSL_PARAM *oqs_sig_gettable_ctx_md_params(void *vpoqs_sigctx)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    printf("OQS SIG provider: gettable_ctx_md_params called\n");
    if (poqs_sigctx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(poqs_sigctx->md);
}

static int oqs_sig_set_ctx_md_params(void *vpoqs_sigctx, const OSSL_PARAM params[])
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    printf("OQS SIG provider: set_ctx_md_params called\n");
    if (poqs_sigctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_set_params(poqs_sigctx->mdctx, params);
}

static const OSSL_PARAM *oqs_sig_settable_ctx_md_params(void *vpoqs_sigctx)
{
    PROV_OQSSIG_CTX *poqs_sigctx = (PROV_OQSSIG_CTX *)vpoqs_sigctx;

    if (poqs_sigctx->md == NULL)
        return 0;

    printf("OQS SIG provider: settable_ctx_md_params called\n");
    return EVP_MD_settable_ctx_params(poqs_sigctx->md);
}

// TBD: Templatize for #ALG where/if necessary
const OSSL_DISPATCH oqs_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))oqs_sig_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))oqs_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))oqs_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))oqs_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))oqs_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))oqs_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))oqs_sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))oqs_sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))oqs_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))oqs_sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))oqs_sig_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))oqs_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))oqs_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))oqs_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))oqs_sig_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))oqs_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))oqs_sig_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))oqs_sig_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))oqs_sig_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))oqs_sig_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))oqs_sig_settable_ctx_md_params },
    { 0, NULL }
};
