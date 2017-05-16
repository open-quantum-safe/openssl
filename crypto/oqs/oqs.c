#define UNUSED __attribute__((unused))

#include <openssl/asn1t.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <oqs/rand.h>
#include <oqs/common.h>
#include <oqs/sig.h>

#include "oqs.h"

/* OQS note: the content of this file should be distributed in the OpenSSL
 * code base to avoid a manual registration of the OQS algs, but this makes
 * it simple to develop and test.
 *
 * Error codes should be reviewed and functions defined for the OQSerr macro. 
 *
 * The code needs to be generalized to support more than one sig alg.
 */

int OQS_up_ref(OQS_PKEY_CTX *key)
{
  int i = CRYPTO_add(&key->references, 1, CRYPTO_LOCK_OQS);
  return ((i > 1) ? 1 : 0);
}

int EVP_PKEY_set1_OQS(EVP_PKEY *pkey, OQS_PKEY_CTX *key)
{             
  int ret = EVP_PKEY_assign(pkey, EVP_PKEY_OQS, key);
  if(ret) OQS_up_ref(key);
  return ret;
}             

int pkey_oqs_init(EVP_PKEY_CTX *ctx)
{
  OQS_PKEY_CTX *oqs  = OPENSSL_malloc(sizeof(OQS_PKEY_CTX));
  if (!oqs) {
    return 0;
  }
  oqs->s = 0;
  oqs->sk = 0;
  oqs->pk = 0;
  oqs->references = 0;
  oqs->md = 0;
  ctx->data = oqs;
  return 1;
}

int pkey_oqs_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)

{
  OQS_PKEY_CTX *dctx, *sctx;
  if (!pkey_oqs_init(dst)) {
    return 0;
  }
  // FIXMEOQS: are these copies safe? should I call OQS_up_ref?

  sctx = src->data;
  dctx = dst->data;
  dctx->s = sctx->s;
  dctx->sk = sctx->sk;
  dctx->pk = sctx->pk;
  dctx->references = sctx->references;
  dctx->md = sctx->md;
  return 1;	
}

void pkey_oqs_cleanup(EVP_PKEY_CTX *ctx)
{
  OQS_PKEY_CTX *oqs = ctx->data;
  if (oqs) {
    OPENSSL_free(oqs);
  }
}

int pkey_oqs_sign_init(EVP_PKEY_CTX *ctx)
{
  OQS_PKEY_CTX *oqs = (OQS_PKEY_CTX*) ctx->pkey->pkey.ptr;
  if (!oqs->sk) {
    OQSerr(0, ERR_R_FATAL);
    return 0;
  }
  return 1;
}

int pkey_oqs_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
		  const unsigned char *tbs, size_t tbslen)
{
  OQS_PKEY_CTX *oqs_ctx = (OQS_PKEY_CTX*) ctx->pkey->pkey.ptr;
  if (!oqs_ctx || !oqs_ctx->s || !oqs_ctx->sk ) {
    OQSerr(0, ERR_R_FATAL);
    return 0;
  }
  if (*siglen != oqs_ctx->s->max_sig_len) {
    OQSerr(0, ERR_R_FATAL);
    return 0;
  }

  if (OQS_SIG_sign(oqs_ctx->s, oqs_ctx->sk, tbs, tbslen, sig, siglen) != 1) {
    OQSerr(0, ERR_R_FATAL);
    return 0;
  }

  return 1;
}

int pkey_oqs_verify(EVP_PKEY_CTX *ctx,
		    const unsigned char *sig, size_t siglen,
		    const unsigned char *tbs, size_t tbslen)
{
  OQS_PKEY_CTX *oqs_ctx = (OQS_PKEY_CTX*) ctx->pkey->pkey.ptr;
  if (!oqs_ctx || !oqs_ctx->s  || !oqs_ctx->pk || sig == NULL || tbs == NULL) {
    OQSerr(0, ERR_R_FATAL);
    return 0;
  }

  if (OQS_SIG_verify(oqs_ctx->s, oqs_ctx->pk, tbs, tbslen, sig, siglen) != 1) {
    OQSerr(0, ERR_R_FATAL);
    return 0;
  }

  return 1;
}

int oqs_pkey_ctx_init(OQS_PKEY_CTX* ctx, enum OQS_SIG_algid algid) {
  if (ctx == NULL) {
    goto err;
  }

  OQS_RAND *rand = NULL;
  OQS_SIG *s;
  uint8_t *priv = NULL;
  uint8_t *pub = NULL;

  rand = OQS_RAND_new(OQS_RAND_alg_default); // TODO: don't hardcode
  if (rand == NULL) {
    goto err;
  }
  s = OQS_SIG_new(rand, algid);
  if (s == NULL) {
    goto err;
  }
  priv = OPENSSL_malloc(s->priv_key_len);
  if (priv == NULL) {
    goto err;
  }
  pub = OPENSSL_malloc(s->pub_key_len);
  if (pub == NULL) {
    goto err;
  }
  ctx->s = s;
  ctx->sk = priv;
  ctx->pk = pub;

  return 1;

 err:
  if (rand) { OQS_RAND_free(rand); }
  if (s) { OQS_SIG_free(s); }
  if (priv) { OPENSSL_free(priv); }
  if (pub) { OPENSSL_free(pub); }
  return 0;
}

void oqs_pkey_ctx_free(OQS_PKEY_CTX* ctx) {
  if (ctx == NULL) {
    return;
  }
  if (ctx->s->rand) { OQS_RAND_free(ctx->s->rand); }
  if (ctx->s) { OQS_SIG_free(ctx->s); }
  if (ctx->sk) { OPENSSL_free(ctx->sk); }
  if (ctx->pk) { OPENSSL_free(ctx->pk); }
  return;
}

int pkey_oqs_keygen_init(EVP_PKEY_CTX *ctx)
{
  if (ctx == NULL) {
    return 0;
  }
  OQS_PKEY_CTX *oqs_ctx = ctx->data;
  return oqs_pkey_ctx_init(oqs_ctx, OQS_SIG_picnic_default); // TODO: don't hardcode
}

int pkey_oqs_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
  OQS_PKEY_CTX *oqs_ctx = (OQS_PKEY_CTX*) ctx->data;
  if (!oqs_ctx || !oqs_ctx->s || !oqs_ctx->sk || !oqs_ctx->pk ) {
    goto err;
  }
  if (OQS_SIG_keygen(oqs_ctx->s, oqs_ctx->sk, oqs_ctx->pk) != 1) {
    goto err;
  }
  
  pkey->pkey.ptr = (void*) oqs_ctx;
  EVP_PKEY_set1_OQS(pkey, oqs_ctx);
  return 1;

 err:
  return 0;
}

static int pkey_oqs_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
  OQS_PKEY_CTX *oqs = ctx->data;
  switch(type)
    {
    case EVP_PKEY_CTRL_MD:
      if (EVP_MD_type((const EVP_MD *)p2) != NID_sha256 &&
	  EVP_MD_type((const EVP_MD *)p2) != NID_sha384 &&
	  EVP_MD_type((const EVP_MD *)p2) != NID_sha512)
	{
	  OQSerr(0, ERR_R_FATAL);
	  return 0;
	}
      oqs->md = (EVP_MD *) p2;
      return 1;
    case EVP_PKEY_CTRL_DIGESTINIT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
    case EVP_PKEY_CTRL_CMS_SIGN:
      return 1; 
    case EVP_PKEY_CTRL_PEER_KEY:
	  OQSerr(0, ERR_R_FATAL);
	  return -2; // error code returned by calling function in p_lib.c
    default:
      return -2;
    }
  return 0;
}

// The EVP OQS methods; 0s are unused
static EVP_PKEY_METHOD oqs_pmeth =
    {
      NID_oqs_picnic_default,
      EVP_PKEY_FLAG_AUTOARGLEN,
      pkey_oqs_init,
      pkey_oqs_copy,
      pkey_oqs_cleanup,
      0, // paramgen_init
      0, //paramgen
      pkey_oqs_keygen_init,
      pkey_oqs_keygen,
      pkey_oqs_sign_init,
      pkey_oqs_sign,
      0, //verify_init
      pkey_oqs_verify,
      0, //verify_recover_init
      0, //verify_recover
      0, //signctx_init
      0, //signctx
      0, //verifyctx_init
      0, //verifyctx
      0, //encrypt_init
      0, //encrypt
      0, //decrypt_init
      0, //decrypt
      0, //derive_init
      0, //derive
      pkey_oqs_ctrl,
      0 // pkey_oqs_ctrl_str
    };

/////////////////////////////////////////////////////////
// ASN.1 artifacts
/////////////////////////////////////////////////////////

// Secret key
typedef struct {
  long algid;
  ASN1_OCTET_STRING *sk;
  ASN1_OCTET_STRING *pk;
} oqsasn1sk;
// Public key
typedef struct {
  long algid;
  ASN1_OCTET_STRING *pk;	
} oqsasn1pk;

ASN1_SEQUENCE(oqsasn1sk) ={
  ASN1_SIMPLE(oqsasn1sk,algid,LONG),
  ASN1_SIMPLE(oqsasn1sk,sk,ASN1_OCTET_STRING),
  ASN1_SIMPLE(oqsasn1sk,pk,ASN1_OCTET_STRING)
}  ASN1_SEQUENCE_END(oqsasn1sk)
DECLARE_ASN1_FUNCTIONS(oqsasn1sk)

ASN1_SEQUENCE(oqsasn1pk) ={
  ASN1_SIMPLE(oqsasn1pk,algid,LONG),
  ASN1_SIMPLE(oqsasn1pk,pk,ASN1_OCTET_STRING)
}  ASN1_SEQUENCE_END(oqsasn1pk)
DECLARE_ASN1_FUNCTIONS(oqsasn1pk)

IMPLEMENT_ASN1_FUNCTIONS(oqsasn1sk)
IMPLEMENT_ASN1_FUNCTIONS(oqsasn1pk)

ASN1_OCTET_STRING *asn1_octet_string_from( unsigned char *d, int len)
{
  ASN1_OCTET_STRING *a = ASN1_OCTET_STRING_new();
  if (!ASN1_OCTET_STRING_set(a, d, len)) {
    return 0;
  }
  return a;
}

static int oqs_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
  OQS_PKEY_CTX *oqs = (OQS_PKEY_CTX*) pkey->pkey.ptr;
  void *pval = NULL;
  int ptype = V_ASN1_UNDEF;
  ASN1_STRING *penc = ASN1_STRING_new(); // FIXMEOQS: leaks! can't free it otherwise fails later
  if (!oqs->pk) {
    OQSerr(0, ERR_R_FATAL);
    return 0;
  }
  oqsasn1pk asn1;
  asn1.algid = OQS_SIG_picnic_default; // FIXMEOQS: don't hardcode
  asn1.pk = asn1_octet_string_from(oqs->pk, oqs->s->pub_key_len);
  if (!asn1.pk) {
    OQSerr(0, ERR_R_FATAL);
    return 0;
  }
  // i2d_TYPE converts an ASN.1 object in an internal standardized form
  // to its DER encoding and stuffs it into a character string
  penc->length = i2d_oqsasn1pk(&asn1,&penc->data);
  return X509_PUBKEY_set0_param(pk, OBJ_nid2obj(NID_oqs_picnic_default),
				ptype, pval, penc->data, penc->length);
}

static int oqs_priv_decode(EVP_PKEY *pkey, PKCS8_PRIV_KEY_INFO *p8)
{
  int rc;
  const unsigned char *p=NULL;
  int plen;
  PKCS8_pkey_get0(NULL, &p, &plen, NULL, p8);

  oqsasn1sk a;
  oqsasn1sk *asn1=&a;
  a.sk = ASN1_OCTET_STRING_new();
  a.pk = ASN1_OCTET_STRING_new();

  // d2i_TYPE converts an ASN.1 object from its DER encoded form to its
  // internal standardized form. 
  d2i_oqsasn1sk(&asn1,(const unsigned char**)&p, plen);

  OQS_PKEY_CTX *oqs_ctx = (OQS_PKEY_CTX*) OPENSSL_malloc(sizeof(OQS_PKEY_CTX)); // FIXMEOQS: leaks
  oqs_pkey_ctx_init(oqs_ctx, asn1->algid);
  memcpy(oqs_ctx->sk, asn1->sk->data, oqs_ctx->s->priv_key_len); // FIXMEOQS: should the len come from the asn1 struct
  memcpy(oqs_ctx->pk, asn1->pk->data, oqs_ctx->s->pub_key_len);
  rc = EVP_PKEY_set1_OQS(pkey, oqs_ctx);

  // cleanup:
  if (a.sk) { ASN1_OCTET_STRING_free(a.sk); }
  if (a.pk) { ASN1_OCTET_STRING_free(a.pk); }

  return rc;
}

static int oqs_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
  unsigned char *p;
  int pklen;
  X509_ALGOR *palg;

  if (!X509_PUBKEY_get0_param(NULL,(const unsigned char**) &p, &pklen, &palg, pubkey))
    {
      OQSerr(0, ERR_R_FATAL);
      return 0;
    }

  oqsasn1pk a;
  oqsasn1pk *asn1=&a;
  a.pk = ASN1_OCTET_STRING_new();
  d2i_oqsasn1pk(&asn1,(const unsigned char **)&p, pklen);
  OQS_PKEY_CTX *oqs_ctx = OPENSSL_malloc(sizeof(OQS_PKEY_CTX)); // FIXMEOQS: leaks
  oqs_pkey_ctx_init(oqs_ctx, asn1->algid);
  memcpy(oqs_ctx->pk, asn1->pk->data, oqs_ctx->s->pub_key_len);
  return EVP_PKEY_set1_OQS(pkey, oqs_ctx);
}

static int oqs_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
  int rc;
  ASN1_INTEGER *params = NULL;
  ASN1_STRING *prkey  = NULL;

  OQS_PKEY_CTX *oqs = (OQS_PKEY_CTX*)pkey->pkey.ptr;
  if (!oqs || !oqs->sk)
    {
      OQSerr(0, ERR_R_FATAL);
      goto err;
    }

  oqsasn1sk asn1;
  asn1.algid = OQS_SIG_picnic_default; // FIXMEOQS: don't hardcode
  asn1.sk = asn1_octet_string_from(oqs->sk, oqs->s->priv_key_len);
  if (!asn1.sk) {
    OQSerr(0, ERR_R_FATAL);
    goto err;
  }
  asn1.pk = asn1_octet_string_from(oqs->pk, oqs->s->pub_key_len);
  if (!asn1.pk) {
    OQSerr(0, ERR_R_FATAL);
    goto err;
  }
  prkey = ASN1_STRING_new(); // FIXMEOQS: leaks! can't free it here otherwise fails later (in apps/genoqs.c)
  prkey->length = i2d_oqsasn1sk(&asn1,&prkey->data);
  if (prkey->length <= 0)
    {
      OQSerr(0, ERR_R_FATAL);
      goto err;
    }

  params=ASN1_INTEGER_new();
  ASN1_INTEGER_set(params,NID_oqs_picnic_default);
  if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_oqs_picnic_default), 0,
		       V_ASN1_NULL,0, prkey->data, prkey->length))
    {
      OQSerr(0, ERR_R_FATAL);
      goto err;
    }

    rc =1;
    goto cleanup;

 err:
  rc = 0;

 cleanup:
  if (asn1.sk) { ASN1_OCTET_STRING_free(asn1.sk); }
  if (asn1.pk) { ASN1_OCTET_STRING_free(asn1.pk); }
  if (params) { ASN1_INTEGER_free(params); }
  return rc;
}

// Returns number of bytes per signatures as per the reference implementation
// FIXMEOQS: this seems wrong. Should return oqs->s->pub_key_len, but SSL code
// depends on this; should fix it so it doesn't call this function.
static int oqs_pkey_size(const EVP_PKEY *pkey)
{
  OQS_PKEY_CTX *oqs = (OQS_PKEY_CTX*)pkey->pkey.ptr;
  int siglen = oqs->s->max_sig_len;
  return siglen;
}

static void oqs_pkey_free(EVP_PKEY *pkey)
{
  if (pkey == NULL) return;
  OQS_PKEY_CTX *oqs = (OQS_PKEY_CTX*)pkey->pkey.ptr;
  oqs_pkey_ctx_free(oqs);
  return;
}

// This function is called from the X509 context and prints the public key
// as we know them from x509 certs xx:xx:xx:xx...
static int oqs_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
			 UNUSED ASN1_PCTX *ctx)
{
  OQS_PKEY_CTX *oqs = (OQS_PKEY_CTX*)pkey->pkey.ptr;
  unsigned char *pk = oqs->pk;
  int i;
  for (i = 0; i < oqs->s->pub_key_len; i++){
    if (i % 16 == 0) {
      if (i) BIO_write(bp, "\n", 1);
      int j;
      for (j=0; j < indent; j++)
	BIO_write(bp, " ", 1);
    }
    char buf[10];
    sprintf(buf, "%02x:", pk[i]);
    BIO_write(bp, buf, 3);
  }
  BIO_write(bp,"\n",1);
  return 1;	
}

// Prints the signature for the X.509 certificate as in openssl x509 -text
static int oqs_sig_print(BIO *bp, UNUSED const X509_ALGOR *sigalg,
			 const ASN1_STRING *sig, int indent, UNUSED ASN1_PCTX *pctx)
{
  if (!sig)
    {
      if (BIO_puts(bp, "\n") <= 0) return 0; else return 1;
    }

  ASN1_STRING *ssig = (ASN1_STRING*) sig;

  if (BIO_write(bp, "\n", 1) != 1)
    {
      OQSerr(0, ERR_R_FATAL);
      return 0;
    }
  int i = 0;
  for (i = 0; (i < ssig->length); i++) {
    if (i % 32 == 0) {
      if (i) BIO_write(bp, "\n", 1);
      int j = 0;
      for (j = 0; j < indent; j++)
	BIO_write(bp, " ", 1);
    }
    char buf[4];
    sprintf(buf, "%02x:", ssig->data[i]);
    BIO_write(bp, buf, 3);
  }
  BIO_write(bp,"\n",1);
  return 1;
}

int oqs_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
  OQS_PKEY_CTX *oqsa = (OQS_PKEY_CTX*)a->pkey.ptr;
  OQS_PKEY_CTX *oqsb = (OQS_PKEY_CTX*)b->pkey.ptr;
  return memcmp(oqsa->pk,oqsb->pk,oqsa->s->pub_key_len) == 0;
}

// The EVP ASN1 OQS methods; 0s are unused
static EVP_PKEY_ASN1_METHOD oqs_ameth =
  {
      NID_oqs_picnic_default, // pkey_id
      NID_oqs_picnic_default, // pkey_base_id
      0, // pkey_flags
      "PicnicWithSHA256", // pem_str
      "OpenSSL OQS method", // info
      oqs_pub_decode, // pub_decode
      oqs_pub_encode, // pub_encode
      oqs_pub_cmp, // pub_cmp
      oqs_pub_print, // pub_print
      oqs_priv_decode, // priv_decode
      oqs_priv_encode, // priv_encode
      0, // priv_print
      oqs_pkey_size, // pkey_size
      0, // pkey_bits
      0, // param_decode
      0, // param_encode
      0, // param_missing
      0, // param_copy
      0, // param_cmp
      0, // param_print
      oqs_sig_print, // sig_print
      oqs_pkey_free, // pkey_free
      0, // pkey_ctrl
      /* Legacy functions for old PEM */
      0, // old_priv_decode
      0, // old_priv_encode
      /* Custom ASN1 signature verification */
      0, // item_verify
      0 // item_sign
  };

void OQS_add_all_algorithms()
{
  // add the OQS methods
  EVP_PKEY_asn1_add0(&oqs_ameth);
  EVP_PKEY_meth_add0(&oqs_pmeth);
  if (!OBJ_create("1 3 6 1 4 1 8301 3 1 3 3 1", "PicnicWithSHA256", "PicnicWithSHA256")) {
      OQSerr(0, ERR_R_FATAL);
      return;
    }

  if(!OBJ_add_sigid(NID_oqs_picnic_default, NID_sha256, NID_oqs_picnic_default /*FIXMEOQS: why the double NID_oqs_picnic_default*/))
    {
      OQSerr(0, ERR_R_FATAL);
      return;
    }
}

void OQS_shutdown()
{
  /* OQS sig hack: calling modified versions of the following functions to free
   * leaky static variables. Should fix that properly by adding OpenSSL functions
   */
    EVP_PKEY_asn1_add0(NULL);
    EVP_PKEY_meth_add0(NULL);
    return;
}
