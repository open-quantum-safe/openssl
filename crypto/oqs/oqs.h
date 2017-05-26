/* crypto/oqs/oqs.h */

#ifndef HEADER_OQS_H
#define HEADER_OQS_H

#ifdef OPENSSL_NO_OQS
#error OQS is disabled.
#endif

#ifdef  __cplusplus
extern "C" {
#endif

/* FIXMEOQS this should be in obj_mac.h (commented out below)
 * but when I do, private key parsing fails. Weird. FIXME */
#define NID_oqs_picnic_default 958

// The order of the following includes matters.

//#include "crypto/crypto.h" /* in openssl/ */

#include <openssl/asn1t.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <oqs/rand.h>
#include <oqs/common.h>
#include <oqs/sig.h>

// #include "crypto/objects/obj_mac.h" /* in openssl/ */
#include "crypto/evp/evp_locl.h" /* in openssl/ */
#include "crypto/asn1/asn1_locl.h" /* in openssl/ */

  /* Adds the OQS algorithm. Should be called after add OPENSSL_add_all_algorithms */
  void OQS_add_all_algorithms();

  /* Shuts down OQS */
  void OQS_shutdown();

/* == internal state/context for EVP OQS
 * Possibly contains a secret key, public key, signature, parameters
 * during runtime
 */
typedef struct
{
  OQS_SIG *s;
  uint8_t *sk;
  uint8_t *pk;
  int references;
  EVP_MD *md;
} OQS_PKEY_CTX;

int EVP_PKEY_set1_OQS(EVP_PKEY *pkey, OQS_PKEY_CTX *key);

#ifdef  __cplusplus
}
#endif

#endif
