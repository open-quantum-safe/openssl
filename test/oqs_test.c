#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/srp.h>
#include <openssl/txt_db.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/provider.h>
#include <openssl/param_build.h>

#include "helpers/ssltestlib.h"
#include "testutil.h"
#include "testutil/output.h"
#include "internal/nelem.h"
#include "internal/ktls.h"
#include "../ssl/ssl_local.h"


static OSSL_LIB_CTX *libctx = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static char *certsdir = NULL;
static char *srpvfile = NULL;
static char *tmpfilename = NULL;


static int test_oqs_groups(int idx)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    // TBD: Iterate through all OQS KEMs:
    const char *group_name = idx == 0 ? "kyber512" : "kyber1024";

    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION,
                                       TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey))
            || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                             NULL, NULL)))
        goto end;

    if (!TEST_true(SSL_set1_groups_list(serverssl, group_name))
            || !TEST_true(SSL_set1_groups_list(clientssl, group_name)))
        goto end;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    testresult = 1;

 end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

int setup_tests(void)
{
    char *modulename;
    char *configfile;

    libctx = OSSL_LIB_CTX_new();
    if (!TEST_ptr(libctx))
        return 0;

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(certsdir = test_get_argument(0))
            || !TEST_ptr(srpvfile = test_get_argument(1))
            || !TEST_ptr(tmpfilename = test_get_argument(2))
            || !TEST_ptr(modulename = test_get_argument(3))
            || !TEST_ptr(configfile = test_get_argument(4)))
        return 0;

    if (!TEST_true(OSSL_LIB_CTX_load_config(libctx, configfile)))
        return 0;

    /* Check we have the expected provider available */
    if (!TEST_true(OSSL_PROVIDER_available(libctx, modulename)))
        return 0;

    cert = test_mk_file_path(certsdir, "servercert.pem");
    if (cert == NULL)
        goto err;

    privkey = test_mk_file_path(certsdir, "serverkey.pem");
    if (privkey == NULL)
        goto err;

    ADD_ALL_TESTS(test_oqs_groups, 2);
    return 1;

 err:
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    return 0;
}

void cleanup_tests(void)
{
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    bio_s_mempacket_test_free();
    bio_s_always_retry_free();
    OSSL_LIB_CTX_free(libctx);
}

