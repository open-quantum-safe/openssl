/*
 * Copyright 2016-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

// TBC: OQS license add-on needed?

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
    char *group_name = NULL;

    switch(idx) {
///// OQS_TEMPLATE_FRAGMENT_GROUP_CASES_START

        case 0: group_name = "frodo640aes"; break;
        case 1: group_name = "frodo640shake"; break;
        case 2: group_name = "frodo976aes"; break;
        case 3: group_name = "frodo976shake"; break;
        case 4: group_name = "bike1l1cpa"; break;
        case 5: group_name = "bike1l3cpa"; break;
        case 6: group_name = "kyber512"; break;
        case 7: group_name = "kyber768"; break;
        case 8: group_name = "kyber1024"; break;
        case 9: group_name = "ntru_hps2048509"; break;
        case 10: group_name = "ntru_hps2048677"; break;
        case 11: group_name = "ntru_hps4096821"; break;
        case 12: group_name = "ntru_hrss701"; break;
        case 13: group_name = "lightsaber"; break;
        case 14: group_name = "saber"; break;
        case 15: group_name = "firesaber"; break;
        case 16: group_name = "sidhp434"; break;
        case 17: group_name = "sidhp503"; break;
        case 18: group_name = "sidhp610"; break;
        case 19: group_name = "sidhp751"; break;
        case 20: group_name = "sikep434"; break;
        case 21: group_name = "sikep503"; break;
        case 22: group_name = "sikep610"; break;
        case 23: group_name = "sikep751"; break;
        case 24: group_name = "bike1l1fo"; break;
        case 25: group_name = "bike1l3fo"; break;
        case 26: group_name = "kyber90s512"; break;
        case 27: group_name = "kyber90s768"; break;
        case 28: group_name = "kyber90s1024"; break;
        case 29: group_name = "hqc128"; break;
        case 30: group_name = "hqc192"; break;
        case 31: group_name = "hqc256"; break;
        case 32: group_name = "ntrulpr653"; break;
        case 33: group_name = "ntrulpr761"; break;
        case 34: group_name = "ntrulpr857"; break;
        case 35: group_name = "sntrup653"; break;
        case 36: group_name = "sntrup761"; break;
        case 37: group_name = "sntrup857"; break;
///// OQS_TEMPLATE_FRAGMENT_GROUP_CASES_END
    }
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
///// OQS_TEMPLATE_FRAGMENT_GROUP_CASECOUNT_START
const int OQS_KEMCOUNT = 38;
///// OQS_TEMPLATE_FRAGMENT_GROUP_CASECOUNT_END

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

    ADD_ALL_TESTS(test_oqs_groups, OQS_KEMCOUNT);
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

