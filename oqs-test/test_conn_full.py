import helpers
import oqs_algorithms
import pytest
import sys
import subprocess
import time
import os

@pytest.fixture(params=oqs_algorithms.signatures)
def ossl_server_sig(ossl, ossl_config, test_artifacts_dir, request):
    # Setup: start ossl server
    helpers.gen_keys(ossl, ossl_config, request.param, test_artifacts_dir)
    ossl_server = subprocess.Popen([ossl, 's_server',
                                          '-cert', os.path.join(test_artifacts_dir, '{}_srv.crt'.format(request.param)),
                                          '-key', os.path.join(test_artifacts_dir, '{}_srv.key'.format(request.param)),
                                          '-CAfile', os.path.join(test_artifacts_dir, '{}_CA.crt'.format(request.param)),
                                          '-tls1_3',
                                          '-quiet',
                                          '-accept', '44433'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
    time.sleep(0.5)
    # Run tests
    yield request.param
    # Teardown: stop ossl server
    ossl_server.kill()

@pytest.mark.parametrize('kex_name', oqs_algorithms.key_exchanges)
def test_sig_kem_pair(ossl, ossl_server_sig, test_artifacts_dir, kex_name):
    output = helpers.run_subprocess([ossl, 's_client',
                                           '-curves', kex_name,
                                           '-CAfile', os.path.join(test_artifacts_dir, '{}_CA.crt'.format(ossl_server_sig)),
                                           '-verify_return_error',
                                           '-connect', 'localhost:44433'],
                                    input='Q'.encode())
    if kex_name.startswith('p256'):
        kex_full_name = "{} hybrid".format(kex_name)
    else:
        kex_full_name = kex_name
    if not "Server Temp Key: {}".format(kex_full_name) in output:
        assert False, "Server temp key missing."

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
