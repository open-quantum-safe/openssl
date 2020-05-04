import oqs_algorithms
import helpers
import pytest
import sys
import subprocess
import time
import os

@pytest.fixture()
def ossl_server_port(ossl, ossl_config, test_artifacts_dir):
    # Setup: start ossl server
    helpers.gen_keys(ossl, ossl_config, 'oqs_sig_default', test_artifacts_dir)
    ossl_server = subprocess.Popen([ossl, 's_server',
                                          '-cert', os.path.join(test_artifacts_dir, 'oqs_sig_default_srv.crt'),
                                          '-key', os.path.join(test_artifacts_dir, 'oqs_sig_default_srv.key'),
                                          '-CAfile', os.path.join(test_artifacts_dir, 'oqs_sig_default_CA.crt'),
                                          '-tls1_3',
                                          '-quiet',
                                          '-accept', '44433'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
    time.sleep(0.5)
    # Run tests
    yield '44433'
    # Teardown: stop ossl server
    ossl_server.kill()

@pytest.mark.parametrize('kex_name', oqs_algorithms.key_exchanges)
def test_kem(ossl, ossl_server_port, test_artifacts_dir, kex_name):
    output = helpers.run_subprocess([ossl, 's_client',
                                           '-curves', kex_name,
                                           '-CAfile', os.path.join(test_artifacts_dir, 'oqs_sig_default_CA.crt'),
                                           '-verify_return_error',
                                           '-connect', 'localhost:{}'.format(ossl_server_port)],
                                    input='Q'.encode())
    if kex_name.startswith('p256'):
        kex_full_name = "{} hybrid".format(kex_name)
    else:
        kex_full_name = kex_name
    if not "Server Temp Key: {}".format(kex_full_name) in output:
        print(output)
        assert False, "Server temp key missing."

@pytest.mark.parametrize('sig_name', oqs_algorithms.signatures)
def test_sig(ossl, ossl_config, test_artifacts_dir, sig_name):
    helpers.gen_keys(ossl, ossl_config, sig_name, test_artifacts_dir)
    ossl_server = subprocess.Popen([ossl, 's_server',
                                          '-cert', os.path.join(test_artifacts_dir, '{}_srv.crt'.format(sig_name)),
                                          '-key', os.path.join(test_artifacts_dir, '{}_srv.key'.format(sig_name)),
                                          '-CAfile', os.path.join(test_artifacts_dir, '{}_CA.crt'.format(sig_name)),
                                          '-tls1_3',
                                          '-quiet',
                                          '-accept', '44433'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
    time.sleep(0.5)
    output = helpers.run_subprocess([ossl, 's_client',
                                           '-curves', 'oqs_kem_default',
                                           '-CAfile', os.path.join(test_artifacts_dir, '{}_CA.crt'.format(sig_name)),
                                           '-verify_return_error',
                                           '-connect', 'localhost:44433'],
                                    input='Q'.encode())
    ossl_server.kill()
    if not "Server Temp Key: oqs_kem_default" in output:
        assert False, "Server temp key missing."

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)
